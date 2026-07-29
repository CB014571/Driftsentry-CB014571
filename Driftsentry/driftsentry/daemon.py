"""Phase 6 - the resident daemon: scheduling, state, and the control API.

This is what turns DriftSentry from a command you run into something that is
running. A rug pull happens after approval, so a detector that only checks when
asked cannot see one unless the user happens to ask at the right moment. The
daemon keeps checking on a schedule and holds the answer, so the interface -
dashboard or CLI - only has to read state and issue commands.

Two rules from the roadmap are enforced here:

  * The control plane never touches the data path. The daemon re-probes servers
    out of band, on its own connections. It cannot add latency to a live tool
    call, because it is not in the live tool call.
  * No detection logic lives above this layer. The daemon calls the same
    verify_server() the CLI uses; the dashboard renders whatever comes back. A
    pretty UI therefore cannot flatter the results, which matters when the
    detector's numbers are the thing being marked.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from driftsentry.alerts import AlertStore, build_alerts
from driftsentry.calibration import active_threshold
from driftsentry.policy import PolicyStore
from driftsentry.store import BaselineStore
from driftsentry.verify import verify_server

log = logging.getLogger("driftsentry.daemon")

# How many past checks to keep per server for the drift timeline.
HISTORY = 120


@dataclass
class ServerState:
    """Everything the dashboard needs to know about one server."""

    name: str
    status: str = "unknown"           # ok | watch | alert | error | unknown
    score: float = 0.0
    threshold: float = 1.0
    triggered_by: str | None = None
    last_check: str | None = None
    next_check_in: float = 0.0
    checks: int = 0
    tools: list[dict[str, Any]] = field(default_factory=list)
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY))
    error: str | None = None
    definition_changed: bool = False
    embedding_backend: str = ""
    policy_status: str = "trusted"
    enforce: bool = False
    checking: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "score": round(self.score, 3),
            "threshold": self.threshold,
            "triggered_by": self.triggered_by,
            "last_check": self.last_check,
            "checks": self.checks,
            "tools": self.tools,
            "history": list(self.history),
            "error": self.error,
            "definition_changed": self.definition_changed,
            "embedding_backend": self.embedding_backend,
            "policy_status": self.policy_status,
            "enforce": self.enforce,
            "checking": self.checking,
        }


class Daemon:
    """Owns the schedule, the current state, and the command surface."""

    def __init__(self, interval: float = 20.0, samples_per_probe: int = 1,
                 monitor_sandbox: bool = True) -> None:
        self.interval = interval
        self.samples_per_probe = samples_per_probe
        self.monitor_sandbox = monitor_sandbox
        self.store = BaselineStore()
        self.alerts = AlertStore()
        self.policy = PolicyStore()
        self.servers: dict[str, ServerState] = {}
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.paused = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._force: set[str] = set()
        self.refresh_servers()

    # -- state -------------------------------------------------------------
    def refresh_servers(self) -> None:
        """Pick up any baselines that appeared since we started."""
        for name in self.store.list_servers():
            if name not in self.servers:
                policy = self.policy.get(name)
                self.servers[name] = ServerState(
                    name=name,
                    policy_status=policy.status,
                    enforce=policy.enforce,
                )

    def snapshot(self) -> dict[str, Any]:
        threshold, source = active_threshold()
        return {
            "started_at": self.started_at,
            "interval": self.interval,
            "paused": self.paused,
            "threshold": threshold,
            "threshold_source": source,
            "servers": [s.to_dict() for s in self.servers.values()],
            "alerts": [a.to_dict() for a in self.recent_alerts(12)],
        }

    def recent_alerts(self, limit: int = 20) -> list:
        found = []
        for name in self.alerts.servers():
            found.extend(self.alerts.history(name))
        found.sort(key=lambda a: a.created_at, reverse=True)
        return found[:limit]

    # -- commands ----------------------------------------------------------
    def scan_now(self, name: str) -> None:
        self._force.add(name)

    def set_policy(self, name: str, status: str, enforce: bool | None = None) -> None:
        updated = self.policy.update(name, status=status, enforce=enforce,
                                     reason=f"set from the dashboard")
        if name in self.servers:
            self.servers[name].policy_status = updated.status
            self.servers[name].enforce = updated.enforce

    def toggle_pause(self) -> bool:
        self.paused = not self.paused
        return self.paused

    # -- the scheduler -----------------------------------------------------
    async def _check(self, state: ServerState) -> None:
        baseline = self.store.load(state.name)
        if baseline is None:
            state.status, state.error = "error", "no baseline"
            return
        state.checking = True
        try:
            report = await verify_server(
                baseline,
                samples_per_probe=self.samples_per_probe,
                monitor_sandbox=self.monitor_sandbox,
            )
        except Exception as exc:  # noqa: BLE001 - one bad cycle must not stop the daemon
            state.status, state.error = "error", f"{type(exc).__name__}: {exc}"
            log.warning("%s: check failed: %s", state.name, exc)
            return
        finally:
            state.checking = False

        state.error = None
        state.status = report.verdict
        state.score = report.score
        state.threshold = report.threshold_ratio
        state.triggered_by = report.triggered_by
        state.definition_changed = report.definition_changed
        state.embedding_backend = report.embedding_backend
        state.last_check = datetime.now(timezone.utc).isoformat()
        state.checks += 1
        state.tools = [
            {"tool": t.tool, "verdict": t.verdict, "score": round(t.score, 3),
             "triggered_by": t.triggered_by}
            for t in report.tools
        ]
        state.history.append({"t": state.last_check, "score": round(report.score, 3),
                              "verdict": report.verdict})

        # Raise an alert only on the TRANSITION into alert, not on every cycle
        # while an attack continues - otherwise a sustained attack floods the
        # feed and the operator stops reading it.
        was = getattr(state, "_last_verdict", None)
        if report.verdict == "alert" and was != "alert":
            for alert in build_alerts(report):
                self.alerts.append(alert)
            self.policy.update(state.name, status="quarantined",
                               reason=report.triggered_by or "drift detected")
            state.policy_status = "quarantined"
        state._last_verdict = report.verdict  # type: ignore[attr-defined]

    async def _run(self) -> None:
        log.info("daemon started; interval %.0fs", self.interval)
        elapsed: dict[str, float] = {}
        tick = 1.0
        while True:
            self.refresh_servers()
            for name, state in list(self.servers.items()):
                forced = name in self._force
                elapsed[name] = elapsed.get(name, self.interval) + tick
                due = elapsed[name] >= self.interval
                if forced or (due and not self.paused):
                    self._force.discard(name)
                    elapsed[name] = 0.0
                    await self._check(state)
                state.next_check_in = max(0.0, self.interval - elapsed.get(name, 0.0))
            await asyncio.sleep(tick)

    def start(self) -> None:
        """Run the scheduler on its own thread, so a UI can own the main one."""
        def _target() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._run())
            except Exception as exc:  # pragma: no cover
                log.error("daemon stopped: %s", exc)

        self._thread = threading.Thread(target=_target, name="driftsentry-daemon", daemon=True)
        self._thread.start()
