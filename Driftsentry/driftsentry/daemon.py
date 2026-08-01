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
import time
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
        self.jobs: dict[str, dict[str, Any]] = {}
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.paused = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._force: set[str] = set()
        # Created inside the loop; guards every probe session so only one runs
        # at a time. See submit() for why that matters.
        self._probe_lock: asyncio.Lock = None  # type: ignore[assignment]
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
            "jobs": list(self.jobs.values()),
            "calibrated": self.calibration_summary(),
        }

    def calibration_summary(self) -> dict[str, Any]:
        """What the threshold is, and whether it can be trusted yet."""
        from driftsentry.calibration import load

        calibration = load()
        if calibration is None:
            return {"present": False,
                    "note": "not calibrated - using a provisional threshold"}
        return {
            "present": True,
            "threshold": calibration.threshold_ratio,
            "observations": calibration.n_observations,
            "servers": calibration.n_servers,
            "far": calibration.empirical_far,
            "weak": calibration.weak,
            "warnings": calibration.warnings,
            "backend": calibration.embedding_backend,
            "created_at": calibration.created_at,
        }

    def recent_alerts(self, limit: int = 20) -> list:
        found = []
        for name in self.alerts.servers():
            found.extend(self.alerts.history(name))
        found.sort(key=lambda a: a.created_at, reverse=True)
        return found[:limit]

    # -- onboarding --------------------------------------------------------
    def start_job(self, kind: str, label: str) -> str:
        """Register a long-running background job the UI can poll.

        Baselining takes minutes - it fires several probes at every safe tool and
        samples each repeatedly. That is far too long for an HTTP request to sit
        open, so the API starts a job, returns immediately, and the dashboard
        follows its progress. Without this the browser would simply time out and
        the user would have no idea whether anything was happening.
        """
        job_id = f"{kind}-{int(time.time() * 1000)}"
        self.jobs[job_id] = {
            "id": job_id, "kind": kind, "label": label, "state": "running",
            "message": "starting...", "started_at": datetime.now(timezone.utc).isoformat(),
            "detail": [],
        }
        # Keep the list short; old finished jobs are noise.
        for old in list(self.jobs)[:-12]:
            if self.jobs[old]["state"] != "running":
                self.jobs.pop(old, None)
        return job_id

    def update_job(self, job_id: str, message: str, detail: str | None = None) -> None:
        job = self.jobs.get(job_id)
        if job:
            job["message"] = message
            if detail:
                job["detail"].append(detail)

    def finish_job(self, job_id: str, ok: bool, message: str) -> None:
        job = self.jobs.get(job_id)
        if job:
            job["state"] = "done" if ok else "failed"
            job["message"] = message
            job["finished_at"] = datetime.now(timezone.utc).isoformat()

    def submit(self, coro) -> None:
        """Run a coroutine on the daemon's own event loop.

        Everything that talks MCP must share ONE event loop. An earlier version
        started each job on a fresh loop in its own thread, which deadlocked the
        process: two loops spawning server subprocesses and writing to the same
        SQLite-backed vector store contend badly, and the API stopped responding
        entirely.

        There is a correctness reason as well as a liveness one. The sandbox
        monitor identifies the server it should watch by diffing this process's
        children before and after launch, so two probe sessions running at once
        would each pick up the other's subprocess and attribute file and network
        activity to the wrong server.
        """
        if self._loop is None:
            raise RuntimeError("daemon is not running")
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    async def connect_server(self, job_id: str, name: str, command: str, args: list[str],
                             cwd: str | None, probes: int, samples: int) -> None:
        """Baseline a new server, then let the scheduler pick it up."""
        from driftsentry.baseline import capture_baseline

        try:
            self.update_job(job_id, f"connecting to {name}...")
            # Serialised against scheduled checks: only one probe session at a time.
            async with self._probe_lock:
                baseline = await capture_baseline(
                    name, command, args, cwd=cwd,
                    n_probes=probes, n_samples=samples,
                )
            self.store.save(baseline)
            probed = [t.tool for t in baseline.tools if t.probed]
            skipped = [t.tool for t in baseline.tools if not t.probed]
            for tool in baseline.tools:
                self.update_job(
                    job_id, f"baselined {name}",
                    f"{tool.tool}: " + ("probed" if tool.probed
                                        else f"not probed - {tool.safety_reason}"),
                )
            self.refresh_servers()
            self.finish_job(
                job_id, True,
                f"{name} connected: {len(probed)} tool(s) baselined, "
                f"{len(skipped)} left to observation",
            )
        except Exception as exc:  # noqa: BLE001 - surface the reason in the UI
            log.warning("connect failed for %s: %s", name, exc)
            self.finish_job(job_id, False, f"{type(exc).__name__}: {exc}")

    async def calibrate(self, job_id: str, repeats: int) -> None:
        """Derive the alert threshold from the servers already trusted."""
        from driftsentry.calibration import save as save_calibration
        from driftsentry.verify import calibrate_servers

        names = [s.name for s in self.servers.values()]

        try:
            self.update_job(job_id, f"probing {len(names)} server(s), {repeats} rounds each...")
            async with self._probe_lock:
                calibration, per_server = await calibrate_servers(
                    names, repeats=repeats, samples_per_probe=2, store=self.store)
            save_calibration(calibration)
            for name, ratios in per_server.items():
                if ratios:
                    self.update_job(job_id, "calibrating",
                                    f"{name}: {len(ratios)} observations, "
                                    f"max ratio {max(ratios):.2f}")
            for warning in calibration.warnings:
                self.update_job(job_id, "calibrating", f"warning: {warning}")
            self.finish_job(
                job_id, True,
                f"threshold set to {calibration.threshold_ratio:.2f} "
                f"from {calibration.n_observations} benign observations",
            )
        except Exception as exc:  # noqa: BLE001
            self.finish_job(job_id, False, f"{type(exc).__name__}: {exc}")

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
        self._probe_lock = asyncio.Lock()
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
                    # Skip this round rather than queue behind a long job: a
                    # connect or calibration can take minutes, and stacking
                    # scheduled checks behind it would produce a burst of stale
                    # probes the moment it finished.
                    if self._probe_lock.locked():
                        continue
                    async with self._probe_lock:
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
