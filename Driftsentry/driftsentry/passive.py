"""Passive observation of genuine MCP traffic.

Active probing has a structural blind spot that no amount of probe
unpredictability closes:

    if request_looks_like_verification:
        behave()
    else:
        attack()

However unguessable a canary is, it is still a canary. A server that attacks only
what it believes to be real user traffic can be honest for every probe DriftSentry
ever sends. The only way to see that behaviour is to watch the traffic it is
actually aimed at.

The proxy already carries every real call. This module reads it.

What is compared, and what deliberately is not
    NOT semantic distance against canary centroids. Real calls carry arguments
    nobody baselined, so their responses are legitimately unlike anything on
    record; scoring that as drift would alarm on ordinary use within minutes.

    Only invariants - things that should hold whatever the input:

      * a network host this tool never contacted
      * a credential-bearing file it never opened
      * a file outside everything it touched at baseline
      * a child process it never spawned
      * credential- or instruction-shaped text it never emitted
      * a response shape class never seen
      * an error state it never entered

Three constraints, in order of importance
    1. It must never block or delay a real call. Everything here is set
       arithmetic and bounded regex, wrapped so a defect cannot propagate into
       the data path.
    2. It is watch-only until calibrated. Real traffic is far more varied than
       canaries, so this is the highest false-alarm risk in the detector and it
       does not get to raise an alert on its own by default.
    3. Active and passive evidence stay separable, because the interesting
       quantity is the DISAGREEMENT between them. A server that is clean under
       probes and dirty on live traffic is not merely suspicious - that gap is
       the signature of probe-aware evasion, and nothing else produces it.

Honest limits
    The proxy does not own a probe's isolated process tree, so file and network
    evidence cannot be attributed to one specific call the way it can during
    active probing - only to the server over a window. Response-derived signals
    (content flags, shape, error state) are exact; process-derived ones are
    coarser, and are reported as such.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from driftsentry.fingerprint import normalize_result
from driftsentry.rules import content_flags, secret_paths

log = logging.getLogger("driftsentry.passive")

#: Cap on text scanned by the content rules. A tool returning megabytes must not
#: turn the proxy into a regex benchmark.
MAX_SCAN_CHARS = 20_000

#: How many observations to retain per tool.
HISTORY = 200


@dataclass
class PassiveObservation:
    """One real, user-driven call as the detector saw it."""

    tool: str
    timestamp: str
    structural_signature: str
    security_flags: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    error_state: bool = False
    response_size: int = 0
    embedding: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # The vector is for offline analysis; it does not belong in a log line.
        data.pop("embedding", None)
        return data


@dataclass
class PassiveFinding:
    """A security invariant broken on real traffic."""

    tool: str
    kind: str
    severity: str                    # high | medium
    detail: str
    evidence: list[str] = field(default_factory=list)
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolInvariants:
    """What a tool was known to do at approval time."""

    tool: str
    hosts: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)
    content_flags: set[str] = field(default_factory=set)
    shape_hashes: set[str] = field(default_factory=set)
    errored: bool = False

    @classmethod
    def from_baseline(cls, baseline, tool: str) -> "ToolInvariants":
        """Union everything the baseline recorded for one tool.

        Union rather than intersection: the question is whether behaviour is
        NEW, so anything seen even once at approval time is normal.
        """
        inv = cls(tool=tool)
        family = baseline.family_for(tool) if hasattr(baseline, "family_for") else None
        if family is not None:
            inv.hosts |= set(family.hosts)
            inv.files |= set(family.files)
            inv.content_flags |= set(family.content_flags)
            inv.shape_hashes |= set(family.shape_hashes)
            inv.errored = family.error_rate > 0.0

        entry = baseline.tool(tool) if hasattr(baseline, "tool") else None
        if entry is not None:
            for probe in entry.probes:
                inv.hosts |= set(probe.hosts)
                inv.files |= set(probe.files)
                inv.content_flags |= set(probe.content_flags)
                inv.shape_hashes |= set(probe.shape_hashes)
                inv.errored = inv.errored or probe.error_rate > 0.0
        return inv


class PassiveMonitor:
    """Evaluates security invariants on live proxied traffic.

    Fed by the proxy. Holds no reference to the data path and can only read.
    """

    def __init__(
        self,
        server: str,
        baseline: Any | None = None,
        *,
        enabled: bool = True,
        alerting: bool = False,
    ) -> None:
        self.server = server
        self.enabled = enabled
        # Off by default. Passive evidence contributes to the report and to the
        # active/passive comparison, but does not raise an alert on its own until
        # it has been calibrated on real traffic.
        self.alerting = alerting
        self._invariants: dict[str, ToolInvariants] = {}
        self._pending: dict[Any, tuple[str, dict[str, Any]]] = {}
        self._observations: dict[str, deque] = {}
        self._findings: list[PassiveFinding] = []
        self._lock = threading.Lock()
        self.calls_seen = 0
        if baseline is not None:
            self.load_baseline(baseline)

    # -- setup --------------------------------------------------------------
    def load_baseline(self, baseline: Any) -> None:
        for entry in getattr(baseline, "tools", []):
            self._invariants[entry.tool] = ToolInvariants.from_baseline(baseline, entry.tool)

    def invariants_for(self, tool: str) -> ToolInvariants | None:
        return self._invariants.get(tool)

    # -- the proxy hooks ----------------------------------------------------
    def on_request(self, request_id: Any, tool: str, args: dict[str, Any]) -> None:
        """Record an in-flight tool call. Never raises."""
        if not self.enabled:
            return
        try:
            with self._lock:
                self._pending[request_id] = (tool, args or {})
        except Exception as exc:  # pragma: no cover - must never reach the pump
            log.debug("passive on_request failed: %s", exc)

    def on_response(
        self,
        request_id: Any,
        result: dict[str, Any],
        *,
        hosts: list[str] | None = None,
        files: list[str] | None = None,
        processes: list[str] | None = None,
    ) -> PassiveObservation | None:
        """Evaluate one completed call. Never raises, never blocks."""
        if not self.enabled:
            return None
        try:
            return self._evaluate(request_id, result, hosts, files, processes)
        except Exception as exc:  # pragma: no cover - a defect here must not
            log.debug("passive on_response failed: %s", exc)   # break the proxy
            return None

    def _evaluate(
        self,
        request_id: Any,
        result: dict[str, Any],
        hosts: list[str] | None,
        files: list[str] | None,
        processes: list[str] | None,
    ) -> PassiveObservation | None:
        with self._lock:
            pending = self._pending.pop(request_id, None)
        if pending is None:
            return None                       # not a tools/call we tracked
        tool, _args = pending
        self.calls_seen += 1

        normalized = normalize_result(result)
        text = normalized.text[:MAX_SCAN_CHARS]
        observation = PassiveObservation(
            tool=tool,
            timestamp=datetime.now(timezone.utc).isoformat(),
            structural_signature=normalized.shape_hash,
            security_flags=content_flags(text),
            hosts=sorted(set(hosts or [])),
            files=sorted(set(files or [])),
            processes=sorted(set(processes or [])),
            error_state=normalized.is_error,
            response_size=normalized.n_chars,
        )

        with self._lock:
            self._observations.setdefault(tool, deque(maxlen=HISTORY)).append(observation)

        for finding in self._check(observation):
            with self._lock:
                self._findings.append(finding)
            log.warning("passive: %s on %r - %s", finding.kind, tool, finding.detail)
        return observation

    # -- invariant checks ---------------------------------------------------
    def _check(self, obs: PassiveObservation) -> list[PassiveFinding]:
        inv = self._invariants.get(obs.tool)
        if inv is None:
            # Never baselined - usually a side-effecting tool held back from
            # probing. Nothing to diff against, so nothing is claimed.
            return []

        findings: list[PassiveFinding] = []

        def add(kind: str, severity: str, detail: str, evidence: list[str]) -> None:
            findings.append(PassiveFinding(
                tool=obs.tool, kind=kind, severity=severity, detail=detail,
                evidence=evidence[:5], observed_at=obs.timestamp,
            ))

        new_hosts = sorted(set(obs.hosts) - inv.hosts)
        if new_hosts:
            add("new_egress_host", "high",
                f"contacted {len(new_hosts)} host(s) never seen at approval", new_hosts)

        new_files = sorted(set(obs.files) - inv.files)
        secrets = secret_paths(new_files)
        if secrets:
            add("secret_file_read", "high",
                "opened credential-bearing file(s) not touched at approval", secrets)
        ordinary = [f for f in new_files if f not in set(secrets)]
        if ordinary:
            add("new_file_access", "medium",
                f"opened {len(ordinary)} file(s) not touched at approval", ordinary)

        new_processes = sorted(set(obs.processes) - inv.processes)
        if new_processes:
            add("new_process", "high",
                "started a child process it never started at approval", new_processes)

        new_flags = sorted(set(obs.security_flags) - inv.content_flags)
        credential = [f for f in new_flags if f.startswith("credential:")]
        instruction = [f for f in new_flags if f.startswith("instruction:")]
        if credential:
            add("credential_shaped_output", "high",
                "returned credential-shaped material it never returned at approval", credential)
        if instruction:
            add("instruction_shaped_output", "medium",
                "returned text directed at the AI assistant rather than the user", instruction)

        if inv.shape_hashes and obs.structural_signature not in inv.shape_hashes:
            add("unseen_response_shape", "medium",
                "response structure differs from every shape seen at approval",
                [obs.structural_signature])

        if obs.error_state and not inv.errored:
            add("error_state_change", "medium",
                "the tool errored on a call where it never errored at approval", [])

        return findings

    # -- reporting ----------------------------------------------------------
    def findings(self, tool: str | None = None) -> list[PassiveFinding]:
        with self._lock:
            found = list(self._findings)
        return [f for f in found if tool is None or f.tool == tool]

    def observations(self, tool: str) -> list[PassiveObservation]:
        with self._lock:
            return list(self._observations.get(tool, ()))

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()
            self._observations.clear()

    def summary(self) -> dict[str, Any]:
        found = self.findings()
        return {
            "server": self.server,
            "enabled": self.enabled,
            "alerting": self.alerting,
            "calls_seen": self.calls_seen,
            "findings": len(found),
            "high_severity": sum(1 for f in found if f.severity == "high"),
            "kinds": sorted({f.kind for f in found}),
            "tools": sorted({f.tool for f in found}),
        }


# --------------------------------------------------------------------------- #
# Active / passive disagreement
# --------------------------------------------------------------------------- #
#: The evidence weights. Kept below the active security rules: passive evidence
#: is coarser (no isolated process tree, no controlled input) so the same
#: observation is worth somewhat less than it would be under a probe.
SEVERITY_SCORE = {"high": 1.6, "medium": 0.9}

#: A tool clean under probes and dirty on real traffic. This is not merely the
#: sum of its parts - honest tools do not behave one way for one caller and
#: another way for another, so the DISAGREEMENT is itself the finding, and it is
#: the only signal in the detector that specifically indicates probe-aware
#: evasion rather than generic misbehaviour.
W_INCONSISTENCY = 2.0


def inconsistency(
    monitor: PassiveMonitor,
    report: Any,
    tool: str,
) -> tuple[float, list[str]]:
    """Score the gap between what probes saw and what real traffic saw.

    Returns ``(score, reasons)``. Zero when both channels agree, whether they
    agree that the tool is clean or that it is not.
    """
    passive = [f for f in monitor.findings(tool) if f.severity == "high"]
    if not passive:
        return 0.0, []

    active_fired = set()
    for scored in getattr(report, "tools", []):
        if scored.tool != tool:
            continue
        pools = [scored.signals] + [p.signals for p in scored.probes]
        for signals in pools:
            for signal in signals:
                if signal.name.startswith("rule:") and signal.score >= 1.0:
                    active_fired.add(signal.name.split(":", 1)[1])

    unmatched = [f for f in passive if f.kind not in active_fired]
    if not unmatched:
        return 0.0, []                       # both channels agree; no gap

    reasons = [
        f"{f.kind} seen on real traffic but not under verification: {f.detail}"
        for f in unmatched
    ]
    score = min(W_INCONSISTENCY, max(SEVERITY_SCORE.get(f.severity, 0.5) for f in unmatched))
    return score, reasons
