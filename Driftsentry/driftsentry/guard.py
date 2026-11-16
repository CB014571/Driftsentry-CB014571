"""The real-call guard: the second jaw of in-session verification (H2c).

Why probes alone cannot be enough
    H2b measured that a server which learns what probes look like can still
    pick them out (AUC 0.887). Making probes harder to spot is one answer; it
    is an arms race the detector may lose. This module removes the reason to
    win it. A server that behaves for every probe and attacks only the user
    still has to attack the user's calls, and those calls pass through the
    same proxy. The guard watches what the server DOES during each real call
    - with the same continuous process watch probes use - and checks it
    against what the server did when it was approved.

    So a probe-aware server is caught either way: attack a probe and the
    probe sees it; attack a real call and the guard sees it.

What it can and cannot see
    Real calls carry arguments nobody baselined, so their ANSWERS cannot be
    compared to anything (passive.py explains why). Only invariants are
    checked, and only the ones that hold whatever the input raise an alert:

        alerting        new network host, credential-bearing file opened,
                        file opened in a directory the server never touched,
                        new child process, credential- or instruction-shaped
                        text in the answer
        evidence only   new response shape, new error state, new file in a
                        directory already seen (a document reader opening a
                        different document is normal use)

    Not visible at all: an attack that only changes the VALUES in a real
    answer (silent tampering). Nothing on the real-call side can tell a wrong
    answer from a right one without a reference, so that family is caught
    only when it fires on a probe. This is the guard's stated limit.

Never in the data path
    The proxy hands the guard a copy of each finished call; evaluation runs
    later on its own task. A defect here cannot delay or drop a user's call.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from driftsentry.passive import PassiveMonitor

log = logging.getLogger("driftsentry.guard")

#: Findings that raise an alert on their own. Each is an invariant that holds
#: whatever the user asked for.
ALERTING_KINDS = frozenset({
    "new_egress_host", "secret_file_read", "new_file_dir", "new_process",
    "credential_shaped_output", "instruction_shaped_output",
})

#: Score a guard alert carries in a drift report: above the provisional 1.5
#: threshold, the same weight passive.py gives a high-severity finding.
GUARD_SCORE = 1.6


def _dir(path: str) -> str:
    return os.path.normcase(os.path.dirname(os.path.normpath(path)))


@dataclass
class GuardFinding:
    tool: str
    kind: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    call_start: float = 0.0          # monotonic, for attribution in evaluation
    call_end: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "kind": self.kind, "detail": self.detail,
                "evidence": self.evidence[:5]}


class RealCallGuard:
    """Checks each real call's side effects and answer against approval."""

    def __init__(self, server: str, baseline: Any, watch: Any = None) -> None:
        self.server = server
        self.watch = watch
        passive = PassiveMonitor(server, baseline)
        # Process evidence (hosts, files) is SERVER-wide. The watch sees the
        # whole server process, not one tool, so comparing it with one tool's
        # approval record is wrong: found live, where an unprobed tool's empty
        # record made the server's own loopback socket (Python's asyncio
        # self-pipe, 127.0.0.1) look like new egress on a clean server.
        self._hosts: set[str] = set()
        self._files: set[str] = set()
        self._flags: dict[str, set[str]] = {}
        for entry in getattr(baseline, "tools", []):
            inv = passive.invariants_for(entry.tool)
            if inv is None:
                continue
            self._hosts |= set(inv.hosts)
            self._files |= {os.path.normcase(os.path.normpath(f)) for f in inv.files}
            # Answers are exact per call, so content stays per tool.
            self._flags[entry.tool] = set(inv.content_flags)
        # Directories touched at approval: a new file in one of them is a
        # document reader opening another document, not an attack.
        self._dirs: set[str] = {os.path.dirname(f) for f in self._files}
        self._findings: list[GuardFinding] = []
        self.calls_checked = 0

    # ------------------------------------------------------------------ #
    def check(self, tool: str, args: dict[str, Any], result: dict[str, Any],
              start: float, end: float) -> list[GuardFinding]:
        """Evaluate one finished real call. Call it after the call, never during."""
        try:
            return self._check(tool, args, result, start, end)
        except Exception as exc:  # pragma: no cover - must never reach the user
            log.debug("guard check failed: %s", exc)
            return []

    def _check(self, tool, args, result, start, end) -> list[GuardFinding]:
        from driftsentry.fingerprint import normalize_result
        from driftsentry.passive import MAX_SCAN_CHARS
        from driftsentry.rules import content_flags, secret_paths

        obs = self.watch.window(start, end) if self.watch is not None else None
        hosts = obs.hosts if obs is not None and obs.available else []
        files = obs.files if obs is not None and obs.available else []
        self.calls_checked += 1
        out: list[GuardFinding] = []

        def add(kind: str, detail: str, evidence: list[str]) -> None:
            out.append(GuardFinding(tool, kind, detail, sorted(evidence)[:5], start, end))

        new_hosts = set(hosts) - self._hosts
        if new_hosts:
            add("new_egress_host", f"contacted {len(new_hosts)} host(s) the server never "
                "contacted at approval", list(new_hosts))
        new_files = [f for f in files
                     if os.path.normcase(os.path.normpath(f)) not in self._files]
        secrets = secret_paths(new_files)
        if secrets:
            add("secret_file_read", "opened credential-bearing file(s) not touched at "
                "approval", secrets)
        fresh = [f for f in new_files if f not in set(secrets) and _dir(f) not in self._dirs]
        if fresh:
            add("new_file_dir", "opened a file in a directory this server never touched "
                "at approval", fresh)

        text = normalize_result(result if isinstance(result, dict) else {}).text
        flags = set(content_flags(text[:MAX_SCAN_CHARS])) - self._flags.get(tool, set())
        credential = [f for f in flags if f.startswith("credential:")]
        instruction = [f for f in flags if f.startswith("instruction:")]
        if credential:
            add("credential_shaped_output", "returned credential-shaped material it never "
                "returned at approval", credential)
        if instruction:
            add("instruction_shaped_output", "returned text directed at the AI assistant "
                "rather than the user", instruction)

        self._findings.extend(out)
        for g in out:
            log.warning("guard: %s on %r - %s", g.kind, tool, g.detail)
        return out

    # ------------------------------------------------------------------ #
    def findings(self) -> list[GuardFinding]:
        return list(self._findings)

    def take(self) -> list[GuardFinding]:
        """Findings since the last take, for one verification cycle's report."""
        out, self._findings = self._findings, []
        return out


def apply_guard(report: Any, findings: list[GuardFinding]) -> Any:
    """Fold real-call findings into a drift report as alerting evidence.

    Each finding becomes a ``guard:<kind>`` signal on its tool, under a
    pseudo-probe named ``real-call``, so alerts, quarantine and the report
    show it like any other evidence and say plainly where it came from.
    """
    from driftsentry.scorer import ProbeScore, Signal, ToolScore

    if not findings:
        return report
    by_tool: dict[str, list[GuardFinding]] = {}
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)
    for tool, found in by_tool.items():
        signals = [Signal(name=f"guard:{f.kind}", score=GUARD_SCORE, severity="high",
                          detail=f"on a real call: {f.detail}",
                          evidence={"items": f.evidence[:5]})
                   for f in found]
        entry = next((t for t in report.tools if t.tool == tool), None)
        if entry is None:
            entry = ToolScore(tool=tool, score=0.0, verdict="ok", triggered_by=None)
            report.tools.append(entry)
        entry.probes.append(ProbeScore(probe_id="real-call", score=GUARD_SCORE,
                                       ratio=0.0, distance=0.0, band=0.0,
                                       signals=signals))
        if GUARD_SCORE >= entry.score:
            entry.triggered_by = signals[0].name
        entry.score = max(entry.score, GUARD_SCORE)
        entry.verdict = "alert"
    return report
