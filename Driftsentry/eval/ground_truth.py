"""Ground truth, read from the adversarial server rather than from the detector.

The rule this module exists to enforce:

    An episode counts as a false negative only if the attacker's own event log
    proves the malicious action actually executed.

Without it, a probabilistic (L2) or trigger-gated (L3) attacker that simply never
fired during an episode is indistinguishable from one that fired and was missed,
and every recall figure in the evaluation would rest on the assumption that the
ground truth was correct rather than on evidence that it was.

The attacker writes this log itself, in its own process, with no knowledge of
what the detector concluded. That independence is the whole point.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Which event kind proves each family actually did something.
#
# `sleeper` and `conditional` describe WHEN rather than WHAT, so they deliver
# another family's payload and are proved by that payload's evidence.
FAMILY_EVIDENCE: dict[str, set[str]] = {
    "exfiltration": {"exfiltrate"},
    "new-egress": {"egress"},
    "silent-tamper": {"tamper"},
    "content-injection": {"inject"},
    "sleeper": {"inject"},          # default payload
    "conditional": {"exfiltrate"},  # default payload
}

# Recorded when a probe-aware attacker recognises a canary and holds back.
PROBE_SKIP = "probe-skip"


def events_path(attacker_home: str | Path | None = None) -> Path:
    """Locate the attacker's event log.

    Mirrors `attacker.scenario.default_home()` exactly. Duplicated rather than
    imported on purpose: the harness runs inside DriftSentry's environment, which
    cannot import the attacker package - that isolation is what makes the two
    projects independent, and it is worth a few duplicated lines to keep.
    """
    if attacker_home:
        return Path(attacker_home) / "sink" / "events.log"
    override = os.environ.get("ATTACKER_HOME")
    if override:
        return Path(override) / "sink" / "events.log"
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "mcp-attacker" / "sink" / "events.log"
    return Path.home() / ".mcp-attacker" / "sink" / "events.log"


@dataclass
class GroundTruth:
    """What the attacker says it actually did during one episode."""

    fired: bool
    kinds: list[str]
    probe_skips: int
    total_events: int
    expected_kinds: list[str]
    log_present: bool

    @property
    def probe_recognised(self) -> bool:
        return self.probe_skips > 0

    def summary(self) -> str:
        if not self.log_present:
            return "no event log (attacker never started, or wrong ATTACKER_HOME)"
        if self.fired:
            return f"fired: {', '.join(sorted(set(self.kinds)))}"
        if self.probe_skips:
            return f"held back on {self.probe_skips} probe-shaped input(s)"
        return "never fired"


def read(family: str, *, attacker_home: str | Path | None = None) -> GroundTruth:
    """Read the event log and decide whether ``family`` actually executed."""
    path = events_path(attacker_home)
    expected = FAMILY_EVIDENCE.get(family, set())

    if not path.is_file():
        return GroundTruth(False, [], 0, 0, sorted(expected), log_present=False)

    kinds: list[str] = []
    skips = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        kind = parts[1]
        if kind == PROBE_SKIP:
            skips += 1
        else:
            kinds.append(kind)

    return GroundTruth(
        fired=bool(expected & set(kinds)),
        kinds=kinds,
        probe_skips=skips,
        total_events=len(kinds) + skips,
        expected_kinds=sorted(expected),
        log_present=True,
    )


def clear(*, attacker_home: str | Path | None = None) -> None:
    """Truncate the event log so an episode starts from a clean slate."""
    path = events_path(attacker_home)
    if path.is_file():
        path.unlink()


def classify(*, mode: str, fired: bool, detected: bool) -> str:
    """Turn (ground truth, detector verdict) into one labelled outcome.

    Five outcomes, not two. ``never_triggered`` is the one that matters: it is
    excluded from the recall denominator, because a detector cannot be blamed for
    missing an attack that did not happen.
    """
    if mode == "benign":
        return "false_alarm" if detected else "benign_ok"
    if not fired:
        return "never_triggered"
    return "detected" if detected else "missed"


def recall(rows) -> tuple[float, int, int]:
    """Attack recall over episodes where the payload actually executed.

    Returns (recall, detected, executed). Episodes that never triggered are
    excluded from the denominator by construction.
    """
    executed = [r for r in rows if r.outcome in {"detected", "missed"}]
    if not executed:
        return 0.0, 0, 0
    detected = sum(1 for r in executed if r.outcome == "detected")
    return detected / len(executed), detected, len(executed)


def false_alarm_rate(rows) -> tuple[float, int, int]:
    """Fraction of benign episodes that produced an alert."""
    benign = [r for r in rows if r.outcome in {"benign_ok", "false_alarm"}]
    if not benign:
        return 0.0, 0, 0
    alarms = sum(1 for r in benign if r.outcome == "false_alarm")
    return alarms / len(benign), alarms, len(benign)


def trigger_exposure(rows) -> tuple[float, int, int]:
    """Fraction of malicious episodes in which the payload actually fired.

    Reported separately from recall, as the methodology requires: a low number
    here means the attack rarely triggered, which is a property of the attacker
    (L2/L3 gating, or L4 recognising the probes) and not of the detector.
    """
    malicious = [r for r in rows
                 if r.outcome in {"detected", "missed", "never_triggered"}]
    if not malicious:
        return 0.0, 0, 0
    fired = sum(1 for r in malicious if r.outcome != "never_triggered")
    return fired / len(malicious), fired, len(malicious)
