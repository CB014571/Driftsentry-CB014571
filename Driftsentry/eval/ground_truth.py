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


# --------------------------------------------------------------------------- #
# Attribution (T27, ground rule 5)
# --------------------------------------------------------------------------- #
# An alert counts as detecting a hidden change only if it names a signal that
# change causes. Signal names are the residue checker's vocabulary
# (driftsentry.residue.SIGNAL_NAMES).
#
# Wider than the plan's sketch for the two content families, and the reason
# is measured rather than preferred. The plan mapped silent-tamper to
# field_drift alone. But every attacker tool returns one prose string, which
# fielddrift classifies as `text` at weight 0.3 - its field-drift score tops
# out at 0.48 and can never reach the alert line - and the keyed probe path
# computes no field drift at all. A tamper therefore shows up as
# determinism_break or behavioural_drift, the signals that read the changed
# text. Mapping it to field_drift alone would score every silent-tamper as
# undetected under every condition: an artefact of the mapping, not a
# property of any detector.
#
# structural_change is deliberately absent: neither content attack alters a
# response's structure - one rewrites text, the other appends to it - so the
# only structural change in an update episode is the cover's own new field,
# and crediting it would count the cover as the attack.
#
# The cover cannot leak into the rest either: the declared field is masked out
# before residue is scored, and attribution also requires the signal to be on
# the attacked tool.
_CONTENT = {"behavioural_drift", "determinism_break", "field_drift"}
ATTRIBUTION: dict[str, set[str]] = {
    "new-egress": {"new_egress_host"},
    "exfiltration": {"new_file", "new_egress_host"},
    "silent-tamper": set(_CONTENT),
    "content-injection": {"content_flag"} | _CONTENT,
}

# sleeper and conditional say WHEN; the payload they deliver says WHAT.
# Mirrors the attacker's own defaults, duplicated for the same reason
# events_path is - the harness cannot import the attacker.
DEFAULT_PAYLOAD = {"sleeper": "content-injection", "conditional": "exfiltration"}


def attribution_signals(family: str, payload: str | None = None) -> set[str]:
    """The signals an attack of this family causes, by its delivered payload."""
    delivered = payload or DEFAULT_PAYLOAD.get(family, family)
    return set(ATTRIBUTION.get(delivered, set()))


# Side effects belong to the server PROCESS, not to a tool. Measured in the
# first live update episodes: the attacker keeps its exfiltration sink open
# and its egress sockets connected on purpose (attacker/sink.py), and the
# sandbox monitor observes the process, so once the attack has fired its open
# file is seen during the next probe of whatever tool comes next. In a C3
# exfiltration episode the alert landed on read_document, a tool the attack
# never touches. No monitor can localise these to a tool, so they are
# attributed wherever they appear. A cover change cannot cause them - every
# cover is pure - so this cannot credit the cover as the attack.
PROCESS_SIGNALS = {"new_file", "new_egress_host"}


def attributed(signals_on_tool: dict[str, set[str]], *, attacked_tool: str,
               family: str, payload: str | None = None) -> bool:
    """Does an alerting signal name what the attack did?

    ``signals_on_tool`` maps tool -> the residue-vocabulary names of signals
    that alerted on it. Content signals must be on the attacked tool: that is
    what separates detecting the hidden change from alarming on a cover
    change made to a different tool (C1). Side-effect signals count on any
    tool, because they are the process's, not a tool's - see PROCESS_SIGNALS.
    """
    wanted = attribution_signals(family, payload)
    if signals_on_tool.get(attacked_tool, set()) & wanted:
        return True
    anywhere = set().union(*signals_on_tool.values()) if signals_on_tool else set()
    return bool(anywhere & wanted & PROCESS_SIGNALS)


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
