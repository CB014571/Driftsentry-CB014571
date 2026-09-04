"""Corroboration: alerting on agreement between independent evidence.

The default scorer takes the strongest single signal. That is the right default -
it keeps attribution unambiguous and stops correlated noise accumulating into an
alert - but it has a known cost, conceded in the scorer's own docstring: an
attacker who holds every individual signal just below the line is not caught.

    semantic   0.71
    structure  0.68
    side effect 0.75
    temporal   0.62

Nothing alerts. Together it is hard to explain innocently.

Summing is not the answer
    The embedding distance and the structural signal read the same response, so
    they move together on any change at all. Adding them would let an ordinary
    benign update on a chatty tool out-score a genuine attack, which is the
    failure this project can least afford.

So signals are grouped into families chosen so that members are correlated WITHIN
a family and roughly independent ACROSS families. Each family contributes the max
of its members - never the sum - and the rule counts how many *families* agree.
Corroboration then means "several independent kinds of evidence", not "a lot of
evidence of one kind".

Thresholds are calibrated, not chosen
    The constants below are starting points from development data. Lowering the
    bar for an alert mechanically raises the false-alarm rate, so the values that
    ship must come from benign calibration data including legitimate updates, and
    the experiment must report the FAR cost beside the recall gain. `max_only`
    remains the default strategy so the two are always comparable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

#: Signal name -> evidence family. Membership reflects what a signal READS, not
#: how severe it is: two signals that read the same response are correlated
#: however different their weights.
FAMILY_OF: dict[str, str] = {
    # A - content of the response
    "behavioural_drift": "A",
    "field_drift": "A",
    "determinism_break": "A",
    "rule:credential_shaped_output": "A",
    "rule:instruction_shaped_output": "A",
    # B - shape and error behaviour
    "structural_change": "B",
    "error_behaviour": "B",
    # C - side effects outside the response
    "rule:new_egress_host": "C",
    "rule:secret_file_read": "C",
    "rule:new_file_access": "C",
    "rule:new_process": "C",
    "rule:tripwire_read": "C",
    # D - the advertised surface
    "definition_hash": "D",
    # E - adaptive-evasion evidence
    "probe_consistency": "E",
    "passive_inconsistency": "E",
    # F - trend over time
    "temporal_trend": "F",
}

FAMILY_NAMES = {
    "A": "content",
    "B": "structure/error",
    "C": "side effects",
    "D": "surface integrity",
    "E": "adaptive evasion",
    "F": "temporal",
}

#: A single family at or above this alerts on its own - unchanged from the
#: default strategy, so corroboration only ever ADDS detections.
T_CRITICAL = 1.0

#: Two independent families at this level, or three at the lower one.
T_HIGH = 0.65
T_MEDIUM = 0.45

#: Families that are conclusive alone whatever their score. A changed definition
#: is not evidence of a rug pull, it is one - corroboration would be redundant.
ALWAYS_CRITICAL = {"D"}

#: Score assigned when corroboration fires but no single family reached the line.
#: Just above the threshold: the evidence is real but circumstantial, and the
#: alert should say so rather than shouting.
W_CORROBORATED = 1.2


@dataclass
class CorroborationResult:
    """Why corroboration did or did not fire."""

    fired: bool
    score: float
    rule: str                                  # which clause matched
    families: dict[str, float] = field(default_factory=dict)
    contributing: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def family_scores(signals) -> dict[str, float]:
    """Reduce a probe's signals to one score per evidence family.

    Max within a family, never sum: members of a family are correlated by
    construction, so adding them would count the same observation twice.
    """
    scores: dict[str, float] = {}
    for signal in signals:
        family = FAMILY_OF.get(signal.name)
        if family is None:
            # Unmapped signals are ignored rather than dumped into a default
            # family, where they would silently corroborate with something they
            # are correlated with.
            continue
        scores[family] = max(scores.get(family, 0.0), signal.score)
    return scores


def evaluate(
    signals,
    *,
    t_critical: float = T_CRITICAL,
    t_high: float = T_HIGH,
    t_medium: float = T_MEDIUM,
) -> CorroborationResult:
    """Apply the corroboration rule to one probe's signals."""
    scores = family_scores(signals)
    if not scores:
        return CorroborationResult(False, 0.0, "no evidence")

    named = {f"{key} ({FAMILY_NAMES.get(key, key)})": round(v, 3)
             for key, v in sorted(scores.items())}

    # 1. Any single family already over the line - identical to max_only.
    critical = [k for k, v in scores.items() if v >= t_critical or k in ALWAYS_CRITICAL]
    if critical:
        best = max(scores.values())
        return CorroborationResult(
            True, best, "single family at or above the alert line",
            named, sorted(critical),
            f"{FAMILY_NAMES.get(critical[0], critical[0])} evidence alone crossed the line",
        )

    # 2. Two independent families both clearly elevated.
    high = sorted(k for k, v in scores.items() if v >= t_high)
    if len(high) >= 2:
        return CorroborationResult(
            True, W_CORROBORATED, f"{len(high)} independent families >= {t_high}",
            named, high,
            "no single signal crossed the line, but "
            + " and ".join(FAMILY_NAMES.get(k, k) for k in high)
            + " are independently elevated",
        )

    # 3. Three families mildly elevated.
    medium = sorted(k for k, v in scores.items() if v >= t_medium)
    if len(medium) >= 3:
        return CorroborationResult(
            True, W_CORROBORATED, f"{len(medium)} independent families >= {t_medium}",
            named, medium,
            "three independent kinds of evidence are mildly elevated at once: "
            + ", ".join(FAMILY_NAMES.get(k, k) for k in medium),
        )

    return CorroborationResult(
        False, max(scores.values()), "no corroboration", named, [],
        "evidence is present but confined to one family",
    )


def calibrate(
    benign_family_scores: list[dict[str, float]],
    *,
    target_far: float = 0.01,
) -> dict[str, float]:
    """Choose t_high and t_medium from benign observations only.

    Both are set so that the corresponding clause would fire on at most
    ``target_far`` of benign cycles. Lowering these thresholds is exactly the
    trade being made - more recall against sub-threshold attackers, more false
    alarms - so the number has to come from data rather than from taste.
    """
    if not benign_family_scores:
        raise ValueError("no benign observations supplied; cannot calibrate")

    def far_at(threshold: float, needed: int) -> float:
        hits = sum(1 for row in benign_family_scores
                   if sum(1 for v in row.values() if v >= threshold) >= needed)
        return hits / len(benign_family_scores)

    t_high = T_HIGH
    for candidate in [x / 100 for x in range(40, 100, 5)]:
        if far_at(candidate, 2) <= target_far:
            t_high = candidate
            break

    t_medium = T_MEDIUM
    for candidate in [x / 100 for x in range(25, 100, 5)]:
        if far_at(candidate, 3) <= target_far:
            t_medium = candidate
            break

    return {
        "t_high": round(t_high, 3),
        "t_medium": round(t_medium, 3),
        "target_far": target_far,
        "empirical_far_high": round(far_at(t_high, 2), 4),
        "empirical_far_medium": round(far_at(t_medium, 3), 4),
        "n_observations": len(benign_family_scores),
    }
