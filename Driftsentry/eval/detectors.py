"""Three detectors, read from one episode.

H2 asks whether active probing beats hash pinning and passive monitoring. The
only honest way to ask that is to score all three on THE SAME episodes:

    hash-only   what mcp-scan and every definition-pinning tool sees. It
                alerts when the advertised tool definition changes, and the
                whole premise of this project is that a behavioural rug pull
                leaves it untouched.
    passive     watches real user traffic for broken invariants. It sees
                attacks that only fire for genuine users, and is blind to any
                tool the user never calls.
    full        the scorer's verdict, with every active signal.

Running them as three separate experiments would make the comparison
unpaired. McNemar needs the pairing - it conditions on the episodes where two
detectors disagreed, which is the actual evidence - so the three verdicts have
to come from one run over one set of traffic.

The passive rule is calibrated and frozen
    Passive monitoring produces findings, not a verdict, so a rule has to turn
    findings into "detected". That rule is a free parameter, and choosing it
    after seeing attack results would be fitting the detector to the test. It
    is therefore fixed on BENIGN episodes only - the weakest rule that raises
    no false alarm - and sealed with a content hash before any attack episode
    is scored.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

#: Severities the passive monitor emits, weakest first.
SEVERITIES = ("low", "medium", "high")

DEFAULT_RULE: dict[str, Any] = {"min_severity": "high", "min_findings": 1}


# --------------------------------------------------------------------------- #
# Reading each detector
# --------------------------------------------------------------------------- #
def hash_detected(report: Any) -> bool:
    """What a definition-pinning scanner would report.

    Taken from the same report the full scorer used, not from a separate run,
    so the two cannot differ by anything except which signals they consult.
    """
    return bool(getattr(report, "definition_changed", False))


def full_detected(report: Any) -> bool:
    return getattr(report, "verdict", "") == "alert"


def passive_detected(passive: dict[str, Any], rule: dict[str, Any] | None = None) -> bool:
    """Apply the frozen rule to what passive monitoring observed.

    ``passive`` is what eval.replay.passive_findings returned. When monitoring
    did not run at all this is False, and ``passive_available`` records why -
    an episode where nothing was watched must not be counted as one that was
    watched and came back clean.
    """
    if not passive.get("available"):
        return False
    rule = rule or DEFAULT_RULE
    floor = SEVERITIES.index(rule.get("min_severity", "high"))
    qualifying = [
        f for f in passive.get("findings", [])
        if _severity_rank(f.get("severity")) >= floor
    ]
    return len(qualifying) >= int(rule.get("min_findings", 1))


def _severity_rank(severity: Any) -> int:
    try:
        return SEVERITIES.index(str(severity).lower())
    except ValueError:
        return 0


# --------------------------------------------------------------------------- #
# Calibrating the passive rule, on benign episodes only
# --------------------------------------------------------------------------- #
def calibrate_passive_rule(
    benign_observations: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """The weakest rule that raises no false alarm on benign traffic.

    Weakest on purpose. A rule tuned to be strict would make passive
    monitoring look worse than it is, and H2 would then credit active probing
    with a margin that came from the rule rather than from the method. Among
    rules that are clean on benign, the most sensitive is the fairest to the
    detector being compared against.

    Benign only, and before any attack episode is scored. Choosing it later
    would be fitting the comparison to its own result.
    """
    for severity in SEVERITIES:            # low first: the most sensitive
        for min_findings in (1, 2, 3):
            rule = {"min_severity": severity, "min_findings": min_findings}
            if not any(passive_detected(obs, rule) for obs in benign_observations):
                return {**rule,
                        "calibrated_on": len(benign_observations),
                        "note": "weakest rule with zero false alarms on benign"}

    return {**DEFAULT_RULE,
            "calibrated_on": len(benign_observations),
            "note": ("no rule was clean on benign; falling back to the default. "
                     "Passive monitoring alarms on this benign traffic, which "
                     "is itself the finding.")}


def freeze_rule(rule: dict[str, Any], path: str | Path) -> dict[str, Any]:
    """Seal the rule so it demonstrably predates the attack episodes."""
    from driftsentry.calibration import freeze

    return freeze(rule, path)


def load_frozen_rule(path: str | Path) -> dict[str, Any]:
    """Load a sealed rule, refusing one that has been edited since."""
    from driftsentry.calibration import verify_frozen

    data = verify_frozen(path)
    return {k: v for k, v in data.items() if not k.startswith("_")}


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def three_way_report(rows: Sequence[Any]) -> str:
    """Detection rate per detector, with the paired tests H2 asks for."""
    from eval.stats import mcnemar_p, wilson

    fired = [r for r in rows if getattr(r, "attack_fired", False)]
    benign = [r for r in rows if getattr(r, "attack_family", "") in
              {"benign", "benign-update"}]

    lines = ["", "=" * 74,
             "  THREE DETECTORS ON THE SAME EPISODES (RQ2 / H2)",
             "=" * 74]

    if not fired:
        return "\n".join(lines + [
            "  no episode in which the attack actually fired - nothing to compare.",
            "  With replay_sessions=0 a probe-aware attacker never fires; that is",
            "  a property of the run, not a result."])

    arms = {
        "hash-only": [bool(getattr(r, "hash_detected", False)) for r in fired],
        "passive": [bool(getattr(r, "passive_detected", False)) for r in fired],
        "full": [bool(getattr(r, "full_detected", False)) for r in fired],
    }

    lines.append(f"  {'detector':<14}{'recall on fired attacks':>30}"
                 f"{'false alarms':>18}")
    for name, flags in arms.items():
        hits = sum(flags)
        rate, low, high = wilson(hits, len(flags))
        fa_field = {"hash-only": "hash_detected", "passive": "passive_detected",
                    "full": "full_detected"}[name]
        fa_hits = sum(1 for r in benign if getattr(r, fa_field, False))
        fa = f"{fa_hits}/{len(benign)}" if benign else "n/a"
        lines.append(f"  {name:<14}{f'{rate:6.1%} [{low:.2f},{high:.2f}] {hits}/{len(flags)}':>30}{fa:>18}")

    lines.append("")
    for other in ("hash-only", "passive"):
        test = mcnemar_p(arms["full"], arms[other])
        verdict = "significant" if test["p"] < 0.05 else "not significant"
        lines.append(
            f"  full vs {other:<10} p={test['p']:.4f} ({verdict}), "
            f"discordant {test['discordant']} "
            f"(full only {test['b10']}, {other} only {test['b01']})")

    lines.append("")
    lines.append("  H2 requires full > hash-only at p < 0.05 on paired episodes.")
    return "\n".join(lines)
