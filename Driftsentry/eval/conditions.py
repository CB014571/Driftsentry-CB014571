"""The countermeasure conditions T20 compares.

RQ4 asks whether realistic probes restore detection, and at what cost. That
is only answerable if the conditions differ in exactly one thing at a time -
which is the whole reason the countermeasures were built but left switched
off. Turning several on at once makes any change unattributable.

The conditions, each adding one thing to the last:

    none        what RQ3 measured. client 1.000, session 0.983,
                timing 0.951, argument 0.763, environment 0.500.
    host        probes announce the identity the real client announced (T17).
                Aimed squarely at client.
    mimic       host, plus probe calls paced from the server's own observed
                gaps (T18). Aimed at timing, and at session through it.
    subsample   a bank of probes with a few drawn per cycle (T19). Aimed at
                an attacker that memorises rather than predicts, which is a
                different threat from the other two.
    all         every countermeasure together. The deployable configuration,
                and the only one where the costs add up.

Each condition is measured the same way: collect traffic with it on, fit a
recogniser per family on THAT traffic, and run the L1/L6 matrix against it.
Re-fitting matters. A recogniser trained against unprotected probing and
tested against protected probing would measure how stale a model goes, not
whether the countermeasure works - which is the mistake that produced the
first session result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Condition:
    """One point in the countermeasure comparison."""

    name: str
    mimic_host: bool = False
    mimic_traffic: bool = False
    subsample_bank: bool = False
    note: str = ""

    def baseline_kwargs(self) -> dict[str, Any]:
        """What capture_baseline accepts: mimic_host, and nothing else.

        Split from verify_kwargs because they genuinely differ, and a single
        dict claiming to serve both was wrong in both directions. It omitted
        subsample_bank, which verify_server does take - so a caller using it
        would have run the subsample condition as the control, the fifth
        flag in this project accepted and dropped. And it included
        mimic_traffic, which capture_baseline does NOT take, so splatting it
        there would have raised TypeError.

        Baselining is not paced. The baseline is captured once against a
        server that is still honest, and a traffic profile learned from that
        server does not exist yet.
        """
        return {"mimic_host": self.mimic_host}

    def verify_kwargs(self) -> dict[str, Any]:
        """What verify_server accepts: all three flags."""
        return {"mimic_host": self.mimic_host,
                "mimic_traffic": self.mimic_traffic,
                "subsample_bank": self.subsample_bank}

    def describe(self) -> str:
        on = [n for n, v in (("host", self.mimic_host),
                             ("traffic", self.mimic_traffic),
                             ("subsample", self.subsample_bank)) if v]
        return f"{self.name}: {', '.join(on) if on else 'no countermeasures'}"


CONDITIONS: tuple[Condition, ...] = (
    Condition("none",
              note="the RQ3 baseline; every channel as measured"),
    Condition("host", mimic_host=True,
              note="closes client, which RQ3 put at 1.000"),
    Condition("mimic", mimic_host=True, mimic_traffic=True,
              note="adds pacing, aimed at timing 0.951 and session 0.983"),
    Condition("subsample", subsample_bank=True,
              note="aimed at memorisation rather than recognition; deliberately "
                   "WITHOUT host or traffic, so its contribution is separable"),
    Condition("all", mimic_host=True, mimic_traffic=True, subsample_bank=True,
              note="the deployable configuration, and the only one whose costs add"),
)

BY_NAME = {c.name: c for c in CONDITIONS}


def h4_verdict(
    results: dict[str, dict[str, Any]],
    *,
    auc_ceiling: float = 0.6,
    recall_within: float = 10.0,
    false_alarm_rise: float = 2.0,
) -> dict[str, Any]:
    """Does the full condition satisfy H4?

    H4, as stated in the plan: with countermeasures the best classifier falls
    to AUC <= 0.6, detection returns to within 10 points of the no-evasion
    level, and false alarms rise by <= 2 points.

    All three, not any. A condition that flattens AUC by making probes so
    slow that detection collapses has not satisfied H4, and nor has one that
    restores detection by alarming on everything.
    """
    baseline = results.get("none") or {}
    full = results.get("all") or {}
    if not full:
        return {"verdict": "UNDEFINED",
                "reason": "the 'all' condition has not been measured"}

    best_auc = full.get("best_auc")
    recall_gap = full.get("recall_gap_pp")
    fa_delta = (full.get("false_alarm_pct", 0.0)
                - baseline.get("false_alarm_pct", 0.0))

    checks = {
        "auc_at_or_below_ceiling": (best_auc is not None and best_auc <= auc_ceiling),
        "recall_within_tolerance": (recall_gap is not None
                                    and abs(recall_gap) <= recall_within),
        "false_alarms_contained": fa_delta <= false_alarm_rise,
    }
    return {
        "verdict": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "best_auc": best_auc,
        "recall_gap_pp": recall_gap,
        "false_alarm_delta_pp": fa_delta,
        "thresholds": {"auc_ceiling": auc_ceiling,
                       "recall_within": recall_within,
                       "false_alarm_rise": false_alarm_rise},
        "note": ("A failed hypothesis is a result. The countermeasures are not "
                 "to be tuned until it passes."),
    }


def cost_table(results: dict[str, dict[str, Any]]) -> str:
    """What each condition costs, beside what it buys."""
    lines = ["", f"  {'condition':<12}{'best AUC':>10}{'recall':>10}"
                 f"{'false alarms':>14}{'cycle s':>10}{'calls':>8}"]
    lines.append("  " + "-" * 64)
    for cond in CONDITIONS:
        row = results.get(cond.name)
        if not row:
            lines.append(f"  {cond.name:<12}{'not measured':>10}")
            continue
        lines.append(
            f"  {cond.name:<12}{row.get('best_auc', float('nan')):>10.3f}"
            f"{row.get('recall_pct', float('nan')):>9.1f}%"
            f"{row.get('false_alarm_pct', float('nan')):>13.1f}%"
            f"{row.get('cycle_seconds', float('nan')):>10.1f}"
            f"{row.get('calls_per_cycle', 0):>8}")
    return "\n".join(lines)
