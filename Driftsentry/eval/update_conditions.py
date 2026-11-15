"""One update, scored five ways (T27, RQ3a).

H3 compares residue checking against the three ways a defence treats an
update today. All five are scored from the SAME re-probe measurement - not five
runs - so the comparison is paired and McNemar applies. A separate run per
condition would give each its own attacker randomness and its own noise, and a
real difference could hide inside that.

    accept_rebaseline  The update is approved, and its new behaviour becomes the
                       baseline. If the definitions changed, whatever was hidden
                       in the update is absorbed: no alert. If they did not
                       change, there is nothing to approve and the full detector
                       runs as usual.
    refuse_all         Every definition change is refused, and so is any
                       behaviour the full detector alerts on. Catches what it
                       catches by alarming on every legitimate update too.
    definition_diff    Alerts when the declared definitions differ, asking for
                       the whole update to be re-approved. Never attributes
                       behaviour, so it can never DETECT a hidden change in the
                       attributed sense H3 counts.
    new_host_only      Alerts only on a new outbound host.
    residue            Declared-diff residue checking: DriftSentry's answer.

A deviation from the plan, stated: definition_diff compares the full declared
definitions rather than running mode="hash-only". Measured on the attacker, the
definition hash does not move for ANY cover change - output fields and
annotations are both outside it - so a hash-only check could never react to an
update at all, which is not the check the report describes ("would only have
asked for re-approval of the whole update"). The hash-only reading is still
recorded, in the existing hash_detected column.

"Definition changed" means the declared diff is non-empty, never the hash,
for the same reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from driftsentry.declared_diff import DeclaredDiff, diff_definitions
from driftsentry.residue import SIGNAL_NAMES
from driftsentry.scorer import ALERT_AT, DriftReport, score_report
from eval.ground_truth import attributed

CONDITIONS = ("accept_rebaseline", "refuse_all", "definition_diff",
              "new_host_only", "residue")


@dataclass
class ConditionResult:
    alert: bool = False
    attributed: bool = False


@dataclass
class UpdateScore:
    diff: DeclaredDiff
    full: DriftReport
    residue: DriftReport
    conditions: dict[str, ConditionResult] = field(default_factory=dict)


def alerting_signals(report: DriftReport) -> dict[str, set[str]]:
    """Tool -> residue-vocabulary names of every signal at the alert line."""
    out: dict[str, set[str]] = {}
    for tool in report.tools:
        pools = [tool.signals] + [p.signals for p in tool.probes]
        for signals in pools:
            for sig in signals:
                if sig.score >= ALERT_AT:
                    out.setdefault(tool.tool, set()).add(SIGNAL_NAMES.get(sig.name, sig.name))
    return out


def new_host_signals(measurement: Any) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for check in measurement.checks:
        if check.new_hosts:
            out.setdefault(check.tool, set()).add("new_egress_host")
    return out


def score_update(
    measurement: Any,                     # driftsentry.baseline.ReprobeReport
    baseline_definitions: list[dict],
    *,
    threshold_ratio: float,
    calibration_source: str = "provisional",
    per_tool: dict[str, float] | None = None,
    family: str = "",
    payload: str | None = None,
    attacked_tool: str = "",
    rules_version: str = "1.0",
) -> UpdateScore:
    """Score one update re-probe under every condition."""
    diff = diff_definitions(baseline_definitions, measurement.observed_definitions)
    full = score_report(measurement, threshold_ratio=threshold_ratio,
                        calibration_source=calibration_source, mode="full",
                        per_tool=per_tool)
    residue = score_report(measurement, threshold_ratio=threshold_ratio,
                           calibration_source=calibration_source, mode="residue",
                           per_tool=per_tool, declared_diff=diff,
                           rules_version=rules_version)

    def attr(signals: dict[str, set[str]]) -> bool:
        return attributed(signals, attacked_tool=attacked_tool,
                          family=family, payload=payload)

    changed = not diff.empty
    full_alert = full.verdict == "alert"
    full_attr = full_alert and attr(alerting_signals(full))
    hosts = new_host_signals(measurement)

    out = UpdateScore(diff=diff, full=full, residue=residue)
    out.conditions = {
        "accept_rebaseline": (ConditionResult() if changed
                              else ConditionResult(full_alert, full_attr)),
        "refuse_all": ConditionResult(changed or full_alert, full_attr),
        "definition_diff": ConditionResult(changed, False),
        "new_host_only": ConditionResult(bool(hosts), attr(hosts)),
        "residue": ConditionResult(
            residue.verdict == "alert",
            residue.verdict == "alert" and attr(alerting_signals(residue))),
    }
    return out
