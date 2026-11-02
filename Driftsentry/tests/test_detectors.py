"""Three detectors scored on one episode, and the rule that must not be tuned.

H2 compares active probing against hash pinning and passive monitoring. Two
things decide whether that comparison means anything.

The three verdicts must come from ONE episode. Running them separately makes
the comparison unpaired, which discards exactly what McNemar uses - the
episodes where two detectors disagreed - and lets a real difference be missed.

The passive rule must be fixed before the attacks are scored. Passive
monitoring emits findings, not a verdict, so some rule has to turn one into
the other. That rule is a free parameter, and choosing it after seeing attack
results is fitting the detector to the test. It is calibrated on benign
episodes only and sealed with a content hash.
"""
from __future__ import annotations

import json

import pytest

from eval.detectors import (
    DEFAULT_RULE,
    calibrate_passive_rule,
    freeze_rule,
    full_detected,
    hash_detected,
    load_frozen_rule,
    passive_detected,
    three_way_report,
)


class _Report:
    def __init__(self, verdict="ok", definition_changed=False):
        self.verdict = verdict
        self.definition_changed = definition_changed


def _passive(findings, available=True):
    return {"available": available, "findings": findings,
            "summary": {"findings": len(findings)}}


def _finding(severity="high", kind="new_egress_host"):
    return {"severity": severity, "kind": kind, "tool": "lookup_customer"}


# --------------------------------------------------------------------------- #
# Reading each detector
# --------------------------------------------------------------------------- #
def test_hash_only_sees_a_definition_change_and_nothing_else():
    """The premise of the project: a behavioural rug pull leaves it untouched."""
    assert hash_detected(_Report(verdict="alert", definition_changed=False)) is False
    assert hash_detected(_Report(verdict="ok", definition_changed=True)) is True


def test_the_full_detector_is_the_scorer_verdict():
    assert full_detected(_Report(verdict="alert")) is True
    assert full_detected(_Report(verdict="watch")) is False


def test_all_three_read_the_same_report_object():
    """They must not be able to differ by anything except which signals they use."""
    report = _Report(verdict="alert", definition_changed=True)
    assert full_detected(report) and hash_detected(report)


# --------------------------------------------------------------------------- #
# The passive rule
# --------------------------------------------------------------------------- #
def test_the_rule_fires_at_or_above_its_severity_floor():
    rule = {"min_severity": "high", "min_findings": 1}
    assert passive_detected(_passive([_finding("high")]), rule) is True
    assert passive_detected(_passive([_finding("low")]), rule) is False


def test_the_rule_counts_findings():
    rule = {"min_severity": "low", "min_findings": 2}
    assert passive_detected(_passive([_finding("low")]), rule) is False
    assert passive_detected(_passive([_finding("low"), _finding("low")]), rule) is True


def test_monitoring_that_never_ran_is_not_a_clean_result():
    """An episode where nothing was watched and one that was watched and came
    back clean are different claims. Conflating them would credit passive
    monitoring with episodes it never saw."""
    assert passive_detected(_passive([_finding("high")], available=False)) is False
    # ...and the caller records which it was, via passive_available.


def test_an_unknown_severity_does_not_crash_the_rule():
    assert passive_detected(_passive([{"severity": "catastrophic"}]),
                            {"min_severity": "high", "min_findings": 1}) is False


# --------------------------------------------------------------------------- #
# Calibration - benign only, weakest clean rule
# --------------------------------------------------------------------------- #
def test_the_weakest_clean_rule_is_chosen():
    """Strictness here would flatter active probing.

    A rule tuned tight makes passive monitoring look worse than it is, and H2
    would credit the margin to the method rather than to the rule.
    """
    rule = calibrate_passive_rule([_passive([]) for _ in range(5)])
    assert rule["min_severity"] == "low"
    assert rule["min_findings"] == 1


def test_calibration_loosens_only_as_far_as_benign_noise_requires():
    from eval.detectors import SEVERITIES

    noisy = [_passive([_finding("low")]) for _ in range(5)]
    rule = calibrate_passive_rule(noisy)
    assert not any(passive_detected(obs, rule) for obs in noisy)

    # Benign noise is one low finding, so the weakest clean rule raises the
    # COUNT rather than the severity floor - keeping it sensitive to a single
    # high-severity finding, which is what an attack would produce.
    assert rule["min_severity"] == "low"
    assert rule["min_findings"] == 2
    assert SEVERITIES.index(rule["min_severity"]) < SEVERITIES.index("high"), (
        "raising the severity floor would blind it to a lone high finding")


def test_benign_traffic_that_always_alarms_is_reported_not_hidden():
    """If no rule is clean, that is the finding and must be said."""
    bad = [_passive([_finding("high")] * 5) for _ in range(5)]
    rule = calibrate_passive_rule(bad)
    assert "no rule was clean" in rule["note"]
    assert rule["min_severity"] == DEFAULT_RULE["min_severity"]


def test_calibration_records_how_much_benign_data_it_saw():
    rule = calibrate_passive_rule([_passive([]) for _ in range(7)])
    assert rule["calibrated_on"] == 7


# --------------------------------------------------------------------------- #
# Freezing
# --------------------------------------------------------------------------- #
def test_a_frozen_rule_round_trips(tmp_path):
    path = tmp_path / "passive_rule.json"
    freeze_rule({"min_severity": "high", "min_findings": 1}, path)
    loaded = load_frozen_rule(path)
    assert loaded["min_severity"] == "high"


def test_a_rule_edited_after_freezing_is_refused(tmp_path):
    """The failure this exists for: loosening the rule once results are in."""
    path = tmp_path / "passive_rule.json"
    freeze_rule({"min_severity": "high", "min_findings": 1}, path)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["min_severity"] = "low"              # suddenly much more sensitive
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="changed since it was frozen"):
        load_frozen_rule(path)


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
class _Row:
    def __init__(self, fired, hash_d, passive_d, full_d, family="content-injection"):
        self.attack_fired = fired
        self.hash_detected = hash_d
        self.passive_detected = passive_d
        self.full_detected = full_d
        self.attack_family = family


def test_the_report_compares_only_episodes_where_the_attack_fired():
    """An attack that never executed is not a missed detection for anyone."""
    rows = [_Row(True, False, False, True) for _ in range(8)]
    rows += [_Row(False, False, False, False) for _ in range(4)]
    text = three_way_report(rows)
    assert "8/8" in text, "only fired episodes belong in the denominator"


def test_the_report_names_the_paired_test_and_its_discordant_counts():
    rows = [_Row(True, False, False, True) for _ in range(10)]
    text = three_way_report(rows)
    assert "full vs hash-only" in text
    assert "discordant" in text
    assert "full only 10" in text


def test_no_fired_episodes_says_so_rather_than_reporting_zero():
    text = three_way_report([_Row(False, False, False, False)])
    assert "nothing to compare" in text
    assert "property of the run, not a result" in text


def test_false_alarms_are_reported_beside_recall():
    rows = [_Row(True, False, False, True) for _ in range(5)]
    rows += [_Row(False, False, True, True, family="benign") for _ in range(3)]
    text = three_way_report(rows)
    assert "false alarms" in text
    assert "/3" in text, "benign episodes form the false-alarm denominator"
