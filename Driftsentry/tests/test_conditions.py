"""The countermeasure conditions, and the hypothesis they are judged by.

RQ4 asks whether realistic probes restore detection and at what cost. It is
only answerable if the conditions differ in one thing at a time, which is
why the countermeasures were built and left switched off rather than turned
on as they were finished.

The tests here are mostly about H4 refusing to pass for the wrong reason. A
countermeasure can flatten AUC by making probing so slow that detection
collapses, or restore detection by alarming on everything. Either would look
like success in a single number, so H4 takes all three conditions together
and these tests check each one can fail on its own.
"""
from __future__ import annotations

import pytest

from eval.conditions import BY_NAME, CONDITIONS, Condition, cost_table, h4_verdict


# --------------------------------------------------------------------------- #
# The ladder
# --------------------------------------------------------------------------- #
def test_the_baseline_condition_has_nothing_switched_on():
    """'none' must reproduce what RQ3 measured, or nothing is comparable."""
    none = BY_NAME["none"]
    assert not (none.mimic_host or none.mimic_traffic or none.subsample_bank)


def test_each_condition_adds_one_thing_to_the_last():
    """One variable at a time, or a change cannot be attributed."""
    host, mimic = BY_NAME["host"], BY_NAME["mimic"]
    assert host.mimic_host and not host.mimic_traffic
    assert mimic.mimic_host and mimic.mimic_traffic and not mimic.subsample_bank


def test_subsample_is_measured_without_the_others():
    """It targets memorisation, a different threat from recognition, so its
    contribution has to be separable rather than bundled."""
    sub = BY_NAME["subsample"]
    assert sub.subsample_bank
    assert not sub.mimic_host and not sub.mimic_traffic


def test_the_full_condition_has_everything():
    full = BY_NAME["all"]
    assert full.mimic_host and full.mimic_traffic and full.subsample_bank


def test_probe_kwargs_only_carry_what_the_probe_path_accepts():
    """subsample_bank is handled at capture, not passed to verify_server."""
    kwargs = BY_NAME["all"].probe_kwargs()
    assert set(kwargs) == {"mimic_host", "mimic_traffic"}
    assert all(kwargs.values())


def test_every_condition_explains_itself():
    for cond in CONDITIONS:
        assert cond.note, cond.name
        assert cond.describe()


# --------------------------------------------------------------------------- #
# H4 - all three, never any
# --------------------------------------------------------------------------- #
def _results(**overrides):
    base = {
        "none": {"best_auc": 1.0, "recall_pct": 0.0, "false_alarm_pct": 8.0},
        "all": {"best_auc": 0.55, "recall_pct": 95.0, "false_alarm_pct": 9.0,
                "recall_gap_pp": -5.0},
    }
    base["all"].update(overrides)
    return base


def test_h4_passes_when_all_three_hold():
    out = h4_verdict(_results())
    assert out["verdict"] == "PASS"
    assert all(out["checks"].values())


def test_h4_fails_when_the_classifier_still_works():
    out = h4_verdict(_results(best_auc=0.85))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["auc_at_or_below_ceiling"] is False


def test_h4_fails_when_detection_does_not_come_back():
    """Flattening AUC by making probing useless is not a countermeasure."""
    out = h4_verdict(_results(recall_gap_pp=-40.0))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["recall_within_tolerance"] is False


def test_h4_fails_when_detection_returns_by_alarming_on_everything():
    out = h4_verdict(_results(false_alarm_pct=30.0))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["false_alarms_contained"] is False


def test_recall_tolerance_is_two_sided():
    """Overshooting the no-evasion level is as suspicious as falling short."""
    assert h4_verdict(_results(recall_gap_pp=+40.0))["verdict"] == "FAIL"


def test_an_unmeasured_full_condition_is_undefined_not_failed():
    """Not having run it is a different statement from having run it and lost."""
    out = h4_verdict({"none": {"best_auc": 1.0}})
    assert out["verdict"] == "UNDEFINED"
    assert "not been measured" in out["reason"]


def test_the_verdict_says_not_to_tune_for_it():
    assert "not to be tuned" in h4_verdict(_results())["note"]


def test_the_thresholds_are_the_ones_the_plan_states():
    out = h4_verdict(_results())
    assert out["thresholds"] == {"auc_ceiling": 0.6, "recall_within": 10.0,
                                 "false_alarm_rise": 2.0}


# --------------------------------------------------------------------------- #
# Cost
# --------------------------------------------------------------------------- #
def test_cost_is_reported_beside_benefit():
    """A countermeasure that triples cycle time has to show that."""
    table = cost_table({
        "none": {"best_auc": 1.0, "recall_pct": 0.0, "false_alarm_pct": 8.0,
                 "cycle_seconds": 17.4, "calls_per_cycle": 18},
        "all": {"best_auc": 0.55, "recall_pct": 95.0, "false_alarm_pct": 9.0,
                "cycle_seconds": 41.2, "calls_per_cycle": 18},
    })
    assert "17.4" in table and "41.2" in table
    assert "cycle s" in table


def test_an_unmeasured_condition_says_so_rather_than_showing_zero():
    table = cost_table({"none": {"best_auc": 1.0, "recall_pct": 0.0,
                                 "false_alarm_pct": 8.0, "cycle_seconds": 17.4,
                                 "calls_per_cycle": 18}})
    assert "not measured" in table
