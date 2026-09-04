"""Regression lock on the drift scorer.

Written BEFORE the corroboration/keyed-probe work so that any change to the
scoring behaviour has to be deliberate. The constraint on this upgrade is
"preserve the working detector", and the only way to hold to that while
refactoring is to pin what the detector currently does.

The expected values here are derived from the documented weights, not copied out
of a run - so if the code and the design ever disagree, this fails rather than
quietly blessing whatever the code happens to do.
"""
from __future__ import annotations

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.scorer import (
    ALERT_AT,
    W_BEHAVIOURAL_MAX,
    W_DEFINITION_HASH,
    W_RULE_HIGH,
    W_RULE_MEDIUM,
    W_STRUCTURAL,
    WATCH_AT,
    score_report,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
THRESHOLD = 2.0


def _check(**kwargs) -> ProbeCheck:
    """A benign probe check; override one field at a time to isolate a signal."""
    defaults = dict(
        tool="lookup_customer",
        probe_id="lookup_customer#0",
        distance=0.01,
        band=0.02,
        ratio=0.5,
        within_band=True,
        shape_known=True,
        new_hosts=[],
        new_files=[],
        new_content_flags=[],
        observed_shape_hash="sha256:deadbeef",
        observed_excerpt="Record: Dana Whitfield",
        baseline_excerpt="Record: Dana Whitfield",
        became_error=False,
    )
    defaults.update(kwargs)
    return ProbeCheck(**defaults)


def _report(checks, *, observed_hash: str = HASH_A) -> ReprobeReport:
    return ReprobeReport(
        server="acme",
        baseline_definition_hash=HASH_A,
        observed_definition_hash=observed_hash,
        checks=checks,
        embedding_backend="onnx:all-MiniLM-L6-v2",
    )


def score(checks, **kwargs):
    return score_report(_report(checks, **kwargs), threshold_ratio=THRESHOLD)


# --------------------------------------------------------------------------- #
# Verdict bands
# --------------------------------------------------------------------------- #
def test_benign_scores_below_watch():
    """ratio 0.5 against threshold 2.0 -> 0.25 evidence units, well clear of watch."""
    report = score([_check(ratio=0.5)])
    assert report.score == pytest.approx(0.25)
    assert report.verdict == "ok"
    assert report.triggered_by is None


def test_behavioural_drift_alerts_and_is_capped():
    """The behavioural signal saturates at W_BEHAVIOURAL_MAX.

    Uncapped this would be 20.0. The cap exists because past a few multiples of
    the threshold the signal has said everything it can, and unbounded numbers
    are unusable in a report or on a plot.
    """
    report = score([_check(ratio=40.0, distance=0.8, within_band=False)])
    assert report.score == pytest.approx(W_BEHAVIOURAL_MAX)
    assert report.verdict == "alert"
    assert report.triggered_by == "behavioural_drift"


def test_structural_change_alone_is_watch_not_alert():
    """Structure moving on its own is deliberately below the alert line.

    Benign updates add optional fields all the time, so this must not alert by
    itself - it becomes decisive only when the embedding signal is also up.
    """
    report = score([_check(shape_known=False)])
    assert report.score == pytest.approx(W_STRUCTURAL)
    assert WATCH_AT <= report.score < ALERT_AT
    assert report.verdict == "watch"
    assert report.triggered_by == "structural_change"


# --------------------------------------------------------------------------- #
# Security rules
# --------------------------------------------------------------------------- #
def test_new_egress_host_is_high_severity():
    report = score([_check(new_hosts=["203.0.113.7"])])
    assert report.score == pytest.approx(W_RULE_HIGH)
    assert report.verdict == "alert"
    assert report.triggered_by == "rule:new_egress_host"


def test_secret_file_read_is_high_severity():
    report = score([_check(new_files=["/home/u/.ssh/id_rsa"])])
    assert report.score == pytest.approx(W_RULE_HIGH)
    assert report.triggered_by == "rule:secret_file_read"


def test_ordinary_new_file_is_medium():
    report = score([_check(new_files=["/tmp/cache/output.txt"])])
    assert report.score == pytest.approx(W_RULE_MEDIUM)
    assert report.verdict == "alert"
    assert report.triggered_by == "rule:new_file_access"


def test_definition_hash_change_dominates():
    report = score([_check(ratio=0.5)], observed_hash=HASH_B)
    assert report.score == pytest.approx(W_DEFINITION_HASH)
    assert report.definition_changed is True
    assert report.triggered_by == "definition_hash"


def test_definition_change_alerts_even_with_no_probeable_tools():
    report = score([], observed_hash=HASH_B)
    assert report.verdict == "alert"
    assert report.tools[0].tool == "<server definition>"


# --------------------------------------------------------------------------- #
# Combination rules - the two decisions most at risk from the upgrade
# --------------------------------------------------------------------------- #
def test_signals_combine_by_maximum_not_sum():
    """Three mid-strength signals must NOT accumulate into a higher score.

    This is the property the corroboration mode is being added ALONGSIDE rather
    than instead of. If this test starts failing, max() has been replaced rather
    than supplemented.
    """
    report = score([_check(ratio=1.6, shape_known=False, became_error=True)])
    behavioural = 1.6 / THRESHOLD          # 0.8
    assert report.score == pytest.approx(max(behavioural, W_STRUCTURAL))
    assert report.score < behavioural + W_STRUCTURAL


def test_worst_probe_decides_the_tool():
    """An attack that fires on only some inputs must not be averaged away."""
    report = score([
        _check(probe_id="lookup_customer#0", ratio=0.2),
        _check(probe_id="lookup_customer#1", ratio=0.2),
        _check(probe_id="lookup_customer#2", ratio=40.0, within_band=False),
    ])
    assert report.verdict == "alert"
    assert report.score == pytest.approx(W_BEHAVIOURAL_MAX)


def test_hash_only_mode_discards_every_behavioural_signal():
    """The control condition must see nothing but the definition hash."""
    checks = [_check(ratio=40.0, new_hosts=["203.0.113.7"], shape_known=False)]
    report = score_report(_report(checks), threshold_ratio=THRESHOLD, mode="hash-only")
    assert report.score == 0.0
    assert report.verdict == "ok"
    assert report.tools[0].tool == "<server definition>"


def test_hash_only_mode_still_catches_a_definition_change():
    report = score_report(
        _report([_check()], observed_hash=HASH_B),
        threshold_ratio=THRESHOLD,
        mode="hash-only",
    )
    assert report.score == pytest.approx(W_DEFINITION_HASH)
    assert report.verdict == "alert"


def test_threshold_normalises_across_noisy_and_quiet_tools():
    """A noisy tool and a deterministic one must alert at the same score.

    This is what makes one global threshold meaningful: the ratio is already
    divided by each probe's own variance band before it gets here.
    """
    quiet = score([_check(ratio=2.0)])
    noisy = score([_check(ratio=2.0, band=1.5, distance=3.0)])
    assert quiet.score == pytest.approx(noisy.score)
