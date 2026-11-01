"""Per-tool thresholds, and the freeze that makes them auditable.

H1 asks whether a threshold per tool halves false alarms on real benign
upgrades without costing detection. Two things have to be right before that
question can be asked honestly.

A tool's threshold must come from its OWN benign runs before the upgrade -
never from runs after it, because the upgrade is the thing being judged. And
once fitted, the thresholds must be demonstrably unchanged when the test data
is scored. A promise in prose is not auditable; a content hash is.

The scorer's default must also stay exactly as it was. Experiments 1 and 2
are the control, and a change in how they score would invalidate them
silently - the golden tests exist for that and are checked here too.
"""
from __future__ import annotations

import json

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.calibration import (
    MIN_OBS_PER_TOOL,
    MIN_THRESHOLD,
    fit_per_tool,
    freeze,
    verify_frozen,
)


def _rows(tool: str, ratios: list[float]) -> list[dict]:
    return [{"tool": tool, "ratio": r} for r in ratios]


# --------------------------------------------------------------------------- #
# Fitting
# --------------------------------------------------------------------------- #
def test_a_quiet_tool_gets_a_lower_bar_than_a_noisy_one():
    """The whole point. One global number is set by the noisiest tool."""
    rows = (_rows("lookup_customer", [0.01] * 12)
            + _rows("get_weather", [3.0, 3.4, 2.8, 3.1, 3.9, 3.2, 2.9, 3.3,
                                    3.0, 3.5, 3.1, 4.0]))
    fit = fit_per_tool(rows, global_threshold=10.0)
    quiet = fit["thresholds"]["lookup_customer"]
    noisy = fit["thresholds"]["get_weather"]
    assert quiet < noisy, "a deterministic tool must not inherit a weather feed's bar"
    assert noisy < 10.0, "and the noisy tool should still beat the global number"


def test_a_tool_with_too_few_observations_keeps_the_global_threshold():
    """A quantile from three points is an extrapolation, not a measurement."""
    rows = _rows("rare_tool", [0.5, 0.6, 0.7])
    fit = fit_per_tool(rows, global_threshold=10.8086)
    assert fit["thresholds"]["rare_tool"] == 10.8086
    assert fit["provenance"]["rare_tool"]["source"] == "global_fallback"
    assert fit["n_per_tool"] == 0


def test_the_minimum_observation_count_is_the_boundary():
    at = fit_per_tool(_rows("t", [1.0] * MIN_OBS_PER_TOOL), global_threshold=9.0)
    below = fit_per_tool(_rows("t", [1.0] * (MIN_OBS_PER_TOOL - 1)), global_threshold=9.0)
    assert at["provenance"]["t"]["source"] == "per_tool"
    assert below["provenance"]["t"]["source"] == "global_fallback"


def test_a_threshold_never_falls_below_the_alert_floor():
    """Below 1.0 would mean alerting on drift smaller than benign variation."""
    fit = fit_per_tool(_rows("quiet", [0.001] * 20), global_threshold=10.0)
    assert fit["thresholds"]["quiet"] >= MIN_THRESHOLD


def test_provenance_records_how_each_threshold_was_reached():
    rows = _rows("t", [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.0])
    prov = fit_per_tool(rows, global_threshold=9.0)["provenance"]["t"]
    assert prov["n"] == 10
    assert prov["source"] == "per_tool"
    assert prov["max_benign_ratio"] == 2.0
    assert "operating_point" in prov and "mean_benign_ratio" in prov


def test_the_rule_is_recorded_alongside_the_thresholds():
    """The calibration servers fix the RULE; test servers supply their own data."""
    fit = fit_per_tool(_rows("t", [1.0] * 10), global_threshold=9.0)
    assert fit["rule"] == {"quantile": 0.99, "margin": 1.25,
                           "floor": MIN_THRESHOLD, "min_obs": MIN_OBS_PER_TOOL}


def test_rows_missing_a_tool_or_ratio_are_skipped_not_guessed():
    rows = _rows("t", [1.0] * 10) + [{"tool": None, "ratio": 5.0}, {"tool": "x"}]
    fit = fit_per_tool(rows, global_threshold=9.0)
    assert set(fit["thresholds"]) == {"t"}


def test_no_rows_gives_no_thresholds_rather_than_an_error():
    fit = fit_per_tool([], global_threshold=9.0)
    assert fit["thresholds"] == {} and fit["n_tools"] == 0


# --------------------------------------------------------------------------- #
# Freezing
# --------------------------------------------------------------------------- #
def test_freeze_then_verify_round_trips(tmp_path):
    path = tmp_path / "thresholds.json"
    sealed = freeze({"thresholds": {"a": 1.5, "b": 2.0}}, path)
    assert sealed["_sha256"] and sealed["_frozen_at"]
    loaded = verify_frozen(path)
    assert loaded["thresholds"] == {"a": 1.5, "b": 2.0}


def test_an_edited_threshold_is_refused(tmp_path):
    """The failure mode this exists for: a quiet re-fit after seeing results."""
    path = tmp_path / "thresholds.json"
    freeze({"thresholds": {"a": 1.5}}, path)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["thresholds"]["a"] = 99.0            # someone "improves" the result
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="changed since it was frozen"):
        verify_frozen(path)


def test_a_file_that_was_never_frozen_is_refused(tmp_path):
    path = tmp_path / "plain.json"
    path.write_text(json.dumps({"thresholds": {"a": 1.0}}), encoding="utf-8")
    with pytest.raises(ValueError, match="never frozen"):
        verify_frozen(path)


def test_key_order_does_not_change_the_digest(tmp_path):
    """Rewriting the file with keys in another order must still verify."""
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    first = freeze({"x": 1, "y": 2}, a)
    second = freeze({"y": 2, "x": 1}, b)
    assert first["_sha256"] == second["_sha256"]


def test_the_timestamp_is_not_part_of_the_digest(tmp_path):
    """Two freezes of the same content agree, so a re-freeze is detectable
    as a content change rather than hidden by a changing timestamp."""
    a = freeze({"v": 1}, tmp_path / "a.json")
    b = freeze({"v": 1}, tmp_path / "b.json")
    assert a["_sha256"] == b["_sha256"]
    assert a["_frozen_at"] <= b["_frozen_at"]


# --------------------------------------------------------------------------- #
# The scorer
# --------------------------------------------------------------------------- #
# Real ProbeCheck and ReprobeReport, built the way the golden tests build
# them. A hand-rolled stub drifts from the dataclasses and ends up testing the
# stub rather than the scorer.
HASH = "sha256:" + "a" * 64


def _check(tool: str, ratio: float) -> ProbeCheck:
    return ProbeCheck(
        tool=tool, probe_id=f"{tool}#0", distance=0.5, band=0.1, ratio=ratio,
        within_band=False, shape_known=True, new_hosts=[], new_files=[],
        new_content_flags=[], observed_shape_hash="sha256:deadbeef",
        observed_excerpt="x", baseline_excerpt="x", became_error=False,
    )


def _report(checks) -> ReprobeReport:
    return ReprobeReport(
        server="acme", baseline_definition_hash=HASH,
        observed_definition_hash=HASH, checks=checks,
        embedding_backend="onnx:all-MiniLM-L6-v2",
    )


def test_per_tool_defaults_to_none_and_changes_nothing():
    from driftsentry.scorer import score_report

    report = _report([_check("get_weather", 5.0)])
    plain = score_report(report, threshold_ratio=10.0)
    explicit = score_report(report, threshold_ratio=10.0, per_tool=None)
    assert plain.score == explicit.score


def test_a_tool_with_its_own_threshold_is_judged_by_it():
    from driftsentry.scorer import score_report

    report = _report([_check("get_weather", 5.0)])
    loose = score_report(report, threshold_ratio=10.0).score
    tight = score_report(report, threshold_ratio=10.0,
                         per_tool={"get_weather": 2.0}).score
    assert tight > loose, "a tighter per-tool bar must raise the score"


def test_a_tool_absent_from_the_map_falls_back_to_the_global_threshold():
    from driftsentry.scorer import score_report

    report = _report([_check("unknown_tool", 5.0)])
    fallback = score_report(report, threshold_ratio=10.0,
                            per_tool={"other": 1.0}).score
    plain = score_report(report, threshold_ratio=10.0).score
    assert fallback == plain
