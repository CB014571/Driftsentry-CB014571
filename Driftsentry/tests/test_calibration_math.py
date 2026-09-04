"""Regression lock on threshold calibration.

The corroboration and temporal work will add thresholds to this module, so the
existing behaviour - especially the `weak` warning, which is what stops an
under-evidenced threshold being quoted as a result - is pinned first.
"""
from __future__ import annotations

import pytest

from driftsentry.calibration import (
    DEFAULT_MARGIN,
    DEFAULT_TARGET_FAR,
    MIN_OBSERVATIONS,
    MIN_SERVERS,
    MIN_THRESHOLD,
    PROVISIONAL_THRESHOLD,
    active_threshold,
    calibrate_from_ratios,
    load,
    save,
)

BACKEND = "onnx:all-MiniLM-L6-v2"


def _ratios(n: int, base: float = 0.5) -> list[float]:
    return [base + (i % 7) * 0.1 for i in range(n)]


def _calibrate(ratios, servers=("a", "b", "c"), **kwargs):
    return calibrate_from_ratios(
        ratios, servers=list(servers), embedding_backend=BACKEND, **kwargs
    )


# --------------------------------------------------------------------------- #
# The method
# --------------------------------------------------------------------------- #
def test_threshold_is_the_quantile_times_the_margin():
    cal = _calibrate([1.0] * 100 + [20.0])
    assert cal.margin == DEFAULT_MARGIN
    assert cal.target_far == DEFAULT_TARGET_FAR
    assert "quantile" in cal.method


def test_one_outlier_cannot_dictate_the_threshold():
    """A max-based threshold would silence the detector permanently.

    A deterministic tool has a near-zero band, so a single flicker yields a ratio
    in the hundreds of thousands. Taking a quantile keeps that from becoming the
    alert line.
    """
    ratios = [0.4] * 200 + [500_000.0]
    cal = _calibrate(ratios)
    assert cal.threshold_ratio < 100
    assert cal.max_benign_ratio == pytest.approx(500_000.0)


def test_threshold_never_drops_below_the_floor():
    """Alerting below ratio 1.0 would contradict the per-probe variance band."""
    cal = _calibrate([0.01] * 100)
    assert cal.threshold_ratio == MIN_THRESHOLD


def test_empty_calibration_set_is_refused():
    with pytest.raises(ValueError):
        _calibrate([])


# --------------------------------------------------------------------------- #
# The `weak` warning - four independent triggers
# --------------------------------------------------------------------------- #
def test_weak_when_too_few_servers():
    cal = _calibrate(_ratios(60), servers=("only-one",))
    assert cal.weak is True
    assert any("server" in w for w in cal.warnings)
    assert cal.n_servers == 1 < MIN_SERVERS


def test_weak_when_too_few_observations():
    cal = _calibrate(_ratios(5))
    assert cal.weak is True
    assert any("observation" in w for w in cal.warnings)
    assert cal.n_observations == 5 < MIN_OBSERVATIONS


def test_weak_when_the_floor_had_to_be_applied():
    cal = _calibrate([0.01] * 100)
    assert cal.weak is True
    assert any("floor" in w for w in cal.warnings)


def test_not_weak_with_adequate_evidence():
    cal = _calibrate(_ratios(120), servers=("a", "b", "c", "d"))
    assert cal.weak is False, cal.warnings
    assert cal.warnings == []


def test_describe_flags_weakness_in_text():
    weak = _calibrate(_ratios(5))
    assert "WEAK" in weak.describe()


# --------------------------------------------------------------------------- #
# Embedding-space safety
# --------------------------------------------------------------------------- #
def test_threshold_is_refused_across_embedding_backends():
    """Distances from two embedding spaces are not comparable.

    Carrying a threshold across them would be meaningless, so the stored value is
    rejected and the provisional one used instead.
    """
    save(_calibrate(_ratios(120), servers=("a", "b", "c")))
    threshold, source = active_threshold("hashing-256")
    assert threshold == PROVISIONAL_THRESHOLD
    assert "provisional" in source


def test_matching_backend_uses_the_stored_threshold():
    cal = _calibrate(_ratios(120), servers=("a", "b", "c"))
    save(cal)
    threshold, source = active_threshold(BACKEND)
    assert threshold == cal.threshold_ratio
    assert "calibrated" in source


def test_uncalibrated_falls_back_to_provisional():
    threshold, source = active_threshold(BACKEND)
    assert threshold == PROVISIONAL_THRESHOLD
    assert "not calibrated" in source


def test_round_trip_preserves_provenance():
    cal = _calibrate(_ratios(120), servers=("a", "b", "c"))
    save(cal)
    loaded = load()
    assert loaded.n_observations == cal.n_observations
    assert loaded.servers == cal.servers
    assert loaded.embedding_backend == cal.embedding_backend
    assert "no rug-pull or test data" in loaded.notes
