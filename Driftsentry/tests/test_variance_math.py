"""Regression lock on the variance model.

Three of these encode bugs that were found the hard way and cost real debugging
time. They exist so the family-baseline work cannot silently reintroduce them.
"""
from __future__ import annotations

import math

import pytest

from driftsentry.embeddings import HashingEmbedding, cosine_distance
from driftsentry.fingerprint import (
    BAND_SIGMA,
    MIN_BAND,
    ProbeSample,
    centroid_of,
    leave_one_out_distances,
    normalize_result,
    summarize_probe,
)


def _unit(*values) -> list[float]:
    norm = math.sqrt(sum(v * v for v in values))
    return [v / norm for v in values]


# --------------------------------------------------------------------------- #
# Cosine distance
# --------------------------------------------------------------------------- #
def test_identical_vectors_have_zero_distance():
    v = _unit(1.0, 2.0, 3.0)
    assert cosine_distance(v, v) == pytest.approx(0.0, abs=1e-12)


def test_distance_is_clamped_to_non_negative():
    """Floating-point error can push cosine just outside [-1, 1].

    Without the clamp this surfaces as a distracting '-0.0000' distance.
    """
    v = _unit(1.0, 0.0)
    assert cosine_distance(v, v) >= 0.0


def test_orthogonal_vectors_are_distance_one():
    assert cosine_distance([1.0, 0.0], [0.0, 1.0]) == pytest.approx(1.0)


def test_empty_vectors_do_not_divide_by_zero():
    assert cosine_distance([0.0, 0.0], [0.0, 0.0]) == 0.0
    assert cosine_distance([0.0, 0.0], [1.0, 0.0]) == 1.0


# --------------------------------------------------------------------------- #
# Leave-one-out - the fix for in-sample variance
# --------------------------------------------------------------------------- #
def test_leave_one_out_is_wider_than_in_sample():
    """The bug this replaced.

    Measuring spread against a centroid fitted to the same samples gives an
    in-sample estimate that is systematically too tight, so the first honest
    re-probe of a naturally noisy tool breaches the band and a benign server
    false-alarms. Held-out distances must be at least as large.
    """
    embeddings = [
        _unit(1.0, 0.05, 0.0),
        _unit(1.0, -0.05, 0.0),
        _unit(1.0, 0.0, 0.06),
        _unit(0.98, 0.02, -0.04),
    ]
    centroid = centroid_of(embeddings)
    in_sample = [cosine_distance(e, centroid) for e in embeddings]
    held_out = leave_one_out_distances(embeddings)
    assert max(held_out) > max(in_sample)


def test_leave_one_out_falls_back_below_three_samples():
    """Nothing to hold out with fewer than three; documented as optimistic."""
    embeddings = [_unit(1.0, 0.0), _unit(0.99, 0.1)]
    assert len(leave_one_out_distances(embeddings)) == 2


def test_identical_samples_give_zero_spread():
    v = _unit(1.0, 2.0, 3.0)
    assert leave_one_out_distances([v, v, v, v]) == pytest.approx([0.0] * 4, abs=1e-12)


# --------------------------------------------------------------------------- #
# The band
# --------------------------------------------------------------------------- #
def _samples(texts: list[str]) -> list[ProbeSample]:
    backend = HashingEmbedding(dim=64)
    vectors = backend.embed(texts)
    out = []
    for text, vec in zip(texts, vectors):
        norm = normalize_result({"content": [{"type": "text", "text": text}]})
        out.append(ProbeSample(embedding=vec, normalized=norm, latency_ms=1.0))
    return out


def test_deterministic_tool_gets_the_noise_floor_not_zero():
    """A zero-width band would divide by zero in the scorer.

    MIN_BAND is 0.01, not 1e-6: the smaller floor implies precision the embedding
    does not have, and produced a drift score of 263,659 on a tool whose baseline
    behaviour was perfectly deterministic.
    """
    baseline = summarize_probe("p#0", "t", {}, _samples(["identical answer"] * 6))
    assert baseline.dist_max == pytest.approx(0.0, abs=1e-9)
    assert baseline.band == MIN_BAND


def test_noisy_tool_gets_a_band_above_the_floor():
    texts = [
        "London: 12C, clear, humidity 60%.",
        "London: 19C, light rain, humidity 88%.",
        "London: 7C, overcast, humidity 45%.",
        "London: 23C, breezy, humidity 71%.",
        "London: 15C, misty, humidity 55%.",
    ]
    baseline = summarize_probe("p#0", "t", {}, _samples(texts))
    assert baseline.band > MIN_BAND


def test_band_covers_both_worst_case_and_sigma_rule():
    texts = ["answer one", "answer two", "answer three", "answer four"]
    baseline = summarize_probe("p#0", "t", {}, _samples(texts))
    assert baseline.band >= baseline.dist_max
    assert baseline.band >= baseline.dist_mean + BAND_SIGMA * baseline.dist_std


# --------------------------------------------------------------------------- #
# Response normalisation
# --------------------------------------------------------------------------- #
def test_structure_ignores_values_but_notices_new_fields():
    a = normalize_result({"content": [{"type": "text", "text": "one"}]})
    b = normalize_result({"content": [{"type": "text", "text": "two"}]})
    assert a.shape_hash == b.shape_hash, "different values must not change shape"

    c = normalize_result({"content": [{"type": "text", "text": "one"}], "extra": {"leak": 1}})
    assert c.shape_hash != a.shape_hash, "a new field must change shape"


def test_list_length_is_not_a_structural_change():
    two = normalize_result({"content": [{"type": "text", "text": "a"},
                                        {"type": "text", "text": "b"}]})
    three = normalize_result({"content": [{"type": "text", "text": "a"},
                                          {"type": "text", "text": "b"},
                                          {"type": "text", "text": "c"}]})
    assert two.shape_hash == three.shape_hash


def test_error_flag_is_carried_through():
    norm = normalize_result({"content": [{"type": "text", "text": "boom"}], "isError": True})
    assert norm.is_error is True
