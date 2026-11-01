"""The family band must measure what the family comparison compares.

The defect this file exists to prevent, stated precisely:

    summarize_family built the band from leave-one-out distances between
    INSTANCE CENTROIDS - each an average of n_samples responses.
    compare_to_family measures max(distance of an INDIVIDUAL sample).

    For a tool with genuine randomness, individual samples scatter far more
    widely than averages of six of them do. Comparing the first against a
    band built from the second makes the ratio exceed 1 by construction, and
    the tool alarms on every honest cycle.

What it cost, measured rather than reasoned about: across 120 verification
cycles against a server that was benign throughout, get_weather scored
between 1.549 and 3.000 - a 100% false-alarm rate - with a band of 0.0173
against real variation of about 0.06.

The tell that identified it: raising samples_per_probe made the ratio WORSE
(3.53 -> 3.79 -> 4.11), because max() over more samples finds a more extreme
one while the band stayed a property of the averages. Sampling noise would
have made it better.

So the property under test is commensurability: whatever compare_to_family
measures, summarize_family must have measured the same kind of thing.
"""
from __future__ import annotations

import math
import random

import pytest

from driftsentry.families import compare_to_family, summarize_family
from driftsentry.fingerprint import MIN_BAND, NormalizedResponse, centroid_of


class _Norm:
    def __init__(self, text: str):
        self.text = text
        self.text_hash = "sha256:" + str(abs(hash(text)))[:16]
        self.shape_hash = "sha256:shape"
        self.n_chars = len(text)
        self.n_blocks = 1
        self.is_error = False


class _Sample:
    """A baseline sample. Only what families.py reads."""

    def __init__(self, embedding, text="r"):
        self.embedding = embedding
        self.normalized = _Norm(text)
        self.hosts: list[str] = []
        self.files: list[str] = []
        self.content_flags: list[str] = []
        self.latency_ms = 1.0


class _Instance:
    def __init__(self, centroid):
        self.centroid = centroid
        self.probe_id = "p"
        self.args: dict = {}


def _unit(vec):
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _noisy(base, sigma, rng, dim=16):
    return _unit([b + rng.gauss(0, sigma) for b in base])


def _family(sigma, *, n_instances=3, n_samples=6, seed=0, dim=16):
    """A tool whose individual responses scatter by ``sigma`` around their
    own instance centre, with instances themselves close together."""
    rng = random.Random(seed)
    base = _unit([rng.gauss(0, 1) for _ in range(dim)])

    instances, groups = [], []
    for _ in range(n_instances):
        centre = _noisy(base, 0.01, rng, dim)          # instances are alike
        samples = [_Sample(_noisy(centre, sigma, rng, dim)) for _ in range(n_samples)]
        groups.append(samples)
        instances.append(_Instance(centroid_of([s.embedding for s in samples])))

    return summarize_family("fam", "get_weather", {"city": "text"},
                            instances, groups), groups, base, rng, dim


# --------------------------------------------------------------------------- #
# The regression
# --------------------------------------------------------------------------- #
def test_a_random_tool_does_not_alarm_on_an_honest_cycle():
    """The 100% false-alarm case, in miniature."""
    family, _, base, rng, dim = _family(sigma=0.25)
    centre = _noisy(base, 0.01, rng, dim)
    fresh = [_Sample(_noisy(centre, 0.25, rng, dim)) for _ in range(2)]

    result = compare_to_family(family, fresh)
    assert result["ratio"] <= 1.0, (
        f"a benign cycle scored {result['ratio']:.2f}x its band - the band "
        f"({family.band:.4f}) does not cover the scatter it is compared against")
    assert result["within_band"]


def test_the_band_covers_individual_samples_not_averages_of_them():
    """The band must be commensurable with what compare_to_family measures."""
    family, groups, _, _, _ = _family(sigma=0.25)
    worst_seen = max(
        compare_to_family(family, [s])["distance"]
        for group in groups for s in group)
    assert family.band >= worst_seen * 0.8, (
        "the band is far below the scatter of the very samples it was built "
        "from, so it cannot be covering individual responses")


def test_more_samples_does_not_make_an_honest_cycle_look_worse():
    """The tell that found the defect.

    With band and measurement commensurable, max() over more samples should
    approach the band rather than run away from it.
    """
    family, _, base, rng, dim = _family(sigma=0.25)
    centre = _noisy(base, 0.01, rng, dim)

    ratios = {}
    for n in (2, 6, 12):
        fresh = [_Sample(_noisy(centre, 0.25, rng, dim)) for _ in range(n)]
        ratios[n] = compare_to_family(family, fresh)["ratio"]

    assert ratios[12] <= ratios[2] * 2.0, f"ratio ran away with sampling: {ratios}"
    assert all(r <= 1.3 for r in ratios.values()), ratios


# --------------------------------------------------------------------------- #
# What must not have been traded away
# --------------------------------------------------------------------------- #
def test_a_real_change_still_leaves_the_band():
    """A wider band must not swallow an actual attack."""
    family, _, base, rng, dim = _family(sigma=0.25)
    elsewhere = _unit([rng.gauss(0, 1) for _ in range(dim)])   # different answer
    moved = [_Sample(_noisy(elsewhere, 0.05, rng, dim)) for _ in range(2)]

    result = compare_to_family(family, moved)
    assert result["ratio"] > 1.0, "a genuinely different response must exceed the band"
    assert not result["within_band"]


def test_a_deterministic_tool_keeps_the_noise_floor():
    """Zero scatter must not produce a zero band - that divides by nothing."""
    family, _, _, _, _ = _family(sigma=0.0)
    assert family.band == pytest.approx(MIN_BAND)
    # The measured scatter is below the floor, which is exactly when the floor
    # has to take over: a band of ~0 divides by nothing and produced a score of
    # 263,659 before MIN_BAND existed.
    assert family.dist_max < MIN_BAND


def test_a_one_sample_family_does_not_crash():
    rng = random.Random(1)
    base = _unit([rng.gauss(0, 1) for _ in range(8)])
    samples = [_Sample(base)]
    family = summarize_family("f", "t", {}, [_Instance(base)], [samples])
    assert family.band >= MIN_BAND


# --------------------------------------------------------------------------- #
# Comparability is a different quantity and keeps its own definition
# --------------------------------------------------------------------------- #
def test_comparability_still_measures_input_sensitivity_not_noise():
    """A noisy tool whose answer does not depend on the INPUT stays comparable.

    Comparability asks how much the argument changes the answer, after
    redaction. Per-sample randomness is not that, so it must not drag
    comparability down - otherwise a weather feed would be judged
    incomparable merely for being random.
    """
    noisy, _, _, _, _ = _family(sigma=0.25)     # instances alike, samples noisy
    quiet, _, _, _, _ = _family(sigma=0.0)
    assert noisy.comparability > 0.8, noisy.comparability
    assert quiet.comparability > 0.8, quiet.comparability


def test_comparability_falls_when_the_input_really_does_change_the_answer():
    rng = random.Random(7)
    dim = 16
    instances, groups = [], []
    for _ in range(3):
        centre = _unit([rng.gauss(0, 1) for _ in range(dim)])   # unrelated answers
        samples = [_Sample(_noisy(centre, 0.01, rng, dim)) for _ in range(6)]
        groups.append(samples)
        instances.append(_Instance(centroid_of([s.embedding for s in samples])))

    family = summarize_family("f", "t", {}, instances, groups)
    assert family.comparability < 0.5, family.comparability
