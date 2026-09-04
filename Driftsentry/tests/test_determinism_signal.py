"""The exact-equality signal for provably deterministic probes.

Closes a measured gap. On the stored acme baseline, `lookup_customer` and
`read_document` both returned byte-identical text on all 8 samples, giving them
the MIN_BAND floor of 0.01. Against a calibrated threshold of 10.81 that means a
cosine distance of 0.108 was required before anything fired - on tools whose
observed variance was exactly zero. A low-drift attacker fits inside that.
"""
from __future__ import annotations

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.embeddings import HashingEmbedding
from driftsentry.fingerprint import (
    MIN_BAND,
    ProbeSample,
    normalize_result,
    summarize_probe,
)
from driftsentry.scorer import ALERT_AT, W_DETERMINISM, score_report

HASH_A = "sha256:" + "a" * 64
THRESHOLD = 10.8086          # the project's real calibrated threshold


def _samples(texts: list[str]) -> list[ProbeSample]:
    backend = HashingEmbedding(dim=64)
    vectors = backend.embed(texts)
    return [
        ProbeSample(
            embedding=vec,
            normalized=normalize_result({"content": [{"type": "text", "text": text}]}),
            latency_ms=1.0,
        )
        for text, vec in zip(texts, vectors)
    ]


def _report(check: ProbeCheck) -> ReprobeReport:
    return ReprobeReport(
        server="acme",
        baseline_definition_hash=HASH_A,
        observed_definition_hash=HASH_A,
        checks=[check],
        embedding_backend="hashing-64",
    )


def _check(**kwargs) -> ProbeCheck:
    defaults = dict(
        tool="lookup_customer", probe_id="lookup_customer#0",
        distance=0.02, band=MIN_BAND, ratio=2.0,
        within_band=False, shape_known=True,
        observed_excerpt="Record: Dana; account ACC-90117734.",
        baseline_excerpt="Record: Dana; account ACC-44120.",
    )
    defaults.update(kwargs)
    return ProbeCheck(**defaults)


# --------------------------------------------------------------------------- #
# Recognising a deterministic probe
# --------------------------------------------------------------------------- #
def test_identical_samples_are_marked_deterministic():
    baseline = summarize_probe("p#0", "t", {}, _samples(["Record: Dana; account ACC-44120."] * 8))
    assert baseline.is_deterministic()
    assert baseline.band == MIN_BAND
    assert len(baseline.text_hashes) == 1


def test_a_varying_probe_is_not_deterministic():
    baseline = summarize_probe("p#0", "t", {}, _samples([
        "London: 12C, clear.", "London: 19C, rain.", "London: 7C, overcast.",
        "London: 23C, breezy.", "London: 15C, misty.",
    ]))
    assert not baseline.is_deterministic()
    assert len(baseline.text_hashes) == 5


def test_a_thin_baseline_is_never_treated_as_deterministic():
    """Two identical samples prove nothing, and treating them as proof would
    turn every hastily captured baseline into a hair-trigger."""
    baseline = summarize_probe("p#0", "t", {}, _samples(["same"] * 2))
    assert not baseline.is_deterministic()


# --------------------------------------------------------------------------- #
# The gap this closes
# --------------------------------------------------------------------------- #
def test_small_change_on_a_deterministic_probe_was_previously_missed():
    """Without the signal, a tiny edit sits comfortably under the alert line."""
    ratio = 0.02 / MIN_BAND                        # distance 0.02 -> ratio 2.0
    report = score_report(
        _report(_check(distance=0.02, ratio=ratio, determinism_break=False)),
        threshold_ratio=THRESHOLD,
    )
    assert report.score < ALERT_AT
    assert report.verdict == "ok"


def test_the_same_change_now_alerts():
    ratio = 0.02 / MIN_BAND
    report = score_report(
        _report(_check(distance=0.02, ratio=ratio, determinism_break=True)),
        threshold_ratio=THRESHOLD,
    )
    assert report.score == pytest.approx(W_DETERMINISM)
    assert report.verdict == "alert"
    assert report.triggered_by == "determinism_break"


def test_it_does_not_fire_on_a_naturally_varying_probe():
    """The signal is only ever set for probes that earned it, so a noisy tool
    is untouched - this is what keeps the false-alarm cost bounded."""
    report = score_report(
        _report(_check(band=0.12, distance=0.10, ratio=0.83, determinism_break=False)),
        threshold_ratio=THRESHOLD,
    )
    assert report.verdict == "ok"


def test_it_stays_below_the_strong_security_rules():
    """Ordering matters: 'this changed at all' is weaker evidence than 'this
    contacted a host it never contacted', and the score must say so."""
    from driftsentry.scorer import W_RULE_HIGH
    assert W_DETERMINISM < W_RULE_HIGH
    assert W_DETERMINISM >= ALERT_AT


def test_old_baselines_without_text_hashes_never_trigger_it():
    """Backward compatibility: a v1 baseline has no text hashes, so the check
    is simply unavailable rather than wrongly firing."""
    from driftsentry.fingerprint import ProbeBaseline
    legacy = ProbeBaseline.from_dict({
        "probe_id": "p#0", "template_id": "t", "args": {}, "centroid": [1.0],
        "n_samples": 8, "dist_mean": 0.0, "dist_std": 0.0, "dist_max": 0.0,
        "band": 0.01, "shape_hashes": ["sha256:x"], "chars_mean": 10.0,
        "chars_std": 0.0, "error_rate": 0.0, "latency_ms_mean": 1.0,
    })
    assert legacy.text_hashes == []
    assert not legacy.is_deterministic()
