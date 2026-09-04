"""Temporal, corroboration, metamorphic, camouflage and tripwire."""
from __future__ import annotations

import random

import pytest

from driftsentry import camouflage, corroboration, metamorphic, tripwire
from driftsentry.temporal import DEFAULT_H, DEFAULT_K, MAX_CUSUM, TemporalDetector

KEY = bytes(range(32))


class _Sig:
    def __init__(self, name, score):
        self.name, self.score = name, score


class _S:
    """Minimal ProbeSample stand-in."""

    def __init__(self, hosts=(), files=(), flags=(), shape="sha256:a", error=False):
        self.hosts, self.files, self.content_flags = list(hosts), list(files), list(flags)
        self.normalized = type("N", (), {"shape_hash": shape, "is_error": error})()


# --------------------------------------------------------------------------- #
# Temporal
# --------------------------------------------------------------------------- #
def test_benign_noise_never_accumulates(tmp_path):
    det = TemporalDetector(path=tmp_path / "t.json")
    for _ in range(60):
        sig = det.update("acme", "lookup", 0.08)
    assert sig.cusum == 0.0
    assert not sig.fired


def test_gradual_climb_is_caught_without_any_cycle_alerting(tmp_path):
    """The case single-point scoring cannot see."""
    det = TemporalDetector(path=tmp_path / "t.json")
    fired_at = None
    for i, score in enumerate([0.20, 0.24, 0.29, 0.35, 0.41, 0.46, 0.52, 0.58], 1):
        assert score < 1.0, "no individual cycle crosses the alert line"
        sig = det.update("acme", "lookup", score)
        if sig.fired and fired_at is None:
            fired_at = i
    assert fired_at is not None, "a sustained climb must eventually be caught"


def test_one_elevated_reading_does_not_fire(tmp_path):
    """A benign update produces a single spike, not a trend."""
    det = TemporalDetector(path=tmp_path / "t.json")
    det.update("acme", "lookup", 0.08)
    sig = det.update("acme", "lookup", 0.73)
    assert not sig.fired


def test_accumulator_is_bounded(tmp_path):
    det = TemporalDetector(path=tmp_path / "t.json")
    for _ in range(500):
        sig = det.update("acme", "lookup", 0.95)
    assert sig.cusum <= MAX_CUSUM


def test_rebaseline_resets_the_accumulator(tmp_path):
    """Evidence gathered against the old normal must not charge the new one."""
    det = TemporalDetector(path=tmp_path / "t.json")
    for _ in range(6):
        det.update("acme", "lookup", 0.6, baseline_id="b1")
    sig = det.update("acme", "lookup", 0.6, baseline_id="b2")
    assert sig.cusum == pytest.approx(0.6 - DEFAULT_K)


def test_state_survives_a_restart(tmp_path):
    """A detector for slow attacks that forgets on restart would never see one."""
    path = tmp_path / "t.json"
    a = TemporalDetector(path=path)
    for _ in range(4):
        a.update("acme", "lookup", 0.5)
    before = a.state("acme", "lookup").cusum_s
    assert TemporalDetector(path=path).state("acme", "lookup").cusum_s == pytest.approx(before)


def test_reset_clears_only_the_named_server(tmp_path):
    det = TemporalDetector(path=tmp_path / "t.json")
    det.update("acme", "lookup", 0.9)
    det.update("other", "lookup", 0.9)
    assert det.reset("acme") == 1
    assert det.state("other", "lookup").cusum_s > 0


def test_calibration_places_k_above_benign(tmp_path):
    det = TemporalDetector(path=tmp_path / "t.json")
    result = det.calibrate([0.05, 0.07, 0.09, 0.06, 0.08] * 20)
    assert result["k"] >= 0.05
    assert det.h >= 0.5


# --------------------------------------------------------------------------- #
# Corroboration
# --------------------------------------------------------------------------- #
def test_correlated_signals_do_not_corroborate():
    """Embedding and structure read the same response; they are one family."""
    result = corroboration.evaluate([_Sig("behavioural_drift", 0.7), _Sig("field_drift", 0.7)])
    assert not result.fired
    assert len(result.families) == 1


def test_two_independent_families_alert():
    """The sub-threshold case max() misses by design."""
    result = corroboration.evaluate([
        _Sig("behavioural_drift", 0.71),          # A
        _Sig("rule:new_file_access", 0.75),       # C
    ])
    assert result.fired
    assert result.score == corroboration.W_CORROBORATED
    assert sorted(result.contributing) == ["A", "C"]


def test_three_mildly_elevated_families_alert():
    result = corroboration.evaluate([
        _Sig("behavioural_drift", 0.5),           # A
        _Sig("structural_change", 0.5),           # B
        _Sig("temporal_trend", 0.5),              # F
    ])
    assert result.fired
    assert len(result.contributing) == 3


def test_one_family_alone_is_not_corroboration():
    result = corroboration.evaluate([_Sig("behavioural_drift", 0.9)])
    assert not result.fired
    assert "one family" in result.detail


def test_a_single_critical_signal_still_alerts():
    """Corroboration only ever ADDS detections; it never removes one."""
    result = corroboration.evaluate([_Sig("rule:new_egress_host", 2.0)])
    assert result.fired
    assert result.score == 2.0


def test_definition_change_is_always_critical():
    result = corroboration.evaluate([_Sig("definition_hash", 0.1)])
    assert result.fired
    assert "D" in result.contributing


def test_unmapped_signals_are_ignored():
    """Better silent than dumped into a family they correlate with."""
    assert not corroboration.evaluate([_Sig("something_new", 5.0)]).fired


def test_calibration_reports_its_own_false_alarm_rate():
    benign = [{"A": 0.1, "B": 0.1}, {"A": 0.2, "C": 0.15}, {"A": 0.05}] * 40
    out = corroboration.calibrate(benign, target_far=0.01)
    assert out["empirical_far_high"] <= 0.01
    assert out["t_high"] >= 0.4


# --------------------------------------------------------------------------- #
# Metamorphic
# --------------------------------------------------------------------------- #
def test_transforms_preserve_meaning():
    args = {"query": "quarterly security review", "limit": 10}
    out, applied = metamorphic.transform(args, random.Random(3))
    assert applied is not None
    assert set(out) == set(args)


def test_every_transform_preserves_meaning():
    """The property the whole signal rests on.

    If a transform could genuinely change what a tool should do, a difference in
    behaviour would be innocent and the evidence worthless. So for any transform
    the generator picks: the same keys survive, and each value is the same once
    normalised for the things a tool is entitled to ignore - surrounding
    whitespace, case, word order within a phrase, and a leading './'.
    """
    def canonical(value):
        if not isinstance(value, str):
            return value
        text = value.strip().lower()
        if text.startswith("./"):
            text = text[2:]
        return tuple(sorted(text.split()))

    args = {"query": "quarterly security review", "path": "docs/report.md", "limit": 10}
    for seed in range(40):
        out, applied = metamorphic.transform(args, random.Random(seed))
        assert set(out) == set(args), f"seed {seed} lost or added a key"
        for key in args:
            assert canonical(out[key]) == canonical(args[key]), (
                f"seed {seed} transform {applied.name if applied else '-'} "
                f"changed {key} beyond recognition"
            )


def test_identical_behaviour_scores_zero():
    a = [_S(hosts=["127.0.0.1"], shape="sha256:x")]
    b = [_S(hosts=["127.0.0.1"], shape="sha256:x")]
    assert metamorphic.consistency(a, b).score == 0.0


def test_divergent_egress_between_equivalent_inputs_is_evidence():
    """The probe-gating signature: benign for one, malicious for the other."""
    clean = [_S(hosts=["127.0.0.1"])]
    dirty = [_S(hosts=["127.0.0.1", "127.0.0.2"])]
    result = metamorphic.consistency(clean, dirty, transform_name="token_order")
    assert result.fired
    assert result.evidence_units() > 0
    assert "hosts" in result.divergences[0]


def test_divergent_security_flags_are_evidence():
    clean = [_S()]
    dirty = [_S(flags=["instruction:override-instruction"])]
    assert metamorphic.consistency(clean, dirty).fired


def test_content_differences_alone_are_not_evidence():
    """Two different search phrases legitimately return different results."""
    a = [_S(hosts=["127.0.0.1"], shape="sha256:same")]
    b = [_S(hosts=["127.0.0.1"], shape="sha256:same")]
    assert metamorphic.consistency(a, b).score == 0.0


def test_empty_samples_are_safe():
    assert metamorphic.consistency([], [_S()]).score == 0.0


# --------------------------------------------------------------------------- #
# Camouflage
# --------------------------------------------------------------------------- #
def test_interval_jitters_but_averages_to_the_base():
    intervals = [camouflage.next_interval(KEY, "acme", c, 20.0) for c in range(400)]
    assert len(set(intervals)) > 300, "a predictable period is itself a tell"
    assert 18.0 < sum(intervals) / len(intervals) < 22.0
    assert all(14.0 <= i <= 26.0 for i in intervals)


def test_interval_is_reproducible_from_the_key():
    a = [camouflage.next_interval(KEY, "acme", c, 20.0) for c in range(10)]
    b = [camouflage.next_interval(KEY, "acme", c, 20.0) for c in range(10)]
    assert a == b
    assert a != [camouflage.next_interval(bytes(32), "acme", c, 20.0) for c in range(10)]


def test_probe_order_varies_across_cycles():
    tools = ["a", "b", "c", "d"]
    orders = {tuple(camouflage.permute(KEY, "acme", c, tools)) for c in range(40)}
    assert len(orders) > 5
    for order in orders:
        assert sorted(order) == sorted(tools), "permutation must not lose a tool"


def test_probe_count_varies_but_never_reaches_zero():
    counts = [camouflage.probe_count(KEY, "acme", "t", c, 3) for c in range(60)]
    assert len(set(counts)) > 1
    assert min(counts) >= 1


def test_residual_session_tells_are_enumerated():
    """The honest half: these are the fingerprints camouflage does NOT remove."""
    tells = camouflage.SessionFingerprint().residual_tells()
    assert len(tells) >= 4
    assert any("tools/list" in t for t in tells)


# --------------------------------------------------------------------------- #
# Tripwires
# --------------------------------------------------------------------------- #
def test_planted_files_carry_unique_keyed_tokens(tmp_path):
    wires = tripwire.plant("acme", KEY, tmp_path)
    assert len(wires.wires) == 3
    assert len(wires.tokens()) == 3
    for wire in wires.wires:
        assert wire.token.startswith(tripwire.TOKEN_PREFIX)
        assert wire.token in open(wire.path, encoding="utf-8").read()


def test_tokens_are_keyed_so_a_server_cannot_forge_one(tmp_path):
    a = tripwire.make_token(KEY, "acme", "demo_credentials.txt")
    b = tripwire.make_token(bytes(32), "acme", "demo_credentials.txt")
    assert a != b


def test_reading_a_tripwire_is_detected(tmp_path):
    wires = tripwire.plant("acme", KEY, tmp_path)
    target = wires.wires[0].path
    assert tripwire.check_reads(wires, [target, "/tmp/unrelated.txt"]) == [wires.wires[0]]
    assert tripwire.check_reads(wires, ["/tmp/unrelated.txt"]) == []


def test_token_in_the_sink_proves_exfiltration(tmp_path):
    """Opening a file might be indiscriminate scanning; the token leaving is not."""
    wires = tripwire.plant("acme", KEY, tmp_path)
    sink = f"stolen data ... {wires.wires[1].token} ... more"
    assert tripwire.check_exfiltration(wires, sink) == [wires.wires[1]]
    assert tripwire.check_exfiltration(wires, "nothing here") == []


def test_tripwire_contents_are_obviously_synthetic(tmp_path):
    wires = tripwire.plant("acme", KEY, tmp_path)
    body = open(wires.wires[0].path, encoding="utf-8").read()
    assert "not a real credential" in body
    assert tripwire.TOKEN_PREFIX in body


def test_tripwire_weights_rank_exfiltration_above_reading():
    assert tripwire.W_TOKEN_EXFILTRATED > tripwire.W_TRIPWIRE_READ
