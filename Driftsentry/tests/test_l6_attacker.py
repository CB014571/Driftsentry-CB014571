"""The L6 attacker: a learned recogniser instead of a hand-written rule.

Why this level exists, in one measurement. With keyed probes the argument
channel reaches AUC 0.786 - the L4 attacker's `looks_like_a_probe` matches an
enumerable pool, and keyed values are no longer reliably in it. But `client`
and `session` each reach 1.000. A classifier can use what a hand-written rule
cannot, so L6 asks what detection costs when the attacker does.

What these tests guard
    that L6 skips what the model calls a probe and fires on what it does not;
    that recognition is recorded as ground truth rather than inferred from a
    missed detection;
    that a missing or broken model makes the attacker fire rather than
    silently stay benign - an attacker that never fires looks like a perfect
    evasion and would be reported as one;
    and that L1 to L5 are untouched, because Experiments 1 and 2 are the
    control.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"

pytestmark = pytest.mark.skipif(
    not ATTACKER.is_dir(), reason=f"attacker project not found at {ATTACKER}")


@pytest.fixture
def atk(monkeypatch, tmp_path):
    """The attacker package, with an isolated home and no cached model."""
    monkeypatch.setenv("ATTACKER_HOME", str(tmp_path))
    if str(ATTACKER) not in sys.path:
        sys.path.insert(0, str(ATTACKER))
    for name in [n for n in sys.modules if n.startswith("attacker")]:
        del sys.modules[name]
    import attacker.attacks as attacks
    import attacker.scenario as scenario
    attacks._recogniser = None
    attacks._recogniser_path = None
    return attacks, scenario


def _model(tmp_path, feature="client_name=probe-x", coef=10.0, family="client"):
    """A model that fires on one known feature. Hand-checkable: with mean 0,
    scale 1 and intercept -5, the feature present gives p = sigmoid(5)."""
    model = {"family": family, "feature_names": [feature],
             "mean": [0.0], "scale": [1.0], "coef": [coef], "intercept": -5.0,
             "trained_on": "sha256:test"}
    (tmp_path / "recogniser.json").write_text(json.dumps(model), encoding="utf-8")
    return model


def _row(**extra):
    base = {"t": 1000.0, "pid": 1, "tool": "lookup_customer",
            "args": {"customer_id": "C-1001"},
            "client_name": "claude-ai", "client_version": "0.1.0",
            "env_count": 13, "has_home": True, "cwd": "/x",
            "parent_name": "", "parent_argc": None,
            "calls_before": 0, "distinct_tools_before": 0,
            "proc_age_s": 0.5, "gap_s": None}
    base.update(extra)
    return base


def _scenario(scenario_mod, **kw):
    return scenario_mod.Scenario(mode="rug-pull", family="content-injection",
                                 level="L6", probe_aware=True, **kw)


# --------------------------------------------------------------------------- #
# The level itself
# --------------------------------------------------------------------------- #
def test_l6_is_a_known_level_and_requires_probe_awareness(atk):
    _, scenario = atk
    assert "L6" in scenario.LEVELS
    assert _scenario(scenario).is_probe_aware() is True
    off = scenario.Scenario(mode="rug-pull", level="L6", probe_aware=False)
    assert any("probe-aware" in p for p in off.validate())


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #
def test_a_call_the_model_calls_a_probe_is_skipped(atk, tmp_path):
    attacks, scenario = atk
    _model(tmp_path)
    fire, why = attacks.should_fire(_scenario(scenario, recogniser_family="client"),
                                    1, {}, features=_row(client_name="probe-x"))
    assert fire is False
    assert "learned recogniser" in why and "probe" in why


def test_a_call_the_model_calls_genuine_fires(atk, tmp_path):
    attacks, scenario = atk
    _model(tmp_path)
    fire, why = attacks.should_fire(_scenario(scenario, recogniser_family="client"),
                                    1, {}, features=_row(client_name="claude-ai"))
    assert fire is True
    assert "genuine" in why


def test_recognition_is_logged_as_ground_truth(atk, tmp_path):
    """Without this, "recognised the probe" and "fired but was missed" look
    identical from outside, and the RQ3 recall figure would rest on an
    assumption rather than evidence."""
    attacks, scenario = atk
    from attacker import sink

    _model(tmp_path)
    attacks.should_fire(_scenario(scenario, recogniser_family="client"),
                        7, {}, features=_row(client_name="probe-x"))
    events = sink.read_events()
    skips = [e for e in events if e[1] == "probe-skip"]
    assert skips, "a skip must be recorded"
    assert "learned" in skips[-1][2] and "call 7" in skips[-1][2]


def test_the_decision_threshold_is_one_half(atk, tmp_path):
    attacks, scenario = atk
    # intercept -5, coef 10 -> absent: p=sigmoid(-5)=0.0067, present: 0.9933
    _model(tmp_path)
    sc = _scenario(scenario, recogniser_family="client")
    assert attacks.should_fire(sc, 1, {}, features=_row(client_name="probe-x"))[0] is False
    assert attacks.should_fire(sc, 2, {}, features=_row(client_name="other"))[0] is True


# --------------------------------------------------------------------------- #
# Failure modes - all must fire, never silently stay benign
# --------------------------------------------------------------------------- #
def test_a_missing_model_fires_rather_than_evading(atk):
    """An attacker that never fires looks like a perfect evasion.

    Reported as one, it would be the most flattering possible result and
    completely false. So a missing model is loud and fires.
    """
    attacks, scenario = atk
    fire, why = attacks.should_fire(_scenario(scenario), 1, {}, features=_row())
    assert fire is True
    assert "no recogniser" in why


def test_a_corrupt_model_fires_rather_than_evading(atk, tmp_path):
    attacks, scenario = atk
    (tmp_path / "recogniser.json").write_text("{not json", encoding="utf-8")
    fire, why = attacks.should_fire(_scenario(scenario), 1, {}, features=_row())
    assert fire is True


def test_a_model_that_cannot_score_fires_rather_than_evading(atk, tmp_path):
    """A malformed but parseable model must not be read as 'stay benign'."""
    attacks, scenario = atk
    (tmp_path / "recogniser.json").write_text(
        json.dumps({"family": "client", "feature_names": ["a"]}), encoding="utf-8")
    fire, _ = attacks.should_fire(_scenario(scenario), 1, {}, features=_row())
    assert fire is True


def test_no_features_at_all_does_not_crash(atk, tmp_path):
    attacks, scenario = atk
    _model(tmp_path)
    fire, _ = attacks.should_fire(_scenario(scenario, recogniser_family="client"),
                                  1, {}, features=None)
    assert isinstance(fire, bool)


# --------------------------------------------------------------------------- #
# Caching
# --------------------------------------------------------------------------- #
def test_the_model_is_read_once_not_on_every_call(atk, tmp_path):
    """Re-reading a file per call would give the server a disk-shaped timing
    signature, which is not the tell this level is meant to test."""
    attacks, scenario = atk
    _model(tmp_path)
    sc = _scenario(scenario, recogniser_family="client")
    attacks.should_fire(sc, 1, {}, features=_row(client_name="probe-x"))

    (tmp_path / "recogniser.json").unlink()      # gone from disk
    fire, why = attacks.should_fire(sc, 2, {}, features=_row(client_name="probe-x"))
    assert fire is False, "the cached model must still be in use"


# --------------------------------------------------------------------------- #
# The control condition must not move
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("level", ["L1", "L2", "L3", "L4", "L5"])
def test_lower_levels_ignore_the_recogniser_entirely(atk, tmp_path, level):
    """Experiments 1 and 2 are the control. A model on disk must not touch them."""
    attacks, scenario = atk
    _model(tmp_path, coef=1e6)                   # would flag everything
    sc = scenario.Scenario(mode="rug-pull", family="content-injection",
                           level=level, probe_aware=level in {"L4", "L5"})
    with_features = attacks.should_fire(sc, 1, {"customer_id": "C-1001"},
                                        features=_row(client_name="probe-x"))
    without = attacks.should_fire(sc, 1, {"customer_id": "C-1001"})
    assert with_features == without, f"{level} changed when features were supplied"


def test_benign_mode_never_consults_the_model(atk, tmp_path):
    attacks, scenario = atk
    _model(tmp_path, coef=1e6)
    sc = scenario.Scenario(mode="benign", level="L6", probe_aware=True)
    fire, why = attacks.should_fire(sc, 1, {}, features=_row())
    assert fire is False and why == "benign mode"
