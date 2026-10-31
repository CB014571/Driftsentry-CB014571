"""The attacker's own observation of a call, read from the detector's side.

Two things are under test here, and the second is the subtle one.

First, that the features a malicious server can compute are what RQ3 says
they are: six families, no environment values, one row per call.

Second, that ``attacker/features.py`` IMPORTS CLEANLY FROM THIS SIDE. The
analysis in T14 trains its classifiers on ``FAMILIES`` imported from the
attacker project, so that the features a model is fitted to are by
construction the ones the attacker computes at runtime. If that import ever
breaks - a third-party dependency creeping into the attacker, say - the two
sides would silently drift apart and every AUC would describe a feature set
nobody actually uses. This file fails loudly instead.
"""
from __future__ import annotations

import ast
import json
import math
import sys
from pathlib import Path

import pytest

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"


@pytest.fixture(scope="module")
def F():
    """The attacker's feature module, imported the way the analysis will."""
    if not ATTACKER.is_dir():
        pytest.skip(f"attacker project not found at {ATTACKER}")
    sys.path.insert(0, str(ATTACKER))
    try:
        from attacker import features
    finally:
        sys.path.remove(str(ATTACKER))
    return features


@pytest.fixture
def row():
    """A representative observation, as ``observe`` would build it."""
    return {
        "t": 1_700_000_000.0, "pid": 4242,
        "tool": "lookup_customer", "args": {"customer_id": "CUS-48217"},
        "client_name": "claude-ai", "client_version": "0.14.2",
        "env_count": 42, "has_home": True, "cwd": r"F:\work\acme",
        "parent_name": "python.exe", "parent_argc": 5,
        "calls_before": 3, "distinct_tools_before": 2,
        "proc_age_s": 9.5, "gap_s": 1.25,
    }


# --------------------------------------------------------------------------- #
# The contract the analysis relies on
# --------------------------------------------------------------------------- #
def test_the_six_families_exist(F):
    assert set(F.FAMILIES) == {
        "argument", "client", "environment", "session", "timing", "all"}


def test_all_is_the_union_of_the_others(F, row):
    expected: dict = {}
    for name, fn in F.FAMILIES.items():
        if name != "all":
            expected.update(fn(row))
    assert F.f_all(row) == expected


def test_every_family_returns_plain_numbers(F, row):
    """DictVectorizer needs scalars. A nested value would fail far from here."""
    for name, fn in F.FAMILIES.items():
        for key, value in fn(row).items():
            assert isinstance(key, str), f"{name}: key {key!r}"
            assert isinstance(value, (int, float)), f"{name}: {key}={value!r}"
            assert not isinstance(value, bool), f"{name}: {key} is a bool"
            assert math.isfinite(value), f"{name}: {key} is not finite"


def test_timestamp_and_pid_are_never_features(F, row):
    """They label and group rows. As features they would leak run order."""
    for name, fn in F.FAMILIES.items():
        keys = set(fn(row))
        assert "t" not in keys and "pid" not in keys, name
        for forbidden in ("1700000000", "4242"):
            assert not any(forbidden in k for k in keys), f"{name} leaks {forbidden}"


def test_a_missing_field_does_not_crash_a_family(F):
    """Rows from an older collection must still score."""
    for name, fn in F.FAMILIES.items():
        assert isinstance(fn({}), dict), name


# --------------------------------------------------------------------------- #
# Safety rules
# --------------------------------------------------------------------------- #
def test_the_module_imports_nothing_outside_the_standard_library(F):
    """psutil is allowed only because it is optional and guarded."""
    tree = ast.parse((ATTACKER / "attacker" / "features.py").read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    allowed = {"__future__", "json", "math", "os", "time", "collections",
               "typing", "attacker", "psutil"}
    assert roots <= allowed, f"unexpected imports: {sorted(roots - allowed)}"
    assert "driftsentry" not in roots, "the attacker must never import the detector"


def test_no_environment_value_can_reach_a_feature(F, monkeypatch):
    secret = "sk-live-this-must-never-be-recorded"
    monkeypatch.setenv("ATTACKER_TEST_SECRET", secret)
    row = {"args": {"customer_id": "CUS-1"}, "env_count": len(__import__("os").environ),
           "has_home": True, "cwd": "/tmp/x", "parent_name": "python.exe",
           "parent_argc": 2, "calls_before": 0, "distinct_tools_before": 0,
           "proc_age_s": 0.1, "gap_s": None}
    blob = json.dumps({n: fn(row) for n, fn in F.FAMILIES.items()})
    assert secret not in blob
    assert "ATTACKER_TEST_SECRET" not in blob


# --------------------------------------------------------------------------- #
# Individual families
# --------------------------------------------------------------------------- #
def test_argument_features_are_computed_from_the_values(F):
    out = F.f_argument({"args": {"path": "docs/index.md"}})
    assert out["arg_len"] == len("docs/index.md")
    assert out["arg_has_space"] == 0.0
    assert out["arg_words"] == 1.0
    assert 0.0 < out["arg_entropy"] < 8.0


def test_entropy_is_zero_for_one_repeated_character(F):
    assert F._entropy("aaaa") == 0.0
    assert F._entropy("") == 0.0
    assert F._entropy("ab") == pytest.approx(1.0)


def test_first_call_in_a_process_is_flagged_rather_than_zeroed(F):
    """gap_s of 0 would read as an instant repeat; -1 says 'no previous call'."""
    first = F.f_timing({"gap_s": None})
    later = F.f_timing({"gap_s": 0.0})
    assert first == {"gap_s": -1.0, "is_first": 1.0}
    assert later == {"gap_s": 0.0, "is_first": 0.0}


def test_client_family_is_a_one_hot_of_name_and_version(F, row):
    out = F.f_client(row)
    assert out == {"client_name=claude-ai": 1.0, "client_version=0.14.2": 1.0}


def test_missing_parent_is_a_sentinel_not_a_zero(F):
    """psutil is optional, so parent_argc is often unknown. 0 would be a lie."""
    assert F.f_environment({"parent_argc": None})["parent_argc"] == -1.0
    assert F.f_environment({"parent_argc": 3})["parent_argc"] == 3.0


# --------------------------------------------------------------------------- #
# p_probe - the attacker scores a model without scikit-learn
# --------------------------------------------------------------------------- #
def test_p_probe_matches_a_hand_computed_logistic(F, row):
    """One feature, known standardisation: the arithmetic is checkable by hand.

        z = intercept + coef * (raw - mean) / scale
          = -1.0 + 2.0 * (42 - 40) / 4 = 0.0   ->  sigmoid(0) = 0.5
    """
    model = {"family": "environment", "feature_names": ["env_count"],
             "mean": [40.0], "scale": [4.0], "coef": [2.0], "intercept": -1.0}
    assert F.p_probe(row, model) == pytest.approx(0.5)

    # env_count 48 -> z = -1 + 2*(48-40)/4 = 3.0
    hotter = dict(row, env_count=48)
    assert F.p_probe(hotter, model) == pytest.approx(1 / (1 + math.exp(-3.0)))


def test_p_probe_treats_an_unseen_feature_as_zero(F):
    """A model trained elsewhere must not crash on a row that lacks a column."""
    model = {"family": "client", "feature_names": ["client_name=never-seen"],
             "mean": [0.0], "scale": [1.0], "coef": [5.0], "intercept": 0.0}
    assert F.p_probe({"client_name": "claude-ai"}, model) == pytest.approx(0.5)


def test_p_probe_separates_the_class_it_was_trained_on(F, row):
    model = {"family": "client", "feature_names": ["client_name=probe-x"],
             "mean": [0.0], "scale": [1.0], "coef": [10.0], "intercept": -5.0}
    assert F.p_probe(row, model) < 0.01
    assert F.p_probe(dict(row, client_name="probe-x"), model) > 0.99


def test_p_probe_cannot_overflow_on_a_confident_model(F, row):
    """exp(1000) would raise. A saturated model must simply return 1.0 or 0.0."""
    for coef, expected in ((1e6, 1.0), (-1e6, 0.0)):
        model = {"family": "environment", "feature_names": ["env_count"],
                 "mean": [0.0], "scale": [1.0], "coef": [coef], "intercept": 0.0}
        assert F.p_probe(row, model) == pytest.approx(expected)


def test_p_probe_survives_a_zero_scale(F, row):
    """A constant feature has zero variance; dividing by it must not blow up."""
    model = {"family": "environment", "feature_names": ["env_count"],
             "mean": [42.0], "scale": [0.0], "coef": [1.0], "intercept": 0.0}
    assert F.p_probe(row, model) == pytest.approx(0.5)
