"""Coverage-guided probing, and field-level drift with volatile masking."""
from __future__ import annotations

import random
import re

import pytest

from driftsentry.coverage import (
    NUMERIC_CATEGORIES,
    STRING_CATEGORIES,
    CoverageModel,
    applicable_categories,
)
from driftsentry.fielddrift import (
    VOLATILE,
    FieldProfile,
    classify,
    compare,
    flatten,
    learn_profiles,
    mask_volatile,
)
from driftsentry.probe_generator import KeyedProbeGenerator
from driftsentry import keys

KEY = bytes(range(32))

# The adversarial server's own conditional trigger, copied from attacks.py.
INTERESTING = re.compile(
    r"[\w.+-]+@[\w-]+\.\w+|sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{6,}|token|secret|password",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #
def test_categories_respect_schema_constraints():
    kind, cats = applicable_categories({"type": "string", "maxLength": 6})
    assert kind == "string"
    assert "email" not in cats, "an email cannot fit in six characters"
    assert "url" not in cats


def test_enums_and_consts_have_nothing_to_vary():
    assert applicable_categories({"enum": ["a", "b"]})[1] == []
    assert applicable_categories({"const": "x"})[1] == []


def test_numeric_fields_get_numeric_categories():
    kind, cats = applicable_categories({"type": "integer", "minimum": 1, "maximum": 10})
    assert kind == "numeric"
    assert set(cats) == set(NUMERIC_CATEGORIES)


def test_least_used_category_is_preferred():
    model = CoverageModel(tool="t")
    schema = {"type": "string"}
    rng = random.Random(0)
    chosen = [model.choose("path", schema, rng) for _ in range(len(STRING_CATEGORIES))]
    # Every applicable category should have been used once before any repeats.
    assert len(set(chosen)) == len(model.fields["path"].applicable)
    assert model.coverage_ratio() == pytest.approx(1.0)


def test_coverage_reaches_the_conditional_attack_trigger(read_document):
    """The measured reason this exists.

    The `conditional` family only fires on inputs containing an email address or
    the words key/token/secret/password. A generator that always draws filenames
    never enters that branch, so the attack is missed by construction rather than
    by evasion.
    """
    def hit_rate(coverage):
        hits = total = 0
        for cycle in range(12):
            gen = KeyedProbeGenerator(KEY, cycle=cycle, coverage=coverage)
            for probe in gen.generate("acme", read_document, count=3, cycle=cycle):
                total += 1
                if INTERESTING.search(probe.args["path"]):
                    hits += 1
        return hits / total

    without = hit_rate(None)
    with_cov = hit_rate(CoverageModel(tool="read_document"))
    assert with_cov > without * 2, f"{without:.1%} -> {with_cov:.1%} is not an improvement"


def test_sensitive_lookalike_values_contain_no_real_secrets():
    """It must LOOK interesting to an attacker without BEING interesting."""
    from driftsentry.probe_templates import gen_sensitive_lookalike
    forbidden = re.compile(r"sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|-----BEGIN")
    for seed in range(60):
        value = gen_sensitive_lookalike(random.Random(seed))
        assert not forbidden.search(value), value
        assert ".." not in value and not value.startswith("/")


def test_coverage_model_round_trips():
    model = CoverageModel(tool="t")
    model.choose("path", {"type": "string"}, random.Random(1))
    restored = CoverageModel.from_dict(model.to_dict())
    assert restored.tool == model.tool
    assert restored.fields["path"].counts == model.fields["path"].counts


# --------------------------------------------------------------------------- #
# Field typing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,value,expected", [
    ("endpoint", "https://api.example.com/v1", "url"),
    ("recipient", "dana@northgate.example", "email"),
    ("account", "382910", "account"),
    ("amount", "GBP 1200.00", "money"),
    ("ref", "CUS-48217", "identifier"),
    ("status", "active", "status"),
    ("path", "docs/report.md", "path"),
    ("summary", "The quarterly review is complete.", "text"),
    ("count", 42, "number"),
    ("enabled", True, "boolean"),
])
def test_field_classification(name, value, expected):
    assert classify(name, value) == expected


def test_flatten_collapses_list_indices():
    flat = flatten({"items": [{"id": "A"}, {"id": "B"}]})
    assert list(flat) == ["items[].id"]


# --------------------------------------------------------------------------- #
# Volatile learning - the half that keeps false alarms down
# --------------------------------------------------------------------------- #
def _samples(n=8, **overrides):
    out = []
    for i in range(n):
        row = {"structuredContent": {
            "account": "382910",
            "email": "dana@northgate.example",
            "status": "active",
            "timestamp": f"2026-08-22T18:00:{i:02d}Z",
            "request_id": f"req-{i:04d}",
        }}
        row["structuredContent"].update(overrides)
        out.append(row)
    return out


def test_volatile_fields_are_learned_not_listed():
    """No allow-list of field names: volatility is observed from the tool."""
    profiles = learn_profiles(_samples())
    assert profiles["structuredContent.timestamp"].volatile
    assert profiles["structuredContent.request_id"].volatile
    assert not profiles["structuredContent.account"].volatile
    assert not profiles["structuredContent.email"].volatile


def test_volatile_movement_alone_scores_zero():
    """Timestamps changing must never look like tampering."""
    profiles = learn_profiles(_samples())
    benign = _samples(1, )[0]
    benign["structuredContent"]["timestamp"] = "2026-09-01T09:00:00Z"
    benign["structuredContent"]["request_id"] = "req-9999"
    score, changes = compare(profiles, benign)
    assert score == 0.0
    assert changes == []


def test_one_digit_account_change_scores_maximum():
    profiles = learn_profiles(_samples())
    tampered = _samples(1)[0]
    tampered["structuredContent"]["account"] = "382911"
    score, changes = compare(profiles, tampered)
    assert score == pytest.approx(1.0)
    assert changes[0].path.endswith("account")


def test_recipient_redirect_is_caught():
    """The postmark-mcp pattern: the answer looks right, the address does not."""
    profiles = learn_profiles(_samples())
    redirected = _samples(1)[0]
    redirected["structuredContent"]["email"] = "collector@attacker.invalid"
    score, changes = compare(profiles, redirected)
    assert score == pytest.approx(1.0)
    assert changes[0].kind == "email"


def test_prose_rewording_scores_low():
    """A benign update rewords text; that must not reach the alert line."""
    base = [{"structuredContent": {"summary": "The quarterly review is complete."}}] * 6
    profiles = learn_profiles(base)
    score, _ = compare(
        profiles, {"structuredContent": {"summary": "Quarterly review has now been completed."}})
    from driftsentry.scorer import ALERT_AT, W_FIELD_DRIFT
    assert score * W_FIELD_DRIFT < ALERT_AT


def test_identity_change_outranks_prose_change():
    profiles = learn_profiles(_samples())
    ident = _samples(1)[0]; ident["structuredContent"]["account"] = "999999"
    prose = _samples(1)[0]; prose["structuredContent"]["status"] = "inactive"
    assert compare(profiles, ident)[0] >= compare(profiles, prose)[0]


def test_masking_replaces_only_volatile_leaves():
    profiles = learn_profiles(_samples())
    masked = mask_volatile(_samples(1)[0], profiles)
    assert masked["structuredContent.timestamp"] == VOLATILE
    assert masked["structuredContent.account"] == "382910"


def test_no_profiles_means_no_signal():
    """A v1 baseline has no field profiles; the signal is unavailable, not wrong."""
    assert compare({}, {"a": 1}) == (0.0, [])


def test_profile_round_trips():
    profiles = learn_profiles(_samples())
    restored = {k: FieldProfile.from_dict(v.to_dict()) for k, v in profiles.items()}
    assert restored["structuredContent.account"].kind == "account"
    assert restored["structuredContent.timestamp"].volatile
