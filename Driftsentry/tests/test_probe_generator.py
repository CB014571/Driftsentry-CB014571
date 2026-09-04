"""The keyed generator: unpredictable to the server, reproducible for experiments."""
from __future__ import annotations

import re

import pytest

from driftsentry import keys
from driftsentry.probe_generator import (
    GENERATOR_VERSION,
    KeyedProbeGenerator,
    UnsupportedSchema,
)

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))


def gen(key: bytes = KEY_A, **kwargs) -> KeyedProbeGenerator:
    return KeyedProbeGenerator(key, **kwargs)


# --------------------------------------------------------------------------- #
# Reproducibility
# --------------------------------------------------------------------------- #
def test_same_key_and_cycle_reproduce_exactly(lookup_customer):
    a = gen(cycle=7).generate("acme", lookup_customer, count=3)
    b = gen(cycle=7).generate("acme", lookup_customer, count=3)
    assert [p.args for p in a] == [p.args for p in b]


def test_a_different_key_gives_different_values(lookup_customer):
    a = gen(KEY_A, cycle=7).generate("acme", lookup_customer, count=3)
    b = gen(KEY_B, cycle=7).generate("acme", lookup_customer, count=3)
    assert [p.args for p in a] != [p.args for p in b]


def test_experiment_keys_are_derivable_and_stable():
    assert keys.derive_experiment_key(42) == keys.derive_experiment_key(42)
    assert keys.derive_experiment_key(42) != keys.derive_experiment_key(43)


# --------------------------------------------------------------------------- #
# Rotation - the property that actually defeats recognition
# --------------------------------------------------------------------------- #
def test_each_cycle_produces_new_values(lookup_customer):
    seen = set()
    for cycle in range(12):
        for probe in gen(cycle=cycle).generate("acme", lookup_customer, count=3):
            seen.add(probe.args["customer_id"])
    # 12 cycles x 3 probes = 36 draws; near-total distinctness is the point.
    assert len(seen) >= 30, f"only {len(seen)} distinct values in 36 draws"


def test_probes_within_one_cycle_do_not_collide(read_document):
    """The fixed generator wastes a third of its budget on duplicates.

    Its probes #1 and #2 are identical, so three probes give two distinct
    inputs. Independent per-field derivation must not reproduce that.
    """
    collisions = 0
    for cycle in range(20):
        probes = gen(cycle=cycle).generate("acme", read_document, count=3)
        if len({p.args["path"] for p in probes}) < 3:
            collisions += 1
    assert collisions <= 2, f"{collisions}/20 cycles produced duplicate probes"


def test_family_id_is_stable_across_cycles(lookup_customer):
    """The family is what a baseline is captured against, so it must not move."""
    ids = {gen(cycle=c).generate("acme", lookup_customer, 1)[0].template_id
           for c in range(10)}
    assert len(ids) == 1
    assert ids.pop() == "customer_id=identifier"


def test_values_depend_on_server_and_tool(lookup_customer):
    a = gen(cycle=1).generate("acme", lookup_customer, count=2)
    b = gen(cycle=1).generate("other-server", lookup_customer, count=2)
    assert [p.args for p in a] != [p.args for p in b]


# --------------------------------------------------------------------------- #
# The key must not leak
# --------------------------------------------------------------------------- #
def test_no_key_material_appears_in_generated_output(lookup_customer):
    """Everything generated here is transmitted to the monitored server."""
    blob = ""
    for cycle in range(30):
        for probe in gen(cycle=cycle).generate("acme", lookup_customer, count=3):
            blob += repr(probe.args) + probe.template_id + probe.probe_id
    assert KEY_A.hex() not in blob
    for start in range(0, 28, 4):                    # any 4-byte window
        assert KEY_A[start:start + 4].hex() not in blob


def test_key_id_does_not_reveal_the_key():
    identifier = keys.key_id(KEY_A)
    assert KEY_A.hex() not in identifier
    assert identifier.startswith("k:")
    assert keys.key_id(KEY_A) != keys.key_id(KEY_B)


def test_key_round_trip_through_the_store():
    keys.set_key("acme", KEY_A)
    assert keys.get("acme") == KEY_A
    assert keys.get_or_create("acme") == KEY_A          # does not overwrite
    fresh = keys.get_or_create("brand-new")
    assert len(fresh) == keys.KEY_BYTES
    assert fresh != KEY_A


# --------------------------------------------------------------------------- #
# Schema validity
# --------------------------------------------------------------------------- #
def _schema(props: dict, required: list[str] | None = None) -> dict:
    return {
        "name": "t",
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required if required is not None else list(props),
        },
    }


def test_supported_scalar_types_are_generated_correctly():
    tool = _schema({
        "note": {"type": "string"},
        "count": {"type": "integer", "minimum": 5, "maximum": 9},
        "ratio": {"type": "number", "minimum": 0, "maximum": 1},
        "flag": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["fast", "slow"]},
    })
    args = gen(cycle=3).generate("s", tool, count=1)[0].args
    assert isinstance(args["note"], str) and args["note"]
    assert isinstance(args["count"], int) and 5 <= args["count"] <= 9
    assert isinstance(args["ratio"], float) and 0.0 <= args["ratio"] <= 1.0
    assert isinstance(args["flag"], bool)
    assert args["mode"] in {"fast", "slow"}


def test_arrays_and_nested_objects():
    tool = _schema({
        "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3},
        "filter": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["query"],
        },
    })
    args = gen(cycle=4).generate("s", tool, count=1)[0].args
    assert 1 <= len(args["tags"]) <= 3
    assert all(isinstance(t, str) for t in args["tags"])
    assert isinstance(args["filter"], dict)
    assert isinstance(args["filter"]["query"], str)


def test_length_constraints_are_respected():
    tool = _schema({"short": {"type": "string", "maxLength": 8},
                    "long": {"type": "string", "minLength": 60}})
    for cycle in range(8):
        args = gen(cycle=cycle).generate("s", tool, count=1)[0].args
        assert len(args["short"]) <= 8
        assert len(args["long"]) >= 60


def test_const_is_passed_through():
    tool = _schema({"version": {"const": "v2"}})
    assert gen(cycle=1).generate("s", tool, count=1)[0].args["version"] == "v2"


@pytest.mark.parametrize("bad", [
    {"thing": {"$ref": "#/defs/Thing"}},
    {"thing": {"allOf": [{"type": "string"}, {"minLength": 3}]}},
    {"thing": {"type": "array"}},                       # no item schema
    {"thing": {"type": "integer-ish"}},                 # unknown type
])
def test_unsupported_schemas_fail_safely(bad):
    """Refuse rather than improvise.

    A probe built from a misunderstood schema gets rejected by the server, and
    that rejection is then recorded as the tool's normal behaviour - a baseline
    that is quietly worthless. Failing loudly lets the caller downgrade the tool
    to observation-only instead.
    """
    with pytest.raises(UnsupportedSchema):
        gen(cycle=1).generate("s", _schema(bad), count=1)


# --------------------------------------------------------------------------- #
# Realism and safety
# --------------------------------------------------------------------------- #
def test_generated_values_are_not_obviously_synthetic(lookup_customer):
    """'probe_918273' is unpredictable and still announces itself as a test."""
    tell = re.compile(r"probe|canary|sentinel|test_|dummy|fixture|driftsentry", re.I)
    for cycle in range(25):
        for probe in gen(cycle=cycle).generate("acme", lookup_customer, count=3):
            value = probe.args["customer_id"]
            assert not tell.search(value), value


def test_emails_use_only_reserved_domains():
    tool = _schema({"recipient": {"type": "string", "format": "email"}})
    for cycle in range(25):
        value = gen(cycle=cycle).generate("s", tool, count=1)[0].args["recipient"]
        assert value.endswith("@example.invalid"), value


def test_urls_stay_on_loopback():
    tool = _schema({"endpoint": {"type": "string", "format": "uri"}})
    for cycle in range(25):
        value = gen(cycle=cycle).generate("s", tool, count=1)[0].args["endpoint"]
        assert value.startswith(("http://127.0.0.1:9/", "http://localhost:9/")), value


def test_filenames_are_relative_and_sandbox_safe():
    tool = _schema({"path": {"type": "string"}})
    for cycle in range(25):
        value = gen(cycle=cycle).generate("s", tool, count=1)[0].args["path"]
        assert not value.startswith(("/", "\\")), value
        assert ".." not in value, value
        assert not re.match(r"^[A-Za-z]:", value), value


def test_generator_version_is_recorded():
    assert GENERATOR_VERSION.startswith("kpg-")
    assert gen().version == GENERATOR_VERSION
