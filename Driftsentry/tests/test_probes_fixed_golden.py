"""Regression lock on the FIXED probe generator.

The fixed generator is Experiment 1's control condition. If its values drift, the
"before" numbers stop being comparable with the "after" numbers and the central
claim of the upgrade becomes unmeasurable. The golden values below are taken from
the stored acme baseline captured on 2026-07-29.
"""
from __future__ import annotations

from driftsentry.probes import ProbeGenerator, classify_tool_safety

SEED = 20260720


def test_fixed_probes_match_the_stored_baseline(lookup_customer):
    """Same seed, same server, same tool -> byte-identical arguments."""
    probes = ProbeGenerator(seed=SEED).generate("acme", lookup_customer, count=3)
    assert [p.args for p in probes] == [
        {"customer_id": "probe@example.invalid"},
        {"customer_id": "sentinel@example.invalid"},
        {"customer_id": "sentinel@example.invalid"},
    ]
    assert [p.template_id for p in probes] == [
        "customer_id=email#0",
        "customer_id=email#2",
        "customer_id=email#2",
    ]


def test_read_document_probes_match_the_stored_baseline(read_document):
    probes = ProbeGenerator(seed=SEED).generate("acme", read_document, count=3)
    assert [p.args["path"] for p in probes] == [
        "pyproject.toml",
        "pyproject.toml",
        "docs/index.md",
    ]


def test_generation_is_stable_across_generator_instances(lookup_customer):
    """Values must not depend on process state.

    random.Random.seed(str, version=2) hashes with SHA-512, unlike hash(), which
    Python randomises per process. Without that the control condition would
    differ between runs and nothing would be reproducible.
    """
    a = ProbeGenerator(seed=SEED).generate("acme", lookup_customer, count=3)
    b = ProbeGenerator(seed=SEED).generate("acme", lookup_customer, count=3)
    assert [p.args for p in a] == [p.args for p in b]


def test_probe_values_depend_on_server_and_tool(lookup_customer, read_document):
    """Keying includes server and tool, so the same seed does not collide."""
    same_tool_other_server = ProbeGenerator(seed=SEED).generate("other", lookup_customer, count=3)
    same_server_this_tool = ProbeGenerator(seed=SEED).generate("acme", lookup_customer, count=3)
    assert [p.args for p in same_tool_other_server] != [p.args for p in same_server_this_tool]


def test_fixed_generator_collides_across_indices(lookup_customer):
    """Documents a real weakness of the fixed generator.

    Probes #1 and #2 produce the SAME value, so three probes give only two
    distinct inputs. That is a third of the probe budget wasted, and it shrinks
    the surface an attacker has to recognise. Locked in as a known property of
    the control condition; the keyed generator must not reproduce it.
    """
    probes = ProbeGenerator(seed=SEED).generate("acme", lookup_customer, count=3)
    distinct = {tuple(sorted(p.args.items())) for p in probes}
    assert len(probes) == 3
    assert len(distinct) == 2


# --------------------------------------------------------------------------- #
# Probe-safety classification
# --------------------------------------------------------------------------- #
def test_side_effecting_tools_are_never_probed():
    for name, verb in (("send_invoice", "send"), ("delete_record", "delete"),
                       ("search_orders", "order")):
        tool = {"name": name, "description": f"{verb} something", "inputSchema": {}}
        safety, reason = classify_tool_safety(tool)
        assert safety == "side-effecting", (name, reason)


def test_read_only_verbs_are_probed():
    for name in ("get_weather", "read_document", "lookup_customer", "list_items"):
        tool = {"name": name, "description": "", "inputSchema": {}}
        safety, _ = classify_tool_safety(tool)
        assert safety == "safe", name


def test_word_boundary_matching_does_not_misfire_on_substrings():
    """'put' occurs inside 'input'.

    A naive substring test denied a behavioural baseline to any tool documented
    as returning "the input text" - a real defect that silently disabled
    detection for those tools.
    """
    tool = {"name": "echo", "description": "Returns the input text unchanged.",
            "inputSchema": {}}
    safety, reason = classify_tool_safety(tool)
    assert safety == "safe", reason


def test_annotations_take_precedence_over_keywords():
    tool = {"name": "get_thing", "description": "reads a thing",
            "annotations": {"destructiveHint": True}, "inputSchema": {}}
    safety, reason = classify_tool_safety(tool)
    assert safety == "side-effecting"
    assert "annotation" in reason


def test_strict_policy_requires_positive_evidence():
    tool = {"name": "frobnicate", "description": "does a thing", "inputSchema": {}}
    assert classify_tool_safety(tool, policy="default")[0] == "safe"
    assert classify_tool_safety(tool, policy="strict")[0] == "side-effecting"
