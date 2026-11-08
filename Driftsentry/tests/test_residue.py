"""T24. Declared-diff residue checking.

One test per row of the permitted-change rules (Table 3.5 of the report),
the plan's listed cases, the masking that makes "explains" computable, and
the freeze.

Thresholds are the detector's own. A probe "drifts" here when its ratio puts
behavioural drift above the alert line at threshold 1.5, which is what the
residue checker inherits from scorer.check_signals - so these tests also pin
that residue means "would still alert", not "moved at all".
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from driftsentry import residue
from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.declared_diff import diff_definitions
from driftsentry.residue import (
    RULES,
    check_update,
    freeze_rules,
    mask_payload,
    strip_paths,
    verify_rules,
)

T = 1.5                    # threshold ratio
DRIFT = 10.0               # a ratio far past the alert line
CLEAN = {"distance": 0.0, "band": 0.01, "ratio": 0.0, "within_band": True,
         "shape_known": True, "determinism_break": False, "field_drift": 0.0,
         "field_changes": [], "comparability": 1.0}

OUT_V1 = {"type": "object", "properties": {"result": {"type": "string"}}}
OUT_V2 = {"type": "object", "properties": {"result": {"type": "string"},
                                           "last_contact": {"type": "string"}}}
IN_V1 = {"type": "object", "properties": {"customer_id": {"type": "string"}}}


def defn(name="lookup_customer", *, description="Look up a customer.",
         inputs=IN_V1, outputs=OUT_V1, annotations=None):
    return {"name": name, "description": description, "inputSchema": inputs,
            "outputSchema": outputs, "annotations": annotations}


def probe(tool="lookup_customer", probe_id="p1", **kw):
    base = dict(tool=tool, probe_id=probe_id, distance=0.0, band=0.01,
                ratio=0.0, within_band=True, shape_known=True,
                arg_names=["customer_id"])
    base.update(kw)
    return ProbeCheck(**base)


def drifting(**kw):
    return probe(distance=0.1, ratio=DRIFT, within_band=False, shape_known=False, **kw)


def run(old, new, checks, **kw):
    report = ReprobeReport(server="s", baseline_definition_hash="a",
                           observed_definition_hash="a", checks=checks,
                           embedding_backend="hash", observed_definitions=new)
    return check_update(report, diff_definitions(old, new),
                        threshold_ratio=T, **kw)


def classes(result, signal):
    return {i.classification for i in result.items if i.signal == signal}


# --------------------------------------------------------------------------- #
# Row 1 - definition unchanged: explains nothing, reduces to the base detector
# --------------------------------------------------------------------------- #
def test_row1_no_declared_change_any_drift_is_residue():
    r = run([defn()], [defn()], [drifting()])
    assert r.verdict == "residue_alert"
    assert classes(r, "behavioural_drift") == {"residue"}
    assert "tool definition unchanged" in r.residue[0].reason


def test_row1_no_declared_change_no_drift_is_accepted():
    r = run([defn()], [defn()], [probe()])
    assert r.verdict == "accepted"
    assert r.items == []


def test_row1_reduces_to_the_base_detector_exactly():
    """Every signal the full detector would alert on is residue, and nothing
    else is - the residue checker adds no evidence and removes none."""
    from driftsentry.scorer import ALERT_AT, check_signals
    c = drifting(new_hosts=["evil.invalid"], new_content_flags=["instruction:override"])
    base = {s.name for s in check_signals(c, threshold_ratio=T) if s.score >= ALERT_AT}
    r = run([defn()], [defn()], [c])
    assert {i.signal for i in r.residue} == {residue.SIGNAL_NAMES[n] for n in base}


# --------------------------------------------------------------------------- #
# Row 2 - output field added or changed
# --------------------------------------------------------------------------- #
def test_row2_drift_confined_to_the_declared_field_is_explained():
    c = drifting(masked=dict(CLEAN))
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert r.verdict == "accepted"
    assert classes(r, "behavioural_drift") == {"explained"}
    assert "last_contact" in next(i.reason for i in r.items
                                  if i.signal == "behavioural_drift")
    assert r.explained_tools == ["lookup_customer"]


def test_row2_drift_outside_the_declared_field_is_residue():
    """The masked response still drifts: something besides last_contact moved."""
    c = drifting(masked=dict(CLEAN, ratio=DRIFT, distance=0.1, within_band=False))
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert r.verdict == "residue_alert"
    assert classes(r, "behavioural_drift") == {"residue"}


def test_row2_declared_output_field_plus_new_host_is_residue_on_network():
    """The report's own example: the field is accepted, the egress is not."""
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert r.verdict == "residue_alert"
    assert classes(r, "new_egress_host") == {"residue"}
    assert classes(r, "behavioural_drift") == {"explained"}


def test_row2_declared_output_field_never_explains_a_file_write():
    c = drifting(masked=dict(CLEAN), new_files=["/tmp/drop.txt"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert classes(r, "new_file") == {"residue"}


def test_row2_declared_field_on_another_tool_explains_nothing_here():
    """C1: the cover change is on a different tool."""
    old = [defn(), defn("search_orders")]
    new = [defn(), defn("search_orders", outputs=OUT_V2)]
    r = run(old, new, [drifting()])
    assert r.verdict == "residue_alert"
    assert "tool definition unchanged" in r.residue[0].reason


def test_row2_masking_that_failed_explains_nothing():
    c = drifting(masked=None, mask_note="no structured content")
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert r.verdict == "residue_alert"


# --------------------------------------------------------------------------- #
# Row 3 - input parameter added or changed
# --------------------------------------------------------------------------- #
IN_V2 = {"type": "object", "properties": {"customer_id": {"type": "integer"}}}


def test_row3_a_probe_that_uses_the_changed_parameter_is_explained():
    r = run([defn()], [defn(inputs=IN_V2)], [drifting(arg_names=["customer_id"])])
    assert r.verdict == "accepted"
    assert classes(r, "behavioural_drift") == {"explained"}


def test_row3_a_probe_that_does_not_use_it_is_residue():
    r = run([defn()], [defn(inputs=IN_V2)], [drifting(arg_names=["other"])])
    assert r.verdict == "residue_alert"


def test_row3_probe_args_can_be_passed_explicitly():
    r = run([defn()], [defn(inputs=IN_V2)], [drifting(arg_names=[])],
            probe_args={"p1": ["customer_id"]})
    assert r.verdict == "accepted"


# --------------------------------------------------------------------------- #
# Row 4 - description changed: explains nothing
# --------------------------------------------------------------------------- #
def test_row4_a_description_change_explains_no_behaviour():
    r = run([defn()], [defn(description="Look up a customer record.")], [drifting()])
    assert r.verdict == "residue_alert"


# --------------------------------------------------------------------------- #
# Row 5 - new tool
# --------------------------------------------------------------------------- #
def test_row5_a_new_tool_needs_its_own_baseline_and_excuses_nothing_else():
    r = run([defn()], [defn(), defn("export_all")], [drifting()])
    assert r.tools_needing_baseline == ["export_all"]
    assert r.verdict == "residue_alert"


# --------------------------------------------------------------------------- #
# Row 6 - readOnlyHint true / openWorldHint false, unchanged
# --------------------------------------------------------------------------- #
NARROW = {"readOnlyHint": True, "openWorldHint": False}


def test_row6_a_closed_world_tool_never_explains_a_new_host():
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn(annotations=NARROW)], [defn(outputs=OUT_V2, annotations=NARROW)], [c])
    assert classes(r, "new_egress_host") == {"residue"}


def test_row6_a_read_only_tool_never_explains_a_file_write():
    c = drifting(masked=dict(CLEAN), new_files=["/tmp/drop.txt"])
    r = run([defn(annotations=NARROW)], [defn(outputs=OUT_V2, annotations=NARROW)], [c])
    assert classes(r, "new_file") == {"residue"}


# --------------------------------------------------------------------------- #
# Row 7 - hint widened: always an escalation
# --------------------------------------------------------------------------- #
def test_row7_read_only_removed_plus_new_file_write_is_an_escalation():
    c = probe(new_files=["/tmp/report.csv"])
    r = run([defn(annotations={"readOnlyHint": True})],
            [defn(annotations={"readOnlyHint": False})], [c])
    assert r.verdict == "escalation"
    assert classes(r, "new_file") == {"escalation"}


def test_row7_open_world_added_plus_new_host_is_an_escalation():
    """The C3 cover for egress families."""
    c = probe(new_hosts=["api.example.invalid"])
    r = run([defn(annotations={"openWorldHint": False})],
            [defn(annotations={"openWorldHint": True})], [c])
    assert r.verdict == "escalation"
    assert classes(r, "new_egress_host") == {"escalation"}


def test_row7_a_widened_hint_is_reported_even_with_no_effect():
    r = run([defn(annotations={"readOnlyHint": True})],
            [defn(annotations={"readOnlyHint": False})], [probe()])
    assert r.verdict == "escalation"
    assert r.escalations == [("lookup_customer", "readOnly_removed")]


def test_row7_read_only_removed_never_covers_a_secret_read():
    """A write permission does not cover reading ~/.ssh."""
    c = probe(new_files=["/home/u/.ssh/id_rsa"])
    r = run([defn(annotations={"readOnlyHint": True})],
            [defn(annotations={"readOnlyHint": False})], [c])
    assert r.verdict == "residue_alert"
    assert classes(r, "new_file") == {"residue"}


def test_row7_an_escalated_tool_is_not_offered_for_re_baselining():
    r = run([defn(annotations={"readOnlyHint": True})],
            [defn(annotations={"readOnlyHint": False})], [probe()])
    assert r.explained_tools == []


# --------------------------------------------------------------------------- #
# Row 8 - open-world tool: new hosts held for review
# --------------------------------------------------------------------------- #
OPEN = {"openWorldHint": True}


def test_row8_open_world_tool_plus_new_host_is_held_for_review():
    c = probe(new_hosts=["news.example.invalid"], masked=dict(CLEAN))
    r = run([defn(annotations=OPEN)], [defn(outputs=OUT_V2, annotations=OPEN)], [c])
    assert r.verdict == "held_for_review"
    assert classes(r, "new_egress_host") == {"held_for_review"}


def test_row8_holding_needs_a_declared_change_on_that_tool():
    """Always-residue: a tool whose definition did not change declared
    nothing, so nothing - not even its open-world hint - excuses a host."""
    c = probe(new_hosts=["news.example.invalid"])
    r = run([defn(annotations=OPEN)], [defn(annotations=OPEN)], [c])
    assert r.verdict == "residue_alert"


def test_row8_explicit_reading_a_defaulted_open_world_tool_holds_nothing():
    """Every attacker tool declares no annotations, so every one is open-world
    by MCP default. Under the explicit reading its new host is residue."""
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c], open_world="explicit")
    assert classes(r, "new_egress_host") == {"residue"}


def test_row8_literal_reading_a_defaulted_open_world_tool_holds_its_host():
    """The other reading, kept testable so the choice is a measured one."""
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c], open_world="default_counts")
    assert classes(r, "new_egress_host") == {"held_for_review"}


def test_row8_literal_reading_explains_response_content_too():
    """Under the literal reading even unmasked drift on a defaulted open-world
    tool is explained - which is why the reading matters for H3."""
    r = run([defn()], [defn(description="changed")], [drifting()],
            open_world="default_counts")
    assert r.verdict == "accepted"


def test_an_unknown_open_world_policy_is_refused():
    with pytest.raises(ValueError):
        run([defn()], [defn()], [probe()], open_world="lenient")


# --------------------------------------------------------------------------- #
# Always residue
# --------------------------------------------------------------------------- #
def test_a_content_flag_inside_a_declared_field_is_residue():
    """Flags are never masked: instruction-shaped text is residue wherever
    it appears, including inside the field the update declared."""
    c = drifting(masked=dict(CLEAN), new_content_flags=["instruction:override"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert classes(r, "content_flag") == {"residue"}
    assert r.verdict == "residue_alert"


def test_a_determinism_break_that_survives_masking_is_residue():
    c = probe(determinism_break=True,
              masked=dict(CLEAN, determinism_break=True))
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert classes(r, "determinism_break") == {"residue"}


def test_a_determinism_break_caused_by_the_declared_field_is_explained():
    c = probe(determinism_break=True, masked=dict(CLEAN))
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    assert classes(r, "determinism_break") == {"explained"}


# --------------------------------------------------------------------------- #
# Verdict and report
# --------------------------------------------------------------------------- #
def test_verdict_order_residue_beats_escalation_beats_held():
    c = probe(new_hosts=["x.invalid"], new_content_flags=["instruction:override"])
    r = run([defn(annotations={"openWorldHint": False})],
            [defn(annotations={"openWorldHint": True})], [c])
    assert r.verdict == "residue_alert"          # the flag
    assert classes(r, "new_egress_host") == {"escalation"}


def test_signal_counts_and_to_dict():
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    counts = r.signal_counts
    assert counts["residue"]["new_egress_host"] == 1
    assert counts["explained"]["behavioural_drift"] == 1
    data = json.loads(json.dumps(r.to_dict()))
    assert data["verdict"] == "residue_alert"
    assert data["rules_version"] == "1.0"


def test_the_residue_view_carries_the_masked_measurement():
    """T25 scores this view, so it must hold what the checker decided."""
    c = drifting(masked=dict(CLEAN), new_hosts=["exfil.invalid"])
    r = run([defn()], [defn(outputs=OUT_V2)], [c])
    view = r.residue_view.checks[0]
    assert view.ratio == 0.0 and view.shape_known
    assert view.new_hosts == ["exfil.invalid"]


# --------------------------------------------------------------------------- #
# Masking
# --------------------------------------------------------------------------- #
def _payload(structured, text=None):
    text = json.dumps(structured, indent=2) if text is None else text
    return {"content": [{"type": "text", "text": text}],
            "structuredContent": structured, "isError": False}


def test_mask_removes_the_field_and_re_renders_the_json_text():
    masked, note = mask_payload(_payload({"body": "b", "last_contact": "d"}),
                                ["last_contact"])
    assert note == ""
    assert masked["structuredContent"] == {"body": "b"}
    assert masked["content"][0]["text"] == json.dumps({"body": "b"}, indent=2)


def test_mask_keeps_the_servers_own_formatting():
    for render in (lambda o: json.dumps(o), lambda o: json.dumps(o, indent=2),
                   lambda o: json.dumps(o, separators=(",", ":"))):
        data = {"body": "b", "last_contact": "d"}
        masked, _ = mask_payload(_payload(data, render(data)), ["last_contact"])
        assert masked["content"][0]["text"] == render({"body": "b"})


def test_mask_leaves_free_text_alone():
    """A declared structured field never explains a change in prose."""
    masked, _ = mask_payload(
        _payload({"result": "r", "last_contact": "d"}, text="Customer C-1 is active."),
        ["last_contact"])
    assert masked["content"][0]["text"] == "Customer C-1 is active."


def test_mask_without_structured_content_explains_nothing():
    masked, note = mask_payload({"content": [{"type": "text", "text": "hi"}]}, ["x"])
    assert masked is None and "no structured content" in note


def test_mask_with_unreproducible_formatting_explains_nothing():
    data = {"body": "b", "last_contact": "d"}
    odd = '{ "body" : "b" , "last_contact" : "d" }'
    masked, note = mask_payload(_payload(data, odd), ["last_contact"])
    assert masked is None and "could not be reproduced" in note


def test_strip_nested_and_array_paths():
    data = {"a": {"b": 1, "c": 2}, "items": [{"sku": 1, "qty": 2}, {"sku": 3, "qty": 4}]}
    assert strip_paths(data, ["a.b", "items[].qty"]) == {
        "a": {"c": 2}, "items": [{"sku": 1}, {"sku": 3}]}


def test_a_root_level_declaration_masks_nothing():
    """Otherwise "the whole output changed" would explain everything."""
    data = {"a": 1}
    assert strip_paths(data, [""]) == {"a": 1}


def test_mask_does_not_touch_the_original():
    data = {"body": "b", "last_contact": "d"}
    payload = _payload(data)
    mask_payload(payload, ["last_contact"])
    assert payload["structuredContent"] == data


# --------------------------------------------------------------------------- #
# Freezing
# --------------------------------------------------------------------------- #
def test_freeze_then_verify(tmp_path):
    path = tmp_path / "rules.json"
    sealed = freeze_rules(path)
    assert sealed["_sha256"] and sealed["_frozen_at"] and sealed["_git_commit"]
    assert verify_rules(path)["rules"]["version"] == "1.0"


def test_a_frozen_file_edited_afterwards_is_refused(tmp_path):
    path = tmp_path / "rules.json"
    freeze_rules(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rules"]["open_world"] = "default_counts"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="changed since it was frozen"):
        verify_rules(path)


def test_code_whose_rules_moved_after_the_freeze_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "rules.json"
    freeze_rules(path)
    monkeypatch.setitem(RULES, "open_world", "default_counts")
    with pytest.raises(ValueError, match="no longer match"):
        verify_rules(path)


def test_the_open_world_reading_is_part_of_the_frozen_rules():
    """The choice that decides H3 on this attacker is hashed with the rest."""
    assert RULES["open_world"] in residue.OPEN_WORLD_POLICIES


# --------------------------------------------------------------------------- #
# The real path, against a real server
# --------------------------------------------------------------------------- #
FIXTURE = Path(__file__).parent / "fixtures" / "tiny_server.py"


@pytest.mark.live
def test_a_real_update_is_masked_and_checked_end_to_end():
    """Baseline on v1, re-probe v2: an output field added and both hints
    widened. The masked measurement must be taken through the real re-probe,
    and the residue checker must explain the field and report the widening."""
    import anyio

    from driftsentry.baseline import capture_baseline, reprobe

    def launch(release):
        return dict(command=sys.executable, args=[str(FIXTURE)],
                    env=dict(os.environ, DS_TINY_RELEASE=release))

    async def go():
        v1, v2 = launch("v1"), launch("v2")
        base = await capture_baseline("tiny", v1["command"], v1["args"],
                                      env=v1["env"], n_probes=1, n_samples=2,
                                      monitor_sandbox=False)
        got = await reprobe(base, v2["command"], v2["args"], env=v2["env"],
                            samples_per_probe=1, monitor_sandbox=False)
        return base, got

    base, got = anyio.run(go)
    check = got.checks[0]
    assert check.masked is not None, check.mask_note
    assert check.arg_names == ["note_id"]
    diff = diff_definitions(base.tool_definitions, got.observed_definitions)
    result = check_update(got, diff, threshold_ratio=T)
    assert sorted(e for _, e in result.escalations) == ["openWorld_added",
                                                        "readOnly_removed"]
    assert result.residue == [], [i.to_dict() for i in result.residue]
    assert result.verdict == "escalation"
