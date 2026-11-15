"""Residue rules v1.1: the MCP SDK's envelope is not the tool's behaviour.

Measured before these were written (15 Nov 2026), on the two real upgrades
v1.0 flagged:
  mcp-server-time 2026.8.18 -> 2026.10.28: on a valid timezone the text is
    byte-identical and the new SDK adds a structuredContent copy; on the keyed
    probes (invalid timezones) both releases error, worded differently.
  mcp-server-git  2026.8.18 -> 2026.10.28: a non-repository path errors in
    both; the new SDK prefixes the error with "Error executing tool git_status: ".
"""
from __future__ import annotations

import json

import pytest

from driftsentry.residue import RULES, RULES_V1_1, framework_normalise, verify_rules

TIME_OLD = {"content": [{"type": "text", "text": json.dumps(
    {"timezone": "Europe/London", "datetime": "2026-11-15T05:43:36+00:00",
     "day_of_week": "Sunday", "is_dst": False}, indent=2)}], "isError": False}


def _time_new():
    data = json.loads(TIME_OLD["content"][0]["text"])
    return {"content": [dict(TIME_OLD["content"][0])], "structuredContent": data,
            "isError": False}


def test_a_mirrored_structured_block_is_removed():
    assert framework_normalise(_time_new(), "get_current_time") == TIME_OLD


def test_structured_content_that_says_something_else_is_kept():
    new = _time_new()
    new["structuredContent"]["exfil"] = "x"
    assert "structuredContent" in framework_normalise(new, "get_current_time")


def test_errors_are_not_rewritten_by_normalisation():
    """The error rule explains a rewording; it does not edit the text."""
    err = {"content": [{"type": "text", "text": "Error executing tool t: boom"}],
           "isError": True}
    assert framework_normalise(err, "t") == err


def test_normalising_never_touches_the_input():
    new = _time_new()
    before = json.dumps(new, sort_keys=True)
    framework_normalise(new, "get_current_time")
    assert json.dumps(new, sort_keys=True) == before


def test_v1_1_keeps_every_v1_0_row_and_never_list():
    assert RULES_V1_1["rows"] == RULES["rows"]
    assert RULES_V1_1["always_residue"] == RULES["always_residue"]
    assert RULES_V1_1["open_world"] == RULES["open_world"]
    assert RULES["version"] == "1.0"


def test_v1_0_frozen_file_still_matches_the_code():
    from pathlib import Path
    frozen = Path(__file__).resolve().parents[1] / "eval_results" / "rq3u" / "rules_frozen.json"
    if not frozen.is_file():
        pytest.skip("no frozen v1.0 file")
    assert verify_rules(frozen)["rules"]["version"] == "1.0"


def test_formalisation_does_not_mask_fields_a_tool_already_returned():
    """A schema added to a schemaless tool: no masking, only the mirror goes."""
    from driftsentry.baseline import _framework_payloads

    out, masked = _framework_payloads([_time_new()], "get_current_time",
                                      ["timezone", "datetime"], had_schema=False)
    assert masked == [] and out == [TIME_OLD]


def test_an_existing_schema_still_masks_declared_fields():
    from driftsentry.baseline import _framework_payloads

    data = {"name": "a", "last_contact": "2026"}
    payload = {"content": [{"type": "text", "text": json.dumps(data)}],
               "structuredContent": data, "isError": False}
    out, masked = _framework_payloads([payload], "lookup_customer", ["last_contact"],
                                      had_schema=True)
    assert masked == ["last_contact"]
    assert "last_contact" not in out[0]["content"][0]["text"]


def test_nothing_changed_means_no_second_measurement():
    from driftsentry.baseline import _framework_payloads

    assert _framework_payloads([TIME_OLD], "get_current_time", None, False) == (None, [])


def test_v1_1_is_opt_in_everywhere():
    import inspect

    from driftsentry.residue import check_update
    from driftsentry.scorer import score_report
    from driftsentry.verify import verify_server
    for fn in (check_update, score_report, verify_server):
        assert inspect.signature(fn).parameters["rules_version"].default == "1.0"


# --------------------------------------------------------------------------- #
# The residue checker under v1.1, on real ProbeCheck objects
# --------------------------------------------------------------------------- #
def _check(**kw):
    from driftsentry.baseline import ProbeCheck
    base = dict(tool="t", probe_id="t@c1#0", distance=0.25, band=0.01, ratio=25.0,
                within_band=False, shape_known=True)
    base.update(kw)
    return ProbeCheck(**base)


def _classify(check, version):
    from driftsentry.declared_diff import diff_definitions
    from driftsentry.residue import check_update
    defs = [{"name": "t", "description": "d", "inputSchema": {"type": "object"}}]
    new = [{"name": "t", "description": "d2", "inputSchema": {"type": "object"}}]
    from driftsentry.baseline import ReprobeReport
    report = ReprobeReport(server="s", baseline_definition_hash="a",
                           observed_definition_hash="b", checks=[check],
                           embedding_backend="hash", observed_definitions=new)
    out = check_update(report, diff_definitions(defs, new), threshold_ratio=10.0,
                       rules_version=version)
    return {(i.signal, i.classification) for i in out.items}


def test_an_error_reworded_is_explained_under_v1_1_only():
    check = _check(framework={"all_error": True, "masked_paths": []})
    assert ("behavioural_drift", "residue") in _classify(check, "1.0")
    assert ("behavioural_drift", "explained") in _classify(check, "1.1")


def test_a_success_that_became_an_error_is_still_residue():
    check = _check(became_error=True, framework={"all_error": True, "masked_paths": []})
    assert ("behavioural_drift", "residue") in _classify(check, "1.1")


def test_side_effects_on_an_error_are_still_residue():
    check = _check(new_files=["C:/sink/exfil.log"],
                   framework={"all_error": True, "masked_paths": []})
    assert ("new_file", "residue") in _classify(check, "1.1")


def test_instructions_in_an_error_are_still_residue():
    check = _check(new_content_flags=["instruction_shaped"],
                   framework={"all_error": True, "masked_paths": []})
    assert ("content_flag", "residue") in _classify(check, "1.1")


def test_a_view_that_makes_things_worse_is_not_used():
    """Raw clean, framework view drifting: nothing is residue."""
    check = _check(distance=0.0, ratio=0.0, within_band=True,
                   framework={"distance": 0.3, "band": 0.01, "ratio": 30.0,
                              "within_band": False, "shape_known": True,
                              "determinism_break": False, "comparability": 1.0,
                              "all_error": False, "masked_paths": []})
    assert not {c for s, c in _classify(check, "1.1") if c == "residue"}
