"""Rules v1.2 (follow-up H3c): v1.1 plus a strict renaming rule."""
from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest

from driftsentry.declared_diff import DeclaredDiff, diff_definitions
from driftsentry.residue import (RULES_V1_1, RULES_V1_2, freeze_rules, match_renames,
                                 rename_back, verify_rules)


def _tool(name, *props, description="d"):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object",
                            "properties": {p: {"type": "string"} for p in props}}}


def test_hyphen_to_underscore_is_a_rename():
    old = [_tool("read-query", "query"), _tool("list-tables")]
    new = [_tool("read_query", "query"), _tool("list_tables")]
    assert match_renames(old, new) == {"read-query": "read_query",
                                       "list-tables": "list_tables"}


def test_case_and_camel_case_are_a_rename():
    assert match_renames([_tool("get_weather", "city")],
                         [_tool("getWeather", "City")]) == {"get_weather": "getWeather"}


def test_a_different_name_is_not_a_rename_however_similar():
    # Similarity is never enough: "read_queries" is a different word.
    assert match_renames([_tool("read_query", "query")],
                         [_tool("read_queries", "query")]) == {}


def test_different_input_fields_are_not_a_rename():
    assert match_renames([_tool("read-query", "query")],
                         [_tool("read_query", "query", "limit")]) == {}


def test_an_ambiguous_pairing_is_refused():
    old = [_tool("read-query", "query")]
    new = [_tool("read_query", "query"), _tool("ReadQuery", "query")]
    assert match_renames(old, new) == {}


def test_unchanged_tools_are_not_touched():
    same = [_tool("echo", "text")]
    assert match_renames(same, same) == {}


def test_rename_back_restores_old_names_only():
    new = [_tool("read_query", "query"), _tool("fresh", "x")]
    back = rename_back(new, {"read-query": "read_query"})
    assert [d["name"] for d in back] == ["read-query", "fresh"]
    assert new[0]["name"] == "read_query"          # input not modified


def test_a_pure_rename_leaves_no_other_declared_change_but_is_not_empty():
    old = [_tool("read-query", "query")]
    new = [_tool("read_query", "query")]
    renames = match_renames(old, new)
    diff = diff_definitions(old, rename_back(new, renames))
    assert not diff.tools_added and not diff.tools_removed and not diff.tools
    diff.tools_renamed = renames
    assert not diff.empty                          # a rename is a declared change
    assert diff.to_dict()["tools_renamed"] == {"read-query": "read_query"}


def test_v1_2_is_v1_1_plus_only_the_renaming_and_removal_rules():
    extra = {k: v for k, v in RULES_V1_2.items() if k not in RULES_V1_1}
    assert set(extra) == {"renaming", "removal"}
    for k, v in RULES_V1_1.items():
        if k not in ("version", "base"):
            assert RULES_V1_2[k] == v
    assert RULES_V1_2["version"] == "1.2" and RULES_V1_2["base"] == "1.1"


def test_v1_2_freezes_and_verifies(tmp_path):
    path = tmp_path / "rules_v1_2.json"
    freeze_rules(path, "1.2")
    assert verify_rules(path, "1.2")["rules"]["version"] == "1.2"
    with pytest.raises(ValueError):
        verify_rules(path, "1.1")


def test_check_update_accepts_v1_2():
    from driftsentry.baseline import ReprobeReport
    from driftsentry.residue import check_update

    report = ReprobeReport(server="s", baseline_definition_hash="a",
                           observed_definition_hash="b", checks=[],
                           embedding_backend="x")
    out = check_update(report, DeclaredDiff(), threshold_ratio=1.5, rules_version="1.2")
    assert out.items == []


def test_the_renaming_session_calls_the_new_name():
    from driftsentry.baseline import _RenamingSession

    called = []

    class S:
        async def call_tool(self, name, arguments=None):
            called.append(name)

        async def list_tools(self):
            return "listed"

    s = _RenamingSession(S(), {"read-query": "read_query"})
    anyio.run(s.call_tool, "read-query", {})
    anyio.run(s.call_tool, "other", {})
    assert called == ["read_query", "other"]
    assert anyio.run(s.list_tools) == "listed"     # everything else passes through


def test_design_case_sqlite_upgrade_pairs_all_six_tools():
    """The design data for v1.2: held-out sqlite under v1.1 renamed every tool."""
    base = (Path(__file__).resolve().parent.parent / "eval_results" / "followup"
            / "h3b" / "held_out" / "sqlite")
    if not (base / "tools_old.json").is_file():
        pytest.skip("sqlite design data not present")
    old = json.loads((base / "tools_old.json").read_text(encoding="utf-8"))
    new = json.loads((base / "tools_new.json").read_text(encoding="utf-8"))
    renames = match_renames(old, new)
    assert len(renames) == 6
    assert renames["read-query"] == "read_query"
    diff = diff_definitions(old, rename_back(new, renames))
    assert not diff.tools_added and not diff.tools_removed


def _check(tool, **kw):
    from driftsentry.baseline import ProbeCheck

    base = dict(tool=tool, probe_id="p1", distance=0.9, band=0.1, ratio=9.0,
                within_band=False, shape_known=False, new_hosts=[], new_files=[],
                new_content_flags=[], observed_shape_hash="", observed_excerpt="",
                baseline_excerpt="", became_error=True)
    base.update(kw)
    return ProbeCheck(**base)


def _report(*checks):
    from driftsentry.baseline import ReprobeReport

    return ReprobeReport(server="s", baseline_definition_hash="a",
                         observed_definition_hash="b", checks=list(checks),
                         embedding_backend="x")


def test_a_removed_tool_failing_is_explained_under_v1_2_only():
    from driftsentry.residue import check_update

    diff = DeclaredDiff(tools_removed=["gone"])
    rep = _report(_check("gone"))
    v12 = check_update(rep, diff, threshold_ratio=1.5, rules_version="1.2")
    assert not [i for i in v12.items if i.classification == "residue"]
    v11 = check_update(rep, diff, threshold_ratio=1.5, rules_version="1.1")
    assert [i for i in v11.items if i.classification == "residue"]


def test_side_effects_during_a_removed_tool_call_stay_residue():
    from driftsentry.residue import check_update

    diff = DeclaredDiff(tools_removed=["gone"])
    rep = _report(_check("gone", new_hosts=["203.0.113.9"]))
    out = check_update(rep, diff, threshold_ratio=1.5, rules_version="1.2")
    assert any(i.classification == "residue" and "egress" in i.signal for i in out.items)
