"""T22. The re-probe keeps the definitions it saw, not just their hash.

Residue checking needs to know WHAT changed in an update, not only whether
anything did. A declared change explains only the behaviour it literally
covers - an added output field explains drift in that field of that tool and
nothing else - so the checker needs the field paths. A hash cannot supply
them.

The measurement that makes this necessary, and which is worth stating because
it also strengthens the Gap 1 argument: the definition hash covers name,
description and inputSchema only (hashing._tool_identity). An added
outputSchema field, or an annotation widened from readOnlyHint true to false,
does NOT change the definition hash. So `definition_changed` is False for
exactly the updates Gap 2 is about, and the residue check must be triggered
by comparing definitions rather than by comparing hashes.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.fingerprint import ServerBaseline
from driftsentry.hashing import tools_definition_hash

TOOL_V1 = {
    "name": "read_notes",
    "description": "Read a note.",
    "inputSchema": {"type": "object",
                    "properties": {"id": {"type": "string"}}},
    "outputSchema": {"type": "object",
                     "properties": {"body": {"type": "string"}}},
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
}

TOOL_V2_OUTPUT_FIELD = {
    **TOOL_V1,
    "outputSchema": {"type": "object",
                     "properties": {"body": {"type": "string"},
                                    "last_contact": {"type": "string"}}},
}

TOOL_V2_WIDENED = {**TOOL_V1,
                   "annotations": {"readOnlyHint": False,
                                   "openWorldHint": True}}


def _report(**kw) -> ReprobeReport:
    base = dict(server="s", baseline_definition_hash="sha256:a",
                observed_definition_hash="sha256:a", checks=[],
                embedding_backend="hash")
    base.update(kw)
    return ReprobeReport(**base)


# --------------------------------------------------------------------------- #
# What the hash does and does not cover
# --------------------------------------------------------------------------- #
def test_an_added_output_field_does_not_change_the_definition_hash():
    """So definition_changed is False for a C2 cover change, and the residue
    check cannot be triggered off the hash."""
    assert (tools_definition_hash([TOOL_V1])
            == tools_definition_hash([TOOL_V2_OUTPUT_FIELD]))


def test_a_widened_annotation_does_not_change_the_definition_hash():
    """A C3 escalation - readOnly removed, open-world added - is invisible to
    pinning. That is a finding for Gap 1, not only a detail for Gap 2."""
    assert (tools_definition_hash([TOOL_V1])
            == tools_definition_hash([TOOL_V2_WIDENED]))


def test_an_input_schema_change_does_change_the_hash():
    """The hash is not useless: it covers name, description and inputSchema."""
    changed = {**TOOL_V1,
               "inputSchema": {"type": "object",
                               "properties": {"id": {"type": "string"},
                                              "verbose": {"type": "boolean"}}}}
    assert (tools_definition_hash([TOOL_V1])
            != tools_definition_hash([changed]))


# --------------------------------------------------------------------------- #
# The report carries the definitions
# --------------------------------------------------------------------------- #
def test_the_report_keeps_the_definitions_it_saw():
    report = _report(observed_definitions=[TOOL_V2_OUTPUT_FIELD])
    assert report.observed_definitions == [TOOL_V2_OUTPUT_FIELD]


def test_the_kept_definitions_include_output_schema_and_annotations():
    """Both are dropped by the hash, and both are what the rules table keys
    on, so losing them anywhere makes residue checking impossible."""
    report = _report(observed_definitions=[TOOL_V2_WIDENED])
    kept = report.observed_definitions[0]
    assert "outputSchema" in kept
    assert kept["annotations"] == {"readOnlyHint": False,
                                   "openWorldHint": True}


def test_a_report_built_without_the_field_still_works():
    """Every existing caller and test constructs ReprobeReport positionally
    or by keyword without this field."""
    report = _report()
    assert report.observed_definitions == []
    assert report.definition_changed is False


def test_two_reports_do_not_share_one_list():
    """A mutable default would make every report alias the same list."""
    a, b = _report(), _report()
    a.observed_definitions.append(TOOL_V1)
    assert b.observed_definitions == []


def test_the_hash_and_the_definitions_can_disagree_about_change():
    """The case the whole task exists for: identical hash, different
    definitions."""
    report = _report(baseline_definition_hash=tools_definition_hash([TOOL_V1]),
                     observed_definition_hash=tools_definition_hash(
                         [TOOL_V2_OUTPUT_FIELD]),
                     observed_definitions=[TOOL_V2_OUTPUT_FIELD])
    assert report.definition_changed is False
    assert report.observed_definitions != [TOOL_V1]


# --------------------------------------------------------------------------- #
# Old baselines still load
# --------------------------------------------------------------------------- #
def _minimal_baseline_dict() -> dict:
    return {
        "server": "s",
        "definition_hash": "sha256:a",
        "tools": [],
        "embedding_backend": "hash",
        "embedding_dim": 8,
        "seed": 0,
        "n_probes": 3,
        "n_samples": 6,
        "captured_at": "2026-01-01T00:00:00Z",
    }


def test_a_baseline_file_written_before_this_task_still_loads():
    """The fixed-probe baseline is the control condition the whole evaluation
    compares against. A file that stops loading invalidates it."""
    loaded = ServerBaseline.from_dict(_minimal_baseline_dict())
    assert loaded.server == "s"
    assert loaded.tool_definitions == []
    assert loaded.probe_mode == "fixed"


def test_a_baseline_round_trips_through_json_with_definitions():
    data = dict(_minimal_baseline_dict(), tool_definitions=[TOOL_V1])
    loaded = ServerBaseline.from_dict(json.loads(json.dumps(data)))
    assert loaded.tool_definitions == [TOOL_V1]
    assert loaded.tool_definitions[0]["annotations"]["readOnlyHint"] is True


def test_the_baseline_keeps_the_full_definition_not_the_hashed_subset():
    """capture_baseline stores model_dump(mode='json'), so outputSchema and
    annotations survive. If that ever narrows to the hashed fields, residue
    checking loses its reference side."""
    loaded = ServerBaseline.from_dict(
        dict(_minimal_baseline_dict(), tool_definitions=[TOOL_V1]))
    stored = loaded.tool_definitions[0]
    for key in ("name", "description", "inputSchema", "outputSchema",
                "annotations"):
        assert key in stored, key


# --------------------------------------------------------------------------- #
# The real path, against a real server
# --------------------------------------------------------------------------- #
# Everything above constructs the report by hand. These two start an actual
# stdio MCP server and go through capture_baseline and reprobe, because the
# question that matters is whether the SDK delivers outputSchema and
# annotations at all - and it was measured that `-> dict` yields
# `outputSchema: null`, so the answer depends on the server.
FIXTURE = Path(__file__).parent / "fixtures" / "tiny_server.py"


def _launch(release: str) -> dict:
    env = dict(os.environ)
    env["DS_TINY_RELEASE"] = release
    return {"command": sys.executable, "args": [str(FIXTURE)], "env": env}


@pytest.mark.live
def test_a_real_reprobe_carries_the_definitions_it_saw():
    import anyio

    from driftsentry.baseline import capture_baseline, reprobe

    launch = _launch("v1")

    async def go():
        base = await capture_baseline(
            "tiny", launch["command"], launch["args"], env=launch["env"],
            n_probes=1, n_samples=2, monitor_sandbox=False)
        got = await reprobe(base, launch["command"], launch["args"],
                            env=launch["env"], samples_per_probe=1,
                            monitor_sandbox=False)
        return base, got

    base, got = anyio.run(go)
    assert got.observed_definitions, "the real path left the field empty"
    tool = got.observed_definitions[0]
    assert tool["name"] == "read_note"
    # The two fields the hash drops and the rules table needs.
    assert tool["outputSchema"] is not None
    assert "last_contact" not in tool["outputSchema"]["properties"]
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["annotations"]["openWorldHint"] is False
    # And the baseline side keeps them too, so the diff has both ends.
    assert base.tool_definitions[0]["outputSchema"] is not None


@pytest.mark.live
def test_an_unset_hint_comes_back_as_none_not_as_a_missing_key():
    """So the differ cannot use `in annotations` to mean "explicitly set":
    that would call every tool explicitly destructive."""
    import anyio

    from driftsentry.baseline import capture_baseline

    launch = _launch("v1")

    async def go():
        return await capture_baseline(
            "tiny", launch["command"], launch["args"], env=launch["env"],
            n_probes=1, n_samples=2, monitor_sandbox=False)

    base = anyio.run(go)
    annotations = base.tool_definitions[0]["annotations"]
    assert "destructiveHint" in annotations
    assert annotations["destructiveHint"] is None


# --------------------------------------------------------------------------- #
# Definitions are recorded in the wire format, whatever the SDK version
# --------------------------------------------------------------------------- #
# Measured 9 Nov: a server venv carrying mcp 2.3.0 dumped its tools as
# input_schema / read_only_hint - the model's field names - and the declared
# diff of mcp-server-time read every input parameter as removed and every hint
# as reverted to its default. by_alias gives the wire names on every version.
def test_definitions_are_dumped_with_wire_names():
    import inspect

    from driftsentry import baseline
    src = inspect.getsource(baseline)
    assert 'definitions = [t.model_dump(mode="json", by_alias=True)' in src
    assert 'observed_definitions = [t.model_dump(mode="json", by_alias=True)' in src


def test_by_alias_changes_nothing_the_hash_or_differ_read_on_this_sdk():
    from mcp.types import Tool, ToolAnnotations

    from driftsentry.hashing import tools_definition_hash
    t = Tool(name="x", description="d",
             inputSchema={"type": "object", "properties": {"a": {"type": "string"}}},
             annotations=ToolAnnotations(readOnlyHint=True))
    plain, alias = t.model_dump(mode="json"), t.model_dump(mode="json", by_alias=True)
    for key in ("name", "description", "inputSchema", "outputSchema", "annotations"):
        assert plain[key] == alias[key], key
    assert tools_definition_hash([plain]) == tools_definition_hash([alias])
