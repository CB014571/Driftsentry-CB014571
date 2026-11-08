"""T23. The declaration differ.

The plan's list, one test each: identical lists are empty; key order and tool
order are ignored; an added output field is found at the right path; a nested
property change; an added required parameter; an annotation flip true->false
is an escalation; absent->explicit default is NOT an escalation; new tool and
removed tool.

Plus the cases T22 measured against a real server, which the plan's list does
not cover and which would each have produced a wrong diff:

  - unset hints arrive as explicit null, so null must read as "not explicit"
  - a plain-dict tool has outputSchema null, which must read as "no structure"
  - Pydantic nests models through $defs/$ref, so a field added inside a nested
    model is invisible unless refs are followed
"""
from __future__ import annotations

import copy

from driftsentry.declared_diff import (
    ANNOTATION_DEFAULTS,
    SchemaChange,
    diff_annotations,
    diff_definitions,
    diff_schema,
)


def tool(name="lookup_customer", *, description="Look up a customer.",
         inputs=None, outputs=None, annotations=None):
    return {
        "name": name,
        "description": description,
        "inputSchema": inputs or {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
        "outputSchema": outputs,
        "annotations": annotations,
    }


OUT_V1 = {"type": "object",
          "properties": {"name": {"type": "string"},
                         "email": {"type": "string"}},
          "required": ["name"]}


# --------------------------------------------------------------------------- #
# The plan's list
# --------------------------------------------------------------------------- #
def test_identical_lists_are_empty():
    tools = [tool(outputs=OUT_V1), tool("search_orders")]
    assert diff_definitions(tools, copy.deepcopy(tools)).empty


def test_tool_order_is_ignored():
    a, b = tool("a"), tool("b")
    assert diff_definitions([a, b], [b, a]).empty


def test_key_order_is_ignored():
    t = tool(outputs=OUT_V1)
    reordered = dict(reversed(list(copy.deepcopy(t).items())))
    reordered["outputSchema"] = dict(reversed(list(OUT_V1.items())))
    assert diff_definitions([t], [reordered]).empty


def test_an_added_output_field_is_found_at_its_path():
    """The C2 cover change: lookup_customer gains last_contact."""
    v2 = copy.deepcopy(OUT_V1)
    v2["properties"]["last_contact"] = {"type": "string"}
    diff = diff_definitions([tool(outputs=OUT_V1)], [tool(outputs=v2)])
    td = diff.tools["lookup_customer"]
    assert td.output_changes == [SchemaChange("last_contact", "added")]
    assert td.input_changes == []
    assert not td.escalations


def test_a_nested_property_change_is_found_at_the_nested_path():
    v1 = {"type": "object", "properties": {"address": {
        "type": "object", "properties": {"city": {"type": "string"}}}}}
    v2 = copy.deepcopy(v1)
    v2["properties"]["address"]["properties"]["city"] = {"type": "integer"}
    assert diff_schema(v1, v2) == [SchemaChange("address.city", "type_changed")]


def test_an_added_required_parameter():
    v2_in = {"type": "object",
             "properties": {"customer_id": {"type": "string"},
                            "region": {"type": "string"}},
             "required": ["customer_id", "region"]}
    diff = diff_definitions([tool()], [tool(inputs=v2_in)])
    assert diff.tools["lookup_customer"].input_changes == [
        SchemaChange("region", "added")]


def test_an_existing_parameter_becoming_required():
    v1_in = {"type": "object", "properties": {"q": {"type": "string"}}}
    v2_in = {**v1_in, "required": ["q"]}
    assert diff_schema(v1_in, v2_in) == [SchemaChange("q", "required_changed")]


def test_an_annotation_flip_true_to_false_is_an_escalation():
    diff = diff_definitions(
        [tool(annotations={"readOnlyHint": True})],
        [tool(annotations={"readOnlyHint": False})])
    assert diff.tools["lookup_customer"].escalations == ["readOnly_removed"]


def test_an_explicit_narrow_hint_dropped_to_absent_is_an_escalation():
    """true -> absent is a widening too: absent defaults to false."""
    diff = diff_definitions(
        [tool(annotations={"readOnlyHint": True})],
        [tool(annotations=None)])
    assert "readOnly_removed" in diff.tools["lookup_customer"].escalations


def test_absent_to_explicit_default_is_not_an_escalation():
    """Nothing a tool may do changed, so it is not even a declared change."""
    diff = diff_definitions(
        [tool(annotations=None)],
        [tool(annotations={"readOnlyHint": False, "openWorldHint": True,
                           "destructiveHint": True})])
    assert diff.empty


def test_a_new_tool_and_a_removed_tool():
    diff = diff_definitions([tool("a"), tool("b")], [tool("b"), tool("c")])
    assert diff.tools_added == ["c"]
    assert diff.tools_removed == ["a"]
    assert "b" not in diff.tools


# --------------------------------------------------------------------------- #
# The escalations
# --------------------------------------------------------------------------- #
def test_open_world_added_is_an_escalation():
    """The C3 cover for egress families."""
    diff = diff_definitions(
        [tool(annotations={"openWorldHint": False})],
        [tool(annotations={"openWorldHint": True})])
    assert diff.tools["lookup_customer"].escalations == ["openWorld_added"]


def test_destructive_added_is_an_escalation():
    diff = diff_definitions(
        [tool(annotations={"destructiveHint": False})],
        [tool(annotations={"destructiveHint": True})])
    assert diff.tools["lookup_customer"].escalations == ["destructive_added"]


def test_narrowing_is_recorded_but_is_not_an_escalation():
    diff = diff_definitions(
        [tool(annotations={"readOnlyHint": False})],
        [tool(annotations={"readOnlyHint": True})])
    td = diff.tools["lookup_customer"]
    assert td.escalations == []
    assert td.annotations["readOnlyHint"].new_value is True


def test_a_defaulted_hint_can_never_be_widened():
    """Every default is already the permissive value."""
    for key, default in ANNOTATION_DEFAULTS.items():
        _, escalations = diff_annotations({}, {key: default})
        assert escalations == [], key


def test_escalations_are_listed_across_the_whole_diff():
    diff = diff_definitions(
        [tool("a", annotations={"readOnlyHint": True}),
         tool("b", annotations={"openWorldHint": False})],
        [tool("a", annotations={"readOnlyHint": False}),
         tool("b", annotations={"openWorldHint": True})])
    assert diff.escalations == [("a", "readOnly_removed"), ("b", "openWorld_added")]


# --------------------------------------------------------------------------- #
# What T22 measured on a real server
# --------------------------------------------------------------------------- #
def test_null_hints_are_not_explicit():
    """Measured: unset hints arrive as null, not as missing keys. Reading
    `"destructiveHint" in annotations` as explicit would call every tool
    explicitly destructive."""
    real_v1 = {"title": None, "readOnlyHint": True, "destructiveHint": None,
               "idempotentHint": None, "openWorldHint": False}
    real_v2 = {"title": None, "readOnlyHint": False, "destructiveHint": None,
               "idempotentHint": None, "openWorldHint": True}
    changes, escalations = diff_annotations(real_v1, real_v2)
    assert set(changes) == {"readOnlyHint", "openWorldHint"}
    assert sorted(escalations) == ["openWorld_added", "readOnly_removed"]
    assert "destructiveHint" not in changes


def test_a_tool_that_starts_declaring_output_reports_each_field_added():
    """Measured: a plain-dict tool has outputSchema null."""
    diff = diff_definitions([tool(outputs=None)], [tool(outputs=OUT_V1)])
    assert diff.tools["lookup_customer"].output_changes == [
        SchemaChange("email", "added"), SchemaChange("name", "added")]


def test_null_output_on_both_sides_is_no_change():
    assert diff_definitions([tool(outputs=None)], [tool(outputs=None)]).empty


def test_a_field_added_inside_a_nested_model_is_found_through_refs():
    """Pydantic nests models as $defs plus $ref. Without following the ref
    both versions show the same string and the added field is invisible."""
    v1 = {"$defs": {"Address": {"type": "object",
                                "properties": {"city": {"type": "string"}}}},
          "type": "object",
          "properties": {"address": {"$ref": "#/$defs/Address"}}}
    v2 = copy.deepcopy(v1)
    v2["$defs"]["Address"]["properties"]["postcode"] = {"type": "string"}
    assert diff_schema(v1, v2) == [SchemaChange("address.postcode", "added")]


def test_an_optional_field_written_two_ways_is_the_same():
    """Optional[str] can arrive as anyOf or as a type list."""
    a = {"type": "object", "properties": {"x": {
        "anyOf": [{"type": "string"}, {"type": "null"}]}}}
    b = {"type": "object", "properties": {"x": {"type": ["null", "string"]}}}
    assert diff_schema(a, b) == []


def test_a_reworded_field_title_is_not_a_declared_change():
    """It changes no behaviour, and a declared change that explains nothing
    would only confuse the residue checker."""
    a = {"type": "object", "properties": {"x": {"type": "string", "title": "X"}}}
    b = {"type": "object", "properties": {"x": {"type": "string",
                                                "title": "The X",
                                                "description": "now explained"}}}
    assert diff_schema(a, b) == []


def test_array_members_use_fielddrift_paths():
    """`items[].sku`, the format fielddrift.flatten reports drift in, so the
    residue checker can match a declared path against a drifted one."""
    v1 = {"type": "object", "properties": {"items": {
        "type": "array", "items": {"type": "object",
                                   "properties": {"sku": {"type": "string"}}}}}}
    v2 = copy.deepcopy(v1)
    v2["properties"]["items"]["items"]["properties"]["qty"] = {"type": "integer"}
    assert diff_schema(v1, v2) == [SchemaChange("items[].qty", "added")]


def test_an_enum_change():
    a = {"type": "object", "properties": {"s": {"type": "string",
                                                "enum": ["a", "b"]}}}
    b = {"type": "object", "properties": {"s": {"type": "string",
                                                "enum": ["a", "b", "c"]}}}
    assert diff_schema(a, b) == [SchemaChange("s", "enum_changed")]


def test_a_description_change():
    diff = diff_definitions([tool()], [tool(description="Look up a customer record.")])
    td = diff.tools["lookup_customer"]
    assert td.description_changed
    assert not td.input_changes and not td.output_changes


def test_a_self_referencing_schema_does_not_hang():
    node = {"$defs": {"N": {"type": "object",
                            "properties": {"next": {"$ref": "#/$defs/N"}}}},
            "$ref": "#/$defs/N"}
    assert diff_schema(node, copy.deepcopy(node)) == []


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def test_to_dict_is_json_serialisable_and_complete():
    import json
    v2 = copy.deepcopy(OUT_V1)
    v2["properties"]["last_contact"] = {"type": "string"}
    diff = diff_definitions(
        [tool(outputs=OUT_V1, annotations={"readOnlyHint": True}), tool("gone")],
        [tool(outputs=v2, annotations={"readOnlyHint": False}), tool("new")])
    data = json.loads(json.dumps(diff.to_dict()))
    assert data["tools_added"] == ["new"]
    assert data["tools_removed"] == ["gone"]
    t = data["tools"]["lookup_customer"]
    assert t["output_changes"] == [{"path": "last_contact", "kind": "added"}]
    assert t["escalations"] == ["readOnly_removed"]


def test_for_tool_returns_an_empty_diff_for_an_untouched_tool():
    diff = diff_definitions([tool()], [tool()])
    assert diff.for_tool("lookup_customer").empty


# --------------------------------------------------------------------------- #
# Against real SDK output
# --------------------------------------------------------------------------- #
import os  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "tiny_server.py"


def _list_tools(release: str) -> list[dict]:
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ, DS_TINY_RELEASE=release)

    async def go():
        params = StdioServerParameters(command=sys.executable,
                                       args=[str(FIXTURE)], env=env)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                listed = await s.list_tools()
                return [t.model_dump(mode="json") for t in listed.tools]

    return anyio.run(go)


@pytest.mark.live
def test_the_differ_reads_a_real_update():
    """v1 -> v2 of the fixture: one output field added and both hints
    widened. Hand-written dicts cannot show whether the SDK's real shapes -
    titles, null hints, $defs - are handled; this does."""
    diff = diff_definitions(_list_tools("v1"), _list_tools("v2"))
    td = diff.tools["read_note"]
    assert td.output_changes == [SchemaChange("last_contact", "added")]
    assert td.input_changes == []
    assert not td.description_changed
    assert sorted(td.escalations) == ["openWorld_added", "readOnly_removed"]
    assert "destructiveHint" not in td.annotations


@pytest.mark.live
def test_a_real_server_diffed_against_itself_is_empty():
    assert diff_definitions(_list_tools("v1"), _list_tools("v1")).empty
