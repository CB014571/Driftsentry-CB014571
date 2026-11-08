"""What an MCP update declares about itself (T23).

When a server is updated its tools/list changes. This module answers one
question, and only that one: between two tool lists, what did the server
DECLARE had changed? It does not look at behaviour. The residue checker
(residue.py) takes this declaration and asks which observed behaviour
changes it can explain.

Pure functions, no I/O. Two tool lists in, one DeclaredDiff out.

Three things measured against a real server (T22) shape this module:

1. The definition hash covers name, description and inputSchema only. An
   added output field and a widened annotation both leave it unchanged, so
   this differ compares full definitions and never the hash.

2. A tool returning a plain dict reports ``outputSchema: null``. FastMCP only
   emits an output schema for a model return type. None is therefore a
   normal value, treated as "no declared output structure", not an error.

3. Unset annotation hints arrive as explicit ``null``, not as missing keys:
   ``{"readOnlyHint": true, "destructiveHint": null, ...}``. "Explicit"
   therefore means "present AND not None". Reading ``key in annotations``
   as explicit would mark every tool explicitly destructive.

Field paths use fielddrift's format - ``a.b`` for nesting, ``items[].x`` for
array members - so a declared output change can be matched directly against
the paths fielddrift reports as drifted.

Schema keys that describe rather than constrain (``title``,
``description``, ``examples``, ``default``) are ignored. A reworded field
title changes no behaviour, and reporting it would hand the residue checker
a declared change that explains nothing.

Annotation defaults are the MCP spec's (2025-06-18): readOnlyHint false,
destructiveHint true, idempotentHint false, openWorldHint true. They are the
PERMISSIVE values, which makes one rule fall out by itself: a hint that was
only defaulted can never be widened, because it is already as wide as it
goes. An escalation needs the old value to have been declared narrow
explicitly.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

#: MCP annotation defaults, spec 2025-06-18.
ANNOTATION_DEFAULTS: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}

#: Escalation name -> (hint, narrow value, wide value).
ESCALATIONS: dict[str, tuple[str, bool, bool]] = {
    "readOnly_removed": ("readOnlyHint", True, False),
    "openWorld_added": ("openWorldHint", False, True),
    "destructive_added": ("destructiveHint", False, True),
}

SCHEMA_CHANGE_KINDS = ("added", "removed", "type_changed",
                       "required_changed", "enum_changed")

# Keys that describe a schema without constraining it.
_DESCRIPTIVE = {"title", "description", "examples", "default", "$comment"}


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SchemaChange:
    """One structural change at one field path."""

    path: str          # fielddrift format; "" is the schema root
    kind: str          # one of SCHEMA_CHANGE_KINDS

    def describe(self) -> str:
        return f"{self.path or '(root)'}: {self.kind}"


@dataclass(frozen=True)
class AnnotationChange:
    """One annotation hint whose effective value or explicitness moved."""

    old_value: bool
    new_value: bool
    old_explicit: bool
    new_explicit: bool


@dataclass
class ToolDiff:
    """Everything declared about one tool present in both lists."""

    name: str
    description_changed: bool = False
    input_changes: list[SchemaChange] = field(default_factory=list)
    output_changes: list[SchemaChange] = field(default_factory=list)
    annotations: dict[str, AnnotationChange] = field(default_factory=dict)
    escalations: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.description_changed or self.input_changes
                    or self.output_changes or self.annotations
                    or self.escalations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description_changed": self.description_changed,
            "input_changes": [asdict(c) for c in self.input_changes],
            "output_changes": [asdict(c) for c in self.output_changes],
            "annotations": {k: asdict(v) for k, v in self.annotations.items()},
            "escalations": list(self.escalations),
        }


@dataclass
class DeclaredDiff:
    """What an update declared, across the whole tool list."""

    tools_added: list[str] = field(default_factory=list)
    tools_removed: list[str] = field(default_factory=list)
    # Only tools present in both lists AND with something declared.
    tools: dict[str, ToolDiff] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (self.tools_added or self.tools_removed or self.tools)

    @property
    def escalations(self) -> list[tuple[str, str]]:
        """(tool, escalation) for every widened hint, in tool order."""
        return [(name, esc) for name in sorted(self.tools)
                for esc in self.tools[name].escalations]

    def for_tool(self, name: str) -> ToolDiff:
        """The declared diff for one tool, empty if it declared nothing."""
        return self.tools.get(name) or ToolDiff(name=name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools_added": list(self.tools_added),
            "tools_removed": list(self.tools_removed),
            "tools": {name: d.to_dict() for name, d in sorted(self.tools.items())},
        }


# --------------------------------------------------------------------------- #
# Schema walking
# --------------------------------------------------------------------------- #
def _resolve(node: Any, root: dict[str, Any], seen: frozenset[str] = frozenset()) -> Any:
    """Follow a local ``$ref`` (``#/$defs/X``) inside the same schema.

    Pydantic emits nested models as ``$defs`` plus ``$ref``. Without this a
    field added inside a nested model would be invisible: both versions would
    show the same ``$ref`` string. A cycle is cut rather than followed.
    """
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if ref in seen or not ref.startswith("#/"):
            return {}
        seen = seen | {ref}
        target: Any = root
        for part in ref[2:].split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        node = target
    return node


def _type_sig(node: Any, root: dict[str, Any]) -> tuple[str, ...]:
    """The set of JSON types a node admits, order-free.

    ``Optional[str]`` arrives as ``anyOf: [{type: string}, {type: null}]``,
    and the same field as plain ``type: [string, null]`` must compare equal.
    """
    node = _resolve(node, root)
    if not isinstance(node, dict):
        return ()
    t = node.get("type")
    if isinstance(t, str):
        return (t,)
    if isinstance(t, list):
        return tuple(sorted(str(x) for x in t))
    for combinator in ("anyOf", "oneOf"):
        members = node.get(combinator)
        if isinstance(members, list):
            out: set[str] = set()
            for m in members:
                out.update(_type_sig(m, root))
            return tuple(sorted(out))
    if "properties" in node:
        return ("object",)
    if "items" in node:
        return ("array",)
    return ()


def _child(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _object_branch(node: Any, root: dict[str, Any]) -> dict[str, Any]:
    """The object-shaped member of a node, through refs and anyOf.

    An optional nested model is ``anyOf: [{$ref: Model}, {type: null}]``. Its
    properties are the model's, and a field added to that model must still be
    found.
    """
    node = _resolve(node, root)
    if not isinstance(node, dict):
        return {}
    if "properties" in node:
        return node
    for combinator in ("anyOf", "oneOf", "allOf"):
        for m in node.get(combinator) or []:
            branch = _object_branch(m, root)
            if branch:
                return branch
    return {}


def _array_items(node: Any, root: dict[str, Any]) -> Any:
    node = _resolve(node, root)
    if not isinstance(node, dict):
        return None
    if "items" in node:
        return node["items"]
    for combinator in ("anyOf", "oneOf"):
        for m in node.get(combinator) or []:
            items = _array_items(m, root)
            if items is not None:
                return items
    return None


def _enum(node: Any, root: dict[str, Any]) -> tuple | None:
    node = _resolve(node, root)
    if isinstance(node, dict) and isinstance(node.get("enum"), list):
        return tuple(sorted(repr(v) for v in node["enum"]))
    if isinstance(node, dict) and "const" in node:
        return (repr(node["const"]),)
    return None


def _walk(old: Any, new: Any, old_root: dict, new_root: dict,
          path: str, out: list[SchemaChange], depth: int = 0) -> None:
    """Compare two schema nodes at one path, recursing into structure."""
    if depth > 32:                       # pathological nesting: stop, do not hang
        return

    if _type_sig(old, old_root) != _type_sig(new, new_root):
        # A node that changed type has no comparable children - an object
        # that became a string has no properties to diff - so report the
        # node and stop here.
        if _type_sig(old, old_root) and _type_sig(new, new_root):
            out.append(SchemaChange(path, "type_changed"))
            return

    if _enum(old, old_root) != _enum(new, new_root):
        out.append(SchemaChange(path, "enum_changed"))

    old_obj, new_obj = _object_branch(old, old_root), _object_branch(new, new_root)
    old_props = old_obj.get("properties") or {}
    new_props = new_obj.get("properties") or {}
    old_req = set(old_obj.get("required") or [])
    new_req = set(new_obj.get("required") or [])

    for key in sorted(set(old_props) | set(new_props)):
        child = _child(path, key)
        if key not in old_props:
            out.append(SchemaChange(child, "added"))
            continue
        if key not in new_props:
            out.append(SchemaChange(child, "removed"))
            continue
        if (key in old_req) != (key in new_req):
            out.append(SchemaChange(child, "required_changed"))
        _walk(old_props[key], new_props[key], old_root, new_root,
              child, out, depth + 1)

    old_items = _array_items(old, old_root)
    new_items = _array_items(new, new_root)
    if old_items is not None or new_items is not None:
        _walk(old_items or {}, new_items or {}, old_root, new_root,
              f"{path}[]", out, depth + 1)


def diff_schema(old: dict[str, Any] | None, new: dict[str, Any] | None) -> list[SchemaChange]:
    """Structural changes between two JSON schemas, as field paths.

    None on either side is "no declared structure" and compares as an empty
    schema, so a tool that starts declaring an output schema reports each of
    its fields as added.
    """
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    out: list[SchemaChange] = []
    _walk(old, new, old, new, "", out)
    # Deterministic and deduplicated: the same path can be reached through
    # two combinator branches.
    return sorted(set(out), key=lambda c: (c.path, c.kind))


# --------------------------------------------------------------------------- #
# Annotations
# --------------------------------------------------------------------------- #
def _hint(annotations: dict[str, Any] | None, key: str) -> tuple[bool, bool]:
    """(effective value, explicit) for one hint.

    Explicit means present and not None - measured: unset hints arrive as
    null, not absent.
    """
    raw = (annotations or {}).get(key)
    if isinstance(raw, bool):
        return raw, True
    return ANNOTATION_DEFAULTS[key], False


def diff_annotations(old: dict[str, Any] | None,
                     new: dict[str, Any] | None) -> tuple[dict[str, AnnotationChange], list[str]]:
    """Moved hints, and the escalations among them.

    A hint is recorded when its effective value changed. Explicitness alone
    moving (absent -> explicit default) changes nothing a tool may do, so it
    is not recorded as a change and can never be an escalation.
    """
    changes: dict[str, AnnotationChange] = {}
    for key in ANNOTATION_DEFAULTS:
        old_v, old_x = _hint(old, key)
        new_v, new_x = _hint(new, key)
        if old_v != new_v:
            changes[key] = AnnotationChange(old_v, new_v, old_x, new_x)

    escalations = []
    for name, (key, narrow, wide) in ESCALATIONS.items():
        change = changes.get(key)
        # old_explicit is implied by old == narrow, because every default is
        # the wide value; it is checked anyway so the rule reads as written.
        if (change and change.old_explicit and change.old_value is narrow
                and change.new_value is wide):
            escalations.append(name)
    return changes, escalations


# --------------------------------------------------------------------------- #
# The whole list
# --------------------------------------------------------------------------- #
def _by_name(tools: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for tool in tools or []:
        name = tool.get("name") if isinstance(tool, dict) else None
        if isinstance(name, str):
            out[name] = tool
    return out


def diff_tool(old: dict[str, Any], new: dict[str, Any]) -> ToolDiff:
    """What one tool declared about itself between two releases."""
    name = new.get("name") or old.get("name") or ""
    annotations, escalations = diff_annotations(old.get("annotations"),
                                                new.get("annotations"))
    return ToolDiff(
        name=name,
        description_changed=((old.get("description") or "").strip()
                             != (new.get("description") or "").strip()),
        input_changes=diff_schema(old.get("inputSchema"), new.get("inputSchema")),
        output_changes=diff_schema(old.get("outputSchema"), new.get("outputSchema")),
        annotations=annotations,
        escalations=escalations,
    )


def diff_definitions(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> DeclaredDiff:
    """What an update declared, from two tools/list results.

    Tools are matched by name, so tool order in either list is irrelevant;
    key order inside a definition is irrelevant because every comparison is
    by key.
    """
    old_by, new_by = _by_name(old), _by_name(new)
    diff = DeclaredDiff(
        tools_added=sorted(set(new_by) - set(old_by)),
        tools_removed=sorted(set(old_by) - set(new_by)),
    )
    for name in sorted(set(old_by) & set(new_by)):
        tool_diff = diff_tool(old_by[name], new_by[name])
        if not tool_diff.empty:
            diff.tools[name] = tool_diff
    return diff
