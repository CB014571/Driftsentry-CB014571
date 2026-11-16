"""Declared-diff residue checking (T24, Gap 2).

When an MCP server is updated, a defence today either re-approves the whole
update - and absorbs whatever was hidden in it into the new baseline - or
refuses every behaviour change, and so false-alarms on every legitimate
update. Residue checking takes the middle path. Each change the update
DECLARES in its tool definitions explains only the behaviour it can literally
explain, by fixed rules. The tool is re-probed, and whatever no declaration
explains is the residue. Residue on any signal is an alert.

How "explains" is computed
    The plan sketched matching field paths out of fielddrift's change strings.
    Reading the code showed that cannot work, for a reason worth stating:
    fielddrift.compare only walks paths that existed at baseline ("absence is
    a structural signal, not this one"). An ADDED field - the C2 cover change
    itself - never appears in field_changes at all. It surfaces only as a
    structural change and as embedding drift on the whole response. And the
    keyed probe path computes no field drift whatsoever.

    So residue is computed the direct way instead. At re-probe time, for a
    tool whose update declared an output change, the response is measured a
    second time with the declared fields REMOVED (`mask_payload`), by the
    detector's own arithmetic. That masked measurement is the residue view:
    the response as it would look if only the declared change had happened.
    Whatever the ordinary detector still finds in it, no declaration
    explains. This works identically on both probe paths, reuses the
    comparison that is already calibrated, and needs no second notion of
    what counts as drift.

Masking text
    A structured MCP response usually carries the same data twice: in
    structuredContent, and rendered as JSON in a text block - and the text
    block is what gets embedded. Removing a field from structuredContent
    alone would leave it in the text. So a text block that parses to exactly
    the structured content is re-rendered without the declared fields, in
    the SAME formatting the server used, found by trying a small set of
    renderers against the original until one reproduces it byte for byte.
    If none does, masking fails and nothing is explained.

    A text block that is not a JSON rendering of the structured content is
    left untouched. A declared output field therefore never explains a
    change in free text. The plan allowed a declared output change to
    explain prose drift "when the new text contains the old text's field
    set"; that is not adopted. Free text has no field set, and a tool that
    declares structured output but changes its prose is changing something
    its declaration does not describe. If in doubt, residue (ground rule 3).

What is never explained, whatever is declared
    New content flags - credential-shaped or instruction-shaped output -
    are not masked, so they stay residue even inside a declared field.
    Secret-file reads stay residue even under a widened readOnly hint:
    a write permission does not cover reading ~/.ssh. A determinism break
    that survives masking is residue. Any signal on a tool whose definition
    did not change is residue, because nothing was declared for it. And a
    root-level output change is not masked: a declaration that the whole
    output changed would otherwise explain everything.

Thresholds are the detector's own
    Residue means "would still alert": a signal in the residue view at or
    above the alert line, scored by scorer.check_signals with the same
    threshold and per-tool calibration as the full detector. So an empty
    diff reduces to the base detector exactly, which is the first row of
    the rules table and what the golden tests can hold it to.

The rules are frozen before any cover-change attack is built
    `python -m driftsentry.residue freeze --out ...` seals RULES with a
    SHA-256, a timestamp and the git commit. `verify_rules` refuses to score
    against a file that changed, or against code whose RULES no longer
    match the frozen ones. Editing a rule after seeing RQ3 results would
    invalidate them; a rule found to be wrong is reported as a finding.
"""
from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable

from driftsentry.declared_diff import DeclaredDiff, ToolDiff, hint

RULES_VERSION = "1.0"

# --------------------------------------------------------------------------- #
# The permitted-change rules, Table 3.5 of the report. Data, so it can be
# frozen, hashed and compared - the implementation below reads OPEN_WORLD
# from here rather than hard-coding it.
# --------------------------------------------------------------------------- #
RULES: dict[str, Any] = {
    "version": RULES_VERSION,
    "rows": [
        {"declared": "none (definition unchanged)",
         "explains": "nothing",
         "never": "any change; the check reduces to the base detector"},
        {"declared": "output field added or changed (outputSchema)",
         "explains": "structure and value changes in that field of that tool",
         "never": "changes in other fields or tools, new outbound hosts, file writes"},
        {"declared": "input parameter added or changed (inputSchema)",
         "explains": "response changes on calls that use the parameter",
         "never": "response changes on probes that do not use it"},
        {"declared": "description changed",
         "explains": "nothing in responses; shown to the user",
         "never": "any behaviour change"},
        {"declared": "new tool",
         "explains": "the new tool's own behaviour, which gets its own baseline",
         "never": "any change in existing tools"},
        {"declared": "readOnlyHint true or openWorldHint false (unchanged)",
         "explains": "nothing",
         "never": "file writes or process starts; outbound connections"},
        {"declared": "hint widened (read-only removed, open-world added)",
         "explains": "the newly allowed kind of effect",
         "never": "reported to the user as a declaration escalation in every case"},
        {"declared": "open-world tool",
         "explains": "changes in response content",
         "never": "a new outbound host is held for user review, counted separately"},
    ],
    "always_residue": [
        "new content flags (instruction-like text, secret-like output)",
        "determinism breaks on fields not declared",
        "any change in a tool whose definition did not change",
    ],
    "annotation_defaults": "MCP spec 2025-06-18: readOnlyHint false, "
                           "destructiveHint true, idempotentHint false, "
                           "openWorldHint true",
    # How the open-world row is read. See OPEN_WORLD_POLICIES.
    "open_world": "explicit",
}

# --------------------------------------------------------------------------- #
# Rules v1.1 - a follow-up, frozen separately. v1.0 above is unchanged and
# remains the rule set every RQ3 result was scored with.
#
# Why it exists. v1.0 flagged 2 of 4 real benign upgrades (mcp-server-time,
# mcp-server-git), failing H3's false-alarm half. Inspecting the raw
# responses showed neither tool changed what it does. Both upgrades moved
# the MCP SDK from 1.30 to 2.3, and the SDK changed the ENVELOPE around the
# tool's answer:
#
#   time   the text answer is byte-identical; the new SDK adds a
#          structuredContent block that is an exact copy of it, and an
#          outputSchema describing fields the tool had always returned.
#          v1.0 read the schema as "fields added", masked them out, and
#          compared an empty object with the old answer.
#   git    every probe hits a non-repository path and errors; the new SDK
#          prefixes every tool error with "Error executing tool <name>: ".
#
# Correction, measured on the design re-run: for mcp-server-time the keyed
# probes are not valid timezones, so every probe takes the ERROR path, and
# there the old release worded its own error ("Error processing
# mcp-server-time query: ...") while the new one lets the SDK word it. So
# the second rule is "an error reworded" (error before and after), which
# covers the SDK prefix and the tool's own rewording alike.
#
# v1.1 explains exactly those two things and nothing else. It
# was designed on those two upgrades, so it is tested on upgrades it was
# not designed on (eval/followup_h3b.py, pre-registered before running).
# Side-effect and content-flag signals are untouched by both rules.
# --------------------------------------------------------------------------- #
RULES_V1_1: dict[str, Any] = {
    "version": "1.1",
    "base": "1.0",
    "rows": RULES["rows"],
    "always_residue": RULES["always_residue"],
    "annotation_defaults": RULES["annotation_defaults"],
    "open_world": RULES["open_world"],
    "framework_normalisation": [
        {"artefact": "structuredContent that is exactly the JSON of a text block "
                     "in the same response",
         "treatment": "removed before comparison: it repeats the text, so any real "
                      "change shows in the text"},
        {"artefact": "an error reworded: the probe's answer was an error at baseline "
                     "and is still an error",
         "treatment": "the change in wording is explained (an update may change how "
                      "it reports a failure, and an SDK upgrade changes the envelope "
                      "around it). A success that became an error, or an error that "
                      "became a success, is not covered; content flags and side "
                      "effects on an error stay residue"},
    ],
    "formalisation": {
        "declared": "outputSchema added to a tool that had none",
        "explains": "nothing by itself: a schema for output the tool already "
                    "returned is not a change in behaviour, so declared fields "
                    "are NOT masked; only the mirrored structuredContent is removed",
        "never": "any change in the text answer",
    },
}

# --------------------------------------------------------------------------- #
# Rules v1.2 (follow-up H3c): v1.1 plus ONE rule, for a tool that was renamed.
#
# Why: under frozen v1.1, held-out sqlite left a residue on every run because
# its upgrade renamed all six tools (read-query -> read_query, ...). Every
# probe then called a name that no longer existed. The tools had not changed;
# only their spelling had. v1.2 pairs such tools and compares the new name's
# behaviour with the old name's approval record.
#
# The pairing is deliberately strict, so it cannot be used to launder a
# replacement tool: names equal once case and punctuation are ignored, input
# fields equal the same way, and one-to-one. The rename is recorded in the
# declared diff, never hidden, and the renamed tool's BEHAVIOUR is compared
# exactly as any other tool's: a renamed tool that now behaves differently is
# still residue.
# --------------------------------------------------------------------------- #
RULES_V1_2: dict[str, Any] = {
    **RULES_V1_1,
    "version": "1.2",
    "base": "1.1",
    "renaming": {
        "declared": "a tool removed and a tool added whose names are equal once "
                    "lower-cased with every non-alphanumeric character removed, and "
                    "whose input-schema property names are equal the same way",
        "condition": "the pairing is one-to-one: no other removed or added tool "
                     "normalises to the same name",
        "explains": "the change of name only: the new name is probed and compared "
                    "with the old name's approval record; any change in behaviour, "
                    "side effects or content flags is scored as residue as always",
        "never": "a pairing by description, by similarity, or of more than one "
                 "candidate",
    },
    "removal": {
        "declared": "a tool the new release no longer lists (and that no renaming "
                    "pairs with a new tool)",
        "explains": "the answer to a probe of that tool: it can no longer be called "
                    "by anyone, so a changed or failed answer is not a change in "
                    "behaviour that can harm",
        "never": "side effects or content flags observed during that call - those "
                 "stay residue",
    },
}


#: The rule set the PRODUCT uses for update checks (proxy, daemon, CLI).
#: v1.1 is the most completely measured set: on the synthetic matrix it
#: detected 45 of 45 hidden changes with 0 of 6 benign updates alarmed, and on
#: held-out real upgrades it left a residue on 1 of 3 (H3b). v1.2 adds rename
#: and removal rules but its synthetic re-run was not completed, so it stays
#: available, not default. Library calls keep their own default ("1.0"), so
#: every frozen experiment still reproduces exactly.
PRODUCT_RULES = "1.1"


def _norm_name(name: str) -> str:
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def _norm_props(definition: dict[str, Any]) -> frozenset[str]:
    schema = definition.get("inputSchema") or definition.get("input_schema") or {}
    return frozenset(_norm_name(p) for p in (schema.get("properties") or {}))


def match_renames(old_defs: list[dict[str, Any]],
                  new_defs: list[dict[str, Any]]) -> dict[str, str]:
    """Rules v1.2: {old name: new name} for tools that were only renamed."""
    old_by = {d.get("name"): d for d in old_defs if d.get("name")}
    new_by = {d.get("name"): d for d in new_defs if d.get("name")}
    removed = [n for n in old_by if n not in new_by]
    added = [n for n in new_by if n not in old_by]

    def key(name: str, d: dict[str, Any]) -> tuple[str, frozenset[str]]:
        return _norm_name(name), _norm_props(d)

    removed_keys: dict[tuple, list[str]] = {}
    for n in removed:
        removed_keys.setdefault(key(n, old_by[n]), []).append(n)
    added_keys: dict[tuple, list[str]] = {}
    for n in added:
        added_keys.setdefault(key(n, new_by[n]), []).append(n)
    out: dict[str, str] = {}
    for k, olds in removed_keys.items():
        news = added_keys.get(k, [])
        if len(olds) == 1 and len(news) == 1:
            out[olds[0]] = news[0]
    return out


def rename_back(new_defs: list[dict[str, Any]], renames: dict[str, str]) -> list[dict[str, Any]]:
    """The observed definitions with each renamed tool given its old name back."""
    back = {new: old for old, new in renames.items()}
    out = []
    for d in new_defs:
        if d.get("name") in back:
            d = {**d, "name": back[d["name"]]}
        out.append(d)
    return out


def framework_normalise(payload: dict[str, Any], tool_name: str) -> dict[str, Any]:
    """Rules v1.1: drop a structuredContent block that only repeats the text.

    The other v1.1 rule (an error reworded) is applied by the residue checker,
    not here: it explains a change rather than removing one.
    Returns a new payload; the input is not modified.
    """
    out = json.loads(json.dumps(payload))
    blocks = [b for b in (out.get("content") or []) if isinstance(b, dict)]
    for key in ("structuredContent", "structured_content"):
        sc = out.get(key)
        if sc is None:
            continue
        for block in blocks:
            if block.get("type") != "text":
                continue
            try:
                parsed = json.loads(block.get("text") or "")
            except (ValueError, TypeError):
                continue
            if parsed == sc:
                out.pop(key)
                break
    return out


#: The two readings of the open-world row, kept explicit because the choice
#: decides H3 on this attacker and must be made before the freeze, not after.
#:
#:   explicit        a new outbound host is held for review only on a tool
#:                   that DECLARES openWorldHint true. A defaulted open-world
#:                   tool's new host is residue. Response content is
#:                   explained only by declared output fields.
#:   default_counts  the row's literal "(declared or by MCP default)": any
#:                   tool whose definition changed and whose effective
#:                   openWorldHint is true holds its new hosts for review,
#:                   and its response-content changes are explained.
OPEN_WORLD_POLICIES = ("explicit", "default_counts")

# Scorer signal name -> residue signal name (T24's vocabulary).
SIGNAL_NAMES: dict[str, str] = {
    "behavioural_drift": "behavioural_drift",
    "structural_change": "structural_change",
    "field_drift": "field_drift",
    "determinism_break": "determinism_break",
    "error_behaviour": "error_behaviour",
    "rule:new_egress_host": "new_egress_host",
    "rule:secret_file_read": "new_file",
    "rule:new_file_access": "new_file",
    "rule:credential_shaped_output": "content_flag",
    "rule:instruction_shaped_output": "content_flag",
}

# The behavioural measurement a declared output field may be masked out of.
_MASKABLE = ("distance", "band", "ratio", "within_band", "shape_known",
             "determinism_break", "field_drift", "field_changes",
             "comparability")


# --------------------------------------------------------------------------- #
# Masking a response
# --------------------------------------------------------------------------- #
_RENDERERS: tuple[Callable[[Any], str], ...] = (
    lambda o: json.dumps(o, indent=2, ensure_ascii=False),
    lambda o: json.dumps(o, indent=2),
    lambda o: json.dumps(o, ensure_ascii=False),
    lambda o: json.dumps(o),
    lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False),
    lambda o: json.dumps(o, separators=(",", ":")),
)


def _strip(node: Any, parts: list[str]) -> None:
    """Remove one declared path, fielddrift format, in place."""
    if not parts:
        return
    head, rest = parts[0], parts[1:]
    is_array = head.endswith("[]")
    key = head[:-2] if is_array else head
    if key:
        if not isinstance(node, dict) or key not in node:
            return
        if not rest:
            del node[key]                # the declared field itself, array or not
            return
        child = node[key]
    else:
        child = node                     # a root array: "[].x"
    if is_array:
        if isinstance(child, list):
            for element in child:
                _strip(element, rest)
        return
    _strip(child, rest)


def strip_paths(obj: Any, paths: Iterable[str]) -> Any:
    """A copy of obj with every declared path removed. Root paths are kept."""
    out = copy.deepcopy(obj)
    for path in sorted(set(p for p in paths if p)):
        _strip(out, path.split("."))
    return out


def mask_payload(payload: dict[str, Any],
                 declared_paths: Iterable[str]) -> tuple[dict[str, Any] | None, str]:
    """The response as it would be had only the declared fields changed.

    Returns (masked, "") or (None, reason). None means the declared change
    could not be separated from the rest of the response, and so explains
    nothing - the residue view keeps the original measurement.
    """
    paths = [p for p in declared_paths if p]
    if not paths:
        return None, "no field-level output change declared"
    structured = payload.get("structuredContent")
    if not isinstance(structured, dict):
        return None, ("an output change was declared but the response carries "
                      "no structured content to remove it from")

    masked = copy.deepcopy(payload)
    masked_structured = strip_paths(structured, paths)
    masked["structuredContent"] = masked_structured

    blocks = masked.get("content")
    if isinstance(blocks, list):
        for block in blocks:
            if not (isinstance(block, dict) and block.get("type") == "text"):
                continue
            text = block.get("text") or ""
            try:
                parsed = json.loads(text)
            except (ValueError, TypeError):
                continue                 # free text: not masked, see docstring
            if parsed != structured:
                continue                 # JSON, but not a rendering of the data
            renderer = next((r for r in _RENDERERS if r(structured) == text), None)
            if renderer is None:
                return None, ("a text block renders the structured content in a "
                              "format that could not be reproduced exactly")
            block["text"] = renderer(masked_structured)
    return masked, ""


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass
class ResidueItem:
    """One observed change, and what became of it."""

    tool: str
    probe_id: str
    signal: str            # residue vocabulary, see SIGNAL_NAMES
    classification: str    # explained | residue | escalation | held_for_review
    reason: str
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResidueReport:
    """The verdict on one update."""

    items: list[ResidueItem] = field(default_factory=list)
    escalations: list[tuple[str, str]] = field(default_factory=list)
    explained_tools: list[str] = field(default_factory=list)
    tools_needing_baseline: list[str] = field(default_factory=list)
    # What the update declared, as DeclaredDiff.to_dict(). Reporting only:
    # nothing here is read back by the rules, so the frozen rules are untouched.
    declared: dict[str, Any] = field(default_factory=dict)
    rules_version: str = RULES_VERSION
    open_world: str = RULES["open_world"]
    # The re-probe as the residue checker sees it: explained parts masked or
    # neutralised, escalated and held side effects removed. T25 scores this.
    residue_view: Any = None

    def _of(self, kind: str) -> list[ResidueItem]:
        return [i for i in self.items if i.classification == kind]

    @property
    def residue(self) -> list[ResidueItem]:
        return self._of("residue")

    @property
    def held_for_review(self) -> list[ResidueItem]:
        return self._of("held_for_review")

    @property
    def verdict(self) -> str:
        if self.residue:
            return "residue_alert"
        if self.escalations or self._of("escalation"):
            return "escalation"
        if self.held_for_review:
            return "held_for_review"
        return "accepted"

    @property
    def signal_counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for item in self.items:
            bucket = counts.setdefault(item.classification, {})
            bucket[item.signal] = bucket.get(item.signal, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "rules_version": self.rules_version,
            "open_world": self.open_world,
            "items": [i.to_dict() for i in self.items],
            "escalations": [list(e) for e in self.escalations],
            "explained_tools": list(self.explained_tools),
            "tools_needing_baseline": list(self.tools_needing_baseline),
            "declared": self.declared,
            "signal_counts": self.signal_counts,
        }


# --------------------------------------------------------------------------- #
# The check
# --------------------------------------------------------------------------- #
def _definitions_by_name(defs: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {d["name"]: d for d in defs or [] if isinstance(d, dict) and "name" in d}


def _holds_new_hosts(tool_def: dict[str, Any] | None, policy: str) -> bool:
    """Does the open-world row hold this tool's new hosts for review?"""
    annotations = (tool_def or {}).get("annotations")
    value, explicit = hint(annotations, "openWorldHint")
    if policy == "explicit":
        return value and explicit
    if policy == "default_counts":
        return value
    raise ValueError(f"unknown open-world policy {policy!r}")


def _explained_by_open_world(tool_def: dict[str, Any] | None, policy: str) -> bool:
    """Under the literal reading, response content on an open-world tool is
    explained. Under the explicit reading it never is - only declared output
    fields explain response content."""
    return policy == "default_counts" and _holds_new_hosts(tool_def, policy)


def _neutralised(check: Any) -> Any:
    """A check whose response changes are all explained."""
    return replace(check, distance=0.0, ratio=0.0, within_band=True,
                   shape_known=True, determinism_break=False,
                   field_drift=0.0, field_changes=[], became_error=False)


def check_update(
    report: Any,                          # driftsentry.baseline.ReprobeReport
    diff: DeclaredDiff,
    probe_args: dict[str, Iterable[str]] | None = None,
    *,
    threshold_ratio: float,
    per_tool: dict[str, float] | None = None,
    open_world: str | None = None,
    rules_version: str = "1.0",
) -> ResidueReport:
    """Classify every observed change on an updated server.

    ``probe_args`` maps probe_id to the argument names that probe set; it
    defaults to each check's own ``arg_names``. Only names matter: a probe
    "uses" a declared input parameter when it sets it.

    ``rules_version="1.1"`` scores each check's ``framework`` view instead:
    the response with the SDK's envelope removed (framework_normalise) and,
    only for a tool that already had an outputSchema, the declared output
    fields masked. Default 1.0, exactly as frozen.
    """
    if rules_version not in ("1.0", "1.1", "1.2"):
        raise ValueError(f"unknown rules version {rules_version!r}")
    # v1.2 is v1.1 plus the renaming rule, which acts BEFORE this function:
    # renamed tools are probed under their new name and the diff is taken
    # with their old name restored (verify.py). Everything here is v1.1.
    framework_rules = rules_version in ("1.1", "1.2")
    removed_tools = (set(getattr(diff, "tools_removed", []) or [])
                     if rules_version == "1.2" else set())
    from driftsentry.rules import secret_paths
    from driftsentry.scorer import ALERT_AT, check_signals

    policy = open_world or RULES["open_world"]
    if policy not in OPEN_WORLD_POLICIES:
        raise ValueError(f"unknown open-world policy {policy!r}")

    new_defs = _definitions_by_name(getattr(report, "observed_definitions", []))
    out = ResidueReport(declared=diff.to_dict(),
                        escalations=list(diff.escalations),
                        tools_needing_baseline=list(diff.tools_added),
                        open_world=policy)
    view_checks = []
    tools_with_findings: set[str] = set()

    for check in report.checks:
        td: ToolDiff = diff.for_tool(check.tool)
        tool_def = new_defs.get(check.tool)
        view = check
        why: dict[str, str] = {}          # residue signal -> explanation

        # -- a declared output field: measure the response without it
        out_paths = sorted({c.path for c in td.output_changes if c.path})
        masked = getattr(check, "masked", None)
        framework = getattr(check, "framework", None)
        if framework_rules:
            # Handled after the side-effect rules, below: v1.1 scores the raw
            # response AND the de-enveloped one, and a content signal is
            # residue only if both show it. The baseline was recorded on raw
            # responses, so stripping the envelope from one side alone could
            # itself create a difference when the old release had it too.
            if framework:
                note = ("error reworded (rules v1.1)"
                        if framework.get("all_error") and not getattr(check, "became_error", False)
                        else "mirrored structured output removed (rules v1.1)")
                if framework.get("masked_paths"):
                    note += "; declared output change: " + ", ".join(framework["masked_paths"])
                for name in ("behavioural_drift", "structural_change",
                             "determinism_break", "field_drift"):
                    why[name] = note
        elif out_paths and masked:
            view = replace(view, **{k: masked[k] for k in _MASKABLE if k in masked})
            for name in ("behavioural_drift", "structural_change",
                         "determinism_break", "field_drift"):
                why[name] = "declared output change: " + ", ".join(out_paths)

        # -- rules v1.2: a tool the update removed cannot be called any more
        if check.tool in removed_tools:
            view = _neutralised(view)
            for name in ("behavioural_drift", "structural_change",
                         "determinism_break", "field_drift", "error_behaviour"):
                why[name] = "tool removed by the update (rules v1.2)"

        # -- a declared input parameter the probe actually set
        in_params = {c.path.split(".")[0].removesuffix("[]")
                     for c in td.input_changes if c.path}
        names = set((probe_args or {}).get(check.probe_id)
                    or getattr(check, "arg_names", []) or [])
        used = sorted(in_params & names)
        if used:
            view = _neutralised(view)
            for name in ("behavioural_drift", "structural_change",
                         "determinism_break", "field_drift", "error_behaviour"):
                why[name] = "declared input change used by this probe: " + ", ".join(used)

        # -- the literal open-world reading explains response content
        if not td.empty and _explained_by_open_world(tool_def, policy):
            view = _neutralised(view)
            for name in ("behavioural_drift", "structural_change",
                         "determinism_break", "field_drift", "error_behaviour"):
                why.setdefault(name, "open-world tool: response content may change")

        # -- side effects a widened or open-world hint covers
        hosts, files = list(view.new_hosts), list(view.new_files)
        if hosts and "openWorld_added" in td.escalations:
            out.items.append(ResidueItem(check.tool, check.probe_id,
                                         "new_egress_host", "escalation",
                                         "open-world added: " + ", ".join(hosts[:5])))
            hosts = []
        elif hosts and not td.empty and _holds_new_hosts(tool_def, policy):
            out.items.append(ResidueItem(check.tool, check.probe_id,
                                         "new_egress_host", "held_for_review",
                                         "open-world tool contacted: " + ", ".join(hosts[:5])))
            hosts = []
        if files and "readOnly_removed" in td.escalations:
            secrets = set(secret_paths(files))
            ordinary = [f for f in files if f not in secrets]
            if ordinary:
                out.items.append(ResidueItem(check.tool, check.probe_id,
                                             "new_file", "escalation",
                                             "read-only removed: " + ", ".join(ordinary[:5])))
            files = [f for f in files if f in secrets]
        view = replace(view, new_hosts=hosts, new_files=files)

        # -- score both, by the detector's own arithmetic
        original = check_signals(check, threshold_ratio=threshold_ratio, per_tool=per_tool)
        residual = check_signals(view, threshold_ratio=threshold_ratio, per_tool=per_tool)
        if framework_rules and framework:
            fw_view = replace(view, **{k: framework[k] for k in _MASKABLE if k in framework})
            # An error before and after: the wording is explained, by
            # neutralising the content measurement. Side effects and content
            # flags are not part of it and are scored as always.
            if framework.get("all_error") and not getattr(check, "became_error", False):
                fw_view = _neutralised(fw_view)
            fw_signals = check_signals(fw_view, threshold_ratio=threshold_ratio,
                                       per_tool=per_tool)
            in_fw = {SIGNAL_NAMES.get(s.name, s.name) for s in fw_signals
                     if s.score >= ALERT_AT}
            residual = [s for s in residual if s.score < ALERT_AT
                        or SIGNAL_NAMES.get(s.name, s.name) in in_fw]
            if len(in_fw) < sum(1 for s in check_signals(view, threshold_ratio=threshold_ratio,
                                                         per_tool=per_tool)
                                if s.score >= ALERT_AT):
                view = fw_view
        view_checks.append(view)
        moved = {i.signal for i in out.items
                 if i.probe_id == check.probe_id and i.tool == check.tool}

        residue_names = set()
        for sig in residual:
            if sig.score >= ALERT_AT:
                name = SIGNAL_NAMES.get(sig.name, sig.name)
                residue_names.add(name)
                reason = ("tool definition unchanged" if td.empty
                          else "no declared change explains it")
                out.items.append(ResidueItem(check.tool, check.probe_id, name,
                                             "residue", f"{reason}: {sig.detail}",
                                             round(sig.score, 4)))
                tools_with_findings.add(check.tool)
        for sig in original:
            if sig.score < ALERT_AT:
                continue
            name = SIGNAL_NAMES.get(sig.name, sig.name)
            if name in residue_names or name in moved:
                continue
            out.items.append(ResidueItem(check.tool, check.probe_id, name,
                                         "explained", why.get(name, "explained"),
                                         round(sig.score, 4)))
        if moved:
            tools_with_findings.add(check.tool)

    escalated = {tool for tool, _ in out.escalations}
    probed = {c.tool for c in report.checks}
    out.explained_tools = sorted(
        name for name in diff.tools
        if name in probed and name not in tools_with_findings
        and name not in escalated)
    out.residue_view = replace(report, checks=view_checks)
    return out


# --------------------------------------------------------------------------- #
# Freezing
# --------------------------------------------------------------------------- #
def _git_commit() -> str:
    try:
        done = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=10, check=False)
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "driftsentry"],
                               capture_output=True, text=True, timeout=10,
                               check=False)
        commit = done.stdout.strip() or "unknown"
        return commit + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _rules_for(version: str) -> dict[str, Any]:
    return {"1.0": RULES, "1.1": RULES_V1_1, "1.2": RULES_V1_2}[version]


def freeze_rules(path: str | Path, version: str = "1.0") -> dict[str, Any]:
    """Seal a rule set with a SHA-256, a timestamp and the commit it came from."""
    from driftsentry.calibration import freeze

    sealed = freeze({"rules": _rules_for(version)}, path)
    sealed["_git_commit"] = _git_commit()
    Path(path).write_text(json.dumps(sealed, indent=2, default=str), encoding="utf-8")
    return sealed


def verify_rules(path: str | Path, version: str = "1.0") -> dict[str, Any]:
    """Refuse a rules file that changed, or code that no longer matches it."""
    from driftsentry.calibration import verify_frozen

    data = verify_frozen(path)
    if data.get("rules") != json.loads(json.dumps(_rules_for(version))):
        raise ValueError(
            f"{path} is intact but the RULES in the code no longer match it. "
            f"A permitted-change rule edited after the freeze invalidates every "
            f"RQ3 result scored with it; report a wrong rule as a finding instead.")
    return data


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m driftsentry.residue")
    sub = parser.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("freeze", help="seal the permitted-change rules")
    f.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="check a sealed rules file against the code")
    v.add_argument("path")
    ns = parser.parse_args(argv)

    if ns.cmd == "freeze":
        sealed = freeze_rules(ns.out)
        print(f"frozen   {ns.out}")
        print(f"sha256   {sealed['_sha256']}")
        print(f"at       {sealed['_frozen_at']}")
        print(f"commit   {sealed['_git_commit']}")
        print(f"rules    v{RULES_VERSION}, open-world reading: {RULES['open_world']}")
        return 0
    data = verify_rules(ns.path)
    print(f"ok  {ns.path}  sha256 {data['_sha256'][:16]}  "
          f"commit {data.get('_git_commit', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
