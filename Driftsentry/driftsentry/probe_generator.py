"""Keyed dynamic probe generation.

The fixed generator draws from a pool of 32 hard-coded values. That pool is
enumerable by reading the source, and an attacker that recognises it can behave
honestly whenever it is being verified - which is exactly what the L4 attacker
does, and why it evades.

This module replaces the pool with a keyed function:

    HMAC-SHA256(key, "version|server|tool|template|cycle|field") -> RNG seed
                                                                 -> grammar
                                                                 -> value

Three properties follow, and they are the whole point:

Unpredictable
    Reading this file tells an attacker the *shape* of what will be sent, never
    the value. Without the key, next cycle's inputs cannot be computed.

Rotating
    ``cycle`` is in the HMAC message, so each verification round asks something
    it has never asked before. This matters more than secrecy: a value the server
    has already seen can always be recognised, whatever produced it, so the
    defence rests on never reusing one.

Reproducible
    The key is an input, not a surprise. Given the same key and cycle, an
    experiment replays exactly - which is what keeps the evaluation defensible
    while the attacker still cannot predict anything.

The family, not the value, is what stays stable
    ``template_id`` records which grammar fills which field ("path=filename"),
    and deliberately does not include the concrete value. That identifier is what
    a baseline is captured against, so behaviour learned at approval time remains
    comparable with a probe generated three hundred cycles later.
"""
from __future__ import annotations

import hmac
import random
from hashlib import sha256
from typing import TYPE_CHECKING, Any

from driftsentry import probe_templates
from driftsentry.probes import Probe

if TYPE_CHECKING:  # pragma: no cover
    from driftsentry.coverage import CoverageModel

#: Bumped when generation changes in a way that alters values for the same key.
#: Stored in the baseline, so a mismatch is a clear error instead of a silent
#: comparison between two different generators.
GENERATOR_VERSION = "kpg-v1"

#: Depth guard for pathological schemas.
MAX_DEPTH = 3


class UnsupportedSchema(ValueError):
    """The schema uses a construct this generator will not guess at.

    Raised rather than improvised. A probe built from a misunderstood schema is
    worse than no probe: the server rejects it, the rejection is recorded as the
    tool's normal behaviour, and the baseline is quietly worthless. Callers
    downgrade the tool to observation-only instead.
    """


class KeyedProbeGenerator:
    """Generates seeded, schema-valid, realistic probes from a secret key."""

    def __init__(
        self,
        key: bytes,
        *,
        cycle: int = 0,
        include_optional: bool = True,
        version: str = GENERATOR_VERSION,
        coverage: "CoverageModel | None" = None,
        shapes: dict[str, Any] | None = None,
    ) -> None:
        if not key:
            raise ValueError("a probe key is required")
        self.key = key
        self.cycle = cycle
        self.include_optional = include_optional
        self.version = version
        # When supplied, the category for each field is chosen by how little it
        # has been exercised rather than by the field's name hint - so a tool is
        # exposed to a spread of input classes over successive cycles instead of
        # many samples of one. Without it, behaviour is exactly as before.
        self.coverage = coverage
        # Per-tool argument shapes learned from genuine traffic (traffic.py
        # ToolShape: lengths, digit and space ratios). When supplied, string
        # values are chosen to look like what users actually send - RQ1 put
        # the argument family at AUC 0.763, enough on its own to take recall
        # to zero. Without it, behaviour is exactly as before.
        self.shapes = shapes or {}

    # -- key derivation -----------------------------------------------------
    def _rng(self, server: str, tool: str, template_id: str, cycle: int,
             field_path: str, index: int) -> random.Random:
        """Derive an independent RNG for one field of one probe.

        Per FIELD, not per probe: two fields of the same probe must not be
        correlated, or a server could infer one from the other and recover part
        of the generation state.
        """
        message = f"{self.version}|{server}|{tool}|{template_id}|{cycle}|{index}|{field_path}"
        digest = hmac.new(self.key, message.encode("utf-8"), sha256).digest()
        return random.Random(int.from_bytes(digest, "big"))

    # -- schema walking -----------------------------------------------------
    def _value(
        self,
        prop_name: str,
        schema: dict[str, Any],
        *,
        server: str,
        tool: str,
        template_id: str,
        cycle: int,
        index: int,
        field_path: str,
        grammars: dict[str, str],
        depth: int = 0,
    ) -> Any:
        if not isinstance(schema, dict):
            raise UnsupportedSchema(f"{field_path}: schema is not an object")

        rng = self._rng(server, tool, template_id, cycle, field_path, index)

        # Fixed values first - nothing to generate.
        if "const" in schema:
            return schema["const"]
        if isinstance(schema.get("enum"), list) and schema["enum"]:
            grammars[field_path] = "enum"
            return rng.choice(schema["enum"])

        # Composite schemas: take one branch. allOf is not a choice, so it is
        # refused rather than guessed at.
        if isinstance(schema.get("allOf"), list) and schema["allOf"]:
            raise UnsupportedSchema(f"{field_path}: allOf is not supported")
        for key in ("anyOf", "oneOf"):
            branches = schema.get(key)
            if isinstance(branches, list) and branches:
                usable = [b for b in branches
                          if isinstance(b, dict) and b.get("type") != "null"]
                if not usable:
                    raise UnsupportedSchema(f"{field_path}: no usable {key} branch")
                return self._value(
                    prop_name, rng.choice(usable), server=server, tool=tool,
                    template_id=template_id, cycle=cycle, index=index,
                    field_path=field_path, grammars=grammars, depth=depth,
                )
        if "$ref" in schema:
            raise UnsupportedSchema(f"{field_path}: $ref is not resolved")

        stype = schema.get("type")
        if isinstance(stype, list):
            stype = next((t for t in stype if t != "null"), None)

        if stype == "boolean":
            grammars[field_path] = "boolean"
            return rng.choice([True, False])

        if stype in {"integer", "number"}:
            low = schema.get("minimum", schema.get("exclusiveMinimum", 1))
            high = schema.get("maximum", schema.get("exclusiveMaximum", 100_000))
            try:
                low, high = float(low), float(high)
            except (TypeError, ValueError):
                low, high = 1.0, 100_000.0
            if high < low:
                low, high = high, low
            category = self._category(field_path, schema, rng)
            if category:
                grammars[field_path] = category
                return probe_templates.generate_numeric_category(
                    category, rng, low, high, integer=(stype == "integer")
                )
            grammars[field_path] = stype
            if stype == "integer":
                return rng.randint(int(low), int(high))
            return round(rng.uniform(low, high), 3)

        if stype == "array":
            items = schema.get("items")
            if not isinstance(items, dict):
                raise UnsupportedSchema(f"{field_path}: array without a single item schema")
            low = max(int(schema.get("minItems", 1)), 1)
            high = max(int(schema.get("maxItems", 2) or 2), low)
            count = rng.randint(low, min(high, 3))
            return [
                self._value(
                    prop_name, items, server=server, tool=tool,
                    template_id=template_id, cycle=cycle, index=index,
                    field_path=f"{field_path}[{i}]", grammars=grammars, depth=depth + 1,
                )
                for i in range(count)
            ]

        if stype == "object" or "properties" in schema:
            if depth >= MAX_DEPTH:
                raise UnsupportedSchema(f"{field_path}: nesting deeper than {MAX_DEPTH}")
            return self._object(
                schema, server=server, tool=tool, template_id=template_id,
                cycle=cycle, index=index, prefix=field_path, grammars=grammars,
                depth=depth + 1,
            )

        if stype == "null":
            return None

        if stype not in (None, "string"):
            raise UnsupportedSchema(f"{field_path}: unsupported type {stype!r}")

        # Strings, and anything untyped. Coverage picks the category when it is
        # driving; otherwise the field's name hint chooses the grammar.
        category = self._category(field_path, schema, rng)
        shape = self.shapes.get(tool)
        if category:
            grammars[field_path] = category
            value = probe_templates.generate_category(category, rng)
        elif shape is not None and getattr(shape, "lengths", None):
            grammar, value = shaped_string(
                probe_templates.grammar_for(prop_name, schema), shape, rng)
            grammars[field_path] = f"shaped:{grammar}"
        else:
            grammar = probe_templates.grammar_for(prop_name, schema)
            grammars[field_path] = grammar
            value = probe_templates.generate(grammar, rng)
        return _fit_length(str(value), schema, rng)

    def _category(
        self, field_path: str, schema: dict[str, Any], rng: random.Random
    ) -> str | None:
        """Ask the coverage model which input class to exercise next."""
        if self.coverage is None:
            return None
        return self.coverage.choose(field_path, schema, rng)

    def _object(
        self,
        schema: dict[str, Any],
        *,
        server: str,
        tool: str,
        template_id: str,
        cycle: int,
        index: int,
        prefix: str = "",
        grammars: dict[str, str],
        depth: int = 0,
    ) -> dict[str, Any]:
        properties = schema.get("properties") or {}
        required = list(schema.get("required") or [])
        args: dict[str, Any] = {}

        for name in required:
            if name not in properties:
                raise UnsupportedSchema(f"required property {name!r} has no schema")
            path = f"{prefix}.{name}" if prefix else name
            args[name] = self._value(
                name, properties[name], server=server, tool=tool,
                template_id=template_id, cycle=cycle, index=index,
                field_path=path, grammars=grammars, depth=depth,
            )

        if self.include_optional:
            for name in (n for n in properties if n not in required):
                path = f"{prefix}.{name}" if prefix else name
                rng = self._rng(server, tool, template_id, cycle, f"{path}?", index)
                if rng.random() < 0.5:
                    args[name] = self._value(
                        name, properties[name], server=server, tool=tool,
                        template_id=template_id, cycle=cycle, index=index,
                        field_path=path, grammars=grammars, depth=depth,
                    )
        return args

    # -- public API ---------------------------------------------------------
    def family_id(self, tool: dict[str, Any]) -> str:
        """The stable identity of a tool's probe family.

        Derived from the schema alone, so it is identical at approval time and at
        cycle 500 - which is what lets a baseline captured once remain comparable
        with values it has never seen.
        """
        schema = tool.get("inputSchema") or {}
        properties = schema.get("properties") or {}
        parts = [
            f"{name}={probe_templates.grammar_for(name, properties[name] or {})}"
            for name in sorted(properties)
        ]
        return ";".join(parts) or "no-args"

    def generate(
        self,
        server: str,
        tool: dict[str, Any],
        count: int = 3,
        *,
        cycle: int | None = None,
    ) -> list[Probe]:
        """Produce ``count`` probes for one tool at one verification cycle."""
        name = tool["name"]
        schema = tool.get("inputSchema") or {}
        template_id = self.family_id(tool)
        use_cycle = self.cycle if cycle is None else cycle

        probes: list[Probe] = []
        for index in range(count):
            grammars: dict[str, str] = {}
            args = self._object(
                schema, server=server, tool=name, template_id=template_id,
                cycle=use_cycle, index=index, grammars=grammars,
            )
            probes.append(
                Probe(
                    probe_id=f"{name}@c{use_cycle}#{index}",
                    tool=name,
                    args=args,
                    template_id=template_id,
                    seed=use_cycle,
                    index=index,
                    choices=dict(grammars),
                )
            )
        return probes


#: Grammars a shaped value may be drawn from besides the field's own. Real
#: users do not respect the name hint: the genuine corpus sends a person's name
#: as a customer_id and an order number as a search query.
SHAPE_ALTERNATES = ("identifier", "search", "person", "city", "filename", "generic")

#: Candidates generated per shaped value. Enough that one usually lands within
#: a character of the target length; all of them are keyed.
SHAPE_CANDIDATES = 24


def _ratio(text: str, pred) -> float:
    return (sum(1 for c in text if pred(c)) / len(text)) if text else 0.0


def _compact(value: str, target: int) -> str | None:
    """A shorter form of the same value, for a short target length.

    ``TASK-35622`` becomes ``T-3562`` and a phrase keeps its leading words.
    Shortening an existing keyed value keeps it harmless and unpredictable;
    inventing a new short format would be a second grammar to recognise.
    """
    if target <= 0:
        return None
    if "-" in value and value.split("-", 1)[1].isdigit():
        prefix, digits = value.split("-", 1)
        for k in range(len(prefix), 0, -1):
            room = target - k - 1
            if room >= 2:
                return f"{prefix[:k]}-{digits[:room]}"
        return None
    if " " in value:
        words, out = value.split(), ""
        for word in words:
            nxt = f"{out} {word}".strip()
            if len(nxt) > target:
                break
            out = nxt
        return out or None
    return None


#: English letter frequencies, so a filled skeleton's letters have roughly the
#: character entropy of real words rather than of uniform noise.
_LETTERS = "etaoinshrdlcumwfgypbvkjxqz"
_LETTER_WEIGHTS = (12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8,
                   2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.0, 0.8, 0.2, 0.2, 0.1, 0.1)

#: How far (in shaped_string's score) a template value may sit from the chosen
#: real pattern before the pattern itself is filled instead.
SKELETON_TOLERANCE = 1.0


def fill_skeleton(pattern: str, rng: random.Random) -> str:
    """A keyed value with exactly ``pattern``'s character classes."""
    out = []
    for ch in pattern:
        if ch == "9":
            out.append(str(rng.randrange(10)))
        elif ch in ("a", "A"):
            letter = rng.choices(_LETTERS, weights=_LETTER_WEIGHTS)[0]
            out.append(letter.upper() if ch == "A" else letter)
        else:
            out.append(ch)
    return "".join(out)


def _skeleton_string(own_grammar: str, pattern: str,
                     rng: random.Random) -> tuple[str, str]:
    """Match ONE real pattern (H2c): a template value if one is close, else fill it.

    A template value is preferred because it is a real word or a real-looking
    ID; when none comes within SKELETON_TOLERANCE of the pattern's length,
    digit, space and word counts, the pattern is filled with keyed characters.
    """
    target = len(pattern)
    digit_t = _ratio(pattern, lambda c: c == "9")
    space_t = _ratio(pattern, str.isspace)
    words_t = len(pattern.split())

    def score(v: str) -> float:
        return (abs(len(v) - target) + 4.0 * abs(_ratio(v, str.isdigit) - digit_t)
                + 4.0 * abs(_ratio(v, str.isspace) - space_t)
                + abs(len(v.split()) - words_t))

    best: tuple[str, str] | None = None
    for i in range(SHAPE_CANDIDATES):
        grammar = own_grammar if i % 2 == 0 else rng.choice(SHAPE_ALTERNATES)
        value = str(probe_templates.generate(grammar, rng))
        for v in (value, _compact(value, target)):
            if v is not None and (best is None or score(v) < score(best[1])):
                best = (grammar, v)
    if best is not None and score(best[1]) <= SKELETON_TOLERANCE:
        return best
    return "skeleton", fill_skeleton(pattern, rng)


def shaped_string(own_grammar: str, shape: Any, rng: random.Random) -> tuple[str, str]:
    """A keyed string whose length and character mix follow genuine traffic.

    The target length is drawn from the observed lengths (not a range), then
    the candidate closest to it in length, digit ratio and space ratio wins.
    Every candidate comes from a template grammar, so values stay as harmless
    as unshaped ones. An empty string is a candidate only when real traffic
    sent one - which the genuine corpus does.
    """
    patterns = list(getattr(shape, "skeletons", []) or [])
    if patterns:
        return _skeleton_string(own_grammar, patterns[rng.randrange(len(patterns))], rng)
    lengths = list(getattr(shape, "lengths", []) or [])
    target = lengths[rng.randrange(len(lengths))]
    digit_t = float(getattr(shape, "digit_ratio", 0.0) or 0.0)
    space_t = float(getattr(shape, "space_ratio", 0.0) or 0.0)

    candidates: list[tuple[str, str]] = []
    if target == 0:
        candidates.append(("empty", ""))
    for i in range(SHAPE_CANDIDATES):
        grammar = own_grammar if i % 2 == 0 else rng.choice(SHAPE_ALTERNATES)
        value = str(probe_templates.generate(grammar, rng))
        candidates.append((grammar, value))
        short = _compact(value, target)
        if short:
            candidates.append((grammar, short))

    def score(item: tuple[str, str]) -> float:
        _, v = item
        return (abs(len(v) - target)
                + 4.0 * abs(_ratio(v, str.isdigit) - digit_t)
                + 4.0 * abs(_ratio(v, str.isspace) - space_t))

    return min(candidates, key=score)


def _fit_length(value: str, schema: dict[str, Any], rng: random.Random) -> str:
    """Respect minLength / maxLength without turning the value into noise."""
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and len(value) < min_len:
        # Pad with more of the same kind of text rather than filler characters,
        # so a length constraint cannot itself become a recognisable tell.
        while len(value) < min_len:
            value = f"{value} {probe_templates.gen_search_phrase(rng)}"
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and len(value) > max_len:
        value = value[:max_len].rstrip()
    return value
