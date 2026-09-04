"""Coverage-guided probe selection.

Keyed probes stop an attacker predicting *what* will be sent. They do nothing
about an attacker that only misbehaves for a particular *kind* of input:

    if looks_like_a_credentials_file(path):
        exfiltrate()
    else:
        behave()

Random values drawn from one grammar may never enter that branch. The
`conditional` family in the adversarial server works exactly this way - it checks
its arguments against a pattern and stays quiet on anything uninteresting - so a
detector that always sends the same *category* of value can miss it however
unpredictable the individual values are.

The fix is coverage, not volume. Each schema field admits a handful of input
categories; the generator tracks which have been exercised and prefers the ones
it has used least. Over a few verification cycles the tool is exposed to a
spread of input classes rather than many samples of one.

Deliberately not a fuzzer
    No mutation engine, no crash oracle, no attempt at exhaustive search. Only
    enough breadth to make conditional logic likely to fire, at a handful of
    probes per cycle. Categories are also capped per cycle so that broadening
    coverage does not itself become a source of novel-but-benign responses.

Everything generated stays inert: the "sensitive-looking" category produces
*names that mention* credentials, never credentials.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Categories
# --------------------------------------------------------------------------- #
#: Input classes for string fields. `sensitive_lookalike` exists specifically to
#: exercise conditional rug-pull logic: it produces safe, synthetic filenames and
#: phrases that *mention* credentials, keys or exports - the shape of input a
#: targeted attacker waits for. No real secret is ever generated.
STRING_CATEGORIES = (
    "natural_language",
    "filename",
    "safe_path",
    "identifier",
    "email",
    "url",
    "short_string",
    "long_string",
    "sensitive_lookalike",
)

NUMERIC_CATEGORIES = ("typical_low", "typical_mid", "typical_high",
                      "boundary_min", "boundary_max")

#: Categories only make sense where the schema allows them. A field constrained
#: to 8 characters cannot hold an email address, and generating one would produce
#: an invalid probe rather than better coverage.
_MIN_LENGTH_FOR = {
    "email": 18, "url": 22, "safe_path": 12, "filename": 8,
    "sensitive_lookalike": 14, "long_string": 40, "natural_language": 12,
}


@dataclass
class FieldCoverage:
    """How often each category has been used for one schema field."""

    field_path: str
    kind: str                                   # string | numeric | other
    counts: dict[str, int] = field(default_factory=dict)
    applicable: list[str] = field(default_factory=list)

    def record(self, category: str) -> None:
        self.counts[category] = self.counts.get(category, 0) + 1

    def least_used(self, rng: random.Random) -> str:
        """Pick an under-tested category, breaking ties with the seeded RNG.

        Ties are broken randomly rather than by declaration order so an attacker
        cannot predict the rotation from the source alone - the category sequence
        is as keyed as the values themselves.
        """
        if not self.applicable:
            return "natural_language"
        lowest = min(self.counts.get(c, 0) for c in self.applicable)
        candidates = [c for c in self.applicable if self.counts.get(c, 0) == lowest]
        return rng.choice(sorted(candidates))

    def ratio(self) -> float:
        """Fraction of applicable categories exercised at least once."""
        if not self.applicable:
            return 1.0
        seen = sum(1 for c in self.applicable if self.counts.get(c, 0) > 0)
        return seen / len(self.applicable)

    def to_dict(self) -> dict[str, Any]:
        return {"field_path": self.field_path, "kind": self.kind,
                "counts": dict(self.counts), "applicable": list(self.applicable)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FieldCoverage":
        return cls(field_path=data["field_path"], kind=data.get("kind", "string"),
                   counts=dict(data.get("counts", {})),
                   applicable=list(data.get("applicable", [])))


def applicable_categories(schema: dict[str, Any]) -> tuple[str, list[str]]:
    """Which categories a field can legally hold, given its schema."""
    if not isinstance(schema, dict):
        return "other", []

    if isinstance(schema.get("enum"), list) or "const" in schema:
        return "other", []                       # nothing to vary

    stype = schema.get("type")
    if isinstance(stype, list):
        stype = next((t for t in stype if t != "null"), None)

    if stype in {"integer", "number"}:
        return "numeric", list(NUMERIC_CATEGORIES)
    if stype == "boolean":
        return "other", []
    if stype not in (None, "string"):
        return "other", []

    max_len = schema.get("maxLength")
    min_len = schema.get("minLength")
    usable = []
    for category in STRING_CATEGORIES:
        need = _MIN_LENGTH_FOR.get(category, 4)
        if isinstance(max_len, int) and max_len < need:
            continue
        if category == "short_string" and isinstance(min_len, int) and min_len > 8:
            continue
        usable.append(category)
    return "string", usable or ["natural_language"]


@dataclass
class CoverageModel:
    """Per-tool record of which input categories have been exercised."""

    tool: str
    fields: dict[str, FieldCoverage] = field(default_factory=dict)
    #: Categories introduced per cycle. Capped, because broadening coverage is
    #: itself a source of never-before-seen (but benign) responses, and a cycle
    #: that changed every field at once would be hard to attribute.
    max_new_per_cycle: int = 2

    def ensure(self, field_path: str, schema: dict[str, Any]) -> FieldCoverage:
        entry = self.fields.get(field_path)
        if entry is None:
            kind, applicable = applicable_categories(schema)
            entry = FieldCoverage(field_path=field_path, kind=kind, applicable=applicable)
            self.fields[field_path] = entry
        return entry

    def choose(self, field_path: str, schema: dict[str, Any],
               rng: random.Random, *, record: bool = True) -> str | None:
        """Category to use next for this field, or None if it does not vary.

        Records the choice by default. Separating "pick" from "count it" reads as
        tidier but is a trap: two picks made before either is recorded both see
        the same zero counts, both choose the same under-tested category, and
        coverage silently stops rotating - which is the one thing this class
        exists to do.
        """
        entry = self.ensure(field_path, schema)
        if not entry.applicable:
            return None
        category = entry.least_used(rng)
        if record:
            entry.record(category)
        return category

    def record(self, field_path: str, category: str | None) -> None:
        if category and field_path in self.fields:
            self.fields[field_path].record(category)

    def coverage_ratio(self) -> float:
        if not self.fields:
            return 1.0
        varying = [f for f in self.fields.values() if f.applicable]
        if not varying:
            return 1.0
        return sum(f.ratio() for f in varying) / len(varying)

    def untested(self) -> dict[str, list[str]]:
        """Categories never yet exercised, per field. Reported in experiments."""
        out: dict[str, list[str]] = {}
        for path, entry in self.fields.items():
            missing = [c for c in entry.applicable if entry.counts.get(c, 0) == 0]
            if missing:
                out[path] = missing
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool,
                "max_new_per_cycle": self.max_new_per_cycle,
                "fields": {k: v.to_dict() for k, v in self.fields.items()}}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageModel":
        return cls(
            tool=data["tool"],
            max_new_per_cycle=data.get("max_new_per_cycle", 2),
            fields={k: FieldCoverage.from_dict(v)
                    for k, v in (data.get("fields") or {}).items()},
        )

    def describe(self) -> str:
        return (f"{self.tool}: {self.coverage_ratio():.0%} of input categories "
                f"exercised across {len(self.fields)} field(s)")
