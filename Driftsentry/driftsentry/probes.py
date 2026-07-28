"""Phase 3 — the canary probe engine.

Generates benign, valid inputs for a tool from its declared JSON Schema, so we
can exercise it at approval time and again on every scheduled re-check. Two
concerns dominate this module, and both are things an examiner will press on.

1. Reproducible but not memorisable
    Probe values are drawn from parameterised template pools using a recorded
    seed. Same seed, same probes — so any run in the evaluation can be replayed
    exactly. Change the seed and the probes change, which is what stops an
    attacker from memorising one fixed set of inputs and behaving well only for
    those. Phase 9's Experiment 4 measures precisely this: how much randomising
    the templates recovers against a probe-aware (L4/L5) attacker.

2. Probe safety
    Some tools have real side effects: send-email, delete-file, place-order. We
    must not fire canaries at them. Each tool is classified before it is probed:

      * The MCP spec's own tool annotations come first — ``readOnlyHint`` and
        ``destructiveHint`` are the principled signal when a server supplies them.
      * Otherwise a keyword heuristic over the name and description decides.
      * Anything classified side-effecting is marked *baseline-by-observation*:
        it is never probed, and the proxy's log of real calls is the only
        evidence we have about it.

    Two honest limitations. (a) The heuristic can misclassify an unusually-named
    tool; ``--safety-policy strict`` narrows probing to tools that are explicitly
    annotated read-only or use a clearly-safe verb. (b) Annotations are part of
    the tool *definition*, which is attacker-controlled — a malicious server can
    claim ``readOnlyHint: true``. That only ever influences whether we probe it,
    never whether we trust the response, but it is a real limit and belongs in
    the threats-to-validity section.

All generated values are inert: local decoy URLs, repository-relative read-only
paths, and `.invalid` email addresses. Probes never touch a real external system.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Literal

Safety = Literal["safe", "side-effecting"]
SafetyPolicy = Literal["default", "strict"]

# Verbs that imply a tool changes state somewhere. Matched against name + description.
_DESTRUCTIVE = (
    "send", "email", "mail", "sms", "notify", "delete", "remove", "drop", "purge",
    "write", "create", "update", "insert", "upsert", "modify", "edit", "rename",
    "post", "put", "patch", "upload", "publish", "deploy", "install", "uninstall",
    "pay", "order", "purchase", "checkout", "charge", "refund", "transfer",
    "execute", "exec", "run", "shell", "command", "spawn", "kill", "shutdown",
    "reset", "revoke", "grant", "provision", "terminate", "archive",
)

# Verbs that reliably imply read-only behaviour.
_SAFE = (
    "get", "list", "read", "search", "query", "find", "fetch", "lookup", "show",
    "describe", "status", "info", "echo", "ping", "count", "summar", "weather",
    "view", "inspect", "check", "resolve", "translate", "reverse",
)

_WORD_RE = re.compile(r"[a-z]+")


def _match_verb(verbs: tuple[str, ...], words: set[str]) -> str | None:
    """Find the first verb that matches a whole word (allowing inflections).

    Matching must respect word boundaries. A naive substring test over the joined
    name and description is badly wrong here: ``"put"`` occurs inside ``"input"``,
    so every tool documented as "returns the input text" would be misclassified as
    state-changing and silently denied a behavioural baseline. Prefix-matching
    whole words still catches "sends", "deleting" and "created" while leaving
    "input", "border" and "output" alone.
    """
    for verb in verbs:
        for word in words:
            if word == verb or word.startswith(verb):
                return verb
    return None


# --------------------------------------------------------------------------- #
# Safety classification
# --------------------------------------------------------------------------- #
def classify_tool_safety(tool: dict[str, Any], policy: SafetyPolicy = "default") -> tuple[Safety, str]:
    """Decide whether a tool may be actively probed, and say why."""
    annotations = tool.get("annotations") or {}
    if annotations.get("destructiveHint") is True:
        return "side-effecting", "annotation: destructiveHint=true"
    if annotations.get("readOnlyHint") is True:
        return "safe", "annotation: readOnlyHint=true"

    haystack = f"{tool.get('name', '')} {tool.get('description', '') or ''}".lower()
    words = set(_WORD_RE.findall(haystack))

    hit = _match_verb(_DESTRUCTIVE, words)
    if hit:
        return "side-effecting", f"name/description suggests state change ({hit!r})"

    safe_hit = _match_verb(_SAFE, words)
    if safe_hit:
        return "safe", f"read-only verb ({safe_hit!r})"

    if policy == "strict":
        # Fail safe: without positive evidence of read-only behaviour, observe only.
        return "side-effecting", "strict policy: no read-only annotation or verb"
    return "safe", "no state-changing signal found (default policy)"


# --------------------------------------------------------------------------- #
# Value templates
# --------------------------------------------------------------------------- #
# Inert values only. URLs point at a closed local decoy port; paths are
# repository-relative and read-only; addresses use the reserved .invalid TLD.
_TEMPLATES: dict[str, list[Any]] = {
    "path": ["README.md", "requirements.txt", "pyproject.toml", "docs/index.md", "data/sample.txt"],
    "query": ["hello world", "quarterly report", "opening hours", "unit test", "blue widget"],
    "text": [
        "The quick brown fox jumps over the lazy dog.",
        "Please summarise the attached document.",
        "Meeting moved to Tuesday at ten.",
        "All systems nominal.",
    ],
    "url": ["http://127.0.0.1:9/decoy", "http://localhost:9/probe", "http://127.0.0.1:9/health"],
    "email": ["probe@example.invalid", "canary@test.invalid", "sentinel@example.invalid"],
    "city": ["London", "Colombo", "Reykjavik", "Lisbon"],
    "name": ["Alex Doe", "Sam Patel", "Jordan Silva"],
    "generic": ["alpha", "bravo", "charlie", "delta", "echo-probe"],
}

# Property-name hints -> template pool.
_NAME_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("path", "file", "filename", "filepath", "dir", "directory", "document"), "path"),
    (("query", "search", "term", "keyword", "q"), "query"),
    (("url", "uri", "endpoint", "link", "href", "host"), "url"),
    (("email", "mail", "recipient", "sender", "to", "cc"), "email"),
    (("city", "location", "place", "region", "country"), "city"),
    (("name", "user", "username", "author", "owner"), "name"),
    (("text", "message", "content", "body", "prompt", "input", "note", "comment"), "text"),
]

_FORMAT_HINTS = {"email": "email", "uri": "url", "url": "url", "hostname": "url", "path": "path"}


def _pool_for(prop_name: str, schema: dict[str, Any]) -> str:
    fmt = str(schema.get("format", "")).lower()
    if fmt in _FORMAT_HINTS:
        return _FORMAT_HINTS[fmt]
    lowered = prop_name.lower()
    for hints, pool in _NAME_HINTS:
        if any(h == lowered or h in lowered for h in hints):
            return pool
    return "generic"


# --------------------------------------------------------------------------- #
# Probe generation
# --------------------------------------------------------------------------- #
@dataclass
class Probe:
    """One reproducible canary: arguments plus the recipe that produced them."""

    probe_id: str
    tool: str
    args: dict[str, Any]
    template_id: str
    seed: int
    index: int
    choices: dict[str, str] = field(default_factory=dict)


class ProbeGenerator:
    """Generates seeded, schema-valid, benign probes for a tool."""

    def __init__(self, seed: int = 20260720, *, include_optional: bool = True) -> None:
        self.seed = seed
        self.include_optional = include_optional

    def _rng(self, server: str, tool: str, index: int) -> random.Random:
        rng = random.Random()
        # str seeding is hashed with SHA-512 (version=2), so this is stable across
        # processes and platforms — unlike hash(), which is randomised per run.
        rng.seed(f"{self.seed}:{server}:{tool}:{index}", version=2)
        return rng

    # -- value generation ---------------------------------------------------
    def _value(
        self,
        prop_name: str,
        schema: dict[str, Any],
        rng: random.Random,
        choices: dict[str, str],
        depth: int = 0,
    ) -> Any:
        if not isinstance(schema, dict):
            return rng.choice(_TEMPLATES["generic"])

        # Composite schemas: take a branch, then generate from it.
        for key in ("anyOf", "oneOf", "allOf"):
            if isinstance(schema.get(key), list) and schema[key]:
                branch = schema[key][0] if key == "allOf" else rng.choice(schema[key])
                return self._value(prop_name, branch, rng, choices, depth)

        if "const" in schema:
            return schema["const"]
        if isinstance(schema.get("enum"), list) and schema["enum"]:
            value = rng.choice(schema["enum"])
            choices[prop_name] = f"enum#{schema['enum'].index(value)}"
            return value
        if "default" in schema and rng.random() < 0.3:
            choices[prop_name] = "default"
            return schema["default"]

        stype = schema.get("type")
        if isinstance(stype, list):  # e.g. ["string", "null"]
            stype = next((t for t in stype if t != "null"), "string")

        if stype == "boolean":
            value = rng.choice([True, False])
            choices[prop_name] = f"bool#{int(value)}"
            return value

        if stype in {"integer", "number"}:
            low = schema.get("minimum", schema.get("exclusiveMinimum", 1))
            high = schema.get("maximum", schema.get("exclusiveMaximum", 100))
            try:
                low, high = float(low), float(high)
            except (TypeError, ValueError):
                low, high = 1.0, 100.0
            if high < low:
                low, high = high, low
            value = rng.randint(int(low), int(high)) if stype == "integer" else round(rng.uniform(low, high), 3)
            choices[prop_name] = f"{stype}#{value}"
            return value

        if stype == "array":
            items = schema.get("items") or {"type": "string"}
            n = max(int(schema.get("minItems", 1)), 1)
            n = min(n, int(schema.get("maxItems", 2)) or 2, 2)
            return [self._value(prop_name, items, rng, choices, depth + 1) for _ in range(n)]

        if stype == "object" or "properties" in schema:
            if depth >= 3:  # guard against pathological nesting
                return {}
            return self._object(schema, rng, choices, depth + 1)

        if stype == "null":
            return None

        # Strings (and anything untyped) come from a template pool.
        pool = _pool_for(prop_name, schema)
        options = _TEMPLATES[pool]
        idx = rng.randrange(len(options))
        value = options[idx]
        choices[prop_name] = f"{pool}#{idx}"

        min_len = schema.get("minLength")
        if isinstance(min_len, int) and len(value) < min_len:
            value = (value * (min_len // max(len(value), 1) + 1))[:min_len]
        max_len = schema.get("maxLength")
        if isinstance(max_len, int) and len(value) > max_len:
            value = value[:max_len]
        return value

    def _object(
        self,
        schema: dict[str, Any],
        rng: random.Random,
        choices: dict[str, str],
        depth: int = 0,
    ) -> dict[str, Any]:
        properties = schema.get("properties") or {}
        required = list(schema.get("required") or [])
        args: dict[str, Any] = {}

        for name in required:
            if name in properties:
                args[name] = self._value(name, properties[name], rng, choices, depth)

        if self.include_optional:
            optional = [n for n in properties if n not in required]
            for name in optional:
                # Include roughly half the optional fields, seeded — so probes
                # exercise more of the surface without always sending everything.
                if rng.random() < 0.5:
                    args[name] = self._value(name, properties[name], rng, choices, depth)
        return args

    # -- public API ---------------------------------------------------------
    def generate(self, server: str, tool: dict[str, Any], count: int = 3) -> list[Probe]:
        """Produce ``count`` reproducible probes for one tool definition."""
        name = tool["name"]
        schema = tool.get("inputSchema") or {}
        probes: list[Probe] = []

        for index in range(count):
            rng = self._rng(server, name, index)
            choices: dict[str, str] = {}
            args = self._object(schema, rng, choices)
            template_id = ";".join(f"{k}={v}" for k, v in sorted(choices.items())) or "no-args"
            probes.append(
                Probe(
                    probe_id=f"{name}#{index}",
                    tool=name,
                    args=args,
                    template_id=template_id,
                    seed=self.seed,
                    index=index,
                    choices=choices,
                )
            )
        return probes
