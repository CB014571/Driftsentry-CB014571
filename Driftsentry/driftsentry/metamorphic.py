"""Differential paired probing: catching a server that treats inputs differently.

A probe-aware server decides, per call, whether it is being watched. That
decision is the weakness. Send two inputs that any honest tool must treat the
same way, and if the server's *security-relevant* behaviour differs between them,
it is conditioning on something no honest implementation conditions on.

    x        ->  behaviour A
    T(x)     ->  behaviour B        A != B  =>  input-conditional behaviour

The transforms are chosen so the relation genuinely holds. Reordering the keys of
a JSON object cannot change what a tool does, because JSON object order carries
no meaning - so any difference is evidence, not noise.

What is compared, and what is not
    Never the response content. Two different search phrases legitimately return
    different results, so comparing text would produce constant false alarms.
    Only invariants: which hosts were contacted, which files opened, which
    security rules fired, the response's shape class, and whether it errored.

Where this works, and where it does not - state both
    Strong against a lookup-table recogniser, which is what a realistic attacker
    has: reordering tokens or changing case moves an input across the boundary of
    a fixed table, so one member of the pair is recognised and the other is not.

    Worth nothing against a perfect recogniser that catches both members. Then
    consistency stays zero and this signal is silent. It raises the cost of
    evasion; it does not close it.
"""
from __future__ import annotations

import random
import re
from dataclasses import asdict, dataclass, field
from typing import Any

#: Evidence weight when two equivalent inputs produce different security
#: behaviour. High: no honest tool has a reason to do this, and it is the only
#: signal that points specifically at input-conditional evasion rather than at
#: misbehaviour in general.
W_CONSISTENCY = 1.8

#: Invariants compared between the pair, and how much each disagreement counts.
_INVARIANT_WEIGHTS = {
    "hosts": 1.0,
    "files": 0.9,
    "processes": 1.0,
    "security_flags": 1.0,
    "shape": 0.5,
    "error": 0.4,
}


@dataclass
class Transform:
    """One semantics-preserving rewrite."""

    name: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


#: Ordered strongest-first. "Strongest" means the relation is hardest to argue
#: with: key order is meaningless in JSON, so MR1 admits no innocent explanation
#: at all, whereas a path alias assumes the tool normalises paths.
TRANSFORMS = [
    Transform("field_order", "object keys reordered - JSON key order is semantically void"),
    Transform("token_order", "words in a phrase reordered - a search tool must not care"),
    Transform("case", "case changed - lookup and search tools normalise case"),
    Transform("whitespace", "surrounding whitespace added - tools strip their input"),
    Transform("path_alias", "equivalent path spelling - same sandbox target"),
]

_WORD = re.compile(r"\S+")


def applicable(args: dict[str, Any]) -> list[Transform]:
    """Which transforms genuinely preserve meaning for these arguments."""
    usable: list[Transform] = []
    if len(args) >= 2:
        usable.append(TRANSFORMS[0])
    for value in args.values():
        if not isinstance(value, str):
            continue
        if len(_WORD.findall(value)) >= 3:
            usable.append(TRANSFORMS[1])
        if value != value.upper() and value != value.lower():
            usable.append(TRANSFORMS[2])
        usable.append(TRANSFORMS[3])
        if "/" in value and not value.startswith("./"):
            usable.append(TRANSFORMS[4])
    # Preserve declaration order (strongest first) while de-duplicating.
    seen, out = set(), []
    for t in usable:
        if t.name not in seen:
            seen.add(t.name)
            out.append(t)
    return out


def transform(args: dict[str, Any], rng: random.Random) -> tuple[dict[str, Any], Transform | None]:
    """Produce ``T(x)`` - superficially different, semantically identical."""
    options = applicable(args)
    if not options:
        return dict(args), None

    # Prefer the strongest applicable relation, but not always: a server that
    # learned to expect one transform could special-case it.
    chosen = options[0] if rng.random() < 0.6 else rng.choice(options)
    out = dict(args)

    if chosen.name == "field_order":
        keys = list(out)
        rng.shuffle(keys)
        out = {k: out[k] for k in keys}
        return out, chosen

    targets = [k for k, v in out.items() if isinstance(v, str)]
    if not targets:
        return out, None
    key = rng.choice(sorted(targets))
    value = out[key]

    if chosen.name == "token_order":
        words = value.split()
        if len(words) >= 3:
            rng.shuffle(words)
            out[key] = " ".join(words)
    elif chosen.name == "case":
        out[key] = value.upper() if value.islower() else value.lower()
    elif chosen.name == "whitespace":
        out[key] = f" {value} "
    elif chosen.name == "path_alias":
        out[key] = f"./{value}" if not value.startswith("./") else value[2:]
    return out, chosen


@dataclass
class ConsistencyResult:
    """How differently the server treated two equivalent inputs."""

    score: float                       # 0-1, weighted disagreement
    transform: str = ""
    divergences: list[str] = field(default_factory=list)

    @property
    def fired(self) -> bool:
        return self.score > 0.0

    def evidence_units(self) -> float:
        return round(self.score * W_CONSISTENCY, 4)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "evidence_units": self.evidence_units()}


def _observation(samples) -> dict[str, Any]:
    """Reduce a set of samples to the invariants worth comparing."""
    return {
        "hosts": {h for s in samples for h in s.hosts},
        "files": {f for s in samples for f in s.files},
        "processes": set(),
        "security_flags": {f for s in samples for f in s.content_flags},
        "shape": {s.normalized.shape_hash for s in samples},
        "error": any(s.normalized.is_error for s in samples),
    }


def consistency(samples_x, samples_tx, *, transform_name: str = "") -> ConsistencyResult:
    """Compare the security behaviour of ``x`` and ``T(x)``.

    Only *security-relevant* divergence counts. Different content is expected
    and ignored; a host contacted for one input and not the other is not.
    """
    if not samples_x or not samples_tx:
        return ConsistencyResult(0.0, transform_name)

    a, b = _observation(samples_x), _observation(samples_tx)
    divergences: list[str] = []
    total = 0.0

    for key in ("hosts", "files", "processes", "security_flags"):
        only_a, only_b = a[key] - b[key], b[key] - a[key]
        if only_a or only_b:
            total += _INVARIANT_WEIGHTS[key]
            detail = ", ".join(sorted(only_a | only_b)[:3])
            divergences.append(f"{key} differ between equivalent inputs: {detail}")

    if a["shape"] != b["shape"]:
        total += _INVARIANT_WEIGHTS["shape"]
        divergences.append("response shape class differs between equivalent inputs")

    if a["error"] != b["error"]:
        total += _INVARIANT_WEIGHTS["error"]
        divergences.append("one equivalent input errored and the other did not")

    ceiling = sum(_INVARIANT_WEIGHTS.values())
    return ConsistencyResult(
        score=round(min(1.0, total / ceiling) if ceiling else 0.0, 4),
        transform=transform_name,
        divergences=divergences,
    )
