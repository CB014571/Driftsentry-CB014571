"""Field-level response comparison, and learning which fields are noise.

A whole-response embedding is a blunt instrument for the change that matters
most:

    "account": "382910"   ->   "382911"

One digit. The sentence means the same thing, the embedding barely moves, and a
detector that only looks at the whole response can miss a payment being
redirected. The `silent-tamper` family is built on exactly this.

So structured responses are also compared field by field, with the comparison
chosen by what the field *is*. An account number is compared for equality,
because any change to it is total. A prose summary is compared for similarity,
because rewording it is normal.

Volatile fields are learned, not guessed
    Sensitivity is worthless if it costs false alarms, and the obvious way to
    lose is timestamps: a field that legitimately differs on every single call
    would fire this signal forever. During baseline sampling any field that
    varies across repeated samples of the SAME probe is marked volatile and
    masked before comparison. Learned from the tool's own behaviour rather than
    from a list of field names, so it works for fields nobody anticipated.

    This half is not optional. Field-level drift shipped without volatile
    masking would raise the false-alarm rate enough to force thresholds up,
    which costs recall - the exact trade this module exists to avoid.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

VOLATILE = "<VOLATILE>"

# --------------------------------------------------------------------------- #
# Field typing
# --------------------------------------------------------------------------- #
_URL = re.compile(r"^\s*[a-z][a-z0-9+.-]*://", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_IDENTIFIER = re.compile(r"^[A-Z]{2,6}-\d{3,}$|^[0-9a-f]{16,}$", re.I)
_MONEY = re.compile(r"^\s*(?:[$£€]|[A-Z]{3}\s)\s*-?\d[\d,]*(?:\.\d{1,2})?\s*$")
_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|\.{1,2}[\\/])?(?:[\w.\-]+[\\/])+[\w.\-]+$")
_HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_STATUS = re.compile(
    r"^(ok|success|succeeded|failed|failure|error|pending|active|inactive|"
    r"granted|denied|allowed|blocked|true|false|enabled|disabled)$", re.I)
_NUMERIC = re.compile(r"^-?\d[\d,]*(?:\.\d+)?$")

#: How much a change to each kind of field counts. Security-relevant identity -
#: where the money goes, which host, which account - is weighted at the top;
#: prose is weighted low because rewording it is what benign updates do.
TYPE_WEIGHTS: dict[str, float] = {
    "url": 1.0,
    "email": 1.0,
    "account": 1.0,
    "identifier": 1.0,
    "hostname": 1.0,
    "path": 0.95,
    "money": 1.0,
    "status": 0.9,
    "instruction": 1.0,
    "number": 0.6,
    "boolean": 0.7,
    "text": 0.3,
}

#: Field names that name a security-relevant value whatever it looks like.
_NAME_TYPES: list[tuple[tuple[str, ...], str]] = [
    (("account", "iban", "sort_code", "card"), "account"),
    (("amount", "total", "price", "balance", "cost", "fee"), "money"),
    (("email", "recipient", "sender", "mailto"), "email"),
    (("url", "uri", "endpoint", "callback", "webhook", "link"), "url"),
    (("host", "hostname", "server", "domain"), "hostname"),
    (("path", "file", "filename", "directory"), "path"),
    (("status", "state", "permission", "role", "access"), "status"),
    (("id", "identifier", "reference", "ref"), "identifier"),
]


def classify(name: str, value: Any) -> str:
    """Decide what kind of thing a field holds, from its name and its value."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if not isinstance(value, str):
        return "text"

    leaf = name.rsplit(".", 1)[-1].lower()
    for hints, kind in _NAME_TYPES:
        if any(hint == leaf or hint in leaf for hint in hints):
            # The name says what it is; confirm with the value where it is cheap.
            if kind == "money" and not (_MONEY.match(value) or _NUMERIC.match(value)):
                break
            return kind

    text = value.strip()
    if _URL.match(text):
        return "url"
    if _EMAIL.match(text):
        return "email"
    if _MONEY.match(text):
        return "money"
    if _IDENTIFIER.match(text):
        return "identifier"
    if _STATUS.match(text):
        return "status"
    if _HOSTNAME.match(text):
        return "hostname"
    if _PATH.match(text) and len(text) < 200:
        return "path"
    if _NUMERIC.match(text):
        return "number"
    return "text"


# --------------------------------------------------------------------------- #
# Flattening
# --------------------------------------------------------------------------- #
def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a JSON value to ``path -> leaf``.

    List indices are collapsed to ``[]`` so that returning three results instead
    of two is not read as every field having changed - the same choice the
    structural signature makes.
    """
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key in sorted(obj):
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(obj[key], child))
    elif isinstance(obj, list):
        for item in obj:
            for path, value in flatten(item, f"{prefix}[]").items():
                out.setdefault(path, value)
    else:
        out[prefix or "value"] = obj
    return out


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #
@dataclass
class FieldProfile:
    """What one field looked like at baseline."""

    path: str
    kind: str
    volatile: bool = False
    values: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FieldProfile":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def learn_profiles(samples: list[dict[str, Any]]) -> dict[str, FieldProfile]:
    """Build field profiles from repeated samples of ONE probe.

    Volatility is decided here and only here. Repeated samples of the same probe
    should differ in nothing but genuinely volatile content, so a field that
    varies across them is noise by definition - no allow-list of field names
    required, and fields nobody thought of are handled correctly.
    """
    if not samples:
        return {}

    flattened = [flatten(s) for s in samples]
    paths = set().union(*(set(f) for f in flattened))

    profiles: dict[str, FieldProfile] = {}
    for path in sorted(paths):
        seen = [f.get(path) for f in flattened]
        present = [v for v in seen if v is not None]
        if not present:
            continue
        rendered = sorted({_render(v) for v in present})
        profiles[path] = FieldProfile(
            path=path,
            kind=classify(path, present[0]),
            # Absent from some samples counts as volatile too: a field that comes
            # and goes cannot be compared for equality.
            volatile=len(rendered) > 1 or len(present) != len(seen),
            values=rendered[:5],
        )
    return profiles


def _render(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
@dataclass
class FieldChange:
    path: str
    kind: str
    before: str
    after: str
    magnitude: float          # 0-1, how much it moved
    weight: float             # how much that kind of field matters
    score: float              # magnitude * weight

    def describe(self) -> str:
        return f"{self.path} ({self.kind}): {self.before!r} -> {self.after!r}"


def _magnitude(kind: str, before: str, after: str) -> float:
    """How far a field moved, on its own terms."""
    if before == after:
        return 0.0

    if kind in {"number", "money"}:
        try:
            a = float(re.sub(r"[^\d.\-]", "", before) or 0)
            b = float(re.sub(r"[^\d.\-]", "", after) or 0)
        except ValueError:
            return 1.0
        if a == b:
            return 0.0
        scale = max(abs(a), abs(b), 1.0)
        # Any change to a monetary value is meaningful, so the relative delta is
        # floored: a one-penny redirect must not score as nothing.
        return max(0.25, min(1.0, abs(a - b) / scale))

    if kind == "text":
        # Prose is compared for similarity, because rewording it is exactly what
        # a benign update does.
        return 1.0 - difflib.SequenceMatcher(None, before, after).ratio()

    # Identity-bearing fields are all-or-nothing: an account number that changed
    # by one digit is a different account.
    return 1.0


def compare(
    profiles: dict[str, FieldProfile],
    observed: dict[str, Any],
) -> tuple[float, list[FieldChange]]:
    """Compare an observed response against learned field profiles.

    Returns ``(field_drift_score, changes)``. The score is the worst single
    weighted change, not a sum: several fields moving together is usually one
    edit, and summing would let a chatty benign response out-score a redirected
    payment.
    """
    if not profiles:
        return 0.0, []

    flat = flatten(observed)
    changes: list[FieldChange] = []

    for path, profile in profiles.items():
        if profile.volatile:
            continue                      # learned noise - masked
        if path not in flat:
            continue                      # absence is a structural signal, not this one
        after = _render(flat[path])
        before = profile.values[0] if profile.values else ""
        if after == before:
            continue
        magnitude = _magnitude(profile.kind, before, after)
        if magnitude <= 0.0:
            continue
        weight = TYPE_WEIGHTS.get(profile.kind, 0.5)
        changes.append(FieldChange(
            path=path, kind=profile.kind, before=before, after=after,
            magnitude=round(magnitude, 4), weight=weight,
            score=round(magnitude * weight, 4),
        ))

    changes.sort(key=lambda c: c.score, reverse=True)
    return (changes[0].score if changes else 0.0), changes


def mask_volatile(obj: Any, profiles: dict[str, FieldProfile]) -> dict[str, Any]:
    """Replace learned-volatile leaves with a placeholder.

    Used before structural and semantic comparison so a timestamp cannot look
    like tampering.
    """
    volatile = {p for p, prof in profiles.items() if prof.volatile}
    flat = flatten(obj)
    return {path: (VOLATILE if path in volatile else value)
            for path, value in flat.items()}
