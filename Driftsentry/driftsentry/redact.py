"""Remove a probe's own arguments from its response before embedding.

The problem this solves is the main cost of dynamic probes.

Many tools echo their input:

    return f"Document {path.strip()}: {body}"
    return f"{city.strip()}: {temperature}C, {condition}, humidity {humidity}%."

So sending a different value produces a different response *by construction*,
with no attack involved. Compare a fresh probe against a baseline captured from
other values and the echoed argument dominates the distance - the detector ends
up measuring its own probe generator rather than the tool.

Redaction removes that term. Both of these:

    "Document security-review-2026.md: No document filed under 'security-review-2026.md'."
    "Document notes/capacity-plan.rtf: No document filed under 'notes/capacity-plan.rtf'."

become:

    "Document <ARG:path>: No document filed under '<ARG:path>'."

which are directly comparable. What survives is the part the tool contributed,
which is the part worth watching.

What it deliberately does not do
    It does not normalise anything else. Numbers, dates and generated content
    stay exactly as they are, because those are the tool's own output and a
    change in them is precisely what the detector exists to notice.
"""
from __future__ import annotations

import re
from typing import Any

#: Placeholder written in place of an argument value.
PLACEHOLDER = "<ARG:{name}>"

#: Values shorter than this are not redacted. A one- or two-character argument
#: would match all over an unrelated response and destroy far more signal than
#: the echo it removes.
MIN_VALUE_CHARS = 4


def _candidates(name: str, value: Any) -> list[str]:
    """Surface forms of one argument that might appear in a response.

    Tools routinely tidy their input before echoing it - `.strip()` is almost
    universal, `.upper()` common for identifiers - so the literal argument is not
    always what comes back.
    """
    if not isinstance(value, str):
        if isinstance(value, bool) or value is None:
            return []
        value = str(value)

    stripped = value.strip()
    if len(stripped) < MIN_VALUE_CHARS:
        return []

    forms = {stripped, value, stripped.upper(), stripped.lower()}
    # A path is often echoed by its final component alone.
    if "/" in stripped or "\\" in stripped:
        tail = re.split(r"[\\/]", stripped)[-1]
        if len(tail) >= MIN_VALUE_CHARS:
            forms.add(tail)
    return [f for f in forms if len(f) >= MIN_VALUE_CHARS]


def _walk(prefix: str, value: Any, out: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _walk(f"{prefix}.{key}" if prefix else str(key), item, out)
    elif isinstance(value, list):
        for item in value:
            _walk(prefix, item, out)
    else:
        for form in _candidates(prefix, value):
            out.append((prefix, form))


def redact(text: str, args: dict[str, Any]) -> str:
    """Replace every occurrence of an argument value with its placeholder."""
    if not text or not args:
        return text

    pairs: list[tuple[str, str]] = []
    _walk("", args, pairs)
    if not pairs:
        return text

    # Longest form first. Substituting a short value that is a substring of a
    # longer one would corrupt the longer match before it is reached - replacing
    # "notes" inside "notes/capacity-plan.rtf" would leave a mangled tail that
    # then fails to match anything.
    pairs.sort(key=lambda pair: len(pair[1]), reverse=True)

    redacted = text
    for name, form in pairs:
        if form in redacted:
            redacted = redacted.replace(form, PLACEHOLDER.format(name=name or "arg"))
    return redacted


def redact_all(text: str, args: dict[str, Any] | None) -> str:
    """Convenience wrapper tolerating a missing argument set."""
    return redact(text, args or {})


def echo_ratio(text: str, args: dict[str, Any]) -> float:
    """How much of a response is just its own input echoed back, 0-1.

    Recorded per family at baseline. A high value means the tool's answer is
    dominated by its input, so cross-input comparison would be measuring the
    probe generator; the family baseline uses this to decide how far to trust
    the embedding signal for that tool.
    """
    if not text:
        return 0.0
    removed = len(text) - len(redact(text, args))
    # The placeholder is longer than some values it replaces, so the difference
    # can go negative; clamp rather than report a nonsensical ratio.
    return max(0.0, min(1.0, removed / len(text)))
