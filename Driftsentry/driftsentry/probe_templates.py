"""Realistic, safe probe grammars.

A probe that is unpredictable can still be obvious. ``probe_918273`` is a
different value every cycle and announces itself as a test in every one of them,
which defeats the point: a server that can classify a request as "verification
traffic" from its shape alone does not need to predict the exact value.

So values are generated from grammars that produce what ordinary tool use looks
like - a document name someone would really open, a phrase someone would really
search for, an identifier in the shape a business system would really issue.

Safety is not traded away for realism
    * emails use the reserved ``.invalid`` TLD (RFC 2606), which cannot resolve
    * URLs point only at loopback on the discard port
    * paths are relative, and stay inside the sandbox
    * nothing generated here can reach an external system

Every generator takes an already-seeded ``random.Random``. None of them owns
randomness, so the caller controls reproducibility completely.
"""
from __future__ import annotations

import random
from typing import Any, Callable

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #
_TOPICS = (
    "security-review", "meeting-notes", "project-status", "quarterly-report",
    "onboarding-guide", "release-notes", "incident-summary", "budget-forecast",
    "team-handbook", "vendor-assessment", "risk-register", "audit-findings",
    "design-proposal", "sprint-retrospective", "capacity-plan", "policy-draft",
)
_MONTHS = ("january", "february", "march", "april", "may", "june", "july",
           "august", "september", "october", "november", "december")
_DOC_EXT = ("md", "txt", "pdf", "docx", "rtf")
_FOLDERS = ("docs", "notes", "reports", "reference", "archive", "shared", "policies")

_SEARCH_HEADS = (
    "quarterly", "annual", "internal", "draft", "final", "updated", "monthly",
    "preliminary", "revised", "approved",
)
_SEARCH_SUBJECTS = (
    "security review", "project documentation", "software testing notes",
    "budget summary", "vendor contract", "incident report", "training material",
    "release checklist", "compliance evidence", "meeting minutes",
    "risk assessment", "onboarding checklist", "support escalation",
)

_ID_PREFIXES = ("CUS", "TASK", "ORD", "REF", "TCK", "INV", "ACC", "PRJ")

_FIRST_NAMES = ("alex", "sam", "jordan", "riley", "casey", "morgan", "avery",
                "quinn", "harper", "rowan", "devon", "kelsey")
_LAST_NAMES = ("reid", "morgan", "hayes", "patel", "silva", "novak", "keller",
               "bennett", "ellis", "fraser", "okafor", "lindqvist")

# Low-cardinality fields are the weak case for keyed generation, and this list
# is the clearest example of it.
#
# An attacker cannot predict which document name will be requested next, because
# document names are effectively unbounded. It CAN enumerate cities, because
# there are only so many - so for a field like this the defence is not secrecy
# but dilution, and even then it is partial. Detection on enum-like fields has to
# lean on the other signals rather than on probe unpredictability.
#
# The four cities the fixed pool used (London, Colombo, Lisbon, Reykjavik) are
# deliberately absent: they were transmitted to the server on every verification
# for the lifetime of the old generator, so they must be treated as known to it.
# Reusing an already-burned value would hand back exactly what rotation buys.
_CITIES = (
    "Toronto", "Dublin", "Helsinki", "Valencia", "Auckland", "Ljubljana",
    "Tallinn", "Bergen", "Porto", "Kraków", "Nagoya", "Adelaide",
    "Bilbao", "Utrecht", "Gothenburg", "Bratislava", "Cork", "Malmö",
    "Antwerp", "Turku", "Graz", "Aarhus", "Bologna", "Leeds",
)

# Loopback only, on the discard port. Nothing here can leave the machine.
_LOOPBACK_HOSTS = ("127.0.0.1:9", "localhost:9")
_URL_PATHS = ("status", "health", "index", "reference", "summary")


# --------------------------------------------------------------------------- #
# Generators
# --------------------------------------------------------------------------- #
def gen_filename(rng: random.Random) -> str:
    """A document name a person would plausibly have on disk."""
    topic = rng.choice(_TOPICS)
    ext = rng.choice(_DOC_EXT)
    style = rng.randrange(4)
    if style == 0:
        return f"{topic}.{ext}"
    if style == 1:
        return f"{topic}-{rng.choice(_MONTHS)}.{ext}"
    if style == 2:
        return f"{topic}-{rng.randrange(2019, 2027)}.{ext}"
    return f"{rng.choice(_FOLDERS)}/{topic}.{ext}"


def gen_search_phrase(rng: random.Random) -> str:
    """A phrase someone would really type into a search tool."""
    subject = rng.choice(_SEARCH_SUBJECTS)
    style = rng.randrange(3)
    if style == 0:
        return subject
    if style == 1:
        return f"{rng.choice(_SEARCH_HEADS)} {subject}"
    return f"{subject} {rng.choice(_MONTHS)}"


def gen_identifier(rng: random.Random) -> str:
    """A business-system identifier: PREFIX-NNNNN."""
    return f"{rng.choice(_ID_PREFIXES)}-{rng.randrange(10_000, 99_999)}"


def gen_email(rng: random.Random) -> str:
    """An address on a reserved, non-resolvable domain."""
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    style = rng.randrange(3)
    if style == 0:
        local = f"{first}.{last}"
    elif style == 1:
        local = f"{first[0]}{last}"
    else:
        local = f"{first}.{last[0]}"
    # .invalid is reserved by RFC 2606 and can never resolve.
    return f"{local}@example.invalid"


def gen_url(rng: random.Random) -> str:
    """A loopback URL on the discard port."""
    return f"http://{rng.choice(_LOOPBACK_HOSTS)}/{rng.choice(_URL_PATHS)}"


def gen_person(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST_NAMES).title()} {rng.choice(_LAST_NAMES).title()}"


def gen_city(rng: random.Random) -> str:
    return rng.choice(_CITIES)


def gen_text(rng: random.Random) -> str:
    """A short, ordinary sentence."""
    subject = rng.choice(_SEARCH_SUBJECTS)
    openings = (
        f"Please summarise the {subject}.",
        f"Could you check the {subject} for {rng.choice(_MONTHS)}?",
        f"The {subject} has been updated.",
        f"Sharing the {subject} ahead of the review.",
        f"No changes to the {subject} this week.",
    )
    return rng.choice(openings)


def gen_generic(rng: random.Random) -> str:
    """Fallback for fields with no name hint - still ordinary-looking."""
    return rng.choice((
        rng.choice(_SEARCH_SUBJECTS),
        rng.choice(_TOPICS).replace("-", " "),
        gen_identifier(rng),
    ))


#: Named grammars, addressable by the family baseline.
GRAMMARS: dict[str, Callable[[random.Random], Any]] = {
    "filename": gen_filename,
    "search": gen_search_phrase,
    "identifier": gen_identifier,
    "email": gen_email,
    "url": gen_url,
    "person": gen_person,
    "city": gen_city,
    "text": gen_text,
    "generic": gen_generic,
}

# Property-name hints -> grammar. Ordered: the first hit wins, so more specific
# hints must come first ("filepath" before "path", "email" before "name").
NAME_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("email", "mail", "recipient", "sender", "cc", "bcc"), "email"),
    (("url", "uri", "endpoint", "link", "href", "webhook"), "url"),
    (("path", "file", "filename", "filepath", "document", "doc", "attachment"), "filename"),
    (("query", "search", "term", "keyword", "q", "filter"), "search"),
    (("id", "identifier", "ref", "reference", "code", "account", "ticket", "order"), "identifier"),
    (("city", "location", "place", "region", "country", "town"), "city"),
    (("name", "user", "username", "author", "owner", "assignee", "customer"), "person"),
    (("text", "message", "content", "body", "prompt", "note", "comment", "description"), "text"),
]

FORMAT_HINTS = {
    "email": "email",
    "uri": "url",
    "url": "url",
    "hostname": "url",
    "path": "filename",
    "date": "generic",
}


# --------------------------------------------------------------------------- #
# Coverage categories
# --------------------------------------------------------------------------- #
# Words a targeted attacker waits for. These generate file NAMES and phrases that
# mention credentials - never credentials themselves. The point is to enter the
# branch of a conditional rug pull, not to hand it anything.
_SENSITIVE_SUBJECTS = (
    "credentials-review", "api-key-rotation", "customer-export",
    "password-policy", "access-token-audit", "secret-rotation-plan",
    "account-export", "key-management-notes",
)


def gen_sensitive_lookalike(rng: random.Random) -> str:
    """A safe value that *looks* like something worth attacking.

    The `conditional` attack family only fires when it sees an email address, or
    the words key / token / secret / password. A detector whose probes never
    contain those shapes cannot exercise that branch, so the attack is missed by
    construction rather than by evasion. Everything here is a synthetic name.
    """
    subject = rng.choice(_SENSITIVE_SUBJECTS)
    style = rng.randrange(4)
    if style == 0:
        return f"{subject}.md"
    if style == 1:
        return f"{rng.choice(_FOLDERS)}/{subject}.txt"
    if style == 2:
        return f"{subject.replace('-', ' ')} {rng.choice(_MONTHS)}"
    return f"{subject.replace('-', ' ')}"


def gen_short_string(rng: random.Random) -> str:
    return rng.choice(_TOPICS).split("-")[0]


def gen_long_string(rng: random.Random) -> str:
    parts = [gen_search_phrase(rng) for _ in range(rng.randint(4, 7))]
    return ". ".join(parts) + "."


def gen_safe_path(rng: random.Random) -> str:
    """Always relative, always inside the sandbox. Never absolute, never '..'."""
    depth = rng.randint(1, 2)
    folders = [rng.choice(_FOLDERS) for _ in range(depth)]
    return "/".join(folders) + "/" + gen_filename(rng).split("/")[-1]


#: Category -> generator. Categories are what the coverage model rotates through;
#: grammars are what a field name hints at. They overlap but are not the same.
CATEGORY_GENERATORS: dict[str, Callable[[random.Random], Any]] = {
    "natural_language": gen_text,
    "filename": gen_filename,
    "safe_path": gen_safe_path,
    "identifier": gen_identifier,
    "email": gen_email,
    "url": gen_url,
    "short_string": gen_short_string,
    "long_string": gen_long_string,
    "sensitive_lookalike": gen_sensitive_lookalike,
}


def generate_category(category: str, rng: random.Random) -> Any:
    return CATEGORY_GENERATORS.get(category, gen_generic)(rng)


def generate_numeric_category(
    category: str, rng: random.Random, low: float, high: float, integer: bool
) -> Any:
    """Draw a number from one region of the allowed range.

    Boundary values are included because off-by-one and range-check branches are
    where conditional logic often lives - but they are the declared minimum and
    maximum, never values outside the schema.
    """
    span = high - low
    if category == "boundary_min":
        value = low
    elif category == "boundary_max":
        value = high
    elif category == "typical_low":
        value = low + span * rng.uniform(0.05, 0.25)
    elif category == "typical_high":
        value = low + span * rng.uniform(0.75, 0.95)
    else:                                          # typical_mid
        value = low + span * rng.uniform(0.35, 0.65)
    return int(round(value)) if integer else round(value, 3)


def grammar_for(prop_name: str, schema: dict[str, Any]) -> str:
    """Choose a grammar for one schema property.

    Schema ``format`` is consulted first because it is declared intent; the
    property name is a heuristic and only used when format says nothing.
    """
    fmt = str(schema.get("format", "")).lower()
    if fmt in FORMAT_HINTS:
        return FORMAT_HINTS[fmt]

    lowered = prop_name.lower()
    for hints, grammar in NAME_HINTS:
        for hint in hints:
            if lowered == hint or hint in lowered:
                return grammar
    return "generic"


def generate(grammar: str, rng: random.Random) -> Any:
    return GRAMMARS.get(grammar, gen_generic)(rng)
