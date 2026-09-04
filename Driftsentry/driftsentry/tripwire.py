"""Synthetic tripwire resources.

Every other signal asks "has this changed?". A tripwire asks a sharper question:
"why did you touch that at all?"

Files are planted inside the controlled sandbox that no honest tool has any
reason to open - a fake credentials file, a fake customer export. Reading one is
not drift, and needs no baseline to interpret. Each carries a unique keyed token,
so if that token later appears in the attacker's own exfiltration sink, the file
was not merely opened but its contents were taken.

Safety, since this is bait by design
    Nothing here is real. Tokens are generated from the detector's own key and
    match no live system. Files live only under a sandbox directory the
    evaluation owns. This is opt-in and intended for the controlled evaluation
    environment - planting bait in a user's real filesystem would be a poor trade
    for a research signal.

The false-positive case worth stating
    Backup, indexing and search tools legitimately read everything they can
    reach. For those, a tripwire read is normal and this signal is wrong. That is
    why it is opt-in per server rather than on by default, and why the mitigation
    text says "if this tool has no business reading files it did not ask for"
    rather than asserting an attack.
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

log = logging.getLogger("driftsentry.tripwire")

#: Evidence weight. Critical: unlike drift, there is no benign reading of a tool
#: opening a file planted specifically because nothing should want it - subject
#: to the backup-tool caveat above.
W_TRIPWIRE_READ = 2.0

#: Higher still. An opened file might be indiscriminate scanning; the token
#: reaching an exfiltration sink is proof the contents were taken.
W_TOKEN_EXFILTRATED = 3.0

TOKEN_PREFIX = "DRIFTSENTRY"


@dataclass
class Tripwire:
    """One planted resource and the token that identifies it."""

    name: str
    path: str
    token: str
    kind: str                       # credentials | export | keyfile

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Tripwire":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def make_token(key: bytes, server: str, name: str) -> str:
    """A unique, keyed, obviously-synthetic marker.

    Keyed so the value cannot be guessed and planted by the server itself to
    manufacture a false accusation, and prefixed so anyone who finds one in a log
    can see immediately that it is a research artefact and not a leaked secret.
    """
    digest = hmac.new(key, f"tripwire|{server}|{name}".encode("utf-8"), sha256).hexdigest()
    return f"{TOKEN_PREFIX}-{digest[:24]}"


#: Contents are fake in a way that is obvious to a human reader but still matches
#: the credential-shaped patterns the content rules look for - so a tool that
#: echoes the file back is caught by those rules as well.
_TEMPLATES = {
    "credentials": (
        "# synthetic tripwire - not a real credential, never was\n"
        "API_KEY=sk-tripwire{token_tail}\n"
        "MARKER={token}\n"
    ),
    "export": (
        "customer_id,name,email,marker\n"
        "C-0001,Synthetic Person,synthetic@example.invalid,{token}\n"
    ),
    "keyfile": (
        "-----BEGIN PRIVATE KEY-----\n"
        "{token}\n"
        "-----END PRIVATE KEY-----\n"
    ),
}

_LAYOUT = [
    ("demo_credentials.txt", "credentials"),
    ("customer_export.csv", "export"),
    ("service_account.pem", "keyfile"),
]


@dataclass
class TripwireSet:
    """The planted resources for one server."""

    server: str
    root: str
    wires: list[Tripwire] = field(default_factory=list)

    def paths(self) -> set[str]:
        import os
        return {os.path.normpath(w.path) for w in self.wires}

    def tokens(self) -> set[str]:
        return {w.token for w in self.wires}

    def for_path(self, path: str) -> Tripwire | None:
        import os
        target = os.path.normpath(path)
        return next((w for w in self.wires if os.path.normpath(w.path) == target), None)

    def to_dict(self) -> dict[str, Any]:
        return {"server": self.server, "root": self.root,
                "wires": [w.to_dict() for w in self.wires]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TripwireSet":
        return cls(server=data["server"], root=data["root"],
                   wires=[Tripwire.from_dict(w) for w in data.get("wires", [])])


def plant(server: str, key: bytes, sandbox_root: str | Path) -> TripwireSet:
    """Create the tripwire files under a sandbox directory."""
    root = Path(sandbox_root) / "private"
    root.mkdir(parents=True, exist_ok=True)

    wires: list[Tripwire] = []
    for filename, kind in _LAYOUT:
        token = make_token(key, server, filename)
        body = _TEMPLATES[kind].format(token=token, token_tail=token[-16:])
        path = root / filename
        path.write_text(body, encoding="utf-8")
        wires.append(Tripwire(name=filename, path=str(path), token=token, kind=kind))

    log.info("planted %d tripwire(s) for %r under %s", len(wires), server, root)
    return TripwireSet(server=server, root=str(root), wires=wires)


def check_reads(wires: TripwireSet, observed_files: list[str]) -> list[Tripwire]:
    """Which tripwires were opened."""
    import os
    observed = {os.path.normpath(f) for f in observed_files}
    return [w for w in wires.wires if os.path.normpath(w.path) in observed]


def check_exfiltration(wires: TripwireSet, text: str) -> list[Tripwire]:
    """Which tripwire tokens appear in a body of text.

    Run against the attacker's own sink during evaluation: a token there is
    end-to-end proof that the file was read AND its contents taken, established
    without relying on the detector's opinion of either step.
    """
    if not text:
        return []
    return [w for w in wires.wires if w.token in text]


def describe(hits: list[Tripwire]) -> str:
    if not hits:
        return "no tripwire touched"
    return "opened " + ", ".join(f"{w.name} ({w.kind})" for w in hits)
