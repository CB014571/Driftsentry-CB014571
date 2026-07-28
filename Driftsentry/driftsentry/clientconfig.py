"""Phase 2 — MCP client config ingestion and rewriting.

The onboarding step: the user hands DriftSentry the config their MCP client
already uses (Claude Desktop, Cursor, VS Code), and DriftSentry returns a
rewritten config in which every supported server is launched *through the proxy*
instead of directly. Afterwards the launch chain is:

    client  ->  driftsentry run  ->  the real server

This is exactly how mcp-scan's proxy mode wires itself in, and it is only the
*setup* step — the detection value comes from the proxy staying resident and
re-probing (Phases 3+).

Config shapes handled
    Clients keep a JSON object mapping a server name to its launch details, under
    either an ``mcpServers`` key (Claude Desktop, Cursor) or ``servers`` (VS Code):

        {"mcpServers": {"shop": {"command": "python", "args": ["shop_server.py"]}}}

    Per entry, ``command`` means a stdio server (we can proxy it) and ``url``
    means a remote HTTP server (deferred — see below).

Deliberate limits
    * **stdio only.** Phase 1 implemented the stdio proxy, matching the roadmap's
      "implement stdio first" and the real MCPoison CVE, which targeted a
      stdio-launched config. HTTP entries are reported and left untouched rather
      than silently half-handled.
    * **Strict JSON.** Some clients tolerate comments (JSONC); we do not parse
      those, and say so rather than guessing.
"""
from __future__ import annotations

import difflib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

# Keys under which known MCP clients list their servers.
_SERVER_KEYS = ("mcpServers", "servers")

Transport = Literal["stdio", "http", "unknown"]
Action = Literal["wrapped", "already-wrapped", "skipped-http", "skipped-unknown", "skipped-filtered"]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
@dataclass
class ServerEntry:
    """One server as it appears in a client config."""

    name: str
    raw: dict[str, Any]
    transport: Transport
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    wrapped: bool = False


@dataclass
class ParsedConfig:
    """A client config plus the location of its server map."""

    data: dict[str, Any]
    servers_key: str
    servers: dict[str, ServerEntry]


def _classify(entry: dict[str, Any]) -> Transport:
    if entry.get("command"):
        return "stdio"
    if entry.get("url"):
        return "http"
    return "unknown"


def is_wrapped(entry: dict[str, Any]) -> bool:
    """True if this entry already launches DriftSentry's proxy.

    Makes ``init`` idempotent: re-running it must never wrap DriftSentry inside
    another DriftSentry, which would double the latency and corrupt the audit log.
    """
    args = [str(a) for a in (entry.get("args") or [])]
    command = str(entry.get("command") or "")
    names_driftsentry = "driftsentry" in Path(command).name.lower() or "driftsentry" in args
    return names_driftsentry and "run" in args and "--exec" in args


def parse_config(path: Path) -> ParsedConfig:
    """Read and validate a client config file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path} is not valid JSON ({exc}). Configs with comments (JSONC) are not supported."
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level.")

    servers_key = next((k for k in _SERVER_KEYS if isinstance(data.get(k), dict)), None)
    if servers_key is None:
        raise ValueError(
            f"{path}: no server map found. Expected one of {_SERVER_KEYS} holding an object."
        )

    servers: dict[str, ServerEntry] = {}
    for name, raw in data[servers_key].items():
        if not isinstance(raw, dict):
            continue
        servers[name] = ServerEntry(
            name=name,
            raw=raw,
            transport=_classify(raw),
            command=raw.get("command"),
            args=[str(a) for a in (raw.get("args") or [])],
            env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
            cwd=raw.get("cwd"),
            url=raw.get("url"),
            wrapped=is_wrapped(raw),
        )
    return ParsedConfig(data=data, servers_key=servers_key, servers=servers)


# --------------------------------------------------------------------------- #
# Rewriting
# --------------------------------------------------------------------------- #
def default_launcher() -> tuple[str, list[str]]:
    """How to invoke DriftSentry from a config, as (command, leading args).

    Prefers the installed console script by *absolute path*, because the MCP
    client that launches it may not share our PATH. Falls back to
    ``<python> -m driftsentry``, which always works inside the project venv.
    """
    scripts_dir = Path(sys.executable).parent
    for candidate in ("driftsentry.exe", "driftsentry"):
        path = scripts_dir / candidate
        if path.exists():
            return str(path), []
    return sys.executable, ["-m", "driftsentry"]


def wrap_entry(name: str, entry: dict[str, Any], launcher: tuple[str, list[str]]) -> dict[str, Any]:
    """Build the replacement entry that routes ``name`` through the proxy.

    Security note on secrets: the original ``env`` block is preserved on the new
    entry, so the client still sets those variables on the DriftSentry process,
    and we pass only the *names* via ``--forward-env`` for the proxy to hand down
    to the real server. Secret values therefore never appear in the command line,
    where any user on the machine could read them from the process list.
    """
    command, prefix = launcher
    args: list[str] = [*prefix, "run", "--server", name]

    if entry.get("cwd"):
        args += ["--cwd", str(entry["cwd"])]
    for key in sorted((entry.get("env") or {})):
        args += ["--forward-env", str(key)]

    # --exec must come last: it consumes the remainder as the real launch command.
    args += ["--exec", str(entry["command"]), *[str(a) for a in (entry.get("args") or [])]]

    wrapped: dict[str, Any] = {"command": command, "args": args}
    if entry.get("env"):
        wrapped["env"] = dict(entry["env"])
    return wrapped


def unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Recover the original server entry from a DriftSentry-wrapped one.

    Used by ``restore --unwrap`` when the backup file has been lost, and to keep
    ``init`` idempotent.
    """
    args = [str(a) for a in (entry.get("args") or [])]
    if "--exec" not in args:
        raise ValueError("entry is not DriftSentry-wrapped (no --exec found)")
    exec_tokens = args[args.index("--exec") + 1:]
    if not exec_tokens:
        raise ValueError("wrapped entry has an empty --exec command")

    original: dict[str, Any] = {"command": exec_tokens[0]}
    if exec_tokens[1:]:
        original["args"] = exec_tokens[1:]
    if "--cwd" in args:
        original["cwd"] = args[args.index("--cwd") + 1]
    if entry.get("env"):
        original["env"] = dict(entry["env"])
    return original


@dataclass
class RewriteReport:
    """What ``init`` did to each server, for printing and for the caller."""

    actions: dict[str, Action] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)

    @property
    def wrapped_servers(self) -> list[str]:
        return [n for n, a in self.actions.items() if a == "wrapped"]

    def summary_lines(self) -> list[str]:
        symbol = {
            "wrapped": "+",
            "already-wrapped": "=",
            "skipped-http": "!",
            "skipped-unknown": "!",
            "skipped-filtered": "-",
        }
        out = []
        for name, action in self.actions.items():
            note = self.notes.get(name, "")
            out.append(f"  {symbol.get(action, '?')} {name}: {action}{(' - ' + note) if note else ''}")
        return out


def rewrite_config(
    parsed: ParsedConfig,
    launcher: tuple[str, list[str]] | None = None,
    only: list[str] | None = None,
) -> tuple[dict[str, Any], RewriteReport]:
    """Return a new config object with supported servers routed through the proxy.

    The input is not mutated: we deep-copy via JSON so the caller can diff the
    before and after safely.
    """
    launcher = launcher or default_launcher()
    new_data = json.loads(json.dumps(parsed.data))  # deep copy
    servers_out = new_data[parsed.servers_key]
    report = RewriteReport()

    for name, entry in parsed.servers.items():
        if only and name not in only:
            report.actions[name] = "skipped-filtered"
            continue
        if entry.wrapped:
            report.actions[name] = "already-wrapped"
            report.notes[name] = "already routed through DriftSentry"
            continue
        if entry.transport == "http":
            report.actions[name] = "skipped-http"
            report.notes[name] = "HTTP transport not proxied yet (stdio first)"
            continue
        if entry.transport != "stdio":
            report.actions[name] = "skipped-unknown"
            report.notes[name] = "no 'command' or 'url' field; cannot classify"
            continue

        servers_out[name] = wrap_entry(name, entry.raw, launcher)
        report.actions[name] = "wrapped"

    return new_data, report


# --------------------------------------------------------------------------- #
# Diff + backup helpers
# --------------------------------------------------------------------------- #
def diff_text(before: dict[str, Any], after: dict[str, Any], label: str = "config") -> str:
    """A short unified diff so the user sees exactly what changed."""
    b = json.dumps(before, indent=2, sort_keys=True).splitlines()
    a = json.dumps(after, indent=2, sort_keys=True).splitlines()
    return "\n".join(
        difflib.unified_diff(b, a, fromfile=f"{label} (before)", tofile=f"{label} (after)", lineterm="")
    )


def make_backup(path: Path) -> Path:
    """Copy ``path`` beside itself with a timestamped backup suffix."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.driftsentry-backup-{stamp}")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backup


def find_backups(path: Path) -> list[Path]:
    """All backups for ``path``, newest first."""
    return sorted(
        path.parent.glob(f"{path.name}.driftsentry-backup-*"),
        key=lambda p: p.name,
        reverse=True,
    )


def write_config(path: Path, data: dict[str, Any]) -> None:
    """Write a config object as pretty JSON with a trailing newline."""
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
