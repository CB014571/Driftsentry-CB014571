"""What the real host calls itself, so probes can say the same thing.

RQ3 measured the cost of not doing this. Probe sessions opened
``ClientSession(read, write)`` with no ``client_info``, so the MCP SDK sent
its default name - "mcp", which appears in no real host. Genuine traffic
announced "claude-ai". A classifier separated the two at AUC 1.000, perfectly,
on that field alone, and an attacker using it took detection from 100% to 0%.

The countermeasure is not subtle and does not need to be: probe sessions
announce the identity the real client announced. The proxy is the only
component that ever sees a genuine handshake, so it records what it saw, and
the probe engine reads it back.

What is recorded, and what is not
    Name, version, and the working directory the real server was given.
    Nothing else. The handshake also carries capabilities, and the process
    environment is right there - neither is recorded, because this file is
    written on every proxied session and environment values routinely hold
    API keys.

This closes one channel. It does nothing for the session or timing families,
which RQ3 found at 1.000 and 0.817; those are T18's problem.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.hostprofile")

#: The SDK's default, and the thing that must never be sent by a probe once a
#: real identity is known. Kept here so the test can assert against it.
SDK_DEFAULT_NAME = "mcp"


def profile_dir() -> Path:
    path = data_dir() / "hostprofile"
    path.mkdir(parents=True, exist_ok=True)
    return path


def profile_path(server: str) -> Path:
    return profile_dir() / f"{server}.json"


def record(server: str, client: dict[str, Any] | None, cwd: str | None = None) -> None:
    """Remember how the real client identified itself.

    Called by the proxy on the initialize handshake. Never raises: a failure
    to record must not affect the session being proxied.
    """
    if not client or not client.get("name"):
        return
    if client.get("name") == SDK_DEFAULT_NAME:
        # Another DriftSentry probe, or something else using the SDK default.
        # Recording it would teach the detector to imitate itself.
        log.debug("not recording the SDK default client name as a host profile")
        return
    try:
        payload = {
            "name": client.get("name"),
            "version": client.get("version") or "unknown",
            "cwd": cwd,
        }
        profile_path(server).write_text(json.dumps(payload, indent=2),
                                        encoding="utf-8")
    except Exception as exc:  # pragma: no cover - never break the proxy
        log.debug("could not record host profile for %s: %s", server, exc)


def load(server: str) -> dict[str, Any] | None:
    """The recorded identity for this server, or None if never seen."""
    path = profile_path(server)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if data.get("name") else None


def implementation(server: str) -> Any | None:
    """An mcp Implementation to open a probe session with, or None.

    None means no genuine handshake has been observed for this server, and
    the caller should fall back rather than invent a name. Inventing one
    would be worse than the SDK default: a name that matches no real host and
    no other probe is a fingerprint of its own.
    """
    profile = load(server)
    if profile is None:
        return None
    from mcp import types

    return types.Implementation(name=profile["name"],
                                version=profile.get("version") or "unknown")
