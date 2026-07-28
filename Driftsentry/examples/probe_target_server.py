"""Phase 3 fixture — a benign server rich enough to exercise the probe engine.

Four tools, each chosen to test a different part of Phase 3:

    lookup       deterministic  -> a near-zero variance band
    weather      naturally noisy -> a real variance band the detector must learn,
                                    or it will false-alarm on every check
    read_notes   touches a file  -> gives the sandbox monitor something to see
    send_email   side-effecting  -> must be classified and NOT probed

This is a benign fixture, not the Phase 7 adversarial testbed. Its only job is to
give baseline capture something realistic to measure.

IMPORTANT: `probe_target_variant.py` must keep every signature and docstring here
byte-identical, so both servers advertise the same tool definitions and therefore
the same definition hash. That is what makes the demo's point: identical hash,
different behaviour.
"""
from __future__ import annotations

import logging
import random
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # never stdout: it carries JSON-RPC
    format="%(asctime)s [probe-target] %(levelname)s %(message)s",
)

ROOT = Path(__file__).resolve().parent.parent
mcp = FastMCP("probe-target")


@mcp.tool()
def lookup(query: str) -> str:
    """Look up a term in the local reference index."""
    return f"Result for '{query}': entry found in section 4.2 of the handbook."


@mcp.tool()
def weather(city: str) -> str:
    """Report the current weather for a city."""
    # Deliberately different on every call. A real weather or search tool behaves
    # this way, and the detector has to learn that this is normal.
    temperature = random.randint(8, 24)
    condition = random.choice(["clear", "cloudy", "light rain", "overcast", "breezy"])
    humidity = random.randint(40, 90)
    return f"{city}: {temperature}C, {condition}, humidity {humidity}%."


@mcp.tool()
def read_notes(path: str) -> str:
    """Read a text file from the workspace."""
    target = (ROOT / path).resolve()
    # Stay inside the project: a probe must never wander the filesystem.
    if not str(target).startswith(str(ROOT)):
        return "Refused: path outside the workspace."
    if not target.is_file():
        return f"No file at {path}."
    return f"First 200 characters of {path}: {target.read_text(encoding='utf-8', errors='replace')[:200]}"


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    # Never actually sends anything — but its NAME and DESCRIPTION are what the
    # safety classifier reads, and it must refuse to probe this tool.
    return f"Queued message to {to} with subject {subject!r} ({len(body)} chars)."


if __name__ == "__main__":
    mcp.run()
