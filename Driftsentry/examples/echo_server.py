"""Phase 0 — minimal echo MCP server.

Exposes two trivial tools (`echo`, `reverse`) over the stdio transport. This is
the known-good server the rest of the project tests against: when the proxy,
probe engine, or scorer misbehave in a later phase, we point them here first to
rule out the server.

CRITICAL — the stdio rule
    The stdio transport carries JSON-RPC frames over *this process's stdout*.
    Anything else written to stdout (a stray print, a library banner) corrupts
    the stream and the client breaks silently. So every diagnostic goes to
    stderr. The roadmap calls this out as the bug that "bites everyone once";
    we enforce the discipline from the first file.

Run directly for a sanity check (it will wait for a client on stdin):
    python examples/echo_server.py
Normally it is launched as a subprocess by examples/echo_client.py.
"""
from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

# Route all logging to stderr — never stdout. See the module docstring.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [echo-server] %(levelname)s %(message)s",
)
log = logging.getLogger("echo-server")

mcp = FastMCP("echo")


@mcp.tool()
def echo(text: str) -> str:
    """Return the input text unchanged."""
    log.info("echo called (%d chars)", len(text))
    return text


@mcp.tool()
def reverse(text: str) -> str:
    """Return the input text reversed."""
    log.info("reverse called (%d chars)", len(text))
    return text[::-1]


if __name__ == "__main__":
    log.info("starting echo server on stdio")
    mcp.run()  # stdio transport by default
