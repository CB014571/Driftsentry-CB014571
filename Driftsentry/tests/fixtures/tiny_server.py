"""A minimal stdio MCP server, for testing the real re-probe path.

Exists because every other test in this repo is unit level and constructs
ReprobeReport by hand. That cannot answer the question T22 turns on: does a
real server's tools/list, through the real SDK, carry outputSchema and
annotations into the dict the residue checker will read? If either is dropped
there is nothing for the permitted-change rules to key on, and no unit test
would notice.

Two things were measured here rather than assumed, and both change how the
differ has to be written:

1. A tool annotated `-> dict` reports `outputSchema: null`. FastMCP only
   emits an output schema when the return type is a model. So the rules
   table's "output field added or changed" row is only reachable against
   servers that declare structured output, and this fixture must use a model
   or it cannot exercise that row at all.

2. Unset annotation hints come back as explicit `null`, not as missing keys:
   `{"title": null, "readOnlyHint": true, "destructiveHint": null,
   "idempotentHint": null, "openWorldHint": false}`. So "absent" is None, and
   the differ's explicit-versus-defaulted test must treat None as not
   explicit. Taking `"destructiveHint" in annotations` as "explicitly set"
   would call every tool explicitly destructive.

Deliberately not the adversarial server: this one is honest, tiny and fast to
start, so it runs inside the test suite with no evaluation workspace, scenario
file or attacker process.

Two releases, chosen by DS_TINY_RELEASE, so the fixture also serves the
declared-diff work:

    v1  one output field; readOnlyHint true, openWorldHint false
    v2  one output field ADDED, and both hints widened - an update the
        definition hash cannot see, because the hash covers name, description
        and inputSchema only
"""
from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

RELEASE = os.environ.get("DS_TINY_RELEASE", "v1")

mcp = FastMCP("tiny")


class NoteV1(BaseModel):
    body: str


class NoteV2(BaseModel):
    body: str
    last_contact: str


if RELEASE == "v2":
    @mcp.tool(annotations={"readOnlyHint": False, "openWorldHint": True})
    def read_note(note_id: str) -> NoteV2:
        """Read a note."""
        return NoteV2(body=f"note {note_id}", last_contact="2026-01-01")
else:
    @mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
    def read_note(note_id: str) -> NoteV1:
        """Read a note."""
        return NoteV1(body=f"note {note_id}")


if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as exc:                                  # noqa: BLE001
        print(f"tiny_server failed: {exc}", file=sys.stderr)
        raise
