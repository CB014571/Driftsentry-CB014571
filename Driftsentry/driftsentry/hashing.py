"""Canonical hashing of MCP tool definitions.

A *classic* rug pull changes a tool's advertised definition — its name,
description, or input schema. Pinning a hash of that definition catches exactly
that case, and it is also the control condition ("hash-only pinning") the Phase 9
evaluation measures the behavioural layer against.

The hash must be canonical: two servers advertising the same tools in a different
order, or with differently-ordered JSON keys, must produce the *same* hash, or we
would flag harmless noise. We therefore sort tools by name and serialise with
sorted keys.

This is deliberately the *only* thing hashing catches. A behavioural rug pull
leaves the definition — and therefore this hash — unchanged; that is the whole
reason DriftSentry exists, and why Phases 3–4 add behavioural signals on top.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _tool_identity(tool: dict[str, Any]) -> dict[str, Any]:
    """Extract only the fields that make up a tool's advertised *definition*.

    Runtime/annotation extras that some servers attach are ignored so the hash
    reflects the contract the client sees, not incidental metadata.
    """
    return {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }


def tools_definition_hash(tools: list[dict[str, Any]]) -> str:
    """Return a stable ``sha256:...`` hash over a list of tool definitions."""
    identities = sorted(
        (_tool_identity(t) for t in tools),
        key=lambda t: (t["name"] or ""),
    )
    canonical = json.dumps(identities, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
