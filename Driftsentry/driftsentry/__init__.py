"""DriftSentry — a proxy-based detector for behavioural rug-pull attacks in the
Model Context Protocol.

DriftSentry sits between an MCP client and an MCP server as a resident proxy. At
approval time it captures a *behavioural* baseline of each tool (not just a hash
of its definition) and then re-verifies on a schedule, so it can detect rug pulls
that leave the tool definition byte-for-byte unchanged — the class of attack that
hash-only scanners (mcp-scan, Snyk Agent Scan) miss.

Package layout (kept deliberately separate from `testbed/` and `eval/`):
    driftsentry/   the detector (this package)
    testbed/       the standalone adversarial MCP server (must NOT import this)
    eval/          the evaluation harness

Built phase by phase per the implementation roadmap.
"""

__version__ = "0.1.0"
