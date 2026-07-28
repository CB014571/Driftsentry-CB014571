"""Phase 0 — minimal MCP client for the echo server.

Launches echo_server.py as a stdio subprocess, runs the MCP handshake, lists the
server's tools, and calls them — printing what comes back at the protocol level.
This is the "loop you fully own" the roadmap asks for: proof we can drive an MCP
server end to end before any DriftSentry logic exists to sit in the middle.

Run:
    python examples/echo_client.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
SERVER = HERE / "echo_server.py"


async def main() -> None:
    # Launch the server with the *same* interpreter running this client, so it
    # picks up the project's virtual environment without needing it activated.
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # MCP handshake: capability + version negotiation.
            init = await session.initialize()
            print(f"Connected to server: {init.serverInfo.name} "
                  f"v{init.serverInfo.version}")

            # tools/list — the request a classic (definition-changing) rug pull
            # tampers with, and where the Phase 4 hash check will attach.
            tools = await session.list_tools()
            print("\nTools advertised:")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description}")

            # tools/call — exercise both tools and show the results.
            for tool_name, args in [
                ("echo", {"text": "hello driftsentry"}),
                ("reverse", {"text": "hello driftsentry"}),
            ]:
                result = await session.call_tool(tool_name, args)
                rendered = " ".join(
                    b.text for b in result.content if getattr(b, "type", None) == "text"
                )
                print(f"\ncall {tool_name}({args}) -> {rendered!r}")

    print("\nPhase 0 loop OK: handshake, list, and call all succeeded.")


if __name__ == "__main__":
    asyncio.run(main())
