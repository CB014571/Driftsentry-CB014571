"""Phase 1 — demonstrate and check the interception proxy.

This is the Phase 1 definition of done, made executable. A normal MCP client is
pointed at DriftSentry's proxy (`driftsentry run`) instead of the echo server.
DriftSentry launches the echo server itself and forwards everything. We then
verify:

  1. Transparency — list/call results are identical to talking to echo directly.
  2. Concurrency — several in-flight calls all return with the right answers,
     proving ids are not crossed or dropped under load.
  3. Audit log — a structured JSONL exchange log was written, including the
     special `tools/list` definition hash.

Run:
    python examples/proxy_demo.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ECHO_SERVER = HERE / "echo_server.py"
SERVER_NAME = "echo-demo"

sys.path.insert(0, str(ROOT))
from driftsentry.paths import logs_dir  # noqa: E402


def _text(result) -> str:
    return " ".join(b.text for b in result.content if getattr(b, "type", None) == "text")


async def main() -> int:
    # The client launches the PROXY, and the proxy launches the echo server.
    # Everything after --exec is the real server's command (path-safe tokens).
    proxy_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "driftsentry", "run",
            "--server", SERVER_NAME,
            "--exec", sys.executable, str(ECHO_SERVER),
        ],
    )

    # Start from a clean log so our assertions reflect this run only.
    log_path = logs_dir() / f"{SERVER_NAME}.jsonl"
    log_path.unlink(missing_ok=True)

    ok = True
    async with stdio_client(proxy_params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"Connected through proxy to: {init.serverInfo.name}")

            # 1. Transparency: list + call behave exactly like the bare server.
            tools = {t.name for t in (await session.list_tools()).tools}
            print(f"Tools via proxy: {sorted(tools)}")
            ok &= tools == {"echo", "reverse"}

            r = await session.call_tool("echo", {"text": "hello driftsentry"})
            ok &= _text(r) == "hello driftsentry"
            r = await session.call_tool("reverse", {"text": "abcxyz"})
            ok &= _text(r) == "zyxcba"
            print("Transparency check:", "PASS" if ok else "FAIL")

            # 2. Concurrency: fire many calls at once; each must get its own answer.
            payloads = [f"msg-{i}" for i in range(8)]
            results = await asyncio.gather(
                *(session.call_tool("echo", {"text": p}) for p in payloads)
            )
            concurrency_ok = all(_text(r) == p for r, p in zip(results, payloads))
            ok &= concurrency_ok
            print("Concurrency check:", "PASS" if concurrency_ok else "FAIL",
                  f"({len(payloads)} in-flight calls)")

    # 3. Audit log: structured records exist, including the tools/list hash.
    lines = [json.loads(l) for l in log_path.read_text(encoding="utf-8").splitlines()]
    has_list_hash = any(r.get("method") == "tools/list" and "definition_hash" in r for r in lines)
    call_records = [r for r in lines if r.get("method") == "tools/call"]
    print(f"\nAudit log: {log_path}")
    print(f"  {len(lines)} records, {len(call_records)} tools/call, "
          f"tools/list hash present: {has_list_hash}")
    if has_list_hash:
        h = next(r["definition_hash"] for r in lines if r.get("method") == "tools/list" and "definition_hash" in r)
        print(f"  definition_hash = {h}")
    ok &= has_list_hash and len(call_records) >= 1

    print("\nPhase 1 result:", "ALL CHECKS PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
