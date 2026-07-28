"""Phase 2 — demonstrate and check config ingestion, rewriting, and restore.

This is the Phase 2 definition of done, made executable. Working entirely inside
a temporary directory (your real Claude/Cursor config is never touched), it:

  1. Builds a realistic client config: a stdio server, a stdio server carrying a
     secret in `env`, and a remote HTTP server.
  2. Runs `driftsentry init --in-place` and checks the rewrite:
       - stdio servers are routed through the proxy,
       - the HTTP server is skipped (stdio-only, honestly reported),
       - the secret's VALUE never reaches the command line, only its NAME.
  3. Launches a real MCP client using the *rewritten* entry, proving the produced
     config actually works — the strongest reading of "produces a working config".
  4. Re-runs init to prove idempotency (no DriftSentry inside DriftSentry).
  5. Runs `driftsentry restore` and checks the config is byte-for-byte original.

Run:
    python examples/init_demo.py
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ECHO_SERVER = HERE / "echo_server.py"
SECRET = "super-secret-value"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the driftsentry CLI the way a user would."""
    return subprocess.run(
        [sys.executable, "-m", "driftsentry", *args],
        capture_output=True, text=True, cwd=str(ROOT),
    )


async def call_through(entry: dict) -> str:
    """Launch the server described by a config entry and call its echo tool."""
    params = StdioServerParameters(
        command=entry["command"],
        args=[str(a) for a in entry.get("args", [])],
        env=entry.get("env"),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("echo", {"text": "through the rewritten config"})
            return " ".join(
                b.text for b in result.content if getattr(b, "type", None) == "text"
            )


def main() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="driftsentry_init_") as tmp:
        tmpdir = Path(tmp)
        config = tmpdir / "claude_desktop_config.json"

        # 1. A realistic config. Absolute paths so it runs from anywhere.
        original = {
            "mcpServers": {
                "echo": {"command": sys.executable, "args": [str(ECHO_SERVER)]},
                "shop": {
                    "command": sys.executable,
                    "args": [str(ECHO_SERVER)],
                    "env": {"SHOP_API_KEY": SECRET},
                },
                "remote-docs": {"url": "https://example.invalid/mcp"},
            }
        }
        config.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")
        print(f"Sample config: {config}\n")

        # 2. Rewrite it.
        proc = run_cli("init", "--config", str(config), "--in-place")
        print(proc.stdout.rstrip())
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return 1

        rewritten = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]

        # stdio servers wrapped, HTTP left alone.
        echo_wrapped = "run" in rewritten["echo"]["args"] and "--exec" in rewritten["echo"]["args"]
        http_untouched = rewritten["remote-docs"] == original["mcpServers"]["remote-docs"]
        print(f"\n  stdio 'echo' wrapped:        {echo_wrapped}")
        print(f"  http 'remote-docs' untouched: {http_untouched}")
        ok &= echo_wrapped and http_untouched

        # The secret must survive in env, but never appear in argv.
        shop = rewritten["shop"]
        secret_in_argv = SECRET in " ".join(str(a) for a in shop["args"])
        name_forwarded = "--forward-env" in shop["args"] and "SHOP_API_KEY" in shop["args"]
        secret_kept = shop.get("env", {}).get("SHOP_API_KEY") == SECRET
        print(f"  secret VALUE in argv:         {secret_in_argv}  (must be False)")
        print(f"  secret NAME forwarded:        {name_forwarded}")
        print(f"  secret preserved in env:      {secret_kept}")
        ok &= (not secret_in_argv) and name_forwarded and secret_kept

        # 3. The rewritten entry must actually work.
        answer = asyncio.run(call_through(rewritten["echo"]))
        works = answer == "through the rewritten config"
        print(f"\n  live call via rewritten entry: {answer!r} -> {'PASS' if works else 'FAIL'}")
        ok &= works

        # 4. Idempotency: a second init must not double-wrap.
        proc2 = run_cli("init", "--config", str(config), "--in-place", "--no-diff")
        idempotent = "already-wrapped" in proc2.stdout
        after2 = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]
        unchanged = after2 == rewritten
        print(f"  second init is a no-op:        {idempotent and unchanged}")
        ok &= idempotent and unchanged

        # 5. Restore must return the config exactly as it was.
        proc3 = run_cli("restore", "--config", str(config))
        print("\n" + proc3.stdout.rstrip())
        restored = json.loads(config.read_text(encoding="utf-8"))
        identical = restored == original
        print(f"\n  restored == original:          {identical}")
        ok &= identical

    print("\nPhase 2 result:", "ALL CHECKS PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
