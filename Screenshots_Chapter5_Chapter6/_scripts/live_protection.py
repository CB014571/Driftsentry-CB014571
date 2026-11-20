"""A real MCP client behind `driftsentry run --in-session` (product 1.1.0).

Usage: python live_protection.py <benign|exfiltration> <work-dir>
Prints only what the product itself recorded: its exchange log, its last
in-session check, its alert store and its policy store.
"""
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

ARMED, WORK = sys.argv[1], Path(sys.argv[2])
shutil.rmtree(WORK, ignore_errors=True)
ATK_HOME, DS_HOME = WORK / "attacker", WORK / "driftsentry"
ATK_HOME.mkdir(parents=True)
DS_HOME.mkdir(parents=True)
os.environ["DRIFTSENTRY_HOME"] = str(DS_HOME)
os.environ["ATTACKER_HOME"] = str(ATK_HOME)
DS = Path(r"F:\fyp project\Driftsentry")
sys.path.insert(0, str(DS))
PROJECT = Path(r"F:\fyp project\mcp rug pull attack server")
DS_PY = str(DS / ".venv" / "Scripts" / "python.exe")
ATK_PY = str(PROJECT / ".venv" / "Scripts" / "python.exe")


async def main():
    from mcp import ClientSession, types
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from driftsentry import keys
    from driftsentry.baseline import capture_baseline
    from driftsentry.store import BaselineStore
    from eval.scenario_control import AttackerControl

    atk = AttackerControl.discover(PROJECT, ATK_HOME)
    atk.benign(seed=3)
    base = await capture_baseline("acme", ATK_PY, ["-m", "attacker", "serve"], cwd=str(PROJECT),
                                  env={"ATTACKER_HOME": str(ATK_HOME)}, probe_mode="keyed",
                                  key=keys.get_or_create("acme"), n_probes=3, n_samples=4)
    BaselineStore().save(base)
    probed = [t.tool for t in base.tools if t.probed]
    print(f"[1] approve  : baseline for 'acme' with keyed probes; tools probed: {', '.join(probed)}")
    if ARMED == "exfiltration":
        atk.arm("exfiltration", level="L1", seed=3)
        print("[2] attacker : server turned malicious after approval (exfiltration, L1)")
    else:
        print("[2] attacker : server left benign")
    print("[3] protect  : driftsentry run --server acme --in-session --verify-interval 4 --exec ...")

    params = StdioServerParameters(
        command=DS_PY,
        args=["-m", "driftsentry", "run", "--server", "acme", "--in-session",
              "--verify-interval", "4", "--forward-env", "ATTACKER_HOME",
              "--cwd", str(PROJECT), "--exec", ATK_PY, "-m", "attacker", "serve"],
        cwd=str(DS), env={"DRIFTSENTRY_HOME": str(DS_HOME), "ATTACKER_HOME": str(ATK_HOME)})
    answered = 0
    async with stdio_client(params, errlog=open(WORK / "proxy_stderr.log", "w")) as (r, w):
        async with ClientSession(r, w, client_info=types.Implementation(
                name="claude-ai", version="0.1.0")) as s:
            await s.initialize()
            calls = [("get_weather", {"city": "Leeds"}), ("search_orders", {"query": "recent"}),
                     ("lookup_customer", {"customer_id": "C-1002"})]
            t0, i = time.time(), 0
            while time.time() - t0 < 45:
                tool, args = calls[i % 3]
                res = await s.call_tool(tool, args)
                if res.content:
                    answered += 1
                i += 1
                await asyncio.sleep(1.5)

    rows = [json.loads(l) for l in (DS_HOME / "logs" / "acme.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    client_calls = sum(r["dir"] == "c2s" and r.get("method") == "tools/call" and r.get("kind") == "request"
                       for r in rows)
    print(f"[4] client   : {client_calls} tool calls sent by the client, {answered} answered")
    print(f"    proxy    : {sum(r['dir'] == 'probe' for r in rows)} probe answers kept from the client "
          f"(the client never saw a probe)")
    last = DS_HOME / "insession" / "acme.last.json"
    if last.exists():
        d = json.loads(last.read_text(encoding="utf-8"))
        print(f"[5] verdict  : last in-session check {d['verdict'].upper()}, score {d['score']:.2f}, "
              f"triggered by {d['triggered_by']}")
    alerts = DS_HOME / "alerts" / "acme.jsonl"
    recs = [json.loads(l) for l in alerts.read_text(encoding="utf-8").splitlines() if l.strip()] \
        if alerts.exists() else []
    print(f"    alerts   : {len(recs)} recorded")
    seen = set()
    for a in recs:
        key = (a.get("tool"), a.get("cause"))
        if key in seen:
            continue
        seen.add(key)
        print(f"               - {a.get('tool')}: {a.get('cause')} (score {a.get('score', 0):.2f}, "
              f"{a.get('severity')})")
    from driftsentry.policy import PolicyStore

    print(f"[6] policy   : server status {str(PolicyStore().get('acme').status).upper()}")


asyncio.run(main())
