"""Phase 5 - demonstrate and check alerting, mitigation and enforcement.

This is the Phase 5 definition of done, made executable. The bar the roadmap sets
is "a drifted tool produces a report a non-expert can act on, with cause and
mitigation", so the checks are about the *content* of the alert, not just that
one was emitted:

  1. Baseline a benign server and calibrate on benign data only.
  2. Detect the drifted twin and build an alert. Assert it contains all four
     required elements: which server/tool, which signal and by how much, a
     concrete before/after, and actionable mitigations.
  3. Show the alert as a user sees it, and confirm it round-trips through the
     JSON record (the machine-readable audit trail).
  4. Check mitigations are TEMPLATED PER CAUSE - a new-egress alert must advise
     rotating credentials, a definition-hash alert must advise re-approval. One
     generic "something changed" message for every cause would not be actionable.
  5. Quarantine the server, then prove the opt-in ENFORCEMENT mode actually
     refuses a live tool call through the proxy - and that with enforcement off
     the same call still succeeds, since detection must never silently block.

Run:
    python examples/alert_demo.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix="driftsentry_phase5_")
os.environ["DRIFTSENTRY_HOME"] = _TMP

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from driftsentry.alerts import AlertStore, build_alerts, mitigations_for, render  # noqa: E402
from driftsentry.baseline import capture_baseline  # noqa: E402
from driftsentry.calibration import save as save_calibration  # noqa: E402
from driftsentry.policy import PolicyStore  # noqa: E402
from driftsentry.store import BaselineStore  # noqa: E402
from driftsentry.verify import calibrate_servers, verify_server  # noqa: E402

BENIGN = HERE / "probe_target_server.py"
DRIFTED = HERE / "probe_target_variant.py"
SERVER = "probe-target"


def hr(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


async def call_through_proxy(enforce: bool) -> tuple[bool, str]:
    """Call a tool through `driftsentry run`, optionally with enforcement on.

    Returns (succeeded, message). The proxy is a subprocess, so DRIFTSENTRY_HOME
    must be handed to it explicitly - the MCP SDK passes only a safe subset of
    the environment to servers it launches.
    """
    args = ["-m", "driftsentry", "run", "--server", SERVER]
    if enforce:
        args.append("--enforce")
    args += ["--exec", sys.executable, str(BENIGN)]

    params = StdioServerParameters(
        command=sys.executable,
        args=args,
        env={"DRIFTSENTRY_HOME": _TMP},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            try:
                result = await session.call_tool("lookup", {"query": "opening hours"})
            except Exception as exc:  # the proxy refused the call
                return False, str(exc)
            text = " ".join(
                b.text for b in result.content if getattr(b, "type", None) == "text"
            )
            if result.isError:
                return False, text
            return True, text


async def main() -> int:
    ok = True
    py = sys.executable

    # -- 1. baseline + calibrate -------------------------------------------
    hr("1. Baseline the benign server and calibrate")
    baseline = await capture_baseline(SERVER, py, [str(BENIGN)], n_probes=2, n_samples=6)
    BaselineStore().save(baseline)
    calibration, _ = await calibrate_servers([SERVER], repeats=2, samples_per_probe=2)
    save_calibration(calibration)
    print(f"  embedding : {baseline.embedding_backend}")
    print(f"  threshold : ratio >= {calibration.threshold_ratio:.3f}")

    # -- 2. detect and build the alert -------------------------------------
    hr("2. Detect the drifted twin and raise an alert")
    report = await verify_server(
        baseline, launch={"command": py, "args": [str(DRIFTED)]}, samples_per_probe=2,
    )
    print(f"  verdict {report.verdict.upper()}  score {report.score:.2f}  "
          f"triggered by {report.triggered_by}")
    alerts = build_alerts(report)
    print(f"  alerts built: {len(alerts)}")
    ok &= report.verdict == "alert" and len(alerts) >= 1
    if not alerts:
        print("\nPhase 5 result: FAILED (no alert produced)")
        return 1

    alert = alerts[0]
    has_server_tool = bool(alert.server and alert.tool)
    has_signal = bool(alert.triggered_by) and alert.score > alert.threshold_score
    has_before_after = bool(alert.before) and bool(alert.after) and alert.before != alert.after
    has_mitigation = len(alert.mitigations) >= 3 and any(m.command for m in alert.mitigations)

    # The payload in the drifted twin is an injected instruction. The scorer's
    # top signal is behavioural_drift (it scores highest), but the ADVICE must
    # address the injection, which is the specific, actionable finding.
    injection_advice = (
        alert.primary_cause == "rule:instruction_shaped_output"
        and any("assistant" in m.detail.lower() for m in alert.mitigations)
    )

    print(f"\n  contains server + tool        : {has_server_tool} ({alert.server}/{alert.tool})")
    print(f"  contains signal + magnitude   : {has_signal} "
          f"({alert.triggered_by}, {alert.score:.2f} vs {alert.threshold_score:.2f})")
    print(f"  contains concrete before/after: {has_before_after}")
    print(f"  contains actionable mitigation: {has_mitigation} ({len(alert.mitigations)} steps)")
    print(f"  advice targets the SPECIFIC cause, not just the loudest signal: "
          f"{injection_advice} (scored on {alert.triggered_by}, advises on {alert.primary_cause})")
    ok &= has_server_tool and has_signal and has_before_after and has_mitigation and injection_advice

    # -- 3. render + persist ------------------------------------------------
    hr("3. The alert as the user sees it")
    render(alert)

    store = AlertStore()
    store.append(alert)
    reloaded = store.history(SERVER)
    roundtrip = bool(reloaded) and reloaded[-1].alert_id == alert.alert_id
    raw = json.loads(store.path_for(SERVER).read_text(encoding="utf-8").splitlines()[-1])
    print(f"\n  JSON record written and reloadable: {roundtrip}")
    print(f"  JSON keys: {sorted(raw)[:8]} ...")
    ok &= roundtrip

    # -- 4. mitigations are per-cause --------------------------------------
    hr("4. Mitigations are templated per cause, not generic")
    egress = mitigations_for("rule:new_egress_host", SERVER, "lookup")
    hashchg = mitigations_for("definition_hash", SERVER, "lookup")
    drift = mitigations_for("behavioural_drift", SERVER, "lookup")

    def joined(ms) -> str:
        return " ".join(f"{m.action} {m.detail}".lower() for m in ms)

    egress_rotates = "rotate" in joined(egress)
    hash_reapproves = "re-approval" in joined(hashchg) or "approval" in joined(hashchg)
    drift_is_measured = "not by itself proof" in joined(drift)
    print(f"  new-egress advises rotating credentials : {egress_rotates}")
    print(f"  definition-hash advises re-approval     : {hash_reapproves}")
    print(f"  plain drift is honest about ambiguity   : {drift_is_measured}")
    print(f"  the three causes give different advice  : "
          f"{len({joined(egress), joined(hashchg), joined(drift)}) == 3}")
    ok &= egress_rotates and hash_reapproves and drift_is_measured

    # -- 5. quarantine + enforcement ---------------------------------------
    hr("5. Quarantine, then opt-in enforcement in the live data path")
    policy_store = PolicyStore()
    policy_store.update(SERVER, status="quarantined", reason="drift alert (demo)",
                        flagged_tools=["lookup"])
    policy = policy_store.get(SERVER)
    print(f"  policy: status={policy.status}  enforce={policy.enforce}")

    # Detection must never silently block: quarantined but not enforcing.
    allowed, message = await call_through_proxy(enforce=False)
    print(f"  call WITHOUT --enforce : {'allowed' if allowed else 'blocked'}  -> {message[:60]!r}")
    ok &= allowed

    # Now opt in.
    policy_store.update(SERVER, enforce=True)
    blocked_ok, message = await call_through_proxy(enforce=True)
    refused = (not blocked_ok) and "driftsentry" in message.lower()
    print(f"  call WITH    --enforce : {'allowed' if blocked_ok else 'BLOCKED'}")
    print(f"    client saw: {message[:110]!r}")
    print(f"\n  enforcement blocks only when opted in: {refused}")
    ok &= refused

    print("\nPhase 5 result:", "ALL CHECKS PASSED" if ok else "FAILED")
    print(f"(state kept in {_TMP})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
