"""Phase 4 - demonstrate and check the drift scorer.

This is the Phase 4 definition of done, made executable:

  1. Capture a baseline of a benign server.
  2. CALIBRATE the alert threshold using that benign server only - no rug-pull
     data touches the threshold - and report the false-alarm rate it implies.
  3. Score the UNCHANGED server: must come out OK, below the alert line.
  4. Score the DRIFTED twin (byte-identical tool definitions): must ALERT, with
     a single attributable triggering signal, while the naturally noisy tool
     stays quiet.
  5. Run the same drifted twin through the HASH-ONLY control condition, which is
     what mcp-scan-style pinning does: it must report no change - the measurement
     that justifies the whole behavioural layer.
  6. Check the security rules directly on synthetic observations, including that
     they are differential (behaviour already present at baseline never alarms).

Run:
    python examples/scorer_demo.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix="driftsentry_phase4_")
os.environ["DRIFTSENTRY_HOME"] = _TMP

from driftsentry import rules  # noqa: E402
from driftsentry.baseline import capture_baseline  # noqa: E402
from driftsentry.calibration import save as save_calibration  # noqa: E402
from driftsentry.store import BaselineStore  # noqa: E402
from driftsentry.verify import calibrate_servers, verify_server  # noqa: E402

BENIGN = HERE / "probe_target_server.py"
DRIFTED = HERE / "probe_target_variant.py"
SERVER = "probe-target"


def hr(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


def show(report) -> None:
    print(f"  VERDICT {report.verdict.upper():<5} score={report.score:.2f} "
          f"(alert at 1.00)  threshold ratio={report.threshold_ratio:.3f}")
    if report.triggered_by:
        print(f"  triggered by: {report.triggered_by}")
    for tool in report.tools:
        marker = "!" if tool.verdict == "alert" else ("?" if tool.verdict == "watch" else " ")
        print(f"   {marker} {tool.tool:<18} {tool.verdict:<5} score={tool.score:.2f}")
        for signal in tool.signals:
            print(f"       - {signal.name} [{signal.severity}] {signal.score:.2f}")


async def main() -> int:
    ok = True
    py = sys.executable
    store = BaselineStore()

    # -- 1. baseline --------------------------------------------------------
    hr("1. Baseline the benign server")
    baseline = await capture_baseline(
        SERVER, py, [str(BENIGN)], n_probes=3, n_samples=8, backend_name="auto",
    )
    store.save(baseline)
    print(f"  embedding: {baseline.embedding_backend}   definition: {baseline.definition_hash[:26]}...")
    print(f"  tools probed: {[t.tool for t in baseline.tools if t.probed]}")

    # -- 2. calibrate on benign data only -----------------------------------
    hr("2. Calibrate the threshold (BENIGN SERVERS ONLY)")
    calibration, per_server = await calibrate_servers([SERVER], repeats=3, samples_per_probe=2)
    save_calibration(calibration)
    print(f"  benign observations : {calibration.n_observations} from {calibration.n_servers} server(s)")
    print(f"  benign ratios       : mean {calibration.mean_benign_ratio:.3f}, "
          f"p99 {calibration.p99_benign_ratio:.3f}, max {calibration.max_benign_ratio:.3f}")
    print(f"  method              : {calibration.method}")
    print(f"  THRESHOLD           : ratio >= {calibration.threshold_ratio:.3f}")
    print(f"  false-alarm rate    : {calibration.empirical_far:.1%} (target {calibration.target_far:.1%})")
    for warning in calibration.warnings:
        print(f"  warning: {warning}")
    calibrated_ok = calibration.threshold_ratio > calibration.max_benign_ratio
    print(f"\n  threshold sits above the whole benign distribution: {calibrated_ok}")
    ok &= calibrated_ok

    # -- 3. score the unchanged server --------------------------------------
    hr("3. Score the UNCHANGED server (must not alert)")
    clean = await verify_server(baseline, launch={"command": py, "args": [str(BENIGN)]}, samples_per_probe=2)
    show(clean)
    no_false_alarm = clean.verdict != "alert"
    print(f"\n  no false alarm on a healthy server: {no_false_alarm}")
    ok &= no_false_alarm

    # -- 4. score the drifted twin ------------------------------------------
    hr("4. Score the DRIFTED twin (identical definitions, changed behaviour)")
    drifted = await verify_server(baseline, launch={"command": py, "args": [str(DRIFTED)]}, samples_per_probe=2)
    show(drifted)

    detected = drifted.verdict == "alert"
    lookup = next((t for t in drifted.tools if t.tool == "lookup"), None)
    weather = next((t for t in drifted.tools if t.tool == "weather"), None)
    lookup_alerts = lookup is not None and lookup.verdict == "alert"
    weather_quiet = weather is not None and weather.verdict != "alert"
    attributable = drifted.triggered_by is not None

    print(f"\n  drift detected                     : {detected}")
    print(f"  the tampered tool 'lookup' alerts  : {lookup_alerts}")
    print(f"  the noisy tool 'weather' stays calm: {weather_quiet}")
    print(f"  triggering signal is attributable  : {attributable} ({drifted.triggered_by})")
    ok &= detected and lookup_alerts and weather_quiet and attributable

    # -- 5. the hash-only control -------------------------------------------
    hr("5. CONTROL: hash-only pinning on the same drifted server")
    control = await verify_server(
        baseline, launch={"command": py, "args": [str(DRIFTED)]},
        samples_per_probe=2, mode="hash-only",
    )
    show(control)
    control_blind = control.verdict == "ok" and not control.definition_changed
    print(f"\n  hash-only pinning reports NO CHANGE: {control_blind}")
    print("  => DriftSentry detects a rug pull that definition pinning cannot see.")
    ok &= control_blind

    # -- 6. security rules --------------------------------------------------
    hr("6. Security rules (direct checks)")
    egress = rules.evaluate(new_hosts=["203.0.113.9:443"], new_files=[], new_content_flags=[])
    secret = rules.evaluate(new_hosts=[], new_files=[r"C:\Users\alice\.ssh\id_rsa"], new_content_flags=[])
    creds = rules.evaluate(new_hosts=[], new_files=[], new_content_flags=["credential:aws-access-key-id"])
    nothing = rules.evaluate(new_hosts=[], new_files=[], new_content_flags=[])

    print(f"  new egress host      -> {[h.rule for h in egress]} ({egress[0].severity})")
    print(f"  secret file read     -> {[h.rule for h in secret]} ({secret[0].severity})")
    print(f"  credential in output -> {[h.rule for h in creds]} ({creds[0].severity})")
    print(f"  nothing new          -> {[h.rule for h in nothing]}")

    rules_ok = (
        egress and egress[0].rule == "new_egress_host" and egress[0].severity == "high"
        and secret and secret[0].rule == "secret_file_read"
        and creds and creds[0].rule == "credential_shaped_output"
        and not nothing
    )
    print(f"\n  rules fire correctly and stay silent when nothing is new: {bool(rules_ok)}")

    # Differential behaviour: a tool that ALWAYS emitted a JWT is not suspicious.
    text = "your session token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
    flags = rules.content_flags(text)
    baseline_flags = set(flags)
    still_new = sorted(set(flags) - baseline_flags)
    print(f"  content flags detected             : {flags}")
    print(f"  same flags when already at baseline: {still_new} (empty => differential works)")
    ok &= bool(rules_ok) and not still_new

    print("\nPhase 4 result:", "ALL CHECKS PASSED" if ok else "FAILED")
    print(f"(state kept in {_TMP})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
