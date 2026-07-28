"""Phase 3 — demonstrate and check baseline capture and the probe engine.

This is the Phase 3 definition of done, made executable:

  1. Capture a behavioural baseline of a benign server: classify each tool for
     probe safety, fire seeded canaries at the safe ones, sample each several
     times, and learn a benign variance band per probe.
  2. Persist to ChromaDB + JSON and reload it.
  3. Re-probe the SAME, unchanged server  -> every probe must land INSIDE its band.
  4. Re-probe a DRIFTED twin whose tool definitions are byte-identical:
        - `lookup`  changed behaviour -> must land OUTSIDE its band
        - `weather` is merely noisy   -> must stay INSIDE its band (no false alarm)
     and confirm the definition hash is UNCHANGED, so hash-only pinning is blind
     to it. That contrast is the whole thesis in one screen.

Run:
    python examples/baseline_demo.py
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

# Isolate all state in a temp dir so the demo never disturbs real baselines.
_TMP = tempfile.mkdtemp(prefix="driftsentry_phase3_")
os.environ["DRIFTSENTRY_HOME"] = _TMP

from driftsentry.baseline import capture_baseline, reprobe  # noqa: E402
from driftsentry.store import BaselineStore  # noqa: E402

BENIGN = HERE / "probe_target_server.py"
DRIFTED = HERE / "probe_target_variant.py"
SERVER_NAME = "probe-target"

# Provisional alert threshold, expressed as a multiple of a probe's benign band.
#
# The band is an estimate of how far benign samples spread, so roughly half of
# future benign samples of a noisy tool land near ratio 1.0 by construction.
# Alerting at ratio > 1.0 would therefore false-alarm constantly. The alert line
# belongs ABOVE the benign distribution -- and Phase 4's job is to calibrate
# exactly where, on a held-out set of benign servers only. 1.5 is a placeholder
# so this demo can talk about detection at all; it is NOT a calibrated threshold.
ALERT_RATIO = 1.5


def hr(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


async def main() -> int:
    ok = True
    py = sys.executable

    # -- 1. capture ---------------------------------------------------------
    hr("1. Capturing behavioural baseline (benign server)")
    baseline = await capture_baseline(
        SERVER_NAME, py, [str(BENIGN)],
        n_probes=3, n_samples=8, seed=20260720, backend_name="auto",
    )
    print(f"embedding backend : {baseline.embedding_backend} (dim {baseline.embedding_dim})")
    print(f"definition hash   : {baseline.definition_hash}")
    print(f"probes/tool       : {baseline.n_probes} x {baseline.n_samples} samples\n")

    for tool in baseline.tools:
        if not tool.probed:
            print(f"  {tool.tool:<12} NOT PROBED  ({tool.safety_reason})")
            continue
        bands = ", ".join(f"{p.band:.4f}" for p in tool.probes)
        print(f"  {tool.tool:<12} probed      bands=[{bands}]")

    # send_email must have been refused; the rest must have been probed.
    email = baseline.tool("send_email")
    probed = {t.tool for t in baseline.tools if t.probed}
    safety_ok = email is not None and not email.probed and probed == {"lookup", "weather", "read_notes"}
    print(f"\n  probe-safety classification correct: {safety_ok}")
    ok &= safety_ok

    # The noisy tool must have a WIDER band than the deterministic one, or we
    # have not actually learned anything about natural variance.
    det = max(p.band for p in baseline.tool("lookup").probes)
    noisy = max(p.band for p in baseline.tool("weather").probes)
    variance_ok = noisy > det
    print(f"  variance learned: weather band {noisy:.4f} > lookup band {det:.4f}: {variance_ok}")
    ok &= variance_ok

    # -- 2. persist + reload ------------------------------------------------
    hr("2. Persisting to ChromaDB + JSON")
    store = BaselineStore()
    path = store.save(baseline)
    reloaded = store.load(SERVER_NAME)
    roundtrip_ok = reloaded is not None and reloaded.definition_hash == baseline.definition_hash
    print(f"  saved to      : {path.name}")
    print(f"  servers stored: {store.list_servers()}")
    print(f"  reload OK     : {roundtrip_ok}")

    probe0 = reloaded.tool("lookup").probes[0]
    nearest = store.nearest(probe0.centroid, reloaded.embedding_backend, reloaded.embedding_dim, n_results=1)
    vector_ok = nearest and nearest[0]["metadata"]["tool"] == "lookup"
    print(f"  chroma nearest: {nearest[0]['id']} (distance {nearest[0]['distance']:.6f})")
    ok &= roundtrip_ok and bool(vector_ok)

    # -- 3. re-probe the unchanged server -----------------------------------
    hr("3. Re-probing the UNCHANGED server (must stay inside the band)")
    same = await reprobe(reloaded, py, [str(BENIGN)], samples_per_probe=2)
    for check in same.checks:
        flag = "ALERT" if check.ratio >= ALERT_RATIO else "ok   "
        print(f"  [{flag}] {check.tool:<11} {check.probe_id:<12} "
              f"dist={check.distance:.4f} band={check.band:.4f} ratio={check.ratio:.2f}")
    no_false_alarm = all(c.ratio < ALERT_RATIO for c in same.checks)
    print(f"\n  definition unchanged        : {not same.definition_changed}")
    print(f"  no false alarm (ratio < {ALERT_RATIO}) : {no_false_alarm}")
    ok &= no_false_alarm and not same.definition_changed

    # -- 4. re-probe the drifted twin ---------------------------------------
    hr("4. Re-probing the DRIFTED twin (identical definitions, changed behaviour)")
    drifted = await reprobe(reloaded, py, [str(DRIFTED)], samples_per_probe=2)
    for check in drifted.checks:
        flag = "ALERT" if check.ratio >= ALERT_RATIO else "ok   "
        print(f"  [{flag}] {check.tool:<11} {check.probe_id:<12} "
              f"dist={check.distance:.4f} band={check.band:.4f} ratio={check.ratio:.2f}")

    lookup_detected = all(c.ratio >= ALERT_RATIO for c in drifted.checks if c.tool == "lookup")
    weather_quiet = all(c.ratio < ALERT_RATIO for c in drifted.checks if c.tool == "weather")
    hash_blind = not drifted.definition_changed

    print(f"\n  definition hash UNCHANGED (hash-only pinning is blind): {hash_blind}")
    print(f"  drifted tool 'lookup' DETECTED                        : {lookup_detected}")
    print(f"  noisy tool 'weather' NOT false-alarmed                : {weather_quiet}")
    ok &= lookup_detected and weather_quiet and hash_blind

    print("\nPhase 3 result:", "ALL CHECKS PASSED" if ok else "FAILED")
    print(f"(state kept in {_TMP})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
