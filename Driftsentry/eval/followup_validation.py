"""The two validation claims that were never measured, measured.

    V-pertool       Per-tool thresholds halve benign-update false alarms at
                    equal recall.
    V-nevercalled   Full DriftSentry catches attacks on a tool the user never
                    calls, which passive monitoring cannot.

Both were planned and are listed as NOT MEASURED in Table 10. They are run
here under a pre-registration written before any of their data, with the
same discipline as H2b and H3b: hypothesis and thresholds frozen with a
sha256, a FAIL reported as a result.

Thresholds come from the same place the evaluation's do. Every episode runs
in a fresh home with no calibration, so the global threshold in every sweep
is the provisional 1.5; per-tool thresholds are fitted with that as their
fallback, from benign calibration runs on seeds no sweep uses.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval_results" / "followup" / "validation"
PREREG = OUT / "preregistration.json"
PER_TOOL_FILE = OUT / "per_tool_frozen.json"

CAL_SEEDS = (301, 302, 303, 304, 305, 306)
CAL_CYCLES = 8
AVOIDED_TOOL = "read_document"
FA_RATIO_AT_MOST = 0.5           # per-tool false alarms at most half the global ones
RECALL_DROP_AT_MOST_PP = 5.0     # "equal recall"


from eval.followup import sha_matches  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preregister() -> dict[str, Any]:
    if PREREG.exists():
        raise FileExistsError(f"{PREREG} exists; a pre-registration is written once")
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    doc = {
        "written": datetime.now().isoformat(timespec="seconds"),
        "code_commit": commit,
        "V-pertool": {
            "claim": "Per-tool thresholds halve benign-update false alarms at equal recall.",
            "pass_if": (f"benign-update false-alarm rate with per-tool thresholds <= "
                        f"{FA_RATIO_AT_MOST} x the rate with the global threshold, AND "
                        f"L1 recall with per-tool thresholds >= global recall - "
                        f"{RECALL_DROP_AT_MOST_PP} points"),
            "fit": (f"driftsentry.calibration.fit_per_tool on keyed benign re-probe ratios "
                    f"from seeds {list(CAL_SEEDS)}, {CAL_CYCLES} cycles each; global "
                    f"fallback = the provisional threshold every episode uses; frozen "
                    f"before either sweep"),
            "sweeps": "keyed, L1, all six families, seeds 1-2, benign seeds 101-103, "
                      "benign-update seeds 201-206; once global, once per-tool",
            "note": "if the global sweep raises no benign-update false alarm, 'halve' "
                    "is undefined and the claim is reported as untestable here",
        },
        "V-nevercalled": {
            "claim": "Full DriftSentry catches attacks on tools the agent never calls, "
                     "which passive cannot.",
            "pass_if": "among episodes whose attack fired, full detects significantly "
                       "more than passive (exact McNemar, p < 0.05, more full-only than "
                       "passive-only discordant pairs)",
            "sweep": (f"keyed, L1, all six families, seeds 1-3, attack confined to "
                      f"{AVOIDED_TOOL!r}, replayed genuine sessions that never call it "
                      f"(2 per cycle), launch parity on"),
        },
    }
    PREREG.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    PREREG.with_suffix(".sha256").write_text(_sha(PREREG) + "\n", encoding="utf-8")
    return doc


def verify_preregistration() -> dict[str, Any]:
    doc = json.loads(PREREG.read_text(encoding="utf-8"))
    if not sha_matches(PREREG, PREREG.with_suffix(".sha256").read_text(encoding="utf-8")):
        raise RuntimeError("validation preregistration.json no longer matches its sha256")
    return doc


# --------------------------------------------------------------------------- #
# V-pertool
# --------------------------------------------------------------------------- #
async def _calibration_ratios(attacker_project: Path, workspace: Path) -> list[dict]:
    """Per-check benign ratios, keyed, on seeds no sweep uses."""
    from driftsentry import keys as key_store
    from driftsentry.baseline import capture_baseline, reprobe
    from eval.launch import probe_launch
    from eval.scenario_control import AttackerControl

    rows: list[dict] = []
    for seed in CAL_SEEDS:
        home = workspace / f"pertool-cal-{seed}"
        shutil.rmtree(home, ignore_errors=True)
        atk_home, ds_home = home / "attacker", home / "driftsentry"
        atk_home.mkdir(parents=True); ds_home.mkdir(parents=True)
        os.environ["DRIFTSENTRY_HOME"] = str(ds_home)
        os.environ["ATTACKER_HOME"] = str(atk_home)
        atk = AttackerControl.discover(attacker_project, home=atk_home)
        atk.benign(seed=seed)
        key = key_store.derive_experiment_key(seed, "val-pertool-cal")
        launch = probe_launch(attacker_project, atk_home)
        baseline = await capture_baseline("target", launch["command"], launch["args"],
                                          cwd=launch["cwd"], env=launch["env"],
                                          probe_mode="keyed", key=key, seed=seed)
        for cycle in range(1, CAL_CYCLES + 1):
            m = await reprobe(baseline, launch["command"], launch["args"], cwd=launch["cwd"],
                              env=launch["env"], samples_per_probe=2, cycle=cycle, key=key)
            rows.extend({"tool": c.tool, "ratio": c.ratio, "seed": seed, "cycle": cycle}
                        for c in m.checks)
        print(f"  calibration seed {seed}: {len(rows)} ratios so far", flush=True)
    return rows


def fit_per_tool_thresholds(attacker_project: str | Path, workspace: str | Path) -> dict:
    from driftsentry.calibration import PROVISIONAL_THRESHOLD, fit_per_tool, freeze

    verify_preregistration()
    if PER_TOOL_FILE.exists():
        raise FileExistsError(f"{PER_TOOL_FILE} exists; per-tool thresholds are fitted once")
    rows = asyncio.run(_calibration_ratios(Path(attacker_project), Path(workspace)))
    (OUT / "per_tool_calibration_ratios.json").write_text(json.dumps(rows), encoding="utf-8")
    fitted = fit_per_tool(rows, global_threshold=PROVISIONAL_THRESHOLD)
    freeze(fitted, PER_TOOL_FILE)
    return fitted


def per_tool_sweeps(attacker_project: str | Path, workspace: str | Path) -> None:
    from driftsentry.calibration import verify_frozen
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    thresholds = dict(verify_frozen(PER_TOOL_FILE)["thresholds"])
    for exp_id, per_tool in (("val_pertool_global", None),
                             ("val_pertool_per_tool", thresholds)):
        spec = SweepSpec(experiment_id=exp_id, probe_mode="keyed", levels=("L1",),
                         seeds=(1, 2), benign_seeds=(101, 102, 103),
                         benign_update_seeds=(201, 202, 203, 204, 205, 206),
                         cycles=4, per_tool=per_tool)
        run_sweep(spec, attacker_project, workspace, OUT)


# --------------------------------------------------------------------------- #
# V-nevercalled
# --------------------------------------------------------------------------- #
def never_called_sweep(attacker_project: str | Path, workspace: str | Path) -> None:
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    spec = SweepSpec(experiment_id="val_never_called", probe_mode="keyed", levels=("L1",),
                     seeds=(1, 2, 3), cycles=4, avoid_tools=(AVOIDED_TOOL,),
                     replay_sessions=2, launch_parity=True)
    run_sweep(spec, attacker_project, workspace, OUT)


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #
def _episodes(exp_id: str) -> dict[str, list[dict[str, str]]]:
    import csv

    path = OUT / f"{exp_id}.csv"
    out: dict[str, list[dict[str, str]]] = {}
    if path.is_file():
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                out.setdefault(row["episode_id"], []).append(row)
    return out


def _t(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def _arms(exp_id: str) -> dict[str, Any]:
    fired = det = upd = upd_fa = 0
    for eid, rows in _episodes(exp_id).items():
        if "benign-update" in eid:
            upd += 1
            upd_fa += any(_t(r.get("detected")) for r in rows)
        elif rows[0].get("attack_level"):
            if _t(rows[0].get("attack_fired")):
                fired += 1
                det += any(_t(r.get("detected")) for r in rows)
    return {"fired": fired, "detected": det,
            "recall_pct": 100.0 * det / fired if fired else None,
            "benign_update_episodes": upd, "benign_update_alarms": upd_fa,
            "benign_update_fa_pct": 100.0 * upd_fa / upd if upd else None}


def verdict() -> dict[str, Any]:
    from eval.stats import mcnemar_p

    verify_preregistration()
    g, p = _arms("val_pertool_global"), _arms("val_pertool_per_tool")
    if g["benign_update_fa_pct"] in (None, 0.0):
        pertool = {"verdict": "UNTESTABLE", "reason": "the global threshold raised no "
                   "benign-update false alarm, so there is nothing to halve"}
    else:
        ok_fa = p["benign_update_fa_pct"] <= FA_RATIO_AT_MOST * g["benign_update_fa_pct"]
        ok_rec = (p["recall_pct"] is not None and g["recall_pct"] is not None
                  and p["recall_pct"] >= g["recall_pct"] - RECALL_DROP_AT_MOST_PP)
        pertool = {"verdict": "PASS" if ok_fa and ok_rec else "FAIL",
                   "checks": {"false_alarms_halved": ok_fa, "recall_held": ok_rec}}
    pertool.update(global_arm=g, per_tool_arm=p)

    full, passive = [], []
    for rows in _episodes("val_never_called").values():
        if not rows[0].get("attack_level") or not _t(rows[0].get("attack_fired")):
            continue
        full.append(any(_t(r.get("full_detected")) for r in rows))
        passive.append(any(_t(r.get("passive_detected")) for r in rows))
    if full:
        t = mcnemar_p(passive, full)
        never = {"verdict": "PASS" if t["p"] < 0.05 and t["b01"] > t["b10"] else "FAIL",
                 "fired": len(full), "full": sum(full), "passive": sum(passive),
                 "mcnemar": t}
    else:
        never = {"verdict": "NOT MEASURED", "reason": "no attack fired"}
    result = {"V-pertool": pertool, "V-nevercalled": never}
    (OUT / "verdict.json").write_text(json.dumps(result, indent=2, default=str),
                                      encoding="utf-8")
    return result
