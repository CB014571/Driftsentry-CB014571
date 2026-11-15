"""H2c - product v1.1: in-session verification that does not have to win.

H2 FAILED and stays failed. H2b (in-session probing) FAILED and stays failed:
the recogniser reached AUC 0.887, on timing (0.802) and argument (0.737).
This is a NEW experiment, designed after both, on the v1.1 product. It is
reported as a post-hoc follow-up under its own pre-registration.

What changed since H2b, each for a measured reason
    timing      H2b probes arrived a median 0.52 s after the previous call
                against 0.03 s for genuine ones. Measured cause: the
                per-probe side-effect window (0.12 s to open, 0.20 s to
                close on Windows) and scoring done between calls. v1.1
                watches the server continuously in a separate process
                (sandbox.ContinuousMonitor, driftsentry/_watcher.py), scores
                after the calls, and paces after the window opens.
    arguments   Values matched the AVERAGE digit/space ratio of real values,
                which describes neither an ID nor a name. v1.1 matches ONE
                real value's character pattern (traffic.skeleton). Design
                check on genuine split B: argument AUC 0.674 -> 0.51.
    guard       New. Every real call is checked for side effects and answer
                content the server never showed at approval
                (driftsentry/guard.py). A server that recognises probes and
                attacks only the user is then caught on the user's calls.

Two claims, frozen separately so neither can hide behind the other
    H2c-1 (unrecognisable)   best recogniser AUC <= 0.6 - H2's bar, unchanged.
    H2c-2 (caught either way) caught-either-way recall at L6 within 10
                             points of L1, and benign false alarms (guard
                             included) up by at most 2 points over the
                             separate-session control - H2's other two bars,
                             unchanged.

    "Caught either way": an episode counts as detected only in a cycle where
    the alert was earned - a probe alert while the attacker's log shows it
    fired on a probe, or a guard alert while it shows it fired on a real
    call. An alert from a side effect left behind by the other kind of call
    is not earned and does not end the episode.

    The guard's known blind spot is stated in advance: an attack that only
    changes answer VALUES on real calls (silent tamper) is invisible to it,
    so for that family H2c-2 rests on probes alone.

Same split discipline as H2b: probe shapes, gaps and startup delays come
from genuine split A only; every replayed genuine call comes from split B.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from eval.followup import (_sha, _true, events_in_windows, genuine_split,  # noqa: F401
                           insession_cycle, profile_from_sessions)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval_results" / "followup" / "h2c"
PREREG = OUT / "preregistration.json"
PROFILE_A = OUT / "profile_split_a.json"

AUC_CEILING = 0.6
RECALL_WITHIN_PP = 10.0
FALSE_ALARM_RISE_PP = 2.0

COLLECT_SESSIONS = 60
REPLAY_SESSIONS = 8
MATRIX_SEEDS = (1, 2)
MATRIX_CYCLES = 4
N_PROBES_BASELINE = 8
PREFIX = "h2c"


def load_profile_a() -> Any:
    from driftsentry.traffic import TrafficProfile

    return TrafficProfile.from_dict(json.loads(PROFILE_A.read_text(encoding="utf-8")))


def shapes_dict() -> dict[str, Any]:
    return dict(load_profile_a().tool_shapes)


# --------------------------------------------------------------------------- #
# Pre-registration
# --------------------------------------------------------------------------- #
def preregister(server_id: str = "target") -> dict[str, Any]:
    if PREREG.exists():
        raise FileExistsError(f"{PREREG} exists; a pre-registration is written once")
    OUT.mkdir(parents=True, exist_ok=True)
    a, b = genuine_split("A"), genuine_split("B")
    profile = profile_from_sessions(a, server_id)
    PROFILE_A.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
    import subprocess

    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    doc = {
        "id": "H2c",
        "written": datetime.now().isoformat(timespec="seconds"),
        "code_commit": commit,
        "status": ("post-hoc follow-up, designed after H2 and H2b failed; both stay "
                   "FAIL. Tests product v1.1."),
        "hypotheses": {
            "H2c-1": (f"With continuous out-of-process watching, scoring after the "
                      f"calls, pacing after the window, and skeleton-matched keyed "
                      f"values, the best cross-validated recogniser (any family, "
                      f"including 'all') re-fitted on v1.1 in-session traffic reaches "
                      f"AUC <= {AUC_CEILING}."),
            "H2c-2": (f"With the real-call guard on, caught-either-way recall at L6 is "
                      f"within {RECALL_WITHIN_PP} points of L1, and benign false alarms "
                      f"(guard included) rise by at most {FALSE_ALARM_RISE_PP} points "
                      f"over separate-session keyed verification on the same seeds."),
        },
        "thresholds": {"auc_ceiling": AUC_CEILING, "recall_within_pp": RECALL_WITHIN_PP,
                       "false_alarm_rise_pp": FALSE_ALARM_RISE_PP,
                       "recall_rule": "one-sided: L6 caught-either-way recall may be at "
                                      "most recall_within_pp points BELOW L1; L6 above "
                                      "L1 is not a failure"},
        "procedure": {
            "collection_sessions": COLLECT_SESSIONS,
            "genuine_sessions_replayed_per_live_session": REPLAY_SESSIONS,
            "samples_per_probe": 1, "subsample_bank": True,
            "baseline_probes_per_family": N_PROBES_BASELINE,
            "guard": True,
            "recogniser": "eval.rq3_distinguish.analyse, 5-fold GroupKFold by process "
                          "(mixed groups, as H2b amendment 1), re-fitted on this "
                          "traffic; best family exported to L6",
            "matrix": {"levels": ["L1", "L6"], "seeds": list(MATRIX_SEEDS),
                       "cycles": MATRIX_CYCLES, "families": "all six"},
            "recall": ("caught either way: an episode is detected only in a cycle whose "
                       "alert was earned - probe-earned (alert and attacker events in a "
                       "probe window) or guard-earned (guard alert and attacker events in "
                       "a genuine window); denominator = episodes whose attack fired"),
            "false_alarm_control": "separate-session keyed verification, benign seeds, "
                                   "re-run here",
            "stated_blind_spot": "silent-tamper on real calls is invisible to the guard",
        },
        "genuine_split": {"rule": "sha256(json(session)) first 8 hex digits mod 2: "
                                  "0 -> A (shapes, skeletons, gaps), 1 -> B (replayed)",
                          "n_sessions_a": len(a), "n_sessions_b": len(b),
                          "profile_a_sha256": _sha(PROFILE_A)},
    }
    PREREG.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    PREREG.with_suffix(".sha256").write_text(_sha(PREREG) + "\n", encoding="utf-8")
    return doc


def verify_preregistration() -> dict[str, Any]:
    doc = json.loads(PREREG.read_text(encoding="utf-8"))
    recorded = PREREG.with_suffix(".sha256").read_text(encoding="utf-8").strip()
    if _sha(PREREG) != recorded:
        raise RuntimeError("H2c preregistration.json no longer matches its sha256")
    if _sha(PROFILE_A) != doc["genuine_split"]["profile_a_sha256"]:
        raise RuntimeError("H2c profile_split_a.json changed after pre-registration")
    return doc


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #
async def collect(attacker_project: str | Path, workspace: str | Path, *,
                  sessions: int = COLLECT_SESSIONS, seed: int = 20261116,
                  progress: bool = True) -> dict[str, Any]:
    """Benign in-session traffic on v1.1, one labelled window per call."""
    from driftsentry import keys as key_store
    from driftsentry.baseline import capture_baseline

    from eval.collect import Collector
    from eval.followup import GENUINE, PROBE
    from eval.launch import probe_launch

    verify_preregistration()
    shapes, profile = shapes_dict(), load_profile_a()
    out = OUT / "collection"
    col = Collector(attacker_project, out, workspace, server_id="h2c", seed=seed,
                    n_probes=N_PROBES_BASELINE, samples_per_probe=1, subsample_bank=True)
    col.prepare()
    key = key_store.derive_experiment_key(seed, "h2c-collect")
    launch = probe_launch(col.attacker_project, col.atk_home)
    baseline = await capture_baseline(
        col.server_id, launch["command"], launch["args"], cwd=launch["cwd"],
        env=launch["env"], n_probes=N_PROBES_BASELINE, n_samples=col.n_samples,
        seed=seed, probe_mode="keyed", key=key,
        monitor_sandbox=col.monitor_sandbox, shapes=shapes)
    cutoff = time.time()
    verdicts: list[str] = []
    for i in range(sessions):
        report, records = await insession_cycle(
            baseline, attacker_project=col.attacker_project, atk_home=col.atk_home,
            ds_home=col.ds_home, server_id=col.server_id, cycle=i + 1, key=key,
            seed=seed + i, replay_sessions=REPLAY_SESSIONS, threshold_ratio=None,
            monitor_sandbox=col.monitor_sandbox, shapes=shapes, profile=profile,
            guard=True)
        for r in records:
            col._window(GENUINE if r.kind == "genuine" else PROBE, r.start, r.end,
                        session=i + 1, tool=r.tool)
        verdicts.append(report.verdict)
        if progress:
            g = sum(1 for r in records if r.kind == "genuine")
            print(f"  [{i + 1:>3}/{sessions}] genuine={g:<3} probes={len(records) - g:<3} "
                  f"verdict={report.verdict} score={report.score:.3f}", flush=True)
    summary = col.finish(cutoff, [])
    summary["benign_verdicts"] = {v: verdicts.count(v) for v in sorted(set(verdicts))}
    (out / "collection.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def fit(attacker_project: str | Path) -> dict[str, Any]:
    from eval.rq3_dataset import build
    from eval.rq3_distinguish import analyse

    verify_preregistration()
    out = OUT / "collection"
    build(out, mixed_groups=True)
    summary = analyse(out / "dataset.jsonl", attacker_project, out_dir=out,
                      n_boot=2000, seed=0)
    scored = {n: r["auc"] for n, r in summary["families"].items() if "auc" in r}
    if not scored:
        raise RuntimeError("no family fitted; the dataset is unusable")
    best = max(scored, key=lambda n: scored[n])
    summary["best_family"], summary["best_auc"] = best, scored[best]
    summary["recogniser"] = str(out / f"recogniser_{best}.json")
    (OUT / "fit.json").write_text(json.dumps(summary, indent=2, default=str),
                                  encoding="utf-8")
    return summary


def matrix(attacker_project: str | Path, workspace: str | Path) -> None:
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    fitted = json.loads((OUT / "fit.json").read_text(encoding="utf-8"))
    for level in ("L1", "L6"):
        spec = SweepSpec(
            experiment_id=f"{PREFIX}_insession_{level}", probe_mode="keyed",
            levels=(level,), seeds=MATRIX_SEEDS, cycles=MATRIX_CYCLES,
            n_probes=N_PROBES_BASELINE, samples_per_probe=1,
            launch_parity=True, replay_sessions=REPLAY_SESSIONS,
            recogniser=fitted["recogniser"], subsample_bank=True,
            in_session=True, shapes=shapes_dict(), guard=True)
        run_sweep(spec, attacker_project, workspace, OUT)


def control(attacker_project: str | Path, workspace: str | Path) -> None:
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    spec = SweepSpec(experiment_id=f"{PREFIX}_control_separate", probe_mode="keyed",
                     families=(), levels=("L1",), cycles=MATRIX_CYCLES,
                     samples_per_probe=1, launch_parity=True, subsample_bank=True)
    run_sweep(spec, attacker_project, workspace, OUT)


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #
def _episodes(experiment_id: str) -> dict[str, list[dict[str, str]]]:
    import csv

    path = OUT / f"{experiment_id}.csv"
    out: dict[str, list[dict[str, str]]] = {}
    if not path.is_file():
        return out
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            out.setdefault(row["episode_id"], []).append(row)
    return out


def _earned(row: dict[str, str]) -> tuple[bool, bool]:
    """(probe-earned, guard-earned) for one cycle row."""
    if not _true(row.get("detected")):
        return False, False
    probe = int(row.get("probe_window_events") or 0) > 0
    guard = _true(row.get("guard_fired")) and int(row.get("genuine_window_events") or 0) > 0
    return probe, guard


def either_way_recall(experiment_id: str) -> dict[str, Any]:
    fired = caught = by_probe = by_guard = 0
    per_family: dict[str, list[int]] = {}
    for rows in _episodes(experiment_id).values():
        if rows[0].get("attack_level", "") == "":
            continue
        if not _true(rows[0].get("attack_fired")):
            continue
        fired += 1
        marks = [_earned(r) for r in rows]
        p = any(m[0] for m in marks)
        g = any(m[1] for m in marks)
        by_probe += p
        by_guard += g
        caught += (p or g)
        fam = per_family.setdefault(rows[0].get("attack_family", "?"), [0, 0])
        fam[0] += 1
        fam[1] += (p or g)
    return {"fired": fired, "caught_either_way": caught, "probe_earned": by_probe,
            "guard_earned": by_guard,
            "recall_pct": (100.0 * caught / fired) if fired else None,
            "per_family": {k: {"fired": v[0], "caught": v[1]} for k, v in per_family.items()}}


def false_alarm_pct(experiment_ids: list[str]) -> dict[str, Any]:
    n = alarms = 0
    for exp in experiment_ids:
        for rows in _episodes(exp).values():
            if rows[0].get("attack_level", "") != "":
                continue
            n += 1
            alarms += any(_true(r.get("detected")) for r in rows)
    return {"episodes": n, "alarms": alarms, "pct": (100.0 * alarms / n) if n else None}


def verdict() -> dict[str, Any]:
    doc = verify_preregistration()
    th = doc["thresholds"]
    fitted = json.loads((OUT / "fit.json").read_text(encoding="utf-8"))
    l1 = either_way_recall(f"{PREFIX}_insession_L1")
    l6 = either_way_recall(f"{PREFIX}_insession_L6")
    fa_in = false_alarm_pct([f"{PREFIX}_insession_L1", f"{PREFIX}_insession_L6"])
    fa_ctl = false_alarm_pct([f"{PREFIX}_control_separate"])
    gap = (None if l1["recall_pct"] is None or l6["recall_pct"] is None
           else l6["recall_pct"] - l1["recall_pct"])
    rise = (None if fa_in["pct"] is None or fa_ctl["pct"] is None
            else fa_in["pct"] - fa_ctl["pct"])
    h1 = fitted["best_auc"] <= th["auc_ceiling"]
    recall_ok = gap is not None and gap >= -th["recall_within_pp"]
    fa_ok = rise is not None and rise <= th["false_alarm_rise_pp"]
    result = {
        "H2c-1": {"verdict": "PASS" if h1 else "FAIL", "best_family": fitted["best_family"],
                  "best_auc": fitted["best_auc"],
                  "family_auc": {n: r.get("auc") for n, r in fitted["families"].items()}},
        "H2c-2": {"verdict": "PASS" if (recall_ok and fa_ok) else "FAIL",
                  "checks": {"recall_within_tolerance": recall_ok,
                             "false_alarms_contained": fa_ok},
                  "recall_L1": l1, "recall_L6": l6, "recall_gap_pp": gap,
                  "false_alarms_insession": fa_in, "false_alarms_control": fa_ctl,
                  "false_alarm_rise_pp": rise},
        "thresholds": th,
        "note": "Post-hoc follow-up; H2 and H2b stay FAIL. A FAIL here is a result too.",
    }
    (OUT / "verdict.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
