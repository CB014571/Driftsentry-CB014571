"""H2b - the follow-up to H2: in-session verification.

H2 FAILED and stays failed. Its countermeasures imitated the surface of a
separate verification session and the best recogniser still reached AUC
0.994. This is a NEW experiment, designed after that result, testing a
different mechanism: probes sent inside the user's own session
(driftsentry/insession.py) with argument values shaped to genuine traffic.
It is reported as a post-hoc follow-up, under its own pre-registered
hypothesis, and does not change the H2 verdict.

The design, and where it would be easy to cheat

    SAME BAR AS H2. The hypothesis uses H2's thresholds unchanged: best AUC
    <= 0.6, recall within 10 points of L1, false alarms up by at most 2
    points. A follow-up that lowered the bar would not answer anything.

    FROZEN BEFORE ANY DATA. ``preregister`` writes the hypothesis, the
    thresholds, the procedure and the genuine split to a file and records its
    sha256. ``verify_preregistration`` fails if any of it changed. The file
    is written before the first collection run.

    SHAPES FROM HALF THE GENUINE DATA. Probe arguments are shaped to genuine
    traffic, and genuine traffic is also what they are compared with. To
    stop the shaping being fitted to its own test, the genuine sessions are
    split in two by a hash of their content: shapes, gaps and startup delays
    are learned from split A only, and every genuine call replayed in this
    experiment comes from split B.

    THE RECOGNISER IS RE-FITTED ON IN-SESSION TRAFFIC, as T20 did per
    condition: a model fitted to the old traffic would measure staleness,
    not recognisability.

    PROBE-EARNED DETECTION. In a shared session a side effect from an attack
    on a GENUINE call (a file still held open) can be visible while a probe
    runs. That is a real benefit in deployment, but it would credit probes
    with detections they did not earn. H2b's recall counts a detection only
    when the attacker's own log shows it fired during a probe call.

    ONE PROBE PER CALL. samples_per_probe is 1: sending the same arguments
    twice in a row is something no genuine session in the corpus does.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval_results" / "followup" / "h2b"
PREREG = OUT / "preregistration.json"
PROFILE_A = OUT / "profile_split_a.json"

GENUINE, PROBE = 0, 1

#: H2's thresholds, unchanged (eval/conditions.h4_verdict).
AUC_CEILING = 0.6
RECALL_WITHIN_PP = 10.0
FALSE_ALARM_RISE_PP = 2.0

#: Procedure, frozen with the hypothesis.
COLLECT_SESSIONS = 60
REPLAY_SESSIONS = 8           # genuine sessions replayed into each live session
MATRIX_SEEDS = (1, 2)
MATRIX_CYCLES = 4
N_PROBES_BASELINE = 8         # shaped values vary more; the family needs to see it


# --------------------------------------------------------------------------- #
# The genuine split
# --------------------------------------------------------------------------- #
def _session_key(calls: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(calls, sort_keys=True).encode("utf-8")).hexdigest()


def genuine_split(part: str) -> list[list[dict[str, Any]]]:
    """Genuine sessions in split ``A`` or ``B``, by a hash of their content."""
    from eval.replay import load_sessions

    want = 0 if part.upper() == "A" else 1
    return [s for s in load_sessions() if int(_session_key(s)[:8], 16) % 2 == want]


def profile_from_sessions(sessions: list[list[dict[str, Any]]], server: str) -> Any:
    """A TrafficProfile learned from recorded sessions (split A).

    Same fields traffic.learn() derives from a proxy log: gaps between calls,
    the delay before a session's first call, and per-tool argument shapes.
    """
    from driftsentry.traffic import MAX_GAP_S, ToolShape, TrafficProfile, _arg_text, skeleton

    gaps, startups, texts = [], [], {}
    for calls in sessions:
        for i, call in enumerate(calls):
            if i == 0 and call.get("proc_age_s") is not None:
                if 0.0 <= call["proc_age_s"] <= MAX_GAP_S:
                    startups.append(float(call["proc_age_s"]))
            elif call.get("gap_s") is not None and 0.0 <= call["gap_s"] <= MAX_GAP_S:
                gaps.append(float(call["gap_s"]))
            texts.setdefault(call["tool"], []).append(_arg_text(call.get("args")))
    shapes = {}
    for tool, values in texts.items():
        joined, lengths = "".join(values), [len(v) for v in values]
        shapes[tool] = ToolShape(
            n_observed=len(values), min_len=min(lengths), max_len=max(lengths),
            median_len=int(statistics.median(lengths)),
            digit_ratio=(sum(c.isdigit() for c in joined) / len(joined)) if joined else 0.0,
            space_ratio=(joined.count(" ") / len(joined)) if joined else 0.0,
            lengths=sorted(lengths),
            skeletons=sorted(skeleton(v) for v in values))
    return TrafficProfile(server=server, n_sessions=len(sessions),
                          n_calls=sum(len(s) for s in sessions),
                          calls_per_session=[len(s) for s in sessions],
                          gaps_s=gaps, startup_s=startups, tool_shapes=shapes)


def load_profile_a() -> Any:
    from driftsentry.traffic import TrafficProfile

    return TrafficProfile.from_dict(json.loads(PROFILE_A.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# Pre-registration
# --------------------------------------------------------------------------- #
def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preregister(server_id: str = "target") -> dict[str, Any]:
    """Freeze the hypothesis, procedure and genuine split. Refuses to overwrite."""
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
        "id": "H2b",
        "written": datetime.now().isoformat(timespec="seconds"),
        "code_commit": commit,
        "status": "post-hoc follow-up to H2, designed after H2 failed; H2 stays FAIL",
        "hypothesis": (
            "Verifying inside the user's own session, with keyed argument values "
            "shaped to genuine traffic (shapes, gaps and startup delays learned "
            "from genuine split A only), makes probes unrecognisable: the best "
            "cross-validated recogniser (any family, including 'all') reaches "
            f"AUC <= {AUC_CEILING}; probe-earned L6 recall is within "
            f"{RECALL_WITHIN_PP} points of L1; and benign false alarms rise by "
            f"at most {FALSE_ALARM_RISE_PP} points over the separate-session control."),
        "thresholds": {"auc_ceiling": AUC_CEILING, "recall_within_pp": RECALL_WITHIN_PP,
                       "false_alarm_rise_pp": FALSE_ALARM_RISE_PP},
        "procedure": {
            "collection_sessions": COLLECT_SESSIONS,
            "genuine_sessions_replayed_per_live_session": REPLAY_SESSIONS,
            "samples_per_probe": 1, "subsample_bank": True,
            "baseline_probes_per_family": N_PROBES_BASELINE,
            "recogniser": "eval.rq3_distinguish.analyse, 5-fold GroupKFold by process, "
                          "re-fitted on this traffic; best family exported to L6",
            "matrix": {"levels": ["L1", "L6"], "seeds": list(MATRIX_SEEDS),
                       "cycles": MATRIX_CYCLES, "families": "all six"},
            "recall": "probe-earned: an episode counts as detected only if an alert "
                      "is raised in a cycle where the attacker's events log shows it "
                      "fired during a probe call; denominator = episodes whose attack "
                      "fired at all; an alert that is not probe-earned does not end "
                      "the episode",
            "false_alarm_control": "separate-session keyed verification on the same "
                                   "benign seeds (condition 'none' of T20, re-run here)",
        },
        "genuine_split": {"rule": "sha256(json(session)) first 8 hex digits mod 2: "
                                  "0 -> A (shapes), 1 -> B (replayed)",
                          "n_sessions_a": len(a), "n_sessions_b": len(b),
                          "profile_a_sha256": _sha(PROFILE_A)},
    }
    PREREG.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    sidecar = PREREG.with_suffix(".sha256")
    sidecar.write_text(_sha(PREREG) + "\n", encoding="utf-8")
    return doc


def verify_preregistration() -> dict[str, Any]:
    """Fail loudly if the pre-registration or the split-A profile changed."""
    doc = json.loads(PREREG.read_text(encoding="utf-8"))
    recorded = PREREG.with_suffix(".sha256").read_text(encoding="utf-8").strip()
    if _sha(PREREG) != recorded:
        raise RuntimeError("preregistration.json no longer matches its recorded sha256")
    if _sha(PROFILE_A) != doc["genuine_split"]["profile_a_sha256"]:
        raise RuntimeError("profile_split_a.json changed after pre-registration")
    return doc


def shapes_dict() -> dict[str, Any]:
    return dict(load_profile_a().tool_shapes)


# --------------------------------------------------------------------------- #
# One in-session verification cycle
# --------------------------------------------------------------------------- #
def _attacker_pids(before: set[int]) -> list[int]:
    """The attacker process(es) behind the proxy - not the proxy itself.

    The proxy writes its own logs; watching it would report those as files
    the server opened, a false alarm made by the measurement.
    """
    import psutil

    out = []
    try:
        for proc in psutil.Process().children(recursive=True):
            if proc.pid in before:
                continue
            try:
                cmd = " ".join(proc.cmdline())
            except Exception:
                continue
            if " attacker" in cmd and "driftsentry" not in cmd:
                out.append(proc.pid)
    except Exception:
        pass
    return out


async def insession_cycle(
    baseline: Any,
    *,
    attacker_project: Path,
    atk_home: Path,
    ds_home: Path,
    server_id: str,
    cycle: int,
    key: bytes,
    seed: int,
    replay_sessions: int,
    threshold_ratio: float | None,
    monitor_sandbox: bool = True,
    shapes: dict[str, Any] | None = None,
    profile: Any = None,
    guard: bool = False,
) -> tuple[Any, list[Any]]:
    """Open one live session through the proxy and verify inside it.

    ``guard`` (H2c): one continuous watch is shared by the probes and the
    real-call guard, and the guard checks every replayed genuine call - the
    same arrangement the product proxy runs.

    Returns the drift report and every call record (genuine and probe), in
    the order the server received them.
    """
    import psutil
    from mcp import ClientSession, types
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from driftsentry.insession import InSessionChannel, expected_probe_calls
    from driftsentry.verify import verify_server
    from eval.agent import load_host_profile
    from eval.launch import agent_launch
    from eval.replay import choose_sessions

    picked = choose_sessions(genuine_split("B"), replay_sessions, seed=seed * 1000 + cycle)
    genuine = [call for session in picked for call in session]
    client_info, _ = load_host_profile()
    launch = agent_launch(attacker_project, atk_home, ds_home, server_id, passive=True)
    params = StdioServerParameters(command=launch["command"], args=launch["args"],
                                   cwd=launch.get("cwd"), env=launch.get("env"))
    try:
        before = {p.pid for p in psutil.Process().children(recursive=True)}
    except Exception:
        before = set()

    async with stdio_client(params, errlog=None) as (read, write):
        async with ClientSession(read, write, client_info=types.Implementation(
                name=client_info["name"], version=client_info["version"])) as session:
            await session.initialize()
            pids = []
            for _ in range(50):              # the proxy starts the attacker itself
                pids = _attacker_pids(before)
                if pids:
                    break
                time.sleep(0.05)
            channel = InSessionChannel(
                session, genuine, key=key, server=server_id, cycle=cycle,
                profile=profile,
                expected_probes=expected_probe_calls(baseline, 1, True))
            watch = None
            if guard and monitor_sandbox and pids:
                from driftsentry.sandbox import ContinuousMonitor

                watch = ContinuousMonitor(pids).start()
            try:
                report = await verify_server(
                    baseline, session=channel, server_pids=pids,
                    samples_per_probe=1, monitor_sandbox=monitor_sandbox,
                    threshold_ratio=threshold_ratio, cycle=cycle, key=key,
                    subsample_bank=True, shapes=shapes, watch=watch)
                records = await channel.finish()
                if guard:
                    from driftsentry.guard import RealCallGuard, apply_guard

                    checker = RealCallGuard(server_id, baseline, watch)
                    for r in records:
                        if r.kind == "genuine" and r.mono_end:
                            checker.check(r.tool, r.args, r.result, r.mono_start, r.mono_end)
                    apply_guard(report, checker.take())
            finally:
                if watch is not None:
                    watch.close()
    return report, records


# --------------------------------------------------------------------------- #
# Probe-earned attribution
# --------------------------------------------------------------------------- #
def _stamp(text: str) -> float | None:
    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def read_attacker_events(atk_home: str | Path) -> list[tuple[str, str, str]]:
    """The attacker's own events log: (timestamp, kind, detail) per act."""
    path = Path(atk_home) / "sink" / "events.log"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


def events_in_windows(events: list[tuple[str, str, str]], records: list[Any],
                      kind: str = "probe") -> int:
    """Attacker events that fall inside a call window of the given kind.

    Needs the attacker's sub-second event stamps; a stamp rounded to the
    second would smear an event across neighbouring calls.
    """
    windows = [(r.start, r.end) for r in records if r.kind == kind and r.end]
    count = 0
    for stamp, _kind, _detail in events:
        t = _stamp(stamp)
        if t is not None and any(s <= t <= e for s, e in windows):
            count += 1
    return count


# --------------------------------------------------------------------------- #
# Stage 1: collect in-session traffic (benign server), one window per call
# --------------------------------------------------------------------------- #
async def collect(attacker_project: str | Path, workspace: str | Path, *,
                  sessions: int = COLLECT_SESSIONS, seed: int = 20261115,
                  progress: bool = True) -> dict[str, Any]:
    """Probe and genuine calls from the SAME live sessions, labelled per call.

    The server stays benign: this stage measures whether probe traffic is
    recognisable, a question about traffic and not about attacks. Every call
    gets its own labelled window, because probes and genuine calls now share
    a session and no session-level window could separate them.
    """
    from driftsentry import keys as key_store
    from driftsentry.baseline import capture_baseline

    from eval.collect import Collector
    from eval.launch import probe_launch

    verify_preregistration()
    shapes, profile = shapes_dict(), load_profile_a()
    out = OUT / "collection"
    col = Collector(attacker_project, out, workspace, server_id="h2b", seed=seed,
                    n_probes=N_PROBES_BASELINE, samples_per_probe=1,
                    subsample_bank=True)
    col.prepare()
    key = key_store.derive_experiment_key(seed, "h2b-collect")
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
            monitor_sandbox=col.monitor_sandbox, shapes=shapes, profile=profile)
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


# --------------------------------------------------------------------------- #
# Stage 2: fit every family on that traffic
# --------------------------------------------------------------------------- #
def fit(attacker_project: str | Path) -> dict[str, Any]:
    """Cross-validated AUC per family on in-session traffic; export the best."""
    from eval.rq3_dataset import build
    from eval.rq3_distinguish import analyse

    verify_preregistration()
    out = OUT / "collection"
    # In-session: one process serves both kinds of call by design (amendment 1).
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


# --------------------------------------------------------------------------- #
# Stage 3: the L1 / L6 matrix in-session, and the separate-session control
# --------------------------------------------------------------------------- #
def matrix(attacker_project: str | Path, workspace: str | Path) -> None:
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    fitted = json.loads((OUT / "fit.json").read_text(encoding="utf-8"))
    for level in ("L1", "L6"):
        spec = SweepSpec(
            experiment_id=f"h2b_insession_{level}", probe_mode="keyed",
            levels=(level,), seeds=MATRIX_SEEDS, cycles=MATRIX_CYCLES,
            n_probes=N_PROBES_BASELINE, samples_per_probe=1,
            launch_parity=True, replay_sessions=REPLAY_SESSIONS,
            recogniser=fitted["recogniser"], subsample_bank=True,
            in_session=True, shapes=shapes_dict())
        run_sweep(spec, attacker_project, workspace, OUT)


def control(attacker_project: str | Path, workspace: str | Path) -> None:
    """Benign arms only, verified the old way (separate session), same seeds."""
    from eval.experiments import SweepSpec, run_sweep

    verify_preregistration()
    spec = SweepSpec(experiment_id="h2b_control_separate", probe_mode="keyed",
                     families=(), levels=("L1",), cycles=MATRIX_CYCLES,
                     samples_per_probe=1, launch_parity=True, subsample_bank=True)
    run_sweep(spec, attacker_project, workspace, OUT)


# --------------------------------------------------------------------------- #
# Stage 4: the verdict, exactly as pre-registered
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


def _true(v: str | None) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def probe_earned_recall(experiment_id: str) -> dict[str, Any]:
    """Recall over attacks that fired, counting only probe-earned detections."""
    fired = earned = any_detected = 0
    for rows in _episodes(experiment_id).values():
        if rows[0].get("attack_level", "") == "":         # benign arm
            continue
        if not _true(rows[0].get("attack_fired")):
            continue
        fired += 1
        if any(_true(r.get("detected")) for r in rows):
            any_detected += 1
        if any(_true(r.get("detected")) and int(r.get("probe_window_events") or 0) > 0
               for r in rows):
            earned += 1
    return {"fired": fired, "probe_earned": earned, "any_detection": any_detected,
            "recall_pct": (100.0 * earned / fired) if fired else None}


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
    l1 = probe_earned_recall("h2b_insession_L1")
    l6 = probe_earned_recall("h2b_insession_L6")
    fa_in = false_alarm_pct(["h2b_insession_L1", "h2b_insession_L6"])
    fa_ctl = false_alarm_pct(["h2b_control_separate"])
    gap = (None if l1["recall_pct"] is None or l6["recall_pct"] is None
           else l6["recall_pct"] - l1["recall_pct"])
    rise = (None if fa_in["pct"] is None or fa_ctl["pct"] is None
            else fa_in["pct"] - fa_ctl["pct"])
    checks = {
        "auc_at_or_below_ceiling": fitted["best_auc"] <= th["auc_ceiling"],
        "recall_within_tolerance": gap is not None and abs(gap) <= th["recall_within_pp"],
        "false_alarms_contained": rise is not None and rise <= th["false_alarm_rise_pp"],
    }
    result = {
        "hypothesis": "H2b", "verdict": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks, "best_family": fitted["best_family"],
        "best_auc": fitted["best_auc"],
        "family_auc": {n: r.get("auc") for n, r in fitted["families"].items()},
        "recall_L1": l1, "recall_L6": l6, "recall_gap_pp": gap,
        "false_alarms_insession": fa_in, "false_alarms_control": fa_ctl,
        "false_alarm_rise_pp": rise, "thresholds": th,
        "note": "Post-hoc follow-up to H2, which stays FAIL. A FAIL here is a result too.",
    }
    (OUT / "verdict.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
