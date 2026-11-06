"""T20 - the countermeasure comparison, and what it costs (Gap 2(c) / RQ4).

RQ4 asks whether probing can be made realistic enough that a server cannot
recognise it, and what that costs. Gap 2's first two parts established the
threat: RQ3 measured four channels that separate probe traffic from genuine
traffic almost perfectly (client 1.000, session 0.983, timing 0.951,
argument 0.763), and Experiment 3 showed an attacker using any one of them
takes detection to zero. This part asks whether anything can be done about
it.

The design, and the two places it would be easy to cheat

    ONE VARIABLE AT A TIME. The five conditions in eval/conditions.py each
    switch on exactly one thing more than the last. Turning several on
    together would make any change unattributable, which is why the
    countermeasures were written and left switched off rather than enabled as
    they were finished.

    THE RECOGNISER IS RE-FITTED PER CONDITION. A model trained against
    unprotected probing and tested against protected probing measures how
    stale a model goes, not whether the countermeasure works. Each condition
    collects its own probe traffic and fits its own recogniser on it.

Why the genuine half is collected once and reused

    A countermeasure changes how the DETECTOR probes. It does not change how
    a user's model behaves, so the genuine class is the same population in
    every condition. The 120 genuine sessions from the RQ3 collection are
    therefore reused, and only probe traffic is collected per condition.

    This is a tighter comparison than re-collecting would be - the genuine
    half is held fixed, so every difference between conditions comes from
    probe traffic - and it costs four runs of 120 local model sessions. The
    limitation to state in the write-up is that the five conditions share
    their genuine rows, so their confidence intervals are correlated and
    should not be read as independent measurements.

What is recorded per condition

    best_auc        the strongest family's cross-validated AUC, which is the
                    attacker's best case.
    recall at L1    detection with the attacker firing on every call.
    recall at L6    detection with the attacker scoring each call against the
                    recogniser fitted on THIS condition's traffic.
    false alarms    from the benign arms of the same sweep. Recall alone says
                    nothing: a detector that alerts on everything scores 100%.
    cycle_seconds   wall clock per verification cycle.
    calls_per_cycle how many tool calls a cycle makes.

The last two are the cost half of RQ4 and the reason the subsample condition
exists at all. A countermeasure that restores detection by tripling the time
and traffic of every cycle has not solved the problem; it has moved it, and
the table has to show that rather than report the AUC alone.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Any

from eval.conditions import BY_NAME, CONDITIONS, Condition

# The RQ3 collection, whose genuine half every condition reuses.
GENUINE_SOURCE = Path("eval_results/rq3")

# Probe cycles collected per condition. The RQ3 collection has 120 genuine
# windows and 120 probe windows; 60 keeps the probe class large enough to fit
# on while halving the collection time, at the cost of a wider interval.
PROBE_CYCLES = 60

# "all" is a superset of the single families, so it is eligible to be the
# best classifier - an attacker is not obliged to use one channel.
GENUINE, PROBE = 0, 1


# --------------------------------------------------------------------------- #
# Probe-only collection
# --------------------------------------------------------------------------- #
async def collect_probes(
    cond: Condition,
    attacker_project: str | Path,
    out_dir: str | Path,
    workspace: str | Path,
    *,
    cycles: int = PROBE_CYCLES,
    seed: int = 20260720,
    progress: bool = True,
) -> dict[str, Any]:
    """Probe traffic under one condition, labelled and timed.

    No agent sessions: the genuine class comes from the RQ3 collection. The
    server stays benign throughout, as in T5 - this measures whether probe
    traffic is recognisable, which is a question about traffic and not about
    attacks.
    """
    from driftsentry import keys as key_store
    from driftsentry.baseline import capture_baseline

    from eval.collect import Collector
    from eval.launch import probe_launch

    collector = Collector(
        attacker_project, out_dir, workspace,
        server_id="t20", seed=seed,
        mimic_host=cond.mimic_host,
        mimic_traffic=cond.mimic_traffic,
        subsample_bank=cond.subsample_bank,
    )
    collector.prepare()

    from eval.profiles import install

    installed = install(collector.server_id,
                        mimic_host=cond.mimic_host,
                        mimic_traffic=cond.mimic_traffic)
    if progress and installed:
        print(f"    profiles: {installed}", flush=True)

    key = key_store.derive_experiment_key(seed, f"t20-{cond.name}")
    launch = probe_launch(collector.attacker_project, collector.atk_home)

    baseline = await capture_baseline(
        collector.server_id, launch["command"], launch["args"],
        cwd=launch["cwd"], env=launch["env"],
        n_probes=collector.n_probes, n_samples=collector.n_samples, seed=seed,
        probe_mode="keyed", key=key,
        monitor_sandbox=collector.monitor_sandbox,
        mimic_host=cond.mimic_host,
    )
    baseline_cutoff = time.time()

    durations: list[float] = []
    for i in range(cycles):
        t0 = time.perf_counter()
        report = await collector.probe_cycle(baseline, cycle=i + 1, key=key)
        durations.append(time.perf_counter() - t0)
        if progress and (i + 1) % 5 == 0:
            mean = sum(durations) / len(durations)
            left = (cycles - i - 1) * mean / 60.0
            print(f"    [{i + 1:>3}/{cycles}] score={getattr(report, 'score', 0.0):.3f}"
                  f"  {mean:.1f}s/cycle  eta {left:.1f}m", flush=True)

    summary = collector.finish(baseline_cutoff, [])
    summary["condition"] = cond.name
    summary["cycle_seconds"] = round(sum(durations) / len(durations), 2) if durations else 0.0
    summary["calls_per_cycle"] = _calls_per_cycle(Path(out_dir))
    (Path(out_dir) / "collection.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _calls_per_cycle(out_dir: Path) -> float:
    """Mean tool calls inside a probe window.

    Counted from the attacker's own rows rather than from the detector's
    intent, so a countermeasure that quietly changes how many calls a cycle
    makes - which subsampling does deliberately - is measured and not assumed.
    """
    features, windows = out_dir / "features.jsonl", out_dir / "windows.jsonl"
    if not (features.is_file() and windows.is_file()):
        return 0.0
    bounds = [(w["start"], w["end"]) for w in _jsonl(windows) if w["label"] == PROBE]
    if not bounds:
        return 0.0
    counts = [0] * len(bounds)
    for row in _jsonl(features):
        t = row.get("t")
        if t is None:
            continue
        for i, (start, end) in enumerate(bounds):
            if start <= t <= end:
                counts[i] += 1
                break
    seen = [c for c in counts if c]
    return round(sum(seen) / len(seen), 1) if seen else 0.0


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# The merged dataset
# --------------------------------------------------------------------------- #
def merge_with_genuine(
    probe_dir: str | Path,
    genuine_dir: str | Path = GENUINE_SOURCE,
) -> Path:
    """Put this condition's probe traffic beside the shared genuine traffic.

    The join in rq3_dataset is by time window, and the two collections ran at
    different times, so concatenating their files cannot mix a row into the
    wrong window. The genuine source's own probe windows are dropped: keeping
    them would put unprotected probe traffic into a protected condition's
    probe class and understate the countermeasure.
    """
    probe_dir, genuine_dir = Path(probe_dir), Path(genuine_dir)
    merged = probe_dir / "merged"
    merged.mkdir(parents=True, exist_ok=True)

    windows = [w for w in _jsonl(genuine_dir / "windows.jsonl") if w["label"] == GENUINE]
    windows += [w for w in _jsonl(probe_dir / "windows.jsonl") if w["label"] == PROBE]
    (merged / "windows.jsonl").write_text(
        "\n".join(json.dumps(w) for w in windows) + "\n", encoding="utf-8")

    with (merged / "features.jsonl").open("w", encoding="utf-8") as handle:
        for source in (genuine_dir / "features.jsonl", probe_dir / "features.jsonl"):
            if source.is_file():
                handle.write(source.read_text(encoding="utf-8").rstrip("\n") + "\n")
    return merged


def fit(probe_dir: str | Path, attacker_project: str | Path) -> dict[str, Any]:
    """Build the dataset, fit every family, and say which one wins."""
    from eval.rq3_dataset import build
    from eval.rq3_distinguish import analyse

    merged = merge_with_genuine(probe_dir)
    build(merged)
    summary = analyse(merged / "dataset.jsonl", attacker_project,
                      out_dir=merged, n_boot=2000, seed=0)

    scored = {name: res["auc"] for name, res in summary["families"].items()
              if "auc" in res}
    if not scored:
        raise RuntimeError("no family fitted; the dataset is unusable")
    best = max(scored, key=lambda n: scored[n])
    summary["best_family"] = best
    summary["best_auc"] = scored[best]
    summary["recogniser"] = str(merged / f"recogniser_{best}.json")
    (Path(probe_dir) / "fit.json").write_text(
        json.dumps({k: v for k, v in summary.items() if k != "families"} |
                   {"families": summary["families"]}, indent=2), encoding="utf-8")
    return summary


# --------------------------------------------------------------------------- #
# The attack matrix under one condition
# --------------------------------------------------------------------------- #
def run_matrix(
    cond: Condition,
    recogniser: str,
    attacker_project: str | Path,
    workspace: str | Path,
    out_dir: str | Path,
    *,
    seeds: tuple[int, ...] = (1, 2),
    families: tuple[str, ...] | None = None,
    cycles: int = 4,
    replay_sessions: int = 2,
) -> dict[str, Any]:
    """L1 against L6 under this condition, with the benign arms.

    launch_parity is on and replay_sessions is above zero for the same
    reasons as Experiment 3: without parity the recogniser separates the
    classes on environment size, a property of the harness; without replayed
    genuine traffic an L6 attacker never fires at all and the recall this
    exists to measure is undefined.
    """
    from eval.experiments import SweepSpec, run_sweep

    rows: dict[str, Any] = {}
    for level in ("L1", "L6"):
        spec = SweepSpec(
            experiment_id=f"t20_{cond.name}_{level}",
            probe_mode="keyed",
            levels=(level,),
            seeds=seeds,
            cycles=cycles,
            **({"families": families} if families else {}),
            launch_parity=True,
            replay_sessions=replay_sessions,
            recogniser=recogniser,
            mimic_host=cond.mimic_host,
            mimic_traffic=cond.mimic_traffic,
            subsample_bank=cond.subsample_bank,
        )
        rows[level] = run_sweep(spec, attacker_project, workspace, out_dir)
    return rows


def _rates(results: list[Any]) -> tuple[float, int, int]:
    """Recall over episodes where the attack actually fired."""
    fired = [r for r in results if r.config.mode == "rug-pull"
             and r.outcome in ("detected", "missed")]
    if not fired:
        return float("nan"), 0, 0
    hits = sum(1 for r in fired if r.outcome == "detected")
    return 100.0 * hits / len(fired), hits, len(fired)


def _false_alarms(results: list[Any]) -> tuple[float, int, int]:
    benign = [r for r in results if r.config.mode == "benign"
              and r.outcome in ("benign_ok", "false_alarm")]
    if not benign:
        return float("nan"), 0, 0
    bad = sum(1 for r in benign if r.outcome == "false_alarm")
    return 100.0 * bad / len(benign), bad, len(benign)


def summarise_condition(cond_name: str, arms: dict[str, list[Any]],
                        collection: dict[str, Any]) -> dict[str, Any]:
    """One row of the RQ4 table."""
    l1_recall, l1_hits, l1_n = _rates(arms["L1"])
    l6_recall, l6_hits, l6_n = _rates(arms["L6"])
    fa, fa_bad, fa_n = _false_alarms(arms["L1"] + arms["L6"])
    return {
        "condition": cond_name,
        "l1_recall_pct": l1_recall,
        "l1_detected": f"{l1_hits}/{l1_n}",
        "recall_pct": l6_recall,
        "l6_detected": f"{l6_hits}/{l6_n}",
        # H4 reads this: how far L6 detection sits from the no-evasion level.
        "recall_gap_pp": (l6_recall - l1_recall
                          if l1_n and l6_n else None),
        "false_alarm_pct": fa,
        "false_alarms": f"{fa_bad}/{fa_n}",
        "cycle_seconds": collection.get("cycle_seconds", float("nan")),
        "calls_per_cycle": collection.get("calls_per_cycle", 0),
    }


# --------------------------------------------------------------------------- #
# The whole comparison
# --------------------------------------------------------------------------- #
def run(
    attacker_project: str | Path,
    workspace: str | Path,
    out_dir: str | Path,
    *,
    conditions: tuple[str, ...] = tuple(c.name for c in CONDITIONS),
    cycles: int = PROBE_CYCLES,
    seeds: tuple[int, ...] = (1, 2),
    families: tuple[str, ...] | None = None,
    resume: bool = True,
    progress: bool = True,
) -> dict[str, Any]:
    """Run every condition, then judge H4.

    Resumable by design. The full comparison is hours of wall clock, and a
    machine that restarts partway through should not lose the conditions
    already measured - a sweep was lost that way once already.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    table_path = out_dir / "t20_results.json"

    results: dict[str, Any] = {}
    if resume and table_path.is_file():
        results = json.loads(table_path.read_text(encoding="utf-8"))

    for name in conditions:
        cond = BY_NAME[name]
        if resume and name in results.get("conditions", {}):
            if progress:
                print(f"\n== {cond.describe()} - already measured, skipping")
            continue

        if progress:
            print(f"\n{'=' * 72}\n== {cond.describe()}\n{'=' * 72}", flush=True)

        cond_dir = out_dir / name
        cond_dir.mkdir(parents=True, exist_ok=True)

        # 1. this condition's probe traffic
        collection_path = cond_dir / "collection.json"
        if resume and collection_path.is_file():
            collection = json.loads(collection_path.read_text(encoding="utf-8"))
            if progress:
                print(f"  probe traffic: reusing {collection['probe_windows']} windows")
        else:
            if progress:
                print(f"  collecting {cycles} probe cycles", flush=True)
            collection = asyncio.run(collect_probes(
                cond, attacker_project, cond_dir,
                Path(workspace) / f"t20-{name}", cycles=cycles,
                progress=progress))

        # 2. the recogniser the attacker would hold against this condition
        fit_path = cond_dir / "fit.json"
        if resume and fit_path.is_file():
            fitted = json.loads(fit_path.read_text(encoding="utf-8"))
        else:
            if progress:
                print("  fitting recognisers", flush=True)
            fitted = fit(cond_dir, attacker_project)
        if progress:
            print(f"  best channel : {fitted['best_family']} "
                  f"AUC {fitted['best_auc']:.3f}", flush=True)

        # 3. the attack matrix, L1 against L6
        if progress:
            print("  running the matrix", flush=True)
        arms = run_matrix(cond, fitted["recogniser"], attacker_project,
                          workspace, out_dir, seeds=seeds, families=families)

        row = summarise_condition(name, arms, collection)
        row["best_auc"] = fitted["best_auc"]
        row["best_family"] = fitted["best_family"]

        results.setdefault("conditions", {})[name] = row
        table_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        if progress:
            print(f"  {name}: L1 {row['l1_recall_pct']:.1f}%  "
                  f"L6 {row['recall_pct']:.1f}%  "
                  f"false alarms {row['false_alarm_pct']:.1f}%", flush=True)

    results["h4"] = _verdict(results.get("conditions", {}))
    table_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def _verdict(conditions: dict[str, Any]) -> dict[str, Any]:
    from eval.conditions import h4_verdict

    return h4_verdict(conditions)


def report(results: dict[str, Any]) -> str:
    """The RQ4 table and H4's verdict."""
    from eval.conditions import cost_table

    conditions = results.get("conditions", {})
    lines = ["", "=" * 72,
             "  T20 - countermeasures against a learned recogniser (RQ4 / H4)",
             "=" * 72,
             cost_table(conditions),
             ""]

    lines += [f"  {'condition':<12}{'channel':>14}{'L1 recall':>12}{'L6 recall':>12}{'gap':>9}",
              "  " + "-" * 60]
    for name in (c.name for c in CONDITIONS):
        row = conditions.get(name)
        if not row:
            lines.append(f"  {name:<12}{'not measured':>14}")
            continue
        gap = row.get("recall_gap_pp")
        lines.append(f"  {name:<12}{row.get('best_family', '?'):>14}"
                     f"{row.get('l1_recall_pct', float('nan')):>11.1f}%"
                     f"{row.get('recall_pct', float('nan')):>11.1f}%"
                     f"{(f'{gap:+.1f}pp' if gap is not None else 'n/a'):>9}")

    h4 = results.get("h4") or {}
    lines += ["", f"  H4: {h4.get('verdict', 'UNDEFINED')}"]
    if "checks" in h4:
        for check, passed in h4["checks"].items():
            lines.append(f"    {'pass' if passed else 'FAIL':<5} {check}")
    if h4.get("reason"):
        lines.append(f"    {h4['reason']}")
    if h4.get("note"):
        lines += ["", f"  {h4['note']}"]
    return "\n".join(lines)
