"""The controlled experiments.

Experiment 1 is the one that has to run before any detector change: it measures
the CURRENT detector, with fixed probes, against the full attack matrix. Those
numbers are the "before" half of every later comparison, and they cannot be
reconstructed once the detector has moved.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from eval import ground_truth
from eval.harness import EpisodeConfig, EpisodeResult, run_episode
from eval.record import ResultWriter

FAMILIES = [
    "exfiltration", "silent-tamper", "content-injection",
    "new-egress", "sleeper", "conditional",
]
LEVELS = ["L1", "L2", "L3", "L4", "L5"]


@dataclass
class SweepSpec:
    """One experiment's independent variables."""

    experiment_id: str
    probe_mode: str = "fixed"
    scoring_mode: str = "max"
    families: Sequence[str] = tuple(FAMILIES)
    levels: Sequence[str] = tuple(LEVELS)
    seeds: Sequence[int] = (1, 2, 3)
    benign_seeds: Sequence[int] = (101, 102, 103)
    benign_update_seeds: Sequence[int] = (201, 202, 203)
    cycles: int = 4
    n_probes: int = 3
    n_samples: int = 6
    samples_per_probe: int = 2
    threshold_ratio: float | None = None
    partition: str = "development"


def _configs(spec: SweepSpec) -> list[EpisodeConfig]:
    """Malicious episodes across the matrix, plus the benign controls.

    The benign arms are not optional decoration. Recall on its own says nothing:
    a detector that alerts on everything scores 100%. Every sweep therefore
    carries stable-benign and benign-update episodes so a false-alarm rate can be
    reported next to the recall figure.
    """
    common = dict(
        probe_mode=spec.probe_mode,
        scoring_mode=spec.scoring_mode,
        cycles=spec.cycles,
        n_probes=spec.n_probes,
        n_samples=spec.n_samples,
        samples_per_probe=spec.samples_per_probe,
        threshold_ratio=spec.threshold_ratio,
        partition=spec.partition,
    )
    out: list[EpisodeConfig] = []

    for seed in spec.benign_seeds:
        out.append(EpisodeConfig(spec.experiment_id, mode="benign", updates=False,
                                 seed=seed, **common))
    for seed in spec.benign_update_seeds:
        out.append(EpisodeConfig(spec.experiment_id, mode="benign", updates=True,
                                 seed=seed, **common))
    for family in spec.families:
        for level in spec.levels:
            for seed in spec.seeds:
                out.append(EpisodeConfig(
                    spec.experiment_id, mode="rug-pull", family=family,
                    level=level, seed=seed, **common,
                ))
    return out


def run_sweep(
    spec: SweepSpec,
    attacker_project: str | Path,
    workspace: str | Path,
    out_dir: str | Path,
    *,
    progress: bool = True,
) -> list[EpisodeResult]:
    """Run every episode in a sweep, writing rows as they complete."""
    configs = _configs(spec)
    results: list[EpisodeResult] = []
    started = time.perf_counter()

    with ResultWriter(Path(out_dir), spec.experiment_id) as writer:
        for i, cfg in enumerate(configs, 1):
            result = run_episode(cfg, attacker_project, workspace)
            results.append(result)
            for row in result.rows:
                writer.append(row)
            if progress:
                elapsed = time.perf_counter() - started
                eta = (elapsed / i) * (len(configs) - i)
                score = max((r.final_score for r in result.rows), default=0.0)
                print(
                    f"  [{i:>3}/{len(configs)}] {cfg.label():26s} seed={cfg.seed:<4} "
                    f"{result.outcome:16s} score={score:6.3f}  eta {eta/60:.1f}m",
                    flush=True,
                )
                if result.error:
                    print(f"        ERROR: {result.error}", flush=True)
    return results


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _episode_rows(results: Iterable[EpisodeResult]):
    """One summary row per episode - the unit an experiment reasons about."""
    class _R:
        __slots__ = ("outcome", "final_score", "attack_level", "attack_family",
                     "detected", "probe_recognised", "time_to_detection")

    out = []
    for res in results:
        r = _R()
        r.outcome = res.outcome
        r.final_score = max((row.final_score for row in res.rows), default=0.0)
        r.attack_level = res.config.level if res.config.mode == "rug-pull" else ""
        r.attack_family = res.config.family if res.config.mode == "rug-pull" else res.config.label()
        r.detected = res.detected
        r.probe_recognised = any(row.probe_recognised for row in res.rows)
        r.time_to_detection = max((row.time_to_detection for row in res.rows), default=0.0)
        out.append(r)
    return out


def summarise(results: Sequence[EpisodeResult]) -> str:
    """Recall by level, false-alarm rate, and trigger exposure."""
    rows = _episode_rows(results)
    lines: list[str] = []

    rec, det, exe = ground_truth.recall(rows)
    far, alarms, benign = ground_truth.false_alarm_rate(rows)
    exp, fired, mal = ground_truth.trigger_exposure(rows)

    lines.append("")
    lines.append("=" * 66)
    lines.append("  OVERALL")
    lines.append("=" * 66)
    lines.append(f"  attack recall      : {rec:6.1%}   ({det}/{exe} executed attacks detected)")
    lines.append(f"  false-alarm rate   : {far:6.1%}   ({alarms}/{benign} benign episodes alerted)")
    lines.append(f"  trigger exposure   : {exp:6.1%}   ({fired}/{mal} malicious episodes actually fired)")
    errors = sum(1 for r in rows if r.outcome == "error")
    if errors:
        lines.append(f"  errored episodes   : {errors}")

    lines.append("")
    lines.append("  RECALL BY LEVEL   (executed attacks only)")
    lines.append("  " + "-" * 62)
    lines.append(f"  {'level':<8}{'recall':>10}{'detected':>11}{'executed':>11}{'never fired':>14}")
    for level in LEVELS:
        subset = [r for r in rows if r.attack_level == level]
        if not subset:
            continue
        lrec, ldet, lexe = ground_truth.recall(subset)
        never = sum(1 for r in subset if r.outcome == "never_triggered")
        lines.append(f"  {level:<8}{lrec:>9.1%}{ldet:>11}{lexe:>11}{never:>14}")

    lines.append("")
    lines.append("  RECALL BY FAMILY")
    lines.append("  " + "-" * 62)
    for family in FAMILIES:
        subset = [r for r in rows if r.attack_family == family]
        if not subset:
            continue
        frec, fdet, fexe = ground_truth.recall(subset)
        lines.append(f"  {family:<20}{frec:>9.1%}{fdet:>11}{fexe:>11}")

    recognised = sum(1 for r in rows if r.probe_recognised)
    if recognised:
        lines.append("")
        lines.append(f"  probe recognised by the attacker in {recognised} episode(s)")
    lines.append("=" * 66)
    return "\n".join(lines)


def experiment_1(attacker_project, workspace, out_dir, **kwargs) -> list[EpisodeResult]:
    """Experiment 1 - the current detector, fixed probes, full attack matrix.

    Establishes the baseline vulnerability. Must be run BEFORE any detection
    change, on untouched code, or the control is contaminated.
    """
    spec = SweepSpec(experiment_id="exp1_fixed_probes", probe_mode="fixed", **kwargs)
    return run_sweep(spec, attacker_project, workspace, out_dir)


def experiment_2(attacker_project, workspace, out_dir, **kwargs) -> list[EpisodeResult]:
    """Experiment 2 - the same matrix with keyed dynamic probes.

    The comparison the whole upgrade rests on. Same families, same levels, same
    seeds and the same threshold as Experiment 1, so the only variable is how
    probe values are chosen. Anything that moves is attributable to that.
    """
    spec = SweepSpec(experiment_id="exp2_keyed_probes", probe_mode="keyed", **kwargs)
    return run_sweep(spec, attacker_project, workspace, out_dir)


def compare(control: Sequence[EpisodeResult], treatment: Sequence[EpisodeResult]) -> str:
    """Recall and false alarms, control against treatment, level by level."""
    a, b = _episode_rows(control), _episode_rows(treatment)
    lines = ["", "=" * 74,
             "  EXPERIMENT 1 (fixed probes)  vs  EXPERIMENT 2 (keyed probes)",
             "=" * 74,
             f"  {'level':<8}{'fixed recall':>15}{'keyed recall':>15}"
             f"{'fixed fired':>14}{'keyed fired':>14}"]

    for level in LEVELS:
        sa = [r for r in a if r.attack_level == level]
        sb = [r for r in b if r.attack_level == level]
        if not sa and not sb:
            continue
        ra, da, ea = ground_truth.recall(sa)
        rb, db, eb = ground_truth.recall(sb)
        fa = sum(1 for r in sa if r.outcome != "never_triggered")
        fb = sum(1 for r in sb if r.outcome != "never_triggered")
        lines.append(
            f"  {level:<8}"
            f"{(f'{ra:.0%} ({da}/{ea})' if ea else 'n/a - never fired'):>15}"
            f"{(f'{rb:.0%} ({db}/{eb})' if eb else 'n/a - never fired'):>15}"
            f"{fa:>14}{fb:>14}"
        )

    fara, alarms_a, benign_a = ground_truth.false_alarm_rate(a)
    farb, alarms_b, benign_b = ground_truth.false_alarm_rate(b)
    lines.append("")
    lines.append(f"  false-alarm rate  fixed {fara:.1%} ({alarms_a}/{benign_a})   "
                 f"keyed {farb:.1%} ({alarms_b}/{benign_b})")

    expa = ground_truth.trigger_exposure(a)
    expb = ground_truth.trigger_exposure(b)
    lines.append(f"  trigger exposure  fixed {expa[0]:.1%} ({expa[1]}/{expa[2]})   "
                 f"keyed {expb[0]:.1%} ({expb[1]}/{expb[2]})")
    lines.append("")
    lines.append("  Trigger exposure is the headline: a probe-aware attacker that never")
    lines.append("  fires is not 'missed', it is deterred from acting while observed.")
    lines.append("  Forcing it to act is what keyed probes are for; catching it is then")
    lines.append("  the job of the signals.")
    lines.append("=" * 74)
    return "\n".join(lines)
