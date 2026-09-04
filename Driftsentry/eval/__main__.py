"""Command line for the evaluation harness.

    python -m eval selftest                 # validate the ground truth first
    python -m eval run --experiment 1       # the control condition
    python -m eval run --experiment 1 --quick
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACKER = ROOT.parent / "mcp rug pull attack server"
DEFAULT_WORKSPACE = ROOT / ".eval_workspace"
DEFAULT_RESULTS = ROOT / "eval_results"


def _quiet() -> None:
    """Silence the detector's own logging; episode progress is the output."""
    logging.disable(logging.WARNING)


def _cmd_selftest(ns: argparse.Namespace) -> int:
    """Check the attacker's ground truth before trusting any measurement."""
    from eval.scenario_control import AttackerControl

    control = AttackerControl.discover(ns.attacker)
    print(f"attacker: {control.project_dir}")
    output = control.selftest()
    passed = output.count("[PASS]")
    failed = output.count("[FAIL]")
    print(f"  {passed} checks passed, {failed} failed")
    if failed:
        print(output)
        return 1

    from eval.ground_truth import FAMILY_EVIDENCE
    print("  ground-truth evidence mapping:")
    for family, kinds in FAMILY_EVIDENCE.items():
        print(f"    {family:<20} -> {', '.join(sorted(kinds))}")
    return 0


def _cmd_run(ns: argparse.Namespace) -> int:
    _quiet()
    from eval.experiments import SweepSpec, run_sweep, summarise

    probe_mode = "keyed" if ns.experiment == 2 else "fixed"
    tag = "keyed_probes" if ns.experiment == 2 else "fixed_probes"

    if ns.quick:
        spec = SweepSpec(
            experiment_id=f"exp{ns.experiment}_{tag}_quick",
            probe_mode=probe_mode,
            families=("content-injection", "exfiltration"),
            levels=("L1", "L4"),
            seeds=(1,),
            benign_seeds=(101,),
            benign_update_seeds=(201,),
            cycles=2, n_probes=2, n_samples=4,
            threshold_ratio=ns.threshold,
        )
    else:
        spec = SweepSpec(
            experiment_id=f"exp{ns.experiment}_{tag}",
            probe_mode=probe_mode,
            seeds=tuple(range(1, ns.seeds + 1)),
            cycles=ns.cycles,
            threshold_ratio=ns.threshold,
        )

    print(f"experiment : {spec.experiment_id}")
    print(f"probe mode : {spec.probe_mode}")
    print(f"threshold  : {spec.threshold_ratio if spec.threshold_ratio else 'from calibration'}")
    print(f"results    : {ns.results}")
    print()

    results = run_sweep(spec, ns.attacker, ns.workspace, ns.results)
    print(summarise(results))
    print(f"\nrows written to {Path(ns.results) / (spec.experiment_id + '.csv')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval", description="DriftSentry evaluation harness")
    parser.add_argument("--attacker", default=str(DEFAULT_ATTACKER),
                        help="path to the adversarial server project")
    parser.add_argument("--workspace", default=str(DEFAULT_WORKSPACE),
                        help="scratch directory for per-episode isolated state")
    parser.add_argument("--results", default=str(DEFAULT_RESULTS),
                        help="where CSV/JSONL results are written")
    sub = parser.add_subparsers(dest="command", required=True)

    st = sub.add_parser("selftest", help="validate the attacker's ground truth")
    st.set_defaults(func=_cmd_selftest)

    run = sub.add_parser("run", help="run an experiment")
    run.add_argument("--experiment", type=int, required=True, choices=[1, 2])
    run.add_argument("--seeds", type=int, default=3, help="seeds per cell (default 3)")
    run.add_argument("--cycles", type=int, default=4, help="verification cycles per episode")
    run.add_argument("--threshold", type=float, default=None,
                     help="explicit drift-ratio threshold; omit to use the stored calibration")
    run.add_argument("--quick", action="store_true", help="tiny sweep, for checking the pipeline")
    run.set_defaults(func=_cmd_run)

    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
