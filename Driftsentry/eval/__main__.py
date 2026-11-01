"""Command line for the evaluation harness.

    python -m eval selftest                 # validate the ground truth first
    python -m eval run --experiment 1       # the control condition
    python -m eval run --experiment 1 --quick
"""
from __future__ import annotations

import argparse
import asyncio
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


def _cmd_collect(ns: argparse.Namespace) -> int:
    """Collect the RQ3 dataset, then build and describe it."""
    _quiet()
    from eval.agent import probe_models
    from eval.collect import collect
    from eval.rq3_dataset import build, describe

    models = [m.strip() for m in ns.models.split(",") if m.strip()]
    if not models:
        print("error: --models is required, e.g. --models llama3.1:8b,qwen2.5:7b",
              file=sys.stderr)
        return 2

    # Fail before an hour of collection rather than after it.
    available = asyncio.run(probe_models())
    if not available:
        print("error: Ollama is not responding on localhost:11434. The genuine "
              "half of this dataset needs a real model choosing real tool calls.",
              file=sys.stderr)
        return 2
    # Ollama registers an untagged pull as "<name>:latest" and treats the two
    # spellings as one model, so the check has to as well. Matching the raw
    # string rejected "mistral-nemo" against a pulled "mistral-nemo:latest",
    # which is a real model being called by its real name.
    def _resolve(name: str) -> str | None:
        for candidate in (name, f"{name}:latest", name.removesuffix(":latest")):
            if candidate in available:
                return candidate
        return None

    resolved, missing = [], []
    for name in models:
        match = _resolve(name)
        (missing, resolved)[match is not None].append(match or name)
    if missing:
        print(f"error: not pulled: {', '.join(missing)}", file=sys.stderr)
        print(f"       available: {', '.join(available)}", file=sys.stderr)
        return 2
    models = resolved

    out_dir = Path(ns.out)
    print(f"models   : {', '.join(models)}")
    print(f"sessions : {ns.sessions} agent sessions, each followed by one probe cycle")
    print(f"out      : {out_dir}")
    print()

    summary = collect(ns.attacker, out_dir, Path(ns.workspace) / "rq3",
                      ns.sessions, models,
                      n_probes=ns.n_probes, n_samples=ns.n_samples)
    print()
    print(f"windows      : {summary['genuine_windows']} genuine, "
          f"{summary['probe_windows']} probe")
    print(f"feature rows : {summary['feature_rows']}")
    if summary["errors"]:
        print(f"errors       : {len(summary['errors'])}")
        for line in summary["errors"][:5]:
            print(f"  {line}")

    print()
    built = build(out_dir)
    print(f"dataset      : {built['rows']} labelled rows "
          f"({built['genuine_rows']} genuine, {built['probe_rows']} probe) "
          f"across {built['groups']} sessions")
    print(f"dropped      : {built['unlabelled_dropped']} between sessions, "
          f"{built['pre_baseline_dropped']} from baselining")
    shape = describe(out_dir / "dataset.jsonl")
    print(f"calls/session: {shape['min_calls_per_group']}-{shape['max_calls_per_group']}")
    print(f"tools seen   : {', '.join(shape['tools'])}")
    print(f"clients seen : {', '.join(shape['clients'])}")
    return 0


def _cmd_rq3(ns: argparse.Namespace) -> int:
    """Which feature family lets a server recognise a probe?"""
    _quiet()
    from eval.rq3_distinguish import analyse, report

    data = Path(ns.data)
    if not data.is_file():
        print(f"error: no dataset at {data}. Run `eval collect` first.", file=sys.stderr)
        return 2

    summary = analyse(data, ns.attacker, out_dir=ns.out or data.parent,
                      n_boot=ns.boot, seed=ns.seed)
    print(report(summary))
    print()
    print(f"  recognisers and ROC points written beside {data.parent}")
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

    collect_p = sub.add_parser("collect", help="collect the RQ3 probe-vs-genuine dataset")
    collect_p.add_argument("--sessions", type=int, default=4,
                           help="agent sessions, each followed by one probe cycle")
    collect_p.add_argument("--models", required=True,
                           help="comma-separated Ollama models, e.g. llama3.1:8b,qwen2.5:7b")
    collect_p.add_argument("--out", default=str(DEFAULT_RESULTS / "rq3"),
                           help="where the dataset is written")
    collect_p.add_argument("--n-probes", type=int, default=3)
    collect_p.add_argument("--n-samples", type=int, default=6)
    collect_p.set_defaults(func=_cmd_collect)

    rq3 = sub.add_parser("rq3", help="which family distinguishes probes from genuine calls")
    rq3.add_argument("--data", default=str(DEFAULT_RESULTS / "rq3" / "dataset.jsonl"))
    rq3.add_argument("--out", default=None, help="where analysis output goes")
    rq3.add_argument("--boot", type=int, default=2000, help="bootstrap resamples")
    rq3.add_argument("--seed", type=int, default=0)
    rq3.set_defaults(func=_cmd_rq3)

    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
