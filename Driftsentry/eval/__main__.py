"""Command line for the evaluation harness.

    python -m eval selftest                 # validate the ground truth first
    python -m eval run --experiment 1       # the control condition
    python -m eval run --experiment 1 --quick
"""
from __future__ import annotations

import argparse
import asyncio
import json
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

    if ns.experiment == 3:
        from eval.experiments import evasion_report, experiment_3

        if not ns.recogniser:
            print("error: --recogniser is required for experiment 3. Train one "
                  "with `eval rq3` first.", file=sys.stderr)
            return 2
        model = Path(ns.recogniser)
        if not model.is_file():
            print(f"error: no recogniser at {model}", file=sys.stderr)
            return 2
        family_name = json.loads(model.read_text(encoding="utf-8")).get("family", "all")

        extra: dict = {"seeds": tuple(range(1, ns.seeds + 1)),
                       "cycles": ns.cycles, "threshold_ratio": ns.threshold}
        if ns.quick:
            extra.update(families=("content-injection", "exfiltration"),
                         seeds=(1,), cycles=2, n_probes=2, n_samples=4,
                         benign_seeds=(101,), benign_update_seeds=())

        print(f"experiment : 3, L1 against L6")
        print(f"recogniser : {model.name}  (family {family_name})")
        print(f"replay     : {ns.replay} genuine session(s) per cycle")
        print()
        results = experiment_3(ns.attacker, ns.workspace, ns.results,
                               recogniser=str(model), family_name=family_name,
                               replay_sessions=ns.replay, **extra)
        print(summarise(results))
        print(evasion_report(results))
        return 0

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


def _cmd_h2b(ns: argparse.Namespace) -> int:
    """H2b: the follow-up to H2 - in-session verification (eval/followup.py)."""
    import asyncio

    from eval import followup

    # Its own workspace, ALWAYS. The collector deletes its workspace on start,
    # and the default one belongs to whatever sweep may be running.
    workspace = Path(ns.workspace_h2b)
    if ns.stage == "preregister":
        doc = followup.preregister()
        print(json.dumps(doc, indent=2))
        print(f"\nfrozen: {followup.PREREG}")
        return 0
    _quiet()
    if ns.stage == "collect":
        print(json.dumps(asyncio.run(followup.collect(ns.attacker, workspace)), indent=2))
    elif ns.stage == "fit":
        res = followup.fit(ns.attacker)
        print(f"best family: {res['best_family']}  AUC {res['best_auc']:.3f}")
        for name, fam in res["families"].items():
            print(f"  {name:<12} {fam.get('auc')}")
    elif ns.stage == "matrix":
        followup.matrix(ns.attacker, workspace)
    elif ns.stage == "control":
        followup.control(ns.attacker, workspace)
    elif ns.stage == "verdict":
        print(json.dumps(followup.verdict(), indent=2))
    return 0


def _cmd_t20(ns: argparse.Namespace) -> int:
    """Do the countermeasures close the channels, and at what cost?"""
    _quiet()
    from eval.t20 import report, run

    out_dir = Path(ns.out)
    names = tuple(n.strip() for n in ns.conditions.split(",") if n.strip())
    print(f"attacker   : {ns.attacker}")
    print(f"conditions : {', '.join(names)}")
    print(f"cycles     : {ns.cycles} probe cycles per condition")
    print(f"out        : {out_dir}")
    print()

    families = tuple(f.strip() for f in ns.families.split(",")) if ns.families else None
    results = run(ns.attacker, ns.workspace, out_dir,
                  conditions=names, cycles=ns.cycles,
                  seeds=tuple(range(1, ns.seeds + 1)), families=families,
                  resume=not ns.restart)
    print(report(results))
    return 0


RQ3U_RULES = DEFAULT_RESULTS / "rq3u" / "rules_frozen.json"


def _cmd_rq3u(ns: argparse.Namespace) -> int:
    """RQ3a: attacks hidden in legitimate updates, scored five ways (T28).

    Refuses to start unless the permitted-change rules verify against their
    frozen file - the rules were sealed before any cover-change attack was
    built, and scoring with rules edited since would invalidate the result.
    A per-tool threshold file is verified the same way when one is given.
    """
    _quiet()
    from driftsentry.calibration import verify_frozen
    from driftsentry.residue import verify_rules
    from eval.experiments import FAMILIES, SweepSpec, run_sweep, summarise

    try:
        rules = verify_rules(RQ3U_RULES)
    except (OSError, ValueError) as exc:
        print(f"error: the frozen rules do not verify, refusing to score: {exc}",
              file=sys.stderr)
        return 2

    per_tool = None
    if ns.per_tool:
        try:
            per_tool = dict(verify_frozen(ns.per_tool)["thresholds"])
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: per-tool thresholds do not verify: {exc}", file=sys.stderr)
            return 2

    def split(text: str) -> tuple[str, ...]:
        return tuple(t.strip() for t in text.split(",") if t.strip())

    families = tuple(FAMILIES) if ns.families == "all" else split(ns.families)
    covers, benign = split(ns.covers), split(ns.benign_updates)
    seeds = tuple(int(s) for s in split(ns.seeds))
    if ns.quick:
        families, covers, benign, seeds = families[:1], ("C0", "C2"), (), seeds[:1]

    unknown = [f for f in families if f not in FAMILIES]
    bad = [c for c in covers + benign if c not in ("C0", "C1", "C2", "C3")]
    if unknown or bad:
        print(f"error: unknown families {unknown} or covers {bad}", file=sys.stderr)
        return 2

    spec = SweepSpec(
        experiment_id="rq3u_L1" + ("_quick" if ns.quick else ""),
        probe_mode=ns.probe_mode,
        families=families, levels=split(ns.levels), seeds=seeds,
        benign_seeds=(), benign_update_seeds=(),
        cycles=ns.cycles,
        update_covers=covers, benign_update_covers=benign,
        per_tool=per_tool,
    )
    n = len(families) * len(spec.levels) * len(covers) * len(seeds) + len(benign) * len(seeds)
    print(f"rules      : v{rules['rules']['version']}  sha256 {rules['_sha256'][:16]}  "
          f"open-world {rules['rules']['open_world']}")
    print(f"thresholds : " + (f"per-tool, {len(per_tool)} tools, from {ns.per_tool}"
                              if per_tool else
                              "GLOBAL calibrated threshold - no per-tool file given"))
    print(f"families   : {', '.join(families)}")
    print(f"covers     : {', '.join(covers)}   benign updates: {', '.join(benign) or 'none'}")
    print(f"seeds      : {seeds}   cycles {ns.cycles}   probes {ns.probe_mode}")
    print(f"episodes   : {n}\n")

    out_dir = Path(ns.results) / "rq3u"
    results = run_sweep(spec, ns.attacker, ns.workspace, out_dir)
    print(summarise(results))
    print(f"\nrows written to {out_dir / (spec.experiment_id + '.csv')}")
    return 0


def _cmd_rq3u_analyse(ns: argparse.Namespace) -> int:
    """T30: RQ3 statistics and the H3 verdict, from the result files."""
    _quiet()
    from eval.rq3u_analyse import main as analyse

    csv_path = Path(ns.csv) if ns.csv else Path(ns.results) / "rq3u" / "rq3u_L1.csv"
    if not csv_path.is_file():
        print(f"error: no RQ3a results at {csv_path}", file=sys.stderr)
        return 2
    analyse(csv_path, Path(ns.results) / "rq1")
    return 0


def _cmd_real(ns: argparse.Namespace) -> int:
    """Gap 3: does the detector alarm on a genuine version upgrade?

    This one installs and runs third-party code from PyPI, which is the whole
    point - the gap asks about real servers - but it is also the only command
    here that executes something nobody in this project wrote. It therefore
    says exactly what it is about to install before it does, and --dry-run
    prints that list and stops.
    """
    _quiet()
    import anyio

    from eval.real_run import load_specs, report, run_all

    try:
        only = tuple(s.strip() for s in ns.servers.split(",") if s.strip()) \
            if ns.servers else ()
        specs = load_specs(only=only)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("Gap 3 installs and runs these releases from PyPI:")
    for spec in specs:
        net = " (reaches the network when called)" if spec.get("network") else ""
        print(f"  {spec['package']}=={spec['old']} and =={spec['new']}{net}")
    print(f"\nenvironments : {Path(ns.workspace) / 'real'}")
    print(f"runs         : {ns.runs} per phase")
    print(f"out          : {Path(ns.results) / 'rq1'}")
    if ns.dry_run:
        print("\n--dry-run: nothing installed, nothing run.")
        return 0
    print()

    done = anyio.run(lambda: run_all(
        Path(ns.workspace) / "real", Path(ns.results) / "rq1",
        only=only, runs=ns.runs, resolve=not ns.no_sdk_walk,
        clean=ns.clean))
    print(report(done))
    return 0


def _cmd_tables(ns: argparse.Namespace) -> int:
    """Assemble every measured result, and name what is still missing."""
    _quiet()
    from eval.tables import build

    text = build(ns.out)
    print(text)
    if ns.out:
        print(f"written to {ns.out}")
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
    run.add_argument("--experiment", type=int, required=True, choices=[1, 2, 3])
    run.add_argument("--recogniser", default=None,
                     help="experiment 3: path to an exported recogniser JSON")
    run.add_argument("--replay", type=int, default=2,
                     help="experiment 3: genuine sessions replayed per cycle")
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

    t20 = sub.add_parser("t20", help="countermeasures against a learned recogniser (RQ4)")
    t20.add_argument("--out", default=str(DEFAULT_RESULTS / "t20"))
    t20.add_argument("--conditions", default="none,host,mimic,subsample,all",
                     help="comma-separated condition names, in order")
    t20.add_argument("--cycles", type=int, default=60,
                     help="probe cycles collected per condition")
    t20.add_argument("--seeds", type=int, default=2, help="seeds per cell")
    t20.add_argument("--families", default=None,
                     help="comma-separated attack families; omit for all six")
    t20.add_argument("--restart", action="store_true",
                     help="discard measured conditions and start over")
    t20.set_defaults(func=_cmd_t20)

    rq3u = sub.add_parser("rq3u", help="attacks hidden in legitimate updates (RQ3a)")
    rq3u.add_argument("--families", default="all",
                      help="comma-separated attack families, or 'all'")
    rq3u.add_argument("--levels", default="L1")
    rq3u.add_argument("--covers", default="C0,C1,C2,C3")
    rq3u.add_argument("--benign-updates", default="C1,C2",
                      help="covers shipped with no attack: the false-alarm set")
    rq3u.add_argument("--seeds", default="1,2,3")
    rq3u.add_argument("--cycles", type=int, default=4)
    rq3u.add_argument("--probe-mode", choices=["keyed", "fixed"], default="keyed")
    rq3u.add_argument("--per-tool", default=None,
                      help="a frozen per-tool threshold file (T8); verified before use")
    rq3u.add_argument("--quick", action="store_true",
                      help="one family, C0 and C2, one seed - checks the pipeline")
    rq3u.set_defaults(func=_cmd_rq3u)

    rq3a = sub.add_parser("rq3u-analyse", help="RQ3 statistics and the H3 verdict (T30)")
    rq3a.add_argument("--csv", default=None,
                      help="an RQ3a results file; default the full sweep")
    rq3a.set_defaults(func=_cmd_rq3u_analyse)

    real = sub.add_parser("real", help="false alarms on real version upgrades (Gap 3)")
    real.add_argument("--servers",
                      default="time,calculator,git,sqlite,duckdb,motherduck,alchemy",
                      help="comma-separated short names from real_servers.json; "
                           "the default is every approved server - the local four "
                           "(7 Nov) and the three databases (9 Nov)")
    real.add_argument("--runs", type=int, default=3,
                      help="probe runs per phase (noise, then upgrade)")
    real.add_argument("--no-sdk-walk", action="store_true",
                      help="do not search for an older SDK a release can run "
                           "on; reproduces the 'unmeasurable' result instead "
                           "of fixing it")
    real.add_argument("--clean", action="store_true",
                      help="rebuild the environments from scratch")
    real.add_argument("--dry-run", action="store_true",
                      help="print what would be installed and stop")
    real.set_defaults(func=_cmd_real)

    tables = sub.add_parser("tables", help="assemble the result tables (T21)")
    tables.add_argument("--out", default=str(DEFAULT_RESULTS / "tables.md"),
                        help="where the Markdown is written")
    tables.set_defaults(func=_cmd_tables)

    h2b = sub.add_parser("h2b", help="follow-up to H2: in-session verification (H2b)")
    h2b.add_argument("stage", choices=("preregister", "collect", "fit", "matrix",
                                       "control", "verdict"))
    h2b.add_argument("--workspace-h2b", default=str(ROOT / ".eval_workspace_h2b"),
                     help="scratch directory for this follow-up only")
    h2b.set_defaults(func=_cmd_h2b)

    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
