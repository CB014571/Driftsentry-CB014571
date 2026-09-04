"""Wait for Experiment 1, then run Experiment 2 with identical settings.

Same seeds, same threshold, same matrix. The ONLY variable is how probe values
are chosen, so anything that moves between the two is attributable to that.
"""
import csv, sys, time, logging, collections
from pathlib import Path
sys.path.insert(0, ".")
logging.disable(logging.WARNING)

ROOT = Path(".").resolve()
CONTROL_LOG = ROOT / "eval_results" / "exp1_console.log"
ATK = ROOT.parent / "mcp rug pull attack server"
WS = ROOT / ".eval_workspace"
OUT = ROOT / "eval_results"
THRESHOLD = 10.8086

print("waiting for Experiment 1 to finish...", flush=True)
while "OVERALL" not in CONTROL_LOG.read_text(encoding="utf-8", errors="replace"):
    time.sleep(30)
print("Experiment 1 finished. Starting Experiment 2 (keyed probes).\n", flush=True)

from eval.experiments import SweepSpec, run_sweep, summarise, compare

spec = SweepSpec(experiment_id="exp2_keyed_probes", probe_mode="keyed",
                 seeds=(1, 2), cycles=4, threshold_ratio=THRESHOLD)
treatment = run_sweep(spec, ATK, WS, OUT)
print(summarise(treatment), flush=True)


def load(name):
    """Rebuild episode-level rows from a finished experiment's CSV."""
    path = OUT / f"{name}.csv"
    if not path.exists():
        return []
    last = {}
    for row in csv.DictReader(path.open(encoding="utf-8")):
        last[row["episode_id"]] = row

    class _R:
        pass

    out = []
    for row in last.values():
        r = _R()
        r.outcome = row["outcome"]
        r.attack_level = row["attack_level"]
        r.attack_family = row["attack_family"]
        r.final_score = float(row["final_score"] or 0)
        r.detected = row["detected"] == "True"
        r.probe_recognised = row["probe_recognised"] == "True"
        r.time_to_detection = float(row["time_to_detection"] or 0)
        out.append(r)
    return out


import eval.experiments as E
control_rows = load("exp1_fixed_probes")
treat_rows = E._episode_rows(treatment)


class _Wrap:
    def __init__(self, rows): self.rows = rows


# compare() expects EpisodeResults; feed it pre-built rows instead.
E._episode_rows = lambda results: results if results and not hasattr(results[0], "config") else \
    [r for r in results]
print(E.compare(control_rows, treat_rows), flush=True)
print("\nEXPERIMENT 2 COMPLETE", flush=True)
