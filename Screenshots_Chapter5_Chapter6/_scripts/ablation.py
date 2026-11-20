"""Signal ablation on Experiment 2 (Chapter 6, Table 6.7), from logged per-signal scores.

An alert fires when any signal reaches 1.0 (scorer.ALERT_AT). Each cycle's
verdict is recomputed from its recorded signal scores; if that reproduces
every recorded verdict, removing a signal can be measured exactly.
"""
import collections
import csv

SIG = ["embedding_score", "structure_score", "error_score", "determinism_score", "field_drift_score",
       "rule_score", "sideeffect_score", "consistency_score", "passive_score", "temporal_score"]
PATH = r"F:\fyp project\Driftsentry\eval_results\exp2_keyed_probes.csv"
rows = list(csv.DictReader(open(PATH, encoding="utf-8")))


def alert(r, keep):
    vals = [float(r[k] or 0) for k in keep]
    if r["definition_changed"] == "True":
        vals.append(3.0)
    return max(vals + [0]) >= 1.0


mismatch = sum(alert(r, SIG) != (r["detected"] == "True") for r in rows)
print(f"Experiment 2 (keyed probes): {len(rows)} cycles; recomputed verdicts that differ from the "
      f"recorded ones: {mismatch}")
eps = collections.defaultdict(list)
for r in rows:
    eps[r["episode_id"]].append(r)
att = [v for v in eps.values() if v[0]["attack_level"] and v[0]["attack_fired"] == "True"]
ben = [v for v in eps.values() if not v[0]["attack_level"]]
fams = sorted({v[0]["attack_family"] for v in att})
print(f"attacks that fired: {len(att)}   benign episodes: {len(ben)}\n")
configs = {
    "Full detector": SIG,
    "Without side-effect rules": [s for s in SIG if s != "sideeffect_score"],
    "Without embedding distance": [s for s in SIG if s != "embedding_score"],
    "Without embedding and determinism": [s for s in SIG if s not in ("embedding_score", "determinism_score")],
    "Embedding distance only": ["embedding_score"],
}
print(f"{'variant':<36}{'detected':>10}{'benign alarmed':>16}   per family")
for name, keep in configs.items():
    det = lambda v: any(alert(r, keep) for r in v)  # noqa: E731
    d, b = sum(det(v) for v in att), sum(det(v) for v in ben)
    pf = ", ".join(f"{f} {sum(det(v) for v in att if v[0]['attack_family'] == f)}/"
                   f"{sum(1 for v in att if v[0]['attack_family'] == f)}" for f in fams)
    print(f"{name:<36}{f'{d}/{len(att)}':>10}{f'{b}/{len(ben)}':>16}   {pf}")
c = collections.Counter(k for v in ben for r in v for k in SIG if float(r[k] or 0) >= 1.0)
print(f"\nsignals at or above the alert line in benign cycles: {dict(c)}")
