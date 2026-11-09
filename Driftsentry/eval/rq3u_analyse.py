"""RQ3 statistics and the H3 verdict (T30).

H3, verbatim from GAPS_PLAN_v2 section 1 - not to be changed:

    residue checking detects >= 80% of hidden changes pooled over cover
    conditions C0-C2, significantly more than accept-and-re-baseline,
    definition-diff and new-host checks (McNemar with Holm correction,
    p < 0.05), AND <= 15% of real benign upgrades leave an unexplained
    residue. The share of evading attacks that needed a visible declaration
    escalation (C3) is reported alongside.

Three decisions about how that is computed, made before the full sweep's
results were looked at and stated so they can be argued with:

  The unit is the EPISODE. An episode detects if any of its cycles did, so a
  long episode is not counted several times. An attack that never fired
  (outcome never_triggered) is excluded from every detection denominator: it
  did not happen, so there was nothing to detect.

  "Detects" means ATTRIBUTED detection (ground rule 5): an alert naming a
  signal the attack causes. Any-alert rates are reported beside it.

  A real upgrade "leaves an unexplained residue" if ANY of its update-checked
  runs ended residue_alert. That is the strict reading - one alarm on a
  benign upgrade is a false alarm a user would have seen - and the per-run
  share is reported beside it.

A verdict that cannot be reached is reported as NOT DECIDABLE with the
reason, never as a pass or a fail: H3 has two halves, and a missing half is
missing, not zero.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from eval.stats import holm, mcnemar_p, wilson
from eval.update_conditions import CONDITIONS

RESULTS = Path(__file__).resolve().parents[1] / "eval_results"
DETECTION_TARGET = 0.80
RESIDUE_TARGET = 0.15
ALPHA = 0.05
BASELINES = ("accept_rebaseline", "definition_diff", "new_host_only")
POOLED_COVERS = ("C0", "C1", "C2")


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "1")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_episodes(path: Path) -> list[dict[str, Any]]:
    """One record per episode, every condition collapsed over its cycles."""
    by_episode: dict[str, list[dict[str, str]]] = defaultdict(list)
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            by_episode[row["episode_id"]].append(row)
    episodes = []
    for episode_id, rows in by_episode.items():
        first = rows[0]
        benign = first["attack_family"].startswith("benign")
        rec: dict[str, Any] = {
            "episode_id": episode_id,
            "cover": first.get("cover", ""),
            "family": "" if benign else first["attack_family"],
            "seed": first.get("seed", ""),
            "benign": benign,
            "outcome": first.get("outcome", ""),
            "escalated": any(r.get("escalations") for r in rows),
        }
        for c in CONDITIONS:
            rec[f"alert_{c}"] = any(_truthy(r.get(f"alert_{c}")) for r in rows)
            rec[f"attributed_{c}"] = any(_truthy(r.get(f"attributed_{c}")) for r in rows)
        episodes.append(rec)
    return episodes


def fired(episodes: list[dict]) -> list[dict]:
    """Attack episodes where the attack actually executed."""
    return [e for e in episodes if not e["benign"]
            and e["outcome"] in ("detected", "missed")]


def load_real_upgrades(directory: Path) -> list[dict[str, Any]]:
    """Update-checked new-phase runs of real servers, one record per server."""
    servers = []
    for path in sorted(Path(directory).glob("rq1_*.jsonl")):
        runs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        new = [r for r in runs if r.get("phase") == "new" and r.get("update_check")
               and not r.get("error")]
        if not new:
            continue
        servers.append({
            "server": new[0]["server"],
            "runs": len(new),
            "residue_runs": sum(1 for r in new if r.get("residue_verdict") == "residue_alert"),
            "escalation_runs": sum(1 for r in new if r.get("residue_verdict") == "escalation"),
            "held_runs": sum(1 for r in new if r.get("residue_verdict") == "held_for_review"),
            "residue_signals": sorted({s for r in new for s in r.get("residue_signals", [])}),
        })
    return servers


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _rate(k: int, n: int) -> dict[str, Any]:
    rate, low, high = wilson(k, n)
    return {"k": k, "n": n, "rate": rate, "low": low, "high": high}


def analyse(episodes: list[dict], real: list[dict]) -> dict[str, Any]:
    attacks = fired(episodes)
    out: dict[str, Any] = {"episodes": len(episodes), "fired_attacks": len(attacks),
                           "never_triggered": sum(1 for e in episodes if not e["benign"]
                                                  and e["outcome"] == "never_triggered")}

    # Detection per condition x cover, attributed and any-alert.
    covers = sorted({e["cover"] for e in attacks})
    out["detection"] = {
        c: {cov: {"attributed": _rate(sum(e[f"attributed_{c}"] for e in attacks if e["cover"] == cov),
                                      sum(1 for e in attacks if e["cover"] == cov)),
                  "any_alert": _rate(sum(e[f"alert_{c}"] for e in attacks if e["cover"] == cov),
                                     sum(1 for e in attacks if e["cover"] == cov))}
            for cov in covers}
        for c in CONDITIONS}

    # Pooled C0-C2, and the paired tests against residue.
    pooled = sorted((e for e in attacks if e["cover"] in POOLED_COVERS),
                    key=lambda e: e["episode_id"])
    residue = [e["attributed_residue"] for e in pooled]
    out["pooled"] = {c: _rate(sum(e[f"attributed_{c}"] for e in pooled), len(pooled))
                     for c in CONDITIONS}
    tests = {b: mcnemar_p([e[f"attributed_{b}"] for e in pooled], residue)
             for b in BASELINES}
    corrected = holm([tests[b]["p"] for b in BASELINES], alpha=ALPHA)
    for b, adj, rej in zip(BASELINES, corrected["adjusted"], corrected["reject"]):
        # b01: only residue detected. Significance only counts in residue's favour.
        tests[b].update(p_holm=adj, significant=rej and tests[b]["b01"] > tests[b]["b10"])
    out["mcnemar_vs_residue"] = tests

    # Synthetic benign updates: any alert is a false alarm.
    benign = [e for e in episodes if e["benign"]]
    out["synthetic_false_alarms"] = {c: _rate(sum(e[f"alert_{c}"] for e in benign), len(benign))
                                     for c in CONDITIONS}

    # C3: of the attacks residue did not attribute, how many showed an escalation.
    c3 = [e for e in attacks if e["cover"] == "C3"]
    evaded = [e for e in c3 if not e["attributed_residue"]]
    out["c3"] = {"fired": len(c3), "residue_attributed": sum(e["attributed_residue"] for e in c3),
                 "evaded": len(evaded),
                 "evaded_with_escalation": _rate(sum(e["escalated"] for e in evaded), len(evaded))}

    # RQ3b: real benign upgrades.
    out["real_upgrades"] = {
        "servers": real,
        "upgrades_with_residue": _rate(sum(1 for s in real if s["residue_runs"]), len(real)),
        "runs_with_residue": _rate(sum(s["residue_runs"] for s in real),
                                   sum(s["runs"] for s in real)),
        "escalation_runs": sum(s["escalation_runs"] for s in real),
        "held_runs": sum(s["held_runs"] for s in real),
    }
    out["h3"] = verdict(out)
    return out


def verdict(out: dict[str, Any]) -> dict[str, Any]:
    """H3 exactly as written. A FAIL is a result; nothing here is tunable."""
    reasons, missing = [], []

    pooled = out["pooled"]["residue"]
    if pooled["n"] == 0:
        missing.append("no fired attack episodes in C0-C2")
        detection_ok = None
    else:
        detection_ok = pooled["rate"] >= DETECTION_TARGET
        reasons.append(f"residue detects {pooled['k']}/{pooled['n']} = {pooled['rate']:.1%} "
                       f"pooled C0-C2 (needs >= {DETECTION_TARGET:.0%}): "
                       f"{'met' if detection_ok else 'NOT met'}")

    sig = out["mcnemar_vs_residue"]
    significance_ok = None if pooled["n"] == 0 else all(sig[b]["significant"] for b in BASELINES)
    for b in BASELINES:
        t = sig[b]
        reasons.append(f"vs {b}: b01={t['b01']} b10={t['b10']} p={t['p']:.4g} "
                       f"Holm p={t['p_holm']:.4g}: "
                       f"{'significant' if t['significant'] else 'NOT significant'}")

    real = out["real_upgrades"]["upgrades_with_residue"]
    if real["n"] == 0:
        missing.append("no real benign upgrades measured (RQ3b)")
        residue_ok = None
    else:
        residue_ok = real["rate"] <= RESIDUE_TARGET
        reasons.append(f"{real['k']}/{real['n']} real upgrades left a residue = {real['rate']:.1%} "
                       f"(needs <= {RESIDUE_TARGET:.0%}): {'met' if residue_ok else 'NOT met'}")

    parts = (detection_ok, significance_ok, residue_ok)
    if any(p is False for p in parts):
        result = "FAIL"
    elif any(p is None for p in parts):
        result = "NOT DECIDABLE"
    else:
        result = "PASS"
    return {"result": result, "reasons": reasons, "missing": missing}


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _fmt(r: dict) -> str:
    if not r["n"]:
        return "not measured"
    return f"{r['rate']:.1%} [{r['low']:.2f}, {r['high']:.2f}] ({r['k']}/{r['n']})"


def report(out: dict[str, Any]) -> str:
    lines = ["", "=" * 78, "  RQ3 - declared-diff residue checking", "=" * 78,
             f"  episodes {out['episodes']}, attacks that fired {out['fired_attacks']}, "
             f"never fired {out['never_triggered']} (excluded)", "",
             "  Attributed detection, per cover:"]
    covers = sorted({cov for c in out["detection"].values() for cov in c})
    for c in CONDITIONS:
        cells = "  ".join(f"{cov} {_fmt(out['detection'][c][cov]['attributed']):>26}"
                          for cov in covers)
        lines.append(f"    {c:<18} {cells}")
    lines += ["", "  Pooled C0-C2, attributed:"]
    for c in CONDITIONS:
        lines.append(f"    {c:<18} {_fmt(out['pooled'][c])}")
    lines += ["", "  Synthetic benign updates - false alarms (any alert):"]
    for c in CONDITIONS:
        lines.append(f"    {c:<18} {_fmt(out['synthetic_false_alarms'][c])}")
    c3 = out["c3"]
    lines += ["", f"  C3: {c3['fired']} fired, residue attributed {c3['residue_attributed']}, "
                  f"evaded {c3['evaded']}; of those, escalated: "
                  f"{_fmt(c3['evaded_with_escalation'])}"]
    real = out["real_upgrades"]
    lines += ["", "  RQ3b - real benign upgrades:",
              f"    upgrades leaving a residue  {_fmt(real['upgrades_with_residue'])}",
              f"    runs ending residue_alert   {_fmt(real['runs_with_residue'])}",
              f"    escalation runs {real['escalation_runs']}, held-for-review runs {real['held_runs']}"]
    for s in real["servers"]:
        lines.append(f"      {s['server']:<14} residue {s['residue_runs']}/{s['runs']} runs  "
                     f"{', '.join(s['residue_signals']) or '-'}")
    h3 = out["h3"]
    lines += ["", f"  H3: {h3['result']}"] + [f"    - {r}" for r in h3["reasons"]]
    lines += [f"    - missing: {m}" for m in h3["missing"]]
    return "\n".join(lines)


def main(csv_path: Path | None = None, real_dir: Path | None = None,
         out_path: Path | None = None) -> dict[str, Any]:
    csv_path = csv_path or RESULTS / "rq3u" / "rq3u_L1.csv"
    real_dir = real_dir or RESULTS / "rq1"
    out = analyse(load_episodes(csv_path), load_real_upgrades(real_dir))
    # Beside the CSV it came from, so analysing the quick file cannot
    # overwrite the full sweep's analysis.
    target = out_path or csv_path.with_name(csv_path.stem + "_analysis.json")
    target.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(report(out))
    print(f"\n  written to {target}")
    return out
