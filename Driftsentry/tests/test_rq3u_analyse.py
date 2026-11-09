"""T30. RQ3 statistics and the H3 verdict.

The verdict is tested for all three outcomes. A verdict function that could
only ever print PASS would look exactly like one that works.
"""
from __future__ import annotations

import csv
import json

from eval import rq3u_analyse as A
from eval.record import FIELD_NAMES
from eval.update_conditions import CONDITIONS

NONE = {c: (False, False) for c in CONDITIONS}


def _write(path, episodes):
    """episodes: (id, cover, family|'benign', outcome, {cond: (alert, attr)}, escalated)."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELD_NAMES)
        w.writeheader()
        for eid, cover, family, outcome, conds, esc in episodes:
            row = {"episode_id": eid, "experiment_id": "rq3u_L1", "cover": cover,
                   "attack_family": f"benign@{cover}" if family == "benign" else family,
                   "outcome": outcome,
                   "escalations": "lookup_customer:readOnly_removed" if esc else ""}
            for c in CONDITIONS:
                alert, attr = conds.get(c, (False, False))
                row[f"alert_{c}"], row[f"attributed_{c}"] = alert, attr
            w.writerow(row)


def _real(directory, residue_runs_per_server):
    directory.mkdir(parents=True, exist_ok=True)
    for i, residue in enumerate(residue_runs_per_server):
        runs = [{"server": f"s{i}", "phase": "old", "run": 1}]
        runs += [{"server": f"s{i}", "phase": "new", "run": r + 1, "update_check": True,
                  "residue_verdict": "residue_alert" if r < residue else "accepted",
                  "residue_signals": ["determinism_break"] if r < residue else []}
                 for r in range(3)]
        (directory / f"rq1_s{i}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in runs), encoding="utf-8")
    return directory


def _attacks(n, *, residue=True, others=False, prefix="e"):
    eps = []
    for i in range(n):
        conds = {c: (others, others) for c in CONDITIONS}
        conds["residue"] = (residue, residue)
        eps.append((f"{prefix}{i}", ("C0", "C1", "C2")[i % 3], "exfiltration",
                    "detected" if residue else "missed", conds, False))
    return eps


def _run(tmp_path, episodes, real):
    _write(tmp_path / "r.csv", episodes)
    return A.analyse(A.load_episodes(tmp_path / "r.csv"),
                     A.load_real_upgrades(_real(tmp_path / "rq1", real)))


# --------------------------------------------------------------------------- #
# The three verdicts
# --------------------------------------------------------------------------- #
def test_a_clear_win_passes(tmp_path):
    assert _run(tmp_path, _attacks(30), [0] * 7)["h3"]["result"] == "PASS"


def test_one_of_seven_real_upgrades_with_residue_is_within_15_percent(tmp_path):
    assert _run(tmp_path, _attacks(30), [1] + [0] * 6)["h3"]["result"] == "PASS"


def test_two_of_seven_real_upgrades_with_residue_fails(tmp_path):
    out = _run(tmp_path, _attacks(30), [1, 1] + [0] * 5)
    assert out["h3"]["result"] == "FAIL"
    assert any("NOT met" in r for r in out["h3"]["reasons"])


def test_low_detection_fails(tmp_path):
    eps = _attacks(10) + _attacks(10, residue=False, prefix="m")
    out = _run(tmp_path, eps, [0] * 7)
    assert out["pooled"]["residue"]["rate"] == 0.5
    assert out["h3"]["result"] == "FAIL"


def test_no_advantage_over_the_baselines_fails(tmp_path):
    """Residue at 100% is not enough if the baselines detect as much."""
    assert _run(tmp_path, _attacks(30, others=True), [0] * 7)["h3"]["result"] == "FAIL"


def test_missing_real_upgrades_is_not_decidable_not_a_pass(tmp_path):
    out = _run(tmp_path, _attacks(30), [])
    assert out["h3"]["result"] == "NOT DECIDABLE"
    assert out["h3"]["missing"]


# --------------------------------------------------------------------------- #
# How the numbers are formed
# --------------------------------------------------------------------------- #
def test_never_triggered_attacks_leave_the_denominator(tmp_path):
    eps = _attacks(9) + [("nt", "C0", "exfiltration", "never_triggered", NONE, False)]
    out = _run(tmp_path, eps, [])
    assert out["pooled"]["residue"]["n"] == 9
    assert out["never_triggered"] == 1


def test_an_episode_counts_once_however_many_cycles(tmp_path):
    path = tmp_path / "r.csv"
    _write(path, _attacks(1))
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    with path.open("a", newline="", encoding="utf-8") as fh:
        csv.DictWriter(fh, fieldnames=FIELD_NAMES).writerows(rows * 3)
    assert len(A.load_episodes(path)) == 1


def test_a_baseline_beating_residue_is_not_residues_significance(tmp_path):
    """Direction matters: b10 > b01 must never read as residue doing better."""
    eps = []
    for i in range(30):
        conds = dict(NONE, accept_rebaseline=(True, True), residue=(i < 3, i < 3))
        eps.append((f"e{i}", ("C0", "C1", "C2")[i % 3], "exfiltration", "detected", conds, False))
    out = _run(tmp_path, eps, [])
    assert out["mcnemar_vs_residue"]["accept_rebaseline"]["significant"] is False


def test_c3_reports_evasions_that_needed_an_escalation(tmp_path):
    eps = [("a", "C3", "exfiltration", "detected", NONE, True),
           ("b", "C3", "exfiltration", "detected", dict(NONE, residue=(True, True)), True)]
    c3 = _run(tmp_path, eps, [])["c3"]
    assert c3["evaded"] == 1
    assert c3["evaded_with_escalation"]["k"] == 1


def test_c3_is_kept_out_of_the_pooled_h3_figure(tmp_path):
    eps = _attacks(3) + [("x", "C3", "exfiltration", "missed", NONE, True)]
    assert _run(tmp_path, eps, [])["pooled"]["residue"]["n"] == 3


def test_benign_updates_give_a_false_alarm_rate_per_condition(tmp_path):
    eps = _attacks(3) + [("b1", "C2", "benign", "benign_ok",
                          dict(NONE, refuse_all=(True, False),
                               definition_diff=(True, False)), False)]
    fa = _run(tmp_path, eps, [])["synthetic_false_alarms"]
    assert fa["refuse_all"]["k"] == 1 and fa["residue"]["k"] == 0


def test_a_real_upgrade_with_any_residue_run_counts_against_h3(tmp_path):
    """The strict reading: one alarm on a benign upgrade is one a user saw."""
    real = _run(tmp_path, _attacks(3), [1, 0])["real_upgrades"]
    assert real["upgrades_with_residue"]["k"] == 1
    assert real["runs_with_residue"] == {**real["runs_with_residue"], "k": 1, "n": 6}
