# Changelog

## 1.0.0 (2026-11-12)

The final-year-project release: both research gaps built, measured and
documented.

### Detector (`Driftsentry/`)

* `driftsentry demo`: the full demonstration from one command. It resets the
  attacker, enrols it with keyed probes, and opens the attacker's test menu
  and the dashboard.
* `driftsentry baseline --probe-mode keyed`: keyed enrolment from the command
  line. The default stays `fixed` so earlier experiment commands reproduce.
* `driftsentry verify --update-check --cycle N`: declared-diff update checking
  from the command line, printed in the same words as the dashboard.
* `driftsentry watch` now uses a new probe cycle on every check and scores
  updates by what they declare, as the dashboard's daemon does.
* The dashboard shows an update panel (UPDATE EXPLAINED, UNDECLARED
  BEHAVIOUR, PERMISSION WIDENED, HELD FOR REVIEW) with what the update
  declared.
* Declared-diff residue checking (`declared_diff.py`, `residue.py`), with
  permitted-change rules frozen before any result was measured.
* Documentation: repository README, detector README, `docs/USER_GUIDE.md`,
  and `docs/VIVA_DEMO.md` rewritten for the two-gap demonstration.

### Attacker (`mcp rug pull attack server/`)

* A numbered test menu (12 tests across both gaps), showing the attacker's
  own ground truth after each test.
* `--home DIR`: one explicit home folder for every process that must agree.
* Cover-change attacks hidden in updates (covers C0 to C3) and a learned
  recogniser (level L6).

### Results

All results are in `Driftsentry/eval_results/tables.md`. H1 PASS, H2 FAIL,
H3 FAIL (detection half met, false-alarm half not), and full DriftSentry
against hash pinning PASS. Experiment 2, per-tool thresholds and the
never-called-tool validation were not measured.

## 0.1.0

Mid-point build: proxy, config ingestion, baselines, drift scorer, alerting,
and the adversarial testbed.
