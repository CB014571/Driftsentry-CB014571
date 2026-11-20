# Screenshots for Chapters 5 and 6

Captured 2026-11-17 from DriftSentry 1.1.0 (main code line, branch gap2-residue). Every terminal screenshot is the real output of the command shown, rendered as an image; the exact text is in raw_outputs/ with the same name. Product commands ran against the project's own attack server in a throwaway data folder.

Two cosmetic filters were applied to every capture, and nothing else: the attack server's own request log lines and its "scenario: <file>" notices were removed, and temporary-folder paths were shortened to <temp>. No result line was edited.

Dashboard screenshots (Chapter 5) and charts (Chapter 6) are copied from report_figures/, where the scripts that made the charts are kept.

## Chapter5 Implementation

| File | Supports | Command |
|---|---|---|
| C5_01_cli_workflow.png | Section 5.5 User interface: the one workflow (approve, protect, check updates, respond) | `driftsentry --help` |
| C5_02_technology_versions.png | Section 5.2 / Table 5.1 Technology stack | `python -c "<print versions of the stack>"` |
| C5_03_attacker_selftest_part1.png | Section 5.4.5 Adversarial server: every family records ground truth; definitions byte-identical | `python -m attacker selftest` |
| C5_03_attacker_selftest_part2.png | Section 5.4.5 Adversarial server: every family records ground truth; definitions byte-identical | `python -m attacker selftest` |
| C5_04_baseline_keyed.png | Section 5.4.2 Baseline capture with keyed probes (the default since 1.1.0) | `driftsentry baseline --server acme --cwd <attack server> --exec python -m attacker serve` |
| C5_05_verify_clean.png | Section 5.4.3 Drift scoring: a clean re-check scores below the alert line | `driftsentry verify --server acme --cycle 2 --plain` |
| C5_06_verify_rugpull_alert_part1.png | Section 5.4.4 Alerting: the alert names the signal, the before and after, and the actions | `driftsentry verify --server acme --cycle 3 --plain` |
| C5_06_verify_rugpull_alert_part2.png | Section 5.4.4 Alerting: the alert names the signal, the before and after, and the actions | `driftsentry verify --server acme --cycle 3 --plain` |
| C5_06_verify_rugpull_alert_part3.png | Section 5.4.4 Alerting: the alert names the signal, the before and after, and the actions | `driftsentry verify --server acme --cycle 3 --plain` |
| C5_07_report_quarantine.png | Section 5.4.4 Alerting, policy store and quarantine | `driftsentry report --server acme --plain` |
| C5_08_update_explained.png | Section 3.5.5 / 5.4: declared-diff residue checking accepts a declared change | `driftsentry verify --server acme --update-check --cycle 4 --plain` |
| C5_09_update_residue_alert_part1.png | Section 3.5.5 / 5.4: the undeclared part of the update is residue and alerts | `driftsentry verify --server acme --update-check --cycle 5 --plain` |
| C5_09_update_residue_alert_part2.png | Section 3.5.5 / 5.4: the undeclared part of the update is residue and alerts | `driftsentry verify --server acme --update-check --cycle 5 --plain` |
| C5_09_update_residue_alert_part3.png | Section 3.5.5 / 5.4: the undeclared part of the update is residue and alerts | `driftsentry verify --server acme --update-check --cycle 5 --plain` |
| C5_10_insession_benign.png | Section 5.4.1 Proxy: probes inside the live session, the real-call guard, quarantine | `python live_protection.py benign   (a real MCP client behind driftsentry run --in-session)` |
| C5_11_insession_attack.png | Section 5.4.1 Proxy: probes inside the live session, the real-call guard, quarantine | `python live_protection.py exfiltration   (a real MCP client behind driftsentry run --in-session)` |
| C5_12_dashboard_overview_ok.png | Section 5.5 User interface: overview, server OK | `copied from report_figures/fig_clean.png` |
| C5_13_dashboard_exfiltration_alert.png | Section 5.5: overview after a rug pull | `copied from report_figures/fig_exfil.png` |
| C5_14_dashboard_alerts_page.png | Figure 5.4: alerts page, signal, before and after, actions | `copied from report_figures/fig_alerts_page.png` |
| C5_15_dashboard_drift_graph.png | Section 5.5: drift score per check | `copied from report_figures/fig_graph.png` |
| C5_16_dashboard_update_explained.png | Section 3.5.5: UPDATE EXPLAINED panel | `copied from report_figures/fig_explained.png` |
| C5_17_dashboard_permission_widened.png | Section 3.5.5: PERMISSION WIDENED (declaration escalation) | `copied from report_figures/fig_test11.png` |
| C5_18_dashboard_undeclared_behaviour.png | Section 3.5.5: UNDECLARED BEHAVIOUR (residue alert, quarantined) | `copied from report_figures/fig_test12.png` |
| C5_19_dashboard_residue.png | Section 3.5.5: update residue panel | `copied from report_figures/fig_residue.png` |
| C5_20_attacker_console.png | Section 5.4.5: adversarial server console | `copied from report_figures/term_menu.png` |
| C5_21_architecture.png | Figure 3.1: architecture (diagram) | `copied from report_figures/fig_arch.png` |

## Chapter6 Results

| File | Supports | Command |
|---|---|---|
| C6_01_exp1_fixed_probes.png | Section 6.4 / Table 5.7: fixed probes, L4 and L5 never fired | `python -m eval run --experiment 1   (summary, eval_results/exp1_console.log)` |
| C6_02_exp2_keyed_probes.png | Section 6.2.1 / 6.4: keyed probes, every fired attack detected | `python -m eval run --experiment 2   (summary, eval_results/exp2_console.log)` |
| C6_03_validation_three_detectors.png | Section 6.2.1 / Table 6.1 | `python -m eval tables   (Table 2. of eval_results/tables.md)` |
| C6_04_rq1_auc_per_family.png | Section 6.2.2 / Table 6.2 | `python -m eval tables   (Table 3. of eval_results/tables.md)` |
| C6_05_rq1_recall_lost.png | Section 6.2.2 / Table 6.2 | `python -m eval tables   (Table 4. of eval_results/tables.md)` |
| C6_06_rq2_countermeasures.png | Section 6.2.3 / Table 6.3 | `python -m eval tables   (Table 6. of eval_results/tables.md)` |
| C6_07_rq3a_hidden_updates.png | Section 6.2.4 / Table 6.5 | `python -m eval tables   (Table 7. of eval_results/tables.md)` |
| C6_08_rq3b_real_upgrades.png | Section 6.2.4 / Table 6.6 | `python -m eval tables   (Table 9. of eval_results/tables.md)` |
| C6_09_hypotheses.png | Sections 6.2 and 6.6 | `python -m eval tables   (Table 10. of eval_results/tables.md)` |
| C6_10_iteration2_h2b_verdict_part1.png | Section 6.2.3 / Table 6.4 | `python -m eval h2b verdict` |
| C6_10_iteration2_h2b_verdict_part2.png | Section 6.2.3 / Table 6.4 | `python -m eval h2b verdict` |
| C6_11_iteration3_h2c_verdict_part1.png | Section 6.2.3 / Table 6.4 | `python -m eval h2c verdict` |
| C6_11_iteration3_h2c_verdict_part2.png | Section 6.2.3 / Table 6.4 | `python -m eval h2c verdict` |
| C6_11_iteration3_h2c_verdict_part3.png | Section 6.2.3 / Table 6.4 | `python -m eval h2c verdict` |
| C6_12_iteration2_h3b_heldout.png | Section 6.2.4 / Table 6.6 | `python -m eval h3b verdict` |
| C6_13_iteration3_h3c_heldout.png | Section 6.2.4 / Table 6.6 | `python -m eval h3c verdict` |
| C6_14_validation_verdicts.png | Section 6.2.1 | `python -m eval validate verdict` |
| C6_15_rq3a_rules_v1_1_part1.png | Section 6.2.4: synthetic half unchanged under v1.1 (45/45, 0/6) | `python -m eval rq3u-analyse --csv eval_results/followup/h3b/rq3u_L1_rules11.csv --real-dir ...held_out` |
| C6_15_rq3a_rules_v1_1_part2.png | Section 6.2.4: synthetic half unchanged under v1.1 (45/45, 0/6) | `python -m eval rq3u-analyse --csv eval_results/followup/h3b/rq3u_L1_rules11.csv --real-dir ...held_out` |
| C6_16_ablation.png | Section 6.4 / Table 6.7 | `python ablation.py` |
| C6_17_figure6_1_auc_per_family.png | Figure 6.1 (chart) | `copied from report_figures/fig6_1_auc_per_family.png` |
| C6_18_chart_rq1.png | Section 6.2.2: RQ1 chart | `copied from report_figures/chart_rq1.png` |
| C6_19_chart_rq3a.png | Section 6.2.4: RQ3a chart | `copied from report_figures/chart_rq3a.png` |

## Tests

| File | Supports | Command |
|---|---|---|
| T_01_full_test_suite.png | Testing: the whole suite passes | `python -m pytest -q -p no:cacheprovider` |
| T_02_scoring_and_signals.png | Testing: Scoring and drift signals | `python -m pytest -v -p no:cacheprovider tests/test_scorer_golden.py tests/test_determinism_signal.py tests/test_redact.py` |
| T_03_probes_keyed_and_safety_part1.png | Testing: Probe generation, keying and probe safety | `python -m pytest -v -p no:cacheprovider tests/test_probe_generator.py tests/test_safety_policy.py tests/test_subsampling.py` |
| T_03_probes_keyed_and_safety_part2.png | Testing: Probe generation, keying and probe safety | `python -m pytest -v -p no:cacheprovider tests/test_probe_generator.py tests/test_safety_policy.py tests/test_subsampling.py` |
| T_04_proxy_injector_insession.png | Testing: Proxy, probe injector and in-session verification | `python -m pytest -v -p no:cacheprovider tests/test_proxy_logging.py tests/test_injector.py tests/test_insession.py` |
| T_05_v1_1_watch_guard.png | Testing: Release 1.1: continuous watch, matched values, real-call guard | `python -m pytest -v -p no:cacheprovider tests/test_h2c.py` |
| T_06_update_checking_part1.png | Testing: Update checking: declared diff and residue rules | `python -m pytest -v -p no:cacheprovider tests/test_declared_diff.py tests/test_residue_scoring.py` |
| T_06_update_checking_part2.png | Testing: Update checking: declared diff and residue rules | `python -m pytest -v -p no:cacheprovider tests/test_declared_diff.py tests/test_residue_scoring.py` |
| T_07_rules_v1_1_v1_2.png | Testing: Residue rules v1.1 and v1.2 | `python -m pytest -v -p no:cacheprovider tests/test_rules_v1_1.py tests/test_rules_v1_2.py` |
| T_08_passive_and_calibration.png | Testing: Passive monitoring and threshold calibration | `python -m pytest -v -p no:cacheprovider tests/test_passive.py tests/test_calibration_math.py` |
| T_09_evaluation_integrity_part1.png | Testing: Evaluation integrity: labels, statistics, recording | `python -m pytest -v -p no:cacheprovider tests/test_rq3_dataset.py tests/test_stats.py` |
| T_09_evaluation_integrity_part2.png | Testing: Evaluation integrity: labels, statistics, recording | `python -m pytest -v -p no:cacheprovider tests/test_rq3_dataset.py tests/test_stats.py` |
| T_10_cli.png | Testing: Command line | `python -m pytest -v -p no:cacheprovider tests/test_cli_update.py` |
