"""Run every command whose output backs Chapters 5 and 6, save the raw text, render screenshots.

Run with the detector's virtual environment. All product commands use a
throwaway data folder (DRIFTSENTRY_HOME, and LOCALAPPDATA for the attack
server), so the real detector and attacker data are never touched.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from render_term import render  # noqa: E402

DS = Path(r"F:\fyp project\Driftsentry")
PROJECT = Path(r"F:\fyp project\mcp rug pull attack server")
DS_PY = str(DS / ".venv" / "Scripts" / "python.exe")
ATK_PY = str(PROJECT / ".venv" / "Scripts" / "python.exe")
WORK = Path(os.environ.get("CAPTURE_WORK", r"C:\Temp\ds_capture"))
RAW = ROOT / "raw_outputs"
INDEX: list[tuple[str, str, str, str]] = []
only = set(sys.argv[1:])


def sandbox_env() -> dict[str, str]:
    env = dict(os.environ)
    env["DRIFTSENTRY_HOME"] = str(WORK / "ds")
    env["LOCALAPPDATA"] = str(WORK / "local")        # the attack server's home
    env.pop("ATTACKER_HOME", None)
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    return env


def run(argv, cwd=DS, env=None, timeout=900) -> str:
    done = subprocess.run(argv, cwd=str(cwd), env=env or sandbox_env(), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return (done.stdout + ("\n" + done.stderr if done.stderr.strip() else "")).rstrip()


def shot(folder, name, title, shown_cmd, text, purpose, keep=None):
    if only and name not in only:
        return
    # The attack server's own request log is noise in every capture.
    text = drop_attacker_log(text)
    # Cosmetic only, disclosed in INDEX.md: the attack server's "scenario: <file>"
    # notices are dropped, and temporary-folder paths are shortened to <temp>.
    text = "\n".join(l for l in text.splitlines() if not l.startswith("scenario: "))
    for long in (str(WORK), str(WORK).replace("/", "\\"), os.environ.get("TEMP", "~~"),
                 r"C:\Users\LEGION\AppData\Local\Temp"):
        text = text.replace(long, "<temp>")
    if keep:
        text = keep(text)
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / f"{name}.txt").write_text(f"> {shown_cmd}\n{text}\n", encoding="utf-8")
    files = render(title, shown_cmd, text, ROOT / folder / f"{name}.png")
    for f in files:
        INDEX.append((folder, f.name, purpose, shown_cmd))
    print("  wrote", ", ".join(f.name for f in files))


def drop_attacker_log(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if "[attacker]" not in l)


def section(path: Path, start: str, stop: str | None = None) -> str:
    s = path.read_text(encoding="utf-8")
    a = s.index(start)
    b = s.index(stop, a + len(start)) if stop else len(s)
    return s[a:b].rstrip()


def summary_of(log: Path) -> str:
    lines = [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines()
             if "[attacker]" not in l and "INFO" not in l]
    start = max(i for i, l in enumerate(lines) if "OVERALL" in l) - 2
    return "\n".join(lines[start:])


C5, C6, T = "Chapter5_Implementation", "Chapter6_Results", "Tests"
today = date.today().isoformat()

# =========================================================================== #
# Chapter 5: the product
# =========================================================================== #
print("Chapter 5")
shutil.rmtree(WORK, ignore_errors=True)
(WORK / "ds").mkdir(parents=True)
(WORK / "local").mkdir(parents=True)

shot(C5, "C5_01_cli_workflow", "DriftSentry 1.1.0: the product workflow",
     "driftsentry --help", run([DS_PY, "-m", "driftsentry", "--help"]),
     "Section 5.5 User interface: the one workflow (approve, protect, check updates, respond)")
shot(C5, "C5_02_technology_versions", "Technology stack actually installed",
     "python -c \"<print versions of the stack>\"",
     # driftsentry's version comes from the code (what `driftsentry --version`
     # prints): the editable install's pip record predates the 1.1.0 bump.
     run([DS_PY, "-c",
          "import sys, importlib.metadata as m, driftsentry as d\n"
          "print('CPython', sys.version.split()[0])\n"
          "print('driftsentry ', d.__version__)\n"
          "for p in ('mcp','chromadb','numpy','psutil','fastapi','uvicorn','pywebview','pytest'):\n"
          "    print(f'{p:<12}', m.version(p))"]),
     "Section 5.2 / Table 5.1 Technology stack")
shot(C5, "C5_03_attacker_selftest", "Adversarial server: ground-truth self-test",
     "python -m attacker selftest", run([ATK_PY, "-m", "attacker", "selftest"], cwd=PROJECT, timeout=1800),
     "Section 5.4.5 Adversarial server: every family records ground truth; definitions byte-identical")

run([ATK_PY, "-m", "attacker", "benign", "--seed", "3"], cwd=PROJECT)
shot(C5, "C5_04_baseline_keyed", "Approve: keyed baseline of the attack server (benign)",
     "driftsentry baseline --server acme --cwd <attack server> --exec python -m attacker serve",
     run([DS_PY, "-m", "driftsentry", "baseline", "--server", "acme", "--cwd", str(PROJECT),
          "--exec", ATK_PY, "-m", "attacker", "serve"]),
     "Section 5.4.2 Baseline capture with keyed probes (the default since 1.1.0)")
shot(C5, "C5_05_verify_clean", "Check: the approved server, unchanged",
     "driftsentry verify --server acme --cycle 2 --plain",
     run([DS_PY, "-m", "driftsentry", "verify", "--server", "acme", "--cycle", "2", "--plain"]),
     "Section 5.4.3 Drift scoring: a clean re-check scores below the alert line")

run([ATK_PY, "-m", "attacker", "attack", "exfiltration", "--level", "L1", "--seed", "3"], cwd=PROJECT)
shot(C5, "C5_06_verify_rugpull_alert", "Check: the same server after a behavioural rug pull",
     "driftsentry verify --server acme --cycle 3 --plain",
     run([DS_PY, "-m", "driftsentry", "verify", "--server", "acme", "--cycle", "3", "--plain"]),
     "Section 5.4.4 Alerting: the alert names the signal, the before and after, and the actions")
shot(C5, "C5_07_report_quarantine", "Respond: alert history and policy",
     "driftsentry report --server acme --plain",
     run([DS_PY, "-m", "driftsentry", "report", "--server", "acme", "--plain"]),
     "Section 5.4.4 Alerting, policy store and quarantine")

# A legitimate update that DECLARES its change (release v2, cover C1), with no
# rewording; rewording (--updates) is behavioural drift, measured separately.
run([ATK_PY, "-m", "attacker", "benign", "--seed", "3", "--release", "v2", "--cover", "C1"], cwd=PROJECT)
shot(C5, "C5_08_update_explained", "On update: a legitimate update, checked against what it declares",
     "driftsentry verify --server acme --update-check --cycle 4 --plain",
     run([DS_PY, "-m", "driftsentry", "verify", "--server", "acme", "--update-check", "--cycle", "4",
          "--plain"]),
     "Section 3.5.5 / 5.4: declared-diff residue checking accepts a declared change")
run([ATK_PY, "-m", "attacker", "attack", "exfiltration", "--level", "L1", "--seed", "3",
     "--release", "v2", "--cover", "C2"], cwd=PROJECT)
shot(C5, "C5_09_update_residue_alert", "On update: an attack hidden inside a legitimate update",
     "driftsentry verify --server acme --update-check --cycle 5 --plain",
     run([DS_PY, "-m", "driftsentry", "verify", "--server", "acme", "--update-check", "--cycle", "5",
          "--plain"]),
     "Section 3.5.5 / 5.4: the undeclared part of the update is residue and alerts")

for armed, name, title in (("benign", "C5_10_insession_benign", "Protect: in-session verification, clean server"),
                           ("exfiltration", "C5_11_insession_attack",
                            "Protect: in-session verification, server turns malicious")):
    shot(C5, name, title, f"python live_protection.py {armed}   (a real MCP client behind "
                          f"driftsentry run --in-session)",
         run([DS_PY, str(HERE / "live_protection.py"), armed, str(WORK / f"live_{armed}")],
             env={**sandbox_env()}),
         "Section 5.4.1 Proxy: probes inside the live session, the real-call guard, quarantine")

# =========================================================================== #
# Chapter 6: results, read from the committed result files
# =========================================================================== #
print("Chapter 6")
R = DS / "eval_results"
shot(C6, "C6_01_exp1_fixed_probes", "Experiment 1: fixed probe values (96 episodes)",
     "python -m eval run --experiment 1   (summary, eval_results/exp1_console.log)",
     summary_of(R / "exp1_console.log"), "Section 6.4 / Table 5.7: fixed probes, L4 and L5 never fired")
shot(C6, "C6_02_exp2_keyed_probes", "Experiment 2: keyed probe values (96 episodes)",
     "python -m eval run --experiment 2   (summary, eval_results/exp2_console.log)",
     summary_of(R / "exp2_console.log"), "Section 6.2.1 / 6.4: keyed probes, every fired attack detected")
out = run([DS_PY, "-m", "eval", "tables"])
T_MD = R / "tables.md"
for name, title, start, stop, purpose in (
    ("C6_03_validation_three_detectors", "Validation: hash pinning, passive monitoring, DriftSentry",
     "### Table 2.", "### Table 3.", "Section 6.2.1 / Table 6.1"),
    ("C6_04_rq1_auc_per_family", "RQ1: separating probes from genuine calls",
     "### Table 3.", "### Table 4.", "Section 6.2.2 / Table 6.2"),
    ("C6_05_rq1_recall_lost", "RQ1: detection lost to a learned recogniser (H1)",
     "### Table 4.", "### Table 5.", "Section 6.2.2 / Table 6.2"),
    ("C6_06_rq2_countermeasures", "RQ2: countermeasures against a learned recogniser (H2)",
     "### Table 6.", "### Table 7.", "Section 6.2.3 / Table 6.3"),
    ("C6_07_rq3a_hidden_updates", "RQ3a: attacks hidden in legitimate updates (H3)",
     "### Table 7.", "### Table 9.", "Section 6.2.4 / Table 6.5"),
    ("C6_08_rq3b_real_upgrades", "RQ3b: residue on real benign upgrades (rules v1.0)",
     "### Table 9.", "### Table 10.", "Section 6.2.4 / Table 6.6"),
    ("C6_09_hypotheses", "All hypotheses, as frozen", "### Table 10.", "## Outstanding" if "## Outstanding" in T_MD.read_text(encoding="utf-8") else None,
     "Sections 6.2 and 6.6"),
):
    try:
        text = section(T_MD, start, stop)
    except ValueError:
        continue
    shot(C6, name, title, f"python -m eval tables   ({start.strip('# ')} of eval_results/tables.md)", text, purpose)
for name, cmd, title, purpose in (
    ("C6_10_iteration2_h2b_verdict", ["h2b", "verdict"], "RQ2 iteration 2 (H2b): pre-registered verdict",
     "Section 6.2.3 / Table 6.4"),
    ("C6_11_iteration3_h2c_verdict", ["h2c", "verdict"], "RQ2 iteration 3 (H2c): pre-registered verdict",
     "Section 6.2.3 / Table 6.4"),
    ("C6_12_iteration2_h3b_heldout", ["h3b", "verdict"], "RQ3 iteration 2 (H3b): held-out real upgrades",
     "Section 6.2.4 / Table 6.6"),
    ("C6_13_iteration3_h3c_heldout", ["h3c", "verdict"], "RQ3 iteration 3 (H3c): held-out real upgrades",
     "Section 6.2.4 / Table 6.6"),
    ("C6_14_validation_verdicts", ["validate", "verdict"], "Validation: never-called tool and per-tool thresholds",
     "Section 6.2.1"),
):
    shot(C6, name, title, "python -m eval " + " ".join(cmd), run([DS_PY, "-m", "eval", *cmd]), purpose)
shot(C6, "C6_15_rq3a_rules_v1_1", "RQ3 iteration 2: the update experiment re-run under rules v1.1",
     "python -m eval rq3u-analyse --csv eval_results/followup/h3b/rq3u_L1_rules11.csv --real-dir ...held_out",
     run([DS_PY, "-m", "eval", "rq3u-analyse", "--csv", "eval_results/followup/h3b/rq3u_L1_rules11.csv",
          "--real-dir", "eval_results/followup/h3b/held_out"]),
     "Section 6.2.4: synthetic half unchanged under v1.1 (45/45, 0/6)")
shot(C6, "C6_16_ablation", "Ablation: removing signals from the detector (Experiment 2)",
     "python ablation.py", run([DS_PY, str(HERE / "ablation.py")]), "Section 6.4 / Table 6.7")

# =========================================================================== #
# Tests
# =========================================================================== #
print("Tests")
shot(T, "T_01_full_test_suite", f"DriftSentry 1.1.0 test suite, {today}",
     "python -m pytest -q -p no:cacheprovider", run([DS_PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"]),
     "Testing: the whole suite passes")
GROUPS = [
    ("T_02_scoring_and_signals", "Scoring and drift signals",
     ["tests/test_scorer_golden.py", "tests/test_determinism_signal.py", "tests/test_redact.py"]),
    ("T_03_probes_keyed_and_safety", "Probe generation, keying and probe safety",
     ["tests/test_probe_generator.py", "tests/test_safety_policy.py", "tests/test_subsampling.py"]),
    ("T_04_proxy_injector_insession", "Proxy, probe injector and in-session verification",
     ["tests/test_proxy_logging.py", "tests/test_injector.py", "tests/test_insession.py"]),
    ("T_05_v1_1_watch_guard", "Release 1.1: continuous watch, matched values, real-call guard",
     ["tests/test_h2c.py"]),
    ("T_06_update_checking", "Update checking: declared diff and residue rules",
     ["tests/test_declared_diff.py", "tests/test_residue_scoring.py"]),
    ("T_07_rules_v1_1_v1_2", "Residue rules v1.1 and v1.2", ["tests/test_rules_v1_1.py", "tests/test_rules_v1_2.py"]),
    ("T_08_passive_and_calibration", "Passive monitoring and threshold calibration",
     ["tests/test_passive.py", "tests/test_calibration_math.py"]),
    ("T_09_evaluation_integrity", "Evaluation integrity: labels, statistics, recording",
     ["tests/test_rq3_dataset.py", "tests/test_stats.py"]),
    ("T_10_cli", "Command line", ["tests/test_cli_update.py"]),
]
for name, title, files in GROUPS:
    shot(T, name, title, "python -m pytest -v -p no:cacheprovider " + " ".join(files),
         run([DS_PY, "-m", "pytest", "-v", "-p", "no:cacheprovider", "--no-header", *files]),
         "Testing: " + title,
         keep=lambda t: "\n".join(re.sub(r"^tests/", "", l) for l in t.splitlines()
                                  if "::" in l or "passed" in l or "failed" in l))

# =========================================================================== #
# Existing real screenshots and charts, copied from report_figures/
# =========================================================================== #
FIG = Path(r"F:\fyp project\report_figures")
COPIES = [
    (C5, "fig_clean.png", "C5_12_dashboard_overview_ok.png", "Section 5.5 User interface: overview, server OK"),
    (C5, "fig_exfil.png", "C5_13_dashboard_exfiltration_alert.png", "Section 5.5: overview after a rug pull"),
    (C5, "fig_alerts_page.png", "C5_14_dashboard_alerts_page.png",
     "Figure 5.4: alerts page, signal, before and after, actions"),
    (C5, "fig_graph.png", "C5_15_dashboard_drift_graph.png", "Section 5.5: drift score per check"),
    (C5, "fig_explained.png", "C5_16_dashboard_update_explained.png", "Section 3.5.5: UPDATE EXPLAINED panel"),
    (C5, "fig_test11.png", "C5_17_dashboard_permission_widened.png",
     "Section 3.5.5: PERMISSION WIDENED (declaration escalation)"),
    (C5, "fig_test12.png", "C5_18_dashboard_undeclared_behaviour.png",
     "Section 3.5.5: UNDECLARED BEHAVIOUR (residue alert, quarantined)"),
    (C5, "fig_residue.png", "C5_19_dashboard_residue.png", "Section 3.5.5: update residue panel"),
    (C5, "term_menu.png", "C5_20_attacker_console.png", "Section 5.4.5: adversarial server console"),
    (C5, "fig_arch.png", "C5_21_architecture.png", "Figure 3.1: architecture (diagram)"),
    (C6, "fig6_1_auc_per_family.png", "C6_17_figure6_1_auc_per_family.png", "Figure 6.1 (chart)"),
    (C6, "chart_rq1.png", "C6_18_chart_rq1.png", "Section 6.2.2: RQ1 chart"),
    (C6, "chart_rq3a.png", "C6_19_chart_rq3a.png", "Section 6.2.4: RQ3a chart"),
]
if not only:
    for folder, src, dst, purpose in COPIES:
        if (FIG / src).exists():
            shutil.copy2(FIG / src, ROOT / folder / dst)
            INDEX.append((folder, dst, purpose, f"copied from report_figures/{src}"))

# =========================================================================== #
# Index
# =========================================================================== #
if not only:
    lines = [f"# Screenshots for Chapters 5 and 6", "",
             f"Captured {today} from DriftSentry 1.1.0 (main code line, branch gap2-residue). Every "
             "terminal screenshot is the real output of the command shown, rendered as an image; the "
             "exact text is in raw_outputs/ with the same name. Product commands ran against the "
             "project's own attack server in a throwaway data folder.", "",
             "Two cosmetic filters were applied to every capture, and nothing else: the attack "
             "server's own request log lines and its \"scenario: <file>\" notices were removed, and "
             "temporary-folder paths were shortened to <temp>. No result line was edited.", "",
             "Dashboard screenshots (Chapter 5) and charts (Chapter 6) are copied from "
             "report_figures/, where the scripts that made the charts are kept.", ""]
    for folder in (C5, C6, T):
        lines += [f"## {folder.replace('_', ' ')}", "", "| File | Supports | Command |", "|---|---|---|"]
        lines += [f"| {f} | {p} | `{c}` |" for fo, f, p, c in INDEX if fo == folder]
        lines.append("")
    (ROOT / "INDEX.md").write_text("\n".join(lines), encoding="utf-8")
print("done:", len(INDEX), "images")
