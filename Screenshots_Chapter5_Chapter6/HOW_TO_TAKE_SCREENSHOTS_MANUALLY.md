# How to take the screenshots yourself

Every command below was tested in Windows PowerShell on 17 Nov 2026. Each step names the file to save,
using the same names as the images in this folder, so INDEX.md still applies.

## How to take a screenshot

- **Win + Shift + S**, then drag a rectangle around the terminal (or choose *Window* mode and click it).
  The image is copied. Click the notification that appears, then **Save** with the name given below.
  You can also paste straight into Word with Ctrl + V.
- Before each shot, type `cls` to clear the screen, so only one command and its output are visible.
- Make the terminal wide (about 120 characters) and the font large enough to read when shrunk to page
  width in Word: Ctrl + mouse wheel in Windows Terminal. Keep the same size and colours for every shot.
- When the output is longer than the window, maximise it. If it still doesn't fit, take two shots
  (`..._part1`, `..._part2`) instead of shrinking the font.
- Never edit the text in a screenshot. Cropping is fine.

## Step 0: set up one PowerShell window (paste this once)

Open a **new** PowerShell window and paste the whole block. Use this window only for screenshots, and close
it when you finish.

```powershell
$DS    = "F:\fyp project\Driftsentry"
$ATK   = "F:\fyp project\mcp rug pull attack server"
$ATKPY = "$ATK\.venv\Scripts\python.exe"
$W     = "F:\ds_capture"
Remove-Item -Recurse -Force $W -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$W\ds", "$W\local" | Out-Null
$env:DRIFTSENTRY_HOME = "$W\ds"
$env:LOCALAPPDATA     = "$W\local"
Remove-Item Env:ATTACKER_HOME -ErrorAction SilentlyContinue
function driftsentry { & "$DS\.venv\Scripts\driftsentry.exe" @args }
function attacker    { & "$ATK\.venv\Scripts\attacker.exe" @args }
function python      { & "$DS\.venv\Scripts\python.exe" @args }
Set-Location $DS
cls
```

What this does:
- All DriftSentry and attack-server data goes into a throwaway folder, `F:\ds_capture`. Your real data
  is not touched, and the paths printed in the output show `F:\ds_capture` instead of your Windows user folder.
- `driftsentry`, `attacker` and `python` run straight from the two virtual environments. You don't need to
  activate anything or change PowerShell's script policy.

**About `2>$null`:** commands that start the attack server end with `2>$null`. It hides the attack server's
own log lines (`... [attacker] INFO call 1: ...`), which otherwise get mixed into DriftSentry's output.
Those lines are real too, so you can leave `2>$null` off if you want them visible. If a command prints
nothing at all, run it again without `2>$null` to see the error.

## Chapter 5: Implementation (run in this order; each step builds on the one before)

| # | Type this | Save as | You should see |
|---|---|---|---|
| 1 | `driftsentry --help` | `C5_01_cli_workflow.png` | The command list, then "The workflow:" with approve, protect, on update, respond |
| 2 | `python -c "import sys,importlib.metadata as m,driftsentry as d; print('CPython', sys.version.split()[0]); print('driftsentry ', d.__version__); [print(f'{p:<12}', m.version(p)) for p in ('mcp','chromadb','numpy','psutil','fastapi','uvicorn','pywebview','pytest')]"` | `C5_02_technology_versions.png` | CPython 3.14.6, driftsentry 1.1.0, then each library's version |
| 3 | `attacker selftest` | `C5_03_attacker_selftest_part1.png`, `_part2` | Rows of `[PASS]`, ending with `SELF TEST PASSED - the ground truth is sound`. **This takes several minutes.** Two shots: the top and the end. |
| – | `attacker benign --seed 3` | *(no shot needed)* | `Status : BENIGN` |
| 4 | `driftsentry baseline --server acme --cwd $ATK --exec $ATKPY -m attacker serve 2>$null` | `C5_04_baseline_keyed.png` | Three tools probed; `search_orders` and `send_invoice` "not probed (name suggests state change)"; `baseline saved` |
| 5 | `driftsentry verify --server acme --cycle 2 --plain 2>$null` | `C5_05_verify_clean.png` | `VERDICT: OK`, score about 0.5, below 1.00 |
| – | `attacker attack exfiltration --level L1 --seed 3` | *(optional shot: the attack being armed)* | `Status : ATTACKING - exfiltration at L1` |
| 6 | `driftsentry verify --server acme --cycle 3 --plain 2>$null` | `C5_06_verify_rugpull_alert_part1.png`, `_part2` | Part 1: `VERDICT: ALERT score 1.10 ... triggered by: rule:new_file_access`. Part 2: the first `DRIFT ALERT [HIGH]` box (WHAT HAPPENED, BEFORE, AFTER, WHAT TO DO) |
| 7 | `driftsentry report --server acme --plain` | `C5_07_report_quarantine.png` | `acme: status=quarantined ... alerts=3` |
| – | `attacker benign --seed 3 --release v2 --cover C1` | *(no shot needed)* | `Status : BENIGN`, release v2 |
| 8 | `driftsentry verify --server acme --update-check --cycle 4 --plain 2>$null` | `C5_08_update_explained.png` | `mode : residue`, `VERDICT: OK`, `UPDATE EXPLAINED - every change was declared` |
| – | `attacker attack exfiltration --level L1 --seed 3 --release v2 --cover C2` | *(no shot needed)* | `Status : ATTACKING` |
| 9 | `driftsentry verify --server acme --update-check --cycle 5 --plain 2>$null` | `C5_09_update_residue_alert_part1.png`, `_part2` | `VERDICT: ALERT`, then under UPDATE: `RESIDUE lookup_customer: new_file (no declared change explains it ...)` |
| 10 | `python "F:\fyp project\Screenshots_Chapter5_Chapter6\_scripts\live_protection.py" benign "$W\live_benign" 2>$null` | `C5_10_insession_benign.png` | About a minute. Lines [1] to [6]: verdict OK, `alerts : 0 recorded`, `server status TRUSTED` |
| 11 | `python "F:\fyp project\Screenshots_Chapter5_Chapter6\_scripts\live_protection.py" exfiltration "$W\live_exfil" 2>$null` | `C5_11_insession_attack.png` | Verdict ALERT, `triggered by guard:new_file_dir`, `server status QUARANTINED` |

Steps 10 and 11 are a real MCP client working through `driftsentry run --in-session`. The script prints only
what DriftSentry itself recorded.

**Numbers that change from run to run:** scores below the alert line (step 5, about 0.5) and the counts in
steps 10 and 11 (for example "110 probe answers") are measured fresh each time, so they can differ slightly
from the existing images. If your Chapter 5 text quotes a number, use the one in **your** screenshot. The
outcomes don't change: OK, ALERT, UPDATE EXPLAINED, RESIDUE, TRUSTED and QUARANTINED.

### The dashboard and the attacker's menu (C5_12 to C5_20)

These come from the demonstration, the same way the existing images were made. Open a **second, ordinary**
PowerShell window (not the setup window above) and type:

```powershell
cd "F:\fyp project\Driftsentry"
.venv\Scripts\driftsentry.exe demo
```

Two windows open: the attacker's test menu and the DriftSentry dashboard. Pick a test number in the menu.
The dashboard checks every 10 seconds, so wait for the next check, then take the screenshot:

| Menu test | Screenshot | Save as |
|---|---|---|
| 1 Clean server | Overview showing the server OK | `C5_12_dashboard_overview_ok.png` |
| 4 Data exfiltration | Overview with the alert | `C5_13_dashboard_exfiltration_alert.png` |
| 4 (same) | The Alerts page | `C5_14_dashboard_alerts_page.png` |
| 4 (same) | The drift graph | `C5_15_dashboard_drift_graph.png` |
| 9 to 12 (update tests) | The update panels: UPDATE EXPLAINED, PERMISSION WIDENED, UNDECLARED BEHAVIOUR, residue | `C5_16` to `C5_19` (the panel title tells you which name to use; the existing PERMISSION WIDENED and UNDECLARED BEHAVIOUR images came from tests 11 and 12) |
| (any) | The attacker's menu window itself | `C5_20_attacker_console.png` |

`C5_21_architecture.png` is a diagram, not a screenshot. Keep it as it is.

## Chapter 6: Results (use the setup window; these only read saved results)

Nothing here re-runs an experiment. Every command reads the committed result files, so your numbers must
match the existing images **exactly**. If one doesn't, stop and check before using it.

| # | Type this | Save as | You should see |
|---|---|---|---|
| 1 | `Get-Content eval_results\exp1_console.log \| Where-Object { $_ -notmatch '\[attacker\]\|INFO' } \| Select-Object -Last 30` | `C6_01_exp1_fixed_probes.png` | OVERALL: 54/54 detected, 3/6 benign alerted, 54/90 fired; L4 and L5 "never fired" 18 each |
| 2 | the same with `exp2_console.log` | `C6_02_exp2_keyed_probes.png` | 75/75 detected, 75/90 fired |
| 3 to 9 | Open `F:\fyp project\Driftsentry\eval_results\tables.md` in VS Code and press **Ctrl + Shift + V** for the formatted view | `C6_03` … `C6_09` | One shot per table: Table 2 (validation), 3 (RQ1 AUC), 4 (recall lost), 6 (RQ2), 7 (RQ3a), 9 (RQ3b), 10 (hypotheses) |
| 10 | `python -m eval h2b verdict` | `C6_10_iteration2_h2b_verdict.png` | The H2b verdict: FAIL |
| 11 | `python -m eval h2c verdict` | `C6_11_iteration3_h2c_verdict.png` | The H2c verdict: FAIL |
| 12 | `python -m eval h3b verdict` | `C6_12_iteration2_h3b_heldout.png` | Held-out real upgrades |
| 13 | `python -m eval h3c verdict` | `C6_13_iteration3_h3c_heldout.png` | Held-out real upgrades |
| 14 | `python -m eval validate verdict` | `C6_14_validation_verdicts.png` | Never-called tool, and per-tool thresholds |
| 15 | `python -m eval rq3u-analyse --csv eval_results/followup/h3b/rq3u_L1_rules11.csv --real-dir eval_results/followup/h3b/held_out` | `C6_15_rq3a_rules_v1_1_part1.png`, `_part2` | The `residue` rows: 100.0% (45/45) of hidden attacks, 0.0% (0/6) false alarms |
| 16 | `python "F:\fyp project\Screenshots_Chapter5_Chapter6\_scripts\ablation.py"` | `C6_16_ablation.png` | First line: `recomputed verdicts that differ from the recorded ones: 0`, then the ablation table |

In the table above, `\|` means a plain `|` when you type it.

`C6_17` to `C6_19` are charts, not screenshots. Insert the PNG files as they are.

When you finish, run `git status` in the setup window. Nothing new under `eval_results` should show as
changed. The two console logs (`exp1_console.log`, `exp2_console.log`) were already marked modified
before today.

## Tests (use the setup window)

| # | Type this | Save as | You should see |
|---|---|---|---|
| 1 | `python -m pytest -q -p no:cacheprovider` | `T_01_full_test_suite.png` | **`869 passed`** (about 2 minutes) |
| 2 | `python -m pytest -v --no-header -p no:cacheprovider tests\test_scorer_golden.py tests\test_determinism_signal.py tests\test_redact.py` | `T_02_scoring_and_signals.png` | Each test marked PASSED, then `N passed` |
| 3 | `... tests\test_probe_generator.py tests\test_safety_policy.py tests\test_subsampling.py` | `T_03_probes_keyed_and_safety.png` | |
| 4 | `... tests\test_proxy_logging.py tests\test_injector.py tests\test_insession.py` | `T_04_proxy_injector_insession.png` | |
| 5 | `... tests\test_h2c.py` | `T_05_v1_1_watch_guard.png` | |
| 6 | `... tests\test_declared_diff.py tests\test_residue_scoring.py` | `T_06_update_checking.png` | |
| 7 | `... tests\test_rules_v1_1.py tests\test_rules_v1_2.py` | `T_07_rules_v1_1_v1_2.png` | |
| 8 | `... tests\test_passive.py tests\test_calibration_math.py` | `T_08_passive_and_calibration.png` | |
| 9 | `... tests\test_rq3_dataset.py tests\test_stats.py` | `T_09_evaluation_integrity.png` | |
| 10 | `... tests\test_cli_update.py` | `T_10_cli.png` | `4 passed` |

In rows 3 to 10, `...` stands for `python -m pytest -v --no-header -p no:cacheprovider`.
For long lists, take the top of the list and the final `passed` line.

For your test-case tables, use `Tests\test_case_catalogue.csv` (opens in Excel). It doesn't need a screenshot.

## When you finish

Close the setup window. Then delete the throwaway data folder:

```powershell
Remove-Item -Recurse -Force F:\ds_capture
```
