# DriftSentry: Viva Demonstration Runbook

A live demonstration of about 10 minutes, covering both research gaps. Every
expected output here was measured through the dashboard's own path. The
detailed reference is [USER_GUIDE.md](USER_GUIDE.md).

**The two claims the demonstration exists to show:**

> 1. A tool can turn malicious after approval while its definition stays
>    byte-for-byte identical. Hash pinning cannot see it. Behavioural
>    re-probing with keyed probes can.
> 2. A malicious change can hide inside a legitimate update. Checking what
>    the update **does** against what it **declares** separates the two.

---

## The day before

1. Run the suite. Pytest must exit 0:

   ```bash
   .venv\Scripts\python -m pytest -q
   ```

2. Do a full dry run of `driftsentry demo` and go through all twelve tests. The
   first run enrols `acme` with keyed probes, which takes a minute or two. Say
   this is the approval step, done once at install. On the day the baseline is
   reused and setup takes seconds.

3. If setup prints `WARNING: the alert threshold is provisional`, calibrate:

   ```bash
   .venv\Scripts\driftsentry calibrate --server acme
   ```

4. Make sure nothing else is using port 8787.

## On the day

```bash
cd "F:/fyp project/Driftsentry"
.venv\Scripts\driftsentry demo
```

Arrange the two windows side by side: the menu on the left, the dashboard on
the right. Point out that they never talk to each other. The menu changes the
server, and the dashboard finds out only by probing it every 10 seconds.

### Part 1: Gap 1 (about 5 minutes)

| Pick | Say | Expect |
|---|---|---|
| **1** | "The server I approved. It is clean." | OK |
| **4** | "Same definitions, byte for byte. Now it copies data to a file. A hash scanner says nothing changed." | ALERT, `new_file_access`. Read out the GROUND line in the menu. |
| **1** then **Trust** | "Back to clean. I trust it again." | OK |
| **7** | "This attacker recognises the fixed probe values a scanner always sends and behaves only while it is being tested. Keyed probes change every cycle and come from a secret, so it cannot." | ALERT |
| **6** | "A sleeper. Benign for 45 seconds, then it turns." | OK, then ALERT about 45 s later |
| **8** | "And this is honest: a legitimate rewording also alerts. That is a false alarm, and it is why Gap 2 exists." | ALERT, `determinism_break` |

### Part 2: Gap 2 (about 4 minutes)

| Pick | Say | Expect |
|---|---|---|
| **9** | "A real update: a new output field. Without update checking this scored WATCH 0.85. With it, the change matches what the update declared, and it is accepted." | OK + **UPDATE EXPLAINED**, declared `output added last_contact` |
| **10** | "The same update, with exfiltration hidden inside it. The declared field is explained. The file access is not declared anywhere, so it is residue." | ALERT + **UNDECLARED BEHAVIOUR**, residue `new_file` |
| **11** | "This update removes `readOnlyHint`. It gives the tool more power, so it is raised even though nothing bad has happened yet." | WATCH + **PERMISSION WIDENED** |
| **12** | "The attacker widens the permission so the exfiltration looks declared. It is still caught." | ALERT + PERMISSION WIDENED |

### Part 3: The numbers (about 1 minute)

Open [eval_results/tables.md](../eval_results/tables.md) at Table 10:

* **H1 PASS.** Client, session and timing features give probes away (AUC
  0.95 to 1.00). A server exploiting them dropped recall from 100% to 0%.
* **H2 FAIL.** The countermeasures did not hide the probes (best AUC 0.994).
  This is reported as a result.
* **H3 FAIL, with the detection half met.** Residue caught 45/45 hidden
  attacks and beat all three baselines (Holm p ≤ 1.9e-9), with 0/6 false
  alarms on synthetic benign updates. But 2 of 4 real benign upgrades left a
  residue, against a 15% target.
* **Validation PASS.** Full DriftSentry 10/10 against hash pinning 0/10
  (McNemar p = 0.002).

## If something breaks

| Symptom | Cause and fix |
|---|---|
| Every check stays OK with an attack armed | The menu and the dashboard's server read different homes. Close both and run `driftsentry demo` again. Do not start the menu by hand without the `--home` the demo prints. |
| `address already in use` | Another dashboard is running. Close it, or use `--port 8790`. |
| `no attacker found at ...` | The attack server's `.venv` is missing or in another folder. Install it, or pass `--attacker DIR`. |
| QUARANTINED will not clear | Press **Trust** in the dashboard (or `driftsentry trust --server acme`), then pick test 1. |

## Questions to expect

**"You built the attacker too. Isn't the detector tuned to it?"**
The two are separate projects with separate environments, and neither can
import the other (show the `ModuleNotFoundError`). The alert threshold is
calibrated on benign behaviour only. The update-checking rules were frozen to a
hashed file before any result was measured, and failed hypotheses were left
failed.

**"Why did H3 fail?"**
The time and git upgrades changed behaviour without declaring it: the new time
release added structured output, and git reworded two descriptions. Whether a
user should be told about that is debatable, but under the frozen rules it is
residue, and it is reported as residue.

**"What was not measured?"**
Experiment 2 (fixed against keyed probes as a rate) was not run; only a
four-cell demonstration exists. Per-tool thresholds and attacks on never-called
tools were not measured. Three real servers could not run their old release on
the current environment.

**"Could this run in production?"**
For stdio servers, yes: `driftsentry init` wraps a real client config and
`restore` removes it. It does not cover HTTP servers, and probing costs one
probe cycle per check per server.
