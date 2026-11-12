# DriftSentry User Guide

This guide covers installing DriftSentry, running the demonstration, and putting
DriftSentry in front of a real MCP client. Every expected output below was
measured through the same path the dashboard uses. None of it is aspirational.

---

## 1. Install

You need Python 3.11 or later. DriftSentry was tested on CPython 3.14 on
Windows 11. The two projects have separate environments on purpose.

```bash
cd "F:/fyp project/Driftsentry"
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock
.venv\Scripts\python -m pip install -e .
```

```bash
cd "F:/fyp project/mcp rug pull attack server"
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e .
```

Check the detector. The whole suite should pass:

```bash
cd "F:/fyp project/Driftsentry"
.venv\Scripts\python -m pytest -q
```

**Semantic embeddings.** Without them DriftSentry falls back to a hashing
backend that measures only lexical change, and it says so. To fetch the
all-MiniLM-L6-v2 ONNX model once (about 79 MB, offline afterwards), enrol any
server with `--embedding onnx`. The demo uses whatever backend is already
installed.

## 2. The demonstration

```bash
cd "F:/fyp project/Driftsentry"
.venv\Scripts\driftsentry demo
```

The terminal reports each setup step:

```
attacker   : F:\fyp project\mcp rug pull attack server
home       : F:\fyp project\mcp rug pull attack server\.demo_home  (shared by the server and the menu)
scenario   : reset to the clean server (release v1n, test 1)
baseline   : enrolling 'acme' with keyed probes (...); this takes a minute or two
```

Then two windows open:

* **The attacker's test menu**, in its own console. You arm attacks here.
* **The DriftSentry dashboard**. It finds them by probing, every 10 seconds.

The two never communicate. The menu writes a scenario file. The dashboard
learns about it only from how the server behaves.

**If an `acme` baseline already exists**, it is reused only when it is already
keyed and launches this attacker the same way. Otherwise it is copied to
`.driftsentry_data/baseline_backups/` and replaced. Backups are never deleted.
Pass `--rebaseline` to force a fresh enrolment.

**If the terminal prints `WARNING: the alert threshold is provisional`**, run
the calibration before presenting:

```bash
.venv\Scripts\driftsentry calibrate --server acme
```

### The twelve tests

Pick a number in the menu and press Enter. After each test the menu shows the
attacker's own record of what it actually did (the ground truth), so you can
compare it with what the dashboard reports.

**Gap 1: attacks behind an unchanged definition.** Every one of these
advertises byte-identical tool definitions, so hash pinning sees nothing.

| # | Test | Dashboard shows |
|---|---|---|
| 1 | Clean server | OK |
| 2 | Content injection | ALERT, behavioural_drift |
| 3 | Silent tamper | ALERT, behavioural_drift |
| 4 | Data exfiltration | ALERT, new_file_access |
| 5 | New egress host | ALERT, new_egress_host |
| 6 | Sleeper | OK for about 45 s, then ALERT |
| 7 | Probe-aware evasion (L4) | ALERT. It recognises fixed probe values, but keyed probes are not recognised. |
| 8 | Legitimate rewording | ALERT, determinism_break. **This is a false alarm**, shown deliberately. |

**Gap 2: attacks hidden in a legitimate update.** These ship a new release
whose definitions change. The dashboard adds an update panel under the server.

| # | Test | Dashboard shows |
|---|---|---|
| 9 | Legitimate update: new field | OK + UPDATE EXPLAINED (declared: output added `last_contact`) |
| 10 | Update hiding exfiltration | ALERT + UNDECLARED BEHAVIOUR, residue `new_file` |
| 11 | Update widens a permission | WATCH + PERMISSION WIDENED |
| 12 | Widened permission covering exfiltration | ALERT + PERMISSION WIDENED |

Test 9 is the point of Gap 2. Without update checking the same release scores
WATCH 0.85, because its response shape changed. With update checking the
change is matched to what the update declared, and it is accepted.

**Between tests**, choose test 1 to return to the clean server. A server
quarantined by an alert stays marked QUARANTINED until you trust it again,
either with its **Trust** button in the dashboard or from a terminal:

```bash
.venv\Scripts\driftsentry trust --server acme
```

### Options

| Option | Effect |
|---|---|
| `--interval 10` | seconds between checks |
| `--rebaseline` | enrol again even if a current keyed baseline exists |
| `--no-menu` | do not open the menu; run it yourself with the command the terminal prints |
| `--no-window` | serve the dashboard at http://127.0.0.1:8787 without opening a window |
| `--port 8787` | dashboard port |
| `--attacker DIR` | the attack server's folder, if it is not next to this project |

### If the dashboard never sees an attack

The dashboard's server and the menu must read the same scenario file. The demo
gives every process the same `--home` folder for this reason. It was measured
that processes started from a packaged Windows app (for example the Claude
desktop app's terminal) get a private copy of `%LOCALAPPDATA%`. When the
attacker's default home was used, the dashboard saw the clean server while
the menu armed an attack in a different file. If you run the menu by hand,
copy the exact command the demo prints. It includes `--home`.

## 3. Protecting a real MCP client

Use local stdio servers you trust at the moment you enrol them. The baseline
is only as good as the behaviour it records.

**1. Wrap the client config.** This writes a new file, and the original is not
changed:

```bash
.venv\Scripts\driftsentry init --config "%APPDATA%\Claude\claude_desktop_config.json" --no-baseline
```

Point the client at the new file, or use `--in-place`, which keeps a
timestamped backup.

**2. Enrol each server with keyed probes:**

`--exec` is the server's own launch command, exactly as the client config
gives it. For example, for mcp-server-time installed into its own environment
(the way the evaluation ran it):

```bash
.venv\Scripts\driftsentry baseline --server time --probe-mode keyed --exec C:\servers\time\.venv\Scripts\python.exe -m mcp_server_time
```

**3. Calibrate the threshold** on the servers you just enrolled, all of them
benign:

```bash
.venv\Scripts\driftsentry calibrate
```

**4. Monitor:**

```bash
.venv\Scripts\driftsentry ui
```

Or monitor a single server in the terminal:

```bash
.venv\Scripts\driftsentry watch --server time
```

**5. When a server updates**, check it once by hand:

```bash
.venv\Scripts\driftsentry verify --server time --update-check --cycle 2
```

Use a new `--cycle` number for each manual check so keyed values never repeat.
`ui` and `watch` do this for you. An explained update lists the tools that are
safe to re-baseline. Re-baselining is your decision and never automatic.

**6. Enforcement.** A quarantine is advisory unless the proxy runs with
`--enforce`, in which case calls to a quarantined server are refused with an
error explaining why.

**Remove DriftSentry** from the client:

```bash
.venv\Scripts\driftsentry restore --config "%APPDATA%\Claude\claude_desktop_config.json"
```

## 4. What it cannot do

* Monitor HTTP/SSE servers. Only stdio is proxied.
* Probe side-effecting tools. These are covered only by observing real calls.
* Hide its probes from a server that classifies by client, session or timing
  features. RQ1 measured that these give probes away, and the countermeasures
  tested did not fix it (H2 failed).
* Tell a benign behaviour change from a malicious one when the update does not
  declare it. Two of four real benign upgrades (mcp-server-time,
  mcp-server-git) were flagged for this reason.

The measured numbers behind each point are in
[../eval_results/tables.md](../eval_results/tables.md).
