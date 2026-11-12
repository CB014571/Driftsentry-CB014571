# DriftSentry

**Detects behavioural rug-pull attacks in the Model Context Protocol (MCP).**

Release 1.0.0. This is the detector half of the final-year project. The project
overview, the research gaps and the headline results are in the
[repository README](../README.md). Every measured number is in
[eval_results/tables.md](eval_results/tables.md).

---

## What it does

1. **Baseline at approval.** When you approve a server, DriftSentry sends each
   safe tool a set of canary probes and records how it answers: response
   embeddings and their natural variance, structure, files opened, and network
   hosts contacted. Tools that look side-effecting (`send_email`,
   `delete_file`) are never probed. They are monitored by observation.
2. **Re-probe on a schedule.** It probes again later and scores the drift
   against the baseline. With **keyed probes** the values are drawn from a
   secret per-server key and change every cycle, so a server cannot learn to
   recognise them and behave only while it is being tested (Gap 1).
3. **Check updates against what they declare.** When the tool definitions
   change, DriftSentry diffs the old and new definitions. Behaviour the new
   definitions declare, such as an added output field, is explained. Anything
   they do not declare is **residue** and alerts. A widened permission, such as
   `readOnlyHint` removed, is an escalation (Gap 2).
4. **Explain and contain.** An alert names the tool, the signal, a before and
   after, and mitigations specific to the cause. The server is marked
   quarantined. With `--enforce` the proxy refuses calls to it.

No language model sits in the decision path. Scoring is deterministic, so a
score can be reproduced from a stored baseline.

## Install

Python 3.11 or later. Developed and tested on CPython 3.14 on Windows 11.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock
.venv\Scripts\python -m pip install -e .
```

`requirements.lock` holds the exact versions used for the results.
`requirements-optional.txt` lists optional semantic-embedding backends.

```bash
.venv\Scripts\python -m pytest -q
```

## Commands

| Command | What it does |
|---|---|
| `driftsentry demo` | The demonstration in one command: the attacker's test menu and the dashboard. See [docs/USER_GUIDE.md](docs/USER_GUIDE.md). |
| `driftsentry ui` | The desktop dashboard, with the monitoring daemon behind it. It checks every enrolled server on a schedule. |
| `driftsentry baseline --server NAME [--probe-mode keyed] --exec CMD...` | Enrol a server. Use `--probe-mode keyed`. `fixed` stays the default only so earlier experiments reproduce. |
| `driftsentry calibrate` | Set the alert threshold from benign servers only. Attack data is never used. |
| `driftsentry verify --server NAME [--update-check] [--cycle N]` | Check once. Exits 1 on an alert. `--update-check` scores a changed definition as an update. `--hash-only` is the mcp-scan-style control. |
| `driftsentry watch --server NAME` | Re-check on a schedule in the terminal. Uses a new probe cycle each time, with update checking on. |
| `driftsentry init --config PATH` | Rewrite an MCP client config so every stdio server runs through the DriftSentry proxy, and baseline each one. The original is not modified unless `--in-place` is given, and then a backup is kept. |
| `driftsentry restore --config PATH` | Take DriftSentry back out of a client config. |
| `driftsentry run --server NAME --exec CMD...` | The transparent stdio proxy itself. `--enforce` blocks calls to a quarantined server. `--passive` also checks live traffic. |
| `driftsentry report`, `quarantine`, `trust` | Alert history and policy state. |

Data is stored under `.driftsentry_data/`, or `DRIFTSENTRY_HOME` if set:
baselines, the calibration, alerts (JSONL), policy and the per-server probe keys.

## How a score is made

| Signal | Catches | Weight |
|---|---|---|
| Definition hash change | A rug pull that edits name, description or input schema | hard trigger (3.0) |
| Embedding distance against the tool's own variance band | Response content shifting while the definition is unchanged | calibrated (1.0 = alert) |
| Structural change | Changed response shape | 0.85 (WATCH on its own, never ALERT) |
| Determinism break | A tool that answered a probe identically now varies | 1.15 |
| Field drift | A specific output field changed value | 1.6 |
| Security rules: new egress host, new file opened, credential- or instruction-shaped output | Exfiltration, new egress, content injection | 2.0 high, 1.1 medium |
| Declaration escalation (update checking) | An update widened a tool's permissions | 0.9 (WATCH unless combined) |

WATCH starts at 0.85 and ALERT at 1.00.

Signals are combined by **maximum**, not by sum. The embedding and structural
signals read the same response and are correlated, so summing would let benign
noise add up to an alert.

**Calibration** sets the threshold at a quantile of the benign drift
distribution (default: 99th percentile × 1.25). It records how much evidence
produced the threshold and warns when that evidence is thin. It never drops
below 1.0.

**Embedding backends.** `--embedding auto` uses the best backend already
installed and never downloads anything: Ollama if running, then a cached ONNX
all-MiniLM-L6-v2, then a dependency-free hashing backend, which measures only
lexical change and warns that it does. Baselines record their backend, and
baselines from different backends are never compared.

**Update checking** (`driftsentry/declared_diff.py`, `driftsentry/residue.py`).
The permitted-change rules are fixed in code and were frozen before any result
was measured (`eval_results/rq3u/rules_frozen.json`, rules version 1.0).
`verify_rules()` fails if the code and the frozen file disagree. Nothing is
re-baselined automatically. A fully explained update lists the tools that are
safe to re-baseline, and the user decides.

## The evaluation

`eval/` is the harness. It launches the attack server as a separate process,
reads ground truth from the attacker's event log, and writes CSV/JSONL to
`eval_results/`.

```bash
.venv\Scripts\python -m eval tables
```

This rebuilds `eval_results/tables.md` from those files. The experiment
subcommands are `run`, `collect`, `rq3`, `t20`, `rq3u`, `rq3u-analyse` and
`real`. Full sweeps take hours.

## Repository layout

```
driftsentry/        the detector
  proxy.py            stdio proxy (data plane)
  baseline.py         probing, variance learning, re-probing
  probe_generator.py  keyed probe values (HMAC per server, per cycle)
  scorer.py           signals, combination, verdict
  declared_diff.py    old against new tool definitions
  residue.py          frozen permitted-change rules and the residue verdict
  calibration.py      benign-only threshold
  alerts.py policy.py the alert card, quarantine, enforcement
  daemon.py api.py    scheduled checking and the localhost API (127.0.0.1)
  ui/index.html       the dashboard
  demo.py             `driftsentry demo`
eval/               the evaluation harness and statistics
eval_results/       raw results and tables.md
tests/              pytest suite
examples/ scripts/  per-component self-checks (scripts/run_all_checks.py)
docs/               user guide, viva runbook, code guide
```

## Limits

* Only stdio servers are proxied. HTTP entries in a client config are reported
  and left alone.
* A tool that is never probed (side-effecting) is covered only by observation
  of real calls.
* Keyed probes defeat a recogniser that keys on probe **values**. RQ1 measured
  that client, session and timing features still give probes away, and the
  countermeasures tested did not close that (H2 failed).
* Update checking flagged 2 of 4 real benign upgrades (time, git). In both,
  behaviour changed in ways their definitions did not declare. This counts
  against H3 and is reported in Table 9.
