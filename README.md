# DriftSentry: Detecting Behavioural Rug-Pull Attacks in the Model Context Protocol

Final-year project, BSc (Hons) Cyber Security.
Shevon Fernando (CB014571), APIIT / University of Staffordshire.
Release 1.0.0. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

---

## The problem

When you install an MCP server, the client shows you the tools it offers and you
approve them once. A **rug pull** is when an approved tool turns malicious later.
Existing defences (mcp-scan, Snyk Agent Scan, mcp-context-protector) pin a hash of
the tool definition. If the definition stays the same, the hash stays the same
and they report nothing. This has happened in the wild: postmark-mcp began
copying users' emails, and MCPoison (CVE-2025-54136) targeted a stdio-launched
configuration.

DriftSentry records how each tool **behaves** when you approve it, using seeded
canary probes. It then re-probes on a schedule and scores how far the behaviour
has drifted.

## The two research gaps

| Gap | Question | What was built |
|---|---|---|
| **1. Recognisable probes** | Behavioural re-probing only works if the server cannot tell a probe from a real call. Which signals give probes away, how much detection is lost, and do countermeasures get it back? (RQ1, RQ2) | Keyed probes (HMAC per server, rotated each cycle), a learned-recogniser attacker (level L6) that sees five feature families, and three countermeasures (host isolation, traffic mimicry, secret subsampling). |
| **2. Attacks hidden in legitimate updates** | Real servers ship updates. Accepting every update hides an attack inside one; refusing every update cries wolf. Can the observed change be checked against what the update *declares*? (RQ3) | Declared-diff residue checking: diff the old and new tool definitions, mask the declared output changes, re-score, and alert only on what the declaration does not explain. The permitted-change rules were frozen before any result was measured (`eval_results/rq3u/rules_frozen.json`). |

## Results

Every number below comes from [Driftsentry/eval_results/tables.md](Driftsentry/eval_results/tables.md),
which `python -m eval tables` generates from the result files. Nothing in it is
typed by hand.

| Hypothesis | Verdict | Measured |
|---|---|---|
| **H1:** a non-argument feature family separates probes from genuine calls at AUC ≥ 0.9, and exploiting it drops recall by ≥ 50 pp | **PASS** | client AUC 1.000, session 0.983, timing 0.951; each dropped recall from 100% to 0% |
| **H2:** mimicry and subsampling bring AUC to ≤ 0.6 with recall within 10 pp | **FAIL** | best AUC 0.994; recall gap −50 pp; false alarms +0.0 pp |
| **H3:** residue detects ≥ 80% of hidden attacks, beats three baselines, and flags ≤ 15% of real upgrades | **FAIL** | 45/45 detected, beats all three baselines (Holm p ≤ 1.9e-9); but 2 of 4 real upgrades left a residue (50%) |
| Full DriftSentry detects more than hash pinning | **PASS** | 10/10 against 0/10, exact McNemar p = 0.002 |

A FAIL is reported as a result. Nothing was tuned afterwards to make it pass.

**Not measured.** Experiment 2 (fixed against keyed probes as a rate) was never
run. Only a four-cell demonstration exists (Table 1b). Per-tool thresholds and
attacks on never-called tools were not measured either. Three of the seven
real-upgrade servers (calculator, sqlite, duckdb) could not be run at their old
release on the current environment. The real-upgrade servers are unlabelled, so
the RQ3b rate is reported unlabelled.

## The two projects in this repository

| Folder | What it is |
|---|---|
| **[`Driftsentry/`](Driftsentry/)** | **The detector.** A stdio proxy, behavioural baselines, a drift scorer, declared-diff residue checking, a monitoring daemon and a desktop dashboard. Also holds the evaluation harness (`eval/`) and its results. |
| **[`mcp rug pull attack server/`](mcp%20rug%20pull%20attack%20server/)** | **The attacker.** A standalone MCP server that produces ground-truth rug pulls (six families, levels L1–L6), malicious changes hidden in updates (covers C0–C3), and benign updates for measuring false alarms. Includes a numbered test menu for demonstrations. |

The detector could be tuned to its own attacks, so the two projects are kept
separate: separate virtual environments, no shared code, and neither can import
the other. They communicate only as processes speaking MCP over stdio:

```bash
"mcp rug pull attack server/.venv/Scripts/python.exe" -c "import driftsentry"
```
```bash
"Driftsentry/.venv/Scripts/python.exe" -c "import attacker"
```

Both should fail with `ModuleNotFoundError`.

## Install

Requires Python 3.11 or later. Developed and tested on CPython 3.14 on Windows 11.

```bash
cd Driftsentry
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock
.venv\Scripts\python -m pip install -e .
```

```bash
cd "mcp rug pull attack server"
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e .
```

Check the detector:

```bash
cd Driftsentry
.venv\Scripts\python -m pytest -q
```

## See it work: one command

```bash
cd Driftsentry
.venv\Scripts\driftsentry demo
```

This command does four things:

1. It resets the attacker to its clean server.
2. It enrols the clean server with keyed probes. This takes a minute or two the first time.
3. It opens the attacker's **test menu** in its own console.
4. It opens the DriftSentry **dashboard**.

Pick a test number in the menu. Within about one check interval (10 s) the
dashboard shows what it found. The menu and the dashboard never talk to each
other: the dashboard finds out only by probing. The step-by-step guide, with
what each of the 12 tests should show, is
[Driftsentry/docs/USER_GUIDE.md](Driftsentry/docs/USER_GUIDE.md).

## Reproduce the results

```bash
cd Driftsentry
.venv\Scripts\python -m eval tables
```

This rebuilds `eval_results/tables.md` from the stored result files. The
experiments themselves (`python -m eval run | collect | rq3 | t20 | rq3u |
rq3u-analyse | real`) take hours. Their raw outputs are in `eval_results/`.

## Documentation

* [`Driftsentry/README.md`](Driftsentry/README.md): the detector, its commands and how it scores
* [`Driftsentry/docs/USER_GUIDE.md`](Driftsentry/docs/USER_GUIDE.md): installing, running the demo, and protecting a real MCP client
* [`Driftsentry/docs/VIVA_DEMO.md`](Driftsentry/docs/VIVA_DEMO.md): the viva demonstration runbook
* [`Driftsentry/docs/CODE_GUIDE.md`](Driftsentry/docs/CODE_GUIDE.md): every module explained
* [`Driftsentry/eval_results/tables.md`](Driftsentry/eval_results/tables.md): every measured result
* [`mcp rug pull attack server/README.md`](mcp%20rug%20pull%20attack%20server/README.md): the attack families, levels and covers

## Ethics and safety

The attack server is a closed-loop research artefact. It contains no working
exploit against any third-party system and contacts no real network destination.
Its "exfiltration" writes to a local file, and its "new egress" connects to a
decoy listener it starts itself on loopback. It handles only synthetic data and
exists only to evaluate defensive tooling. The real servers used for RQ3b are
local, open-source MCP servers run on synthetic data, and none of them uses the
network.
