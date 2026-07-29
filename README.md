# DriftSentry — Detecting Behavioural Rug-Pull Attacks in the Model Context Protocol

Final year project, BSc (Hons) Cyber Security.
Shevon Fernando (CB014571) — APIIT / University of Staffordshire.

---

## The problem

When you install an MCP server, the client shows you the tools it offers and you
approve them. **That approval happens once.**

A **rug pull** is when a tool you already approved turns malicious afterwards,
while its advertised definition — name, description, input schema — stays
byte-for-byte identical. This has happened in the wild: the postmark-mcp package
silently began copying users' emails; MCPoison (CVE-2025-54136) targeted a
stdio-launched configuration; Invariant Labs demonstrated a sleeper variant.

Existing defences (mcp-scan, Snyk Agent Scan, mcp-context-protector) pin a **hash
of the tool definition**. If the definition never changes, the hash never
changes, and they report that nothing is wrong. A one-shot scanner cannot help
either, because the attack happens *after* the scan.

## The two projects in this repository

They are deliberately kept apart.

| Folder | What it is |
|---|---|
| **[`Driftsentry/`](Driftsentry/)** | **The detector.** A resident proxy between the MCP client and server. At approval time it captures a *behavioural* baseline of each tool using seeded canary probes; later it replays them and scores how far behaviour has drifted. |
| **[`mcp rug pull attack server/`](mcp%20rug%20pull%20attack%20server/)** | **The attacker.** A standalone adversarial MCP server producing ground-truth rug pulls across six families and five complexity levels — plus the benign and benign-update modes needed to measure false alarms. |

**Why two projects and not one.** The obvious objection to a project that builds
both the attack and the defence is that the defence may be tuned to its own
attacks. So the separation is enforced rather than asserted: separate projects,
separate virtual environments, no shared code, and neither can import the other.
They meet only as operating-system processes speaking MCP over stdio — the same
way DriftSentry would meet any third-party server.

You can check this in two commands:

```bash
"mcp rug pull attack server/.venv/Scripts/python.exe" -c "import driftsentry"   # ImportError
"Driftsentry/.venv/Scripts/python.exe" -c "import attacker"                     # ImportError
```

## Results so far

Six attack families, all advertising byte-identical tool definitions:

| | Detected |
|---|---|
| Definition-hash pinning (what mcp-scan does) | **0 / 6** |
| DriftSentry | **6 / 6** |

False alarms, with the threshold calibrated on benign servers only and measured
on a seed it had never seen:

| | Score (alert at 1.00) |
|---|---|
| Benign server | 0.10 |
| Benign server that legitimately **updated** | 0.79 |

Detection against an adapting attacker:

| Level | Result |
|---|---|
| L1 always malicious | ALERT |
| L2 malicious on 40% of calls | ALERT |
| L3 only after a trigger | ALERT |
| L4 **probe-aware** — recognises the canary inputs | **evades** |

L4 evading is reported deliberately, not hidden. Fixed probe templates lose to an
attacker that can recognise them; randomised templates are the mitigation, and
measuring how much they recover is the project's main research contribution.

## Getting started

Each project has its own environment and its own README.

```bash
cd Driftsentry
py -m venv .venv && .venv\Scripts\activate
pip install -r requirements.lock && pip install -e .
```

```bash
cd "mcp rug pull attack server"
py -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt && pip install -e .
```

Then run the whole evaluation end to end:

```bash
cd Driftsentry
python examples/midpoint_demo.py
```

## Documentation

* [`Driftsentry/docs/CODE_GUIDE.md`](Driftsentry/docs/CODE_GUIDE.md) — **every module explained, and the detection logic in full**
* [`Driftsentry/docs/TESTING.md`](Driftsentry/docs/TESTING.md) — how to verify it works
* [`Driftsentry/docs/VIVA_DEMO.md`](Driftsentry/docs/VIVA_DEMO.md) — demonstration runbook and expected questions
* [`Driftsentry/docs/MIDPOINT_SCRIPT.md`](Driftsentry/docs/MIDPOINT_SCRIPT.md) — the mid-point presentation script
* [`mcp rug pull attack server/README.md`](mcp%20rug%20pull%20attack%20server/README.md) — the attack families and levels

## Status

Built in phases. Complete: the interception proxy, config ingestion, the probe
engine, the drift scorer with benign-only threshold calibration, the alerting and
mitigation layer, and the full adversarial testbed.

Remaining: the resident daemon and scheduler with a monitoring dashboard, the
labelled corpus with a disjoint calibration/test split, the four evaluation
experiments, and the reproducibility package.

## Ethics and safety

The attack server is a closed-loop research artefact. It contains no working
exploit against any third-party system, contacts no real network destination
(its "exfiltration" writes to a local file and its "new egress" connects to a
decoy listener it starts itself on loopback), and handles only synthetic data. It
exists solely to evaluate defensive tooling.
