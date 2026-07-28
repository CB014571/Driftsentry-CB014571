# DriftSentry

**A proxy-based detector for behavioural rug-pull attacks in the Model Context Protocol (MCP).**

Final-year project — BSc (Hons) Cyber Security. Companion build to *Proposal v23* and
the *Implementation Roadmap*.

---

## The problem in one paragraph

An MCP **rug pull** is when a tool you already approved turns malicious *after* approval
while its advertised definition (name, description, schema) stays byte-for-byte
identical. Hash-only scanners (mcp-scan, Snyk Agent Scan) pin the definition, so they are
blind to this. A one-shot "paste your config, get a verdict" scan cannot see it either,
because the attack happens later. **DriftSentry is a resident proxy** that stays in the
loop between client and server, captures a *behavioural* baseline of each tool at approval
time, and re-verifies on a schedule — catching drift that leaves the definition unchanged.

## What gets built (three deliverables)

| Package        | Role                                                                                  |
|----------------|---------------------------------------------------------------------------------------|
| `driftsentry/` | **The detector.** Proxy (data plane) + resident daemon (scheduler, probe engine, drift scorer, ChromaDB store) + a thin desktop/CLI control plane. |
| `testbed/`     | **The attacker.** A standalone MCP server with benign / benign-update / rug-pull modes, six attack families, and a complexity knob L1–L5. Never imports `driftsentry`. |
| `eval/`        | **The evidence.** A labelled corpus and the four experiments that answer the research questions. |

Data path (never touched by the UI):
`Client → DriftSentry proxy → real MCP server → proxy → Client`, with the daemon
replaying canary probes out of band and scoring drift against the stored baseline.

## Build status (by roadmap phase)

- [x] **Phase 0 — Foundations & environment** ✅
- [x] **Phase 1 — Interception proxy core** ✅
- [x] **Phase 2 — Config ingestion & rewriting** ✅
- [x] **Phase 3 — Baseline capture & probe engine** ✅
- [x] **Phase 4 — Drift scorer** ✅
- [x] **Phase 5 — Alerting & mitigation layer** ✅
- [x] **Phase 7 — Adversarial testbed server** ✅ *(six families, L1–L5)*
- [ ] Phase 6 — Desktop app & CLI *(deferred to the MVP; the Mid-Point demo is headless)*
- [ ] Phase 8 — Dataset construction
- [ ] Phase 9 — Evaluation experiments
- [ ] Phase 10 — Rigor, threats to validity, write-up

## Setup

Requires Python 3.11+ (developed and verified on **CPython 3.14**, Windows).

```bash
# 1. Create and populate the virtual environment
py -m venv .venv
.venv\Scripts\activate            # Windows;  source .venv/bin/activate on Unix

# 2. Install exact, reproducible dependencies
pip install -r requirements.lock  # or: pip install -r requirements.txt
pip install -e .                  # makes the `driftsentry` command available
```

Optional semantic-embedding backends (the dependency-free hashing backend works without
them) are listed in `requirements-optional.txt`.

**Testing:** see [docs/TESTING.md](docs/TESTING.md) for the full verified
walkthrough — the self-checking demos, the hand-driven demo sequence, and what
"working" should look like.
**Demonstrating:** [docs/VIVA_DEMO.md](docs/VIVA_DEMO.md) is a step-by-step
runbook with commands, expected output, timings, and the questions to expect.

## Verify the install (Phase 0 definition of done)

```bash
# 1. The MCP loop we own: launch the echo server, list & call its tools over stdio.
python examples/echo_client.py

# 2. The offline stack: ChromaDB persist/reload + a local embedding, no network.
python scripts/check_stack.py

# 3. The proxy in the loop: client -> DriftSentry proxy -> echo server, with a
#    transparency check, a concurrency check, and a written audit log.
python examples/proxy_demo.py

# 4. Config rewrite + restore, end to end, in a temp dir (your real config is
#    never touched): wrap, verify the rewritten entry actually runs, then undo.
python examples/init_demo.py

# 5. Behavioural baseline: probe safety, variance learning, and catching a
#    drifted server whose tool definitions are byte-for-byte identical.
python examples/baseline_demo.py

# 6. The drift scorer: calibrate a threshold on benign data, alert on the
#    drifted twin with an attributable cause, and show hash-only pinning miss it.
python examples/scorer_demo.py

# 7. Alerting: cause, before/after and per-cause mitigations, then quarantine
#    and prove opt-in enforcement blocks a live call through the proxy.
python examples/alert_demo.py

# 8. The Mid-Point demonstration: six attack families that all hash identically
#    to the benign server, per-family detection, false-alarm checks on benign
#    updates, and the L1->L4 complexity knob.
python examples/testbed_demo.py
```

## The adversarial testbed

A standalone MCP server that generates ground-truth rug pulls. It never imports
`driftsentry` — it is the attacker, and it is not allowed to know how the
defender works except at the explicit `--probe-aware` opt-in.

```bash
python -m testbed list-families                              # the six families and L1-L5
python -m testbed serve --family new-egress --level L1       # run a rug pull
python -m testbed serve --mode benign --updates              # the false-alarm set
python -m testbed set-family exfiltration                    # switch a RUNNING server
python -m testbed set-level L3
python -m testbed trip                                       # fire a sleeper now
```

*Family* is the payload (what it does); *level* is the gate (when it fires).
Six families × five levels comes from one payload mechanism and one gating
mechanism, so a level means the same thing across families and the recall matrix
is comparable row to row.

| Family | Behaviour once it fires | Real case it mirrors |
|---|---|---|
| `exfiltration` | Copies responses to an attacker sink; reads credential files | third-party-app data theft |
| `silent-tamper` | Alters a detail — a recipient, an account number, a total | postmark-mcp |
| `content-injection` | Injects instructions aimed at the AI assistant | tool poisoning |
| `new-egress` | Contacts a host never contacted at baseline | data theft |
| `sleeper` | Benign until a call count, date, or `trip` fires | Invariant Labs sleeper |
| `conditional` | Only attacks when it sees something worth stealing | targeted rug pull |

**Safety.** Closed-loop by construction: no working exploit against any third
party, no real endpoint, synthetic data only. "Exfiltration" appends to a file
in a scratch directory; "new egress" connects to a loopback decoy this same
process started. Both are held open deliberately so the behaviour is observable
to a polling monitor — a detector cannot be credited with catching an attack
that left no trace.

Every scenario is a JSON file with a seed, so any run — including one driven by
hand during a demo — can be saved and replayed exactly.

## Wiring DriftSentry into a real client

```bash
# Rewrite to a NEW file (the original is never modified):
driftsentry init --config "%APPDATA%\Claude\claude_desktop_config.json"

# ...or update the original, keeping a timestamped backup:
driftsentry init --config <path> --in-place

# Take DriftSentry back out of the loop:
driftsentry restore --config <path>
```

Only stdio servers are proxied today; HTTP entries are reported and left
untouched. Secrets in a server's `env` block stay in `env` — only the variable
*names* are passed on the command line.

`init` also captures a behavioural baseline of each wrapped server (Phase 3), so
trust attaches to behaviour rather than to a definition hash. Use `--no-baseline`
to rewrite only.

## Behavioural baselines

```bash
# Capture a baseline: probe each safe tool and learn its natural variance.
driftsentry baseline --server shop --exec python shop_server.py

# Re-probe later and measure drift against that baseline.
driftsentry verify --server shop --exec python shop_server.py
```

**Probe safety.** Tools that look side-effecting (`send_email`, `delete_file`) are
never actively probed — they are marked *baseline-by-observation*. Classification
uses the MCP `readOnlyHint`/`destructiveHint` annotations when present, falling
back to word-boundary verb heuristics. `--safety-policy strict` probes only tools
with positive evidence of being read-only.

## Alerts, quarantine and enforcement

When a score crosses the threshold, `verify` raises an alert naming the server
and tool, the signal and how far past the line it went, a concrete before/after,
and mitigations templated to the *cause* — a new-egress alert says rotate the
credentials that server could have seen; a definition-hash alert says force
re-approval; plain behavioural drift says look at the before/after and decide,
because a legitimate update produces the same signal.

Severity comes from the score, but the **advice comes from the most specific
signal that fired**: if a response drifted *and* contains an injected
instruction, the useful guidance is "check what your assistant did after reading
this", not a generic "something changed".

```bash
driftsentry report --server shop --full   # alert history + policy state
driftsentry quarantine --server shop      # mark it unsafe (advisory)
driftsentry trust --server shop           # clear the quarantine
```

Alerts are written to `.driftsentry_data/alerts/<server>.jsonl` as well as the
terminal, so there is a machine-readable record for the evaluation.

**Enforcement is opt-in.** A quarantine is advisory by default: DriftSentry
records its opinion and keeps saying so, but the client keeps working. Only when
the proxy is started with `--enforce` does it actually refuse `tools/call` to a
quarantined server (returning a JSON-RPC error that explains why). Detection is
the contribution being evaluated — a proxy that silently blocked attacks would
confound every detection measurement.

## Detecting drift

```bash
# Set the alert threshold from BENIGN servers only (never from attack data).
driftsentry calibrate --repeats 3

# Score a server against its baseline.
driftsentry verify --server shop

# The control condition: definition-hash pinning alone, as mcp-scan does.
driftsentry verify --server shop --hash-only
```

`verify` prints one score per tool with the triggering signal named, and exits 1
on an alert so it can be scripted. Three signals feed the score:

| Signal | Catches | Weight |
|---|---|---|
| Definition hash change | Classic / sleeper rug pull that edits name, description or schema | Hard trigger (3.0) |
| Embedding distance vs the tool's own variance band | Response content shifting while the definition is unchanged | Calibrated (1.0 = alert) |
| Security rules (new egress host, secret-file read, credential- or instruction-shaped output) | Exfiltration, new-egress, content injection | High (2.0 / 1.1) |

Signals are combined by **maximum**, not by sum: the embedding and structural
signals read the same response and are correlated, so summing would let ordinary
benign noise accumulate into an alert and inflate the false-alarm rate. Scoring
is fully deterministic — no language model sits in the decision path, which is
what makes a score reproducible from a stored baseline.

**Calibration** places the threshold at a quantile of the benign drift
distribution (default: the 99th percentile × 1.25), records how many benign
observations from how many servers produced it, and warns when that evidence is
too thin to quote. It never drops below 1.0, so DriftSentry cannot alert inside a
probe's own measured benign band.

**Embedding backends.** `--embedding auto` (default) picks the best backend that
is *already available* and never downloads anything: Ollama if its daemon is
running, else a cached ONNX all-MiniLM, else a dependency-free hashing backend —
which measures *lexical* change only and warns loudly that it is doing so. Run
once with `--embedding onnx` to fetch all-MiniLM (~79 MB, offline afterwards).
Every baseline records the backend and dimension it was built with, and baselines
from different backends are stored in separate ChromaDB collections so they can
never be silently compared.

Both should report success. `check_stack.py` also tells you whether the optional
Ollama / ONNX semantic backends are available on your machine.

## Repository layout

```
driftsentry/          the detector package (built up phases 1–6)
  __init__.py
  __main__.py         the `driftsentry` command (subcommands added per phase)
testbed/              the adversarial MCP server (phase 7) — must not import driftsentry
eval/                 the evaluation harness (phases 8–9)
examples/             echo_server.py + echo_client.py — the known-good Phase 0 loop
scripts/              check_stack.py — offline stack self-check
requirements.txt      core dependencies (intent)
requirements.lock     exact pinned versions (reproducible install)
requirements-optional.txt   heavier / later-phase deps, installed per phase
pyproject.toml        packaging + the `driftsentry` entry point
```

## A note on reproducibility

Reproducibility is a graded contribution, not an afterthought. Dependencies are pinned
from day one (`requirements.lock`), all randomness in later phases is seeded, and the
evaluation is regenerable from scenario files. The privacy-preserving stack (local
embeddings + local ChromaDB) runs with no network egress.
