# DriftSentry — implementation brief (context for ChatGPT)

Paste this whole block into ChatGPT as background. Everything here is taken from
the real codebase, verified 2026-08-15. Where something is not built, it says so.

---

## What the project is

DriftSentry is a BSc Cyber Security final-year project. It detects **behavioural
rug-pull attacks** against Model Context Protocol (MCP) servers.

The threat: an MCP server advertises tools to an AI assistant; the user approves
a tool once, based on its name, description and JSON input schema. A malicious
server can later change what the tool *does* — return altered data, copy answers
to an attacker, inject instructions aimed at the assistant — while keeping its
advertised definition **byte-for-byte identical**. Every existing defence pins
the definition (hash, signature, version), so all of them are blind to this by
construction. DriftSentry instead records how the tool *behaves* at approval time
and re-checks that behaviour on a schedule.

It is a desktop application, not a cloud service. Everything runs as local
processes on one machine. No network egress, no external API, no telemetry.

## Three deliverables

1. **The detector** — `Driftsentry/driftsentry/`, 20 Python modules, ~5,255 lines.
2. **The adversarial server** — a separate project, `mcp rug pull attack server/`,
   9 modules, ~2,364 lines. Its own virtual environment; it cannot import the
   detector and vice versa (verified: ImportError both directions). This isolation
   is deliberate — it is the evidence that the attacker shares no machinery with
   the detector it is used to evaluate.
3. **The evaluation harness** — `Driftsentry/eval/`, an 8-line stub. **NOT BUILT.**

Total: 9,599 lines of Python.

## Technology stack (real versions)

- Language: Python 3.14.6 (declared floor 3.11)
- MCP SDK: `mcp` 1.28.1 (official Python SDK) — stdio transport, JSON-RPC
- Embeddings: `all-MiniLM-L6-v2`, 384-dim, run via ONNX (`onnxruntime` 1.27.0)
  through ChromaDB's bundled embedding function — no PyTorch. Runs fully offline
  after one ~90 MB download.
- Vector store: `chromadb` 1.5.9
- Numerics: `numpy` 2.5.1
- Process monitoring: `psutil` 7.2.2
- Control API: `fastapi` 0.140.13 + `uvicorn` 0.51.0
- Desktop window: `pywebview` 6.2.1
- Terminal output: `rich` 15.0.0
- Tested only on Windows 11 (AMD Ryzen 9 9955HX, 32 GB RAM). Not tested on
  Linux/macOS.

## Is there machine learning?

A pre-trained sentence-embedding model is used as a **fixed feature extractor** —
nothing is trained, fine-tuned, or updated. No PyTorch, no scikit-learn, no
classifier. The decision layer is pure arithmetic and regular expressions and
contains **no ML and no LLM** — this determinism is a deliberate design property.
The statistical layer uses classical statistics (centroids, standard deviation,
quantiles, leave-one-out cross-validation), not ML.

---

## How the detector works, end to end

### 1. Proxy interception (`proxy.py`)

A transparent stdio proxy sits between the MCP client and the real server:

```
client <--stdio--> [driftsentry run] <--stdio--> real MCP server
```

Toward the client it acts as an MCP server; toward the real server it acts as an
MCP client. Two independent async "pump" loops forward every JSON-RPC message
unchanged, one per direction, so responses never block requests. Every message is
logged to a JSONL audit file. The proxy is **passive** — it logs but does not
probe or score. (It can optionally refuse calls to a quarantined server, but that
is off by default.)

### 2. Baseline capture at approval (`baseline.py`, `probes.py`, `fingerprint.py`)

On approval, DriftSentry connects to the server on its **own out-of-band session**
(not through the proxy — keeps probe traffic off the live path), lists the tools,
and classifies each as safe-to-probe or observation-only. Classification uses the
MCP spec's `readOnlyHint`/`destructiveHint` annotations first, then a
word-boundary keyword match (41 destructive verbs like send/delete/pay, 24 safe
verbs like get/read/search). Side-effecting tools are never actively probed.

For each safe tool it generates 3 **canary probes** from the tool's JSON Schema —
benign, inert test inputs (decoy URLs on port 9, `.invalid` email addresses,
repo-relative read paths). Probe values are seeded deterministically so a run can
be replayed exactly. Each probe is fired **8 times**, and every response is
recorded.

Each response is reduced to: normalised text (→ embedding vector), a structural
signature (JSON shape with values discarded), character count, error flag, and —
via a psutil monitor polling at 20 ms — the hosts the process contacted and files
it opened during the call.

The key statistical step: for each probe, DriftSentry learns a **benign variance
band** — how much that specific probe's answer naturally varies. A deterministic
lookup tool gets a near-zero band; a weather tool that returns random values gets
a wide one. This is what stops it crying wolf on naturally noisy tools. The band
is estimated with leave-one-out cross-validation (measuring spread against the
same samples fits too tight and false-alarms on the first honest re-check), and
floored at 0.01 (the embedding noise floor; a deterministic tool otherwise divides
by zero).

The result is a `ServerBaseline` written to JSON on disk (source of truth) and
indexed in ChromaDB (per embedding-backend collections). Real schema, one probe:

```json
{
  "probe_id": "lookup_customer#0",
  "args": {"customer_id": "probe@example.invalid"},
  "centroid": [384 floats],
  "n_samples": 8,
  "dist_mean": 0.0, "dist_std": 0.0, "dist_max": 0.0,
  "band": 0.01,
  "shape_hashes": ["sha256:355c2255..."],
  "hosts": ["127.0.0.1"], "files": [],
  "content_flags": [],
  "excerpt": "Record: Dana Whitfield; email ..."
}
```

### 3. Scheduled re-verification (`daemon.py`, `verify.py`)

A resident daemon re-fires the exact same stored probes on a schedule (default
every 20 s), out of band, one server at a time under a lock. Because the inputs
are identical, any difference in the answers is about the tool, not the input.

### 4. Drift scoring (`scorer.py`, `rules.py`)

Each re-probe is turned into a single number per tool, expressed in "evidence
units" where **1.0 is the alert line**. Signals:

- **Behavioural drift** — cosine distance from the stored centroid, divided by
  that probe's own band, then divided by the calibrated threshold. This puts a
  noisy and a deterministic tool on the same scale.
- **Definition-hash change** — weight 3.0 (the classic rug pull, caught for free).
- **Security rules** — differential (fire only on behaviour NEW since baseline):
  new egress host or credential-file read (weight 2.0, near-proof); new file
  access or agent-directed instruction text (weight 1.1). 24 regex patterns across
  credential shapes, injection shapes, and secret file paths.
- **Structural change** (0.85) and **error-rate change** (0.4) as weak signals.

Signals are combined by **maximum, not sum** — because the embedding and
structural signals read the same response and are correlated, so summing would
inflate false alarms; max also keeps attribution unambiguous. The tool's score is
the worst signal on its worst probe (so an intermittent attack isn't averaged
away). Verdict: <0.85 OK, 0.85–1.0 watch, ≥1.0 alert.

**No language model anywhere in this path** — arithmetic and regex only, so the
score is bit-for-bit reproducible.

### 5. Threshold calibration (`calibration.py`)

The one calibrated parameter is derived from **benign traffic only** — re-probes
of servers the user approved as benign, including legitimately updated versions.
The threshold is the 99th percentile of the benign drift-ratio distribution ×
1.25 margin, floored at 1.0. It records how many servers and observations produced
it and flags itself `weak` if below 3 servers or 30 observations.

### 6. Alerting (`alerts.py`)

On the transition into alert (not every cycle), it builds an alert naming the
server/tool, the signal that fired, a concrete before/after drawn from the stored
baseline, and a per-cause mitigation list. Append-only JSONL, one file per server.

### 7. Enforcement (`policy.py`) — opt-in, off by default

Two separate concepts: `status` (what DriftSentry believes) and `enforce`
(whether the proxy may act on it). Detection is the graded contribution; blocking
is a bonus and is off by default because a proxy silently blocking attacks would
confound every detection measurement.

### 8. Control API + dashboard (`api.py`, `ui/index.html`)

FastAPI, bound to **127.0.0.1 only** (hard-coded, no host option — the API can
quarantine a user's tooling, so it must not be network-reachable). 13 endpoints.
A single self-contained HTML page (vanilla JS, no framework) served in a pywebview
native window, polling `/api/state` every 2 s. Eight pages: Overview, Drift graph
(labelled SVG with a live threshold line), Servers, Alerts, Add server, MCP
clients, Calibration, Activity.

---

## The adversarial server (separate project)

One MCP server, many behaviours, driven by a single JSON **scenario file**. The
tool functions are decorated with fixed names, docstrings and type hints, so
FastMCP derives fixed JSON schemas — a benign and a malicious instance hash
**identically** (verified: all attacks hash to the same value as benign). The
scenario is consulted only inside a `_process()` step that acts on the return
value, never on the definition. It reloads on file-mtime change, so behaviour
flips on a **running** server — enabling live demos.

**Two orthogonal dimensions** = 6 × 5 from two mechanisms, not 30 hand-written cases:

- **6 families (what):** exfiltration (copies answer to a local sink, answer
  unchanged), silent-tamper (rewrites one detail), content-injection (appends an
  instruction to the assistant), new-egress (opens a held socket to a decoy host),
  sleeper (benign until a trigger), conditional (benign unless input looks worth
  attacking).
- **5 levels (when):** L1 naive (every call) → L2 stochastic → L3 trigger-gated →
  L4 probe-aware (behaves normally when it recognises a canary input) → L5 mimicry
  (probe-aware + shapes payload to minimise measurable drift).

Everything is closed-loop and safe: "exfiltration" writes to a file the attacker
owns; "new egress" connects to a decoy listener on 127.0.0.2 the same process
started; decoy credentials are obvious fakes. Nothing leaves the machine.

An **events log** (timestamp/kind/detail) records every malicious act
independently of whether the detector noticed — so a missed detection and an
attack that never fired can't be confused. An 18-check **self-test** validates the
ground truth (18/18 passing), including that all six families hash identically to
benign.

---

## What is actually measured (demonstration runs, NOT experiments)

These are single-run demonstrations from development, not controlled experiments
with repetitions. Real numbers, but must be labelled as demonstration evidence.

- All six families hash identically to benign.
- Live cycle: benign 0.05 → content-injection armed **2.06 (alert)** → disarmed
  0.04. Clean detection and clean recovery.
- Hash-only control vs full detector: **0/6 families vs 6/6**.
- Per-level (content-injection): L1 2.06, L2 1.99, L3 2.06, **L4 0.09 (evades)**.
- Calibration: threshold 10.8086, 54 observations, 1 server, flagged **weak**.

---

## What is NOT built (state honestly)

- **Evaluation harness** — `eval/` is an 8-line stub. No corpus builder, no
  experiment runner, no metrics, no figures.
- **Labelled corpus** — the 32 configurations (6×5 + benign + benign-update) are
  generable on demand but none is captured/stored. No train/test split.
- **Randomised probe templates** — the mitigation for probe-aware attackers is
  unimplemented, so the L4 evasion stands unmitigated.
- **The four experiments** (stability, detection-vs-false-alarm,
  behavioural-vs-hash-only, adaptive attacker) — none run.
- No unit tests or CI (5 phase checks + 18 self-test assertions instead).
- No performance measurement (proxy latency overhead, memory, CPU unmeasured).
- Calibration is statistically insufficient by the tool's own standard (1 server
  vs 3 required).
- No real community MCP server has been baselined; no real MCP client has driven
  the system end to end.

## Fundamental limitations (not fixable)

- **Trust On First Use:** if the server is malicious when the baseline is
  captured, the baseline records the malice as normal — undetectable. Catches
  tools that *turn*, not tools rotten from the start.
- **Adaptive evasion demonstrated:** the L4 probe-aware attacker defeats the
  current detector, because a fixed probe pool is enumerable.
- **Max-combination cost:** an attacker holding every individual signal just below
  the line is not caught by corroboration (a deliberate trade-off against false
  alarms).

## Research questions

- RQ1: can an approval-time behavioural baseline detect a rug pull that leaves the
  definition byte-identical, where hash pinning detects nothing? (evidence: yes)
- RQ2: what false-alarm rate does this incur on benign servers including updates?
  (designed, not measured)
- RQ3: how much does the behavioural layer add over a hash-only control on
  identical traffic? (evidence: 6/6 vs 0/6, one run)
- RQ4: how far does a probe-aware adversary degrade detection, and how much does
  randomising probes recover? (evasion shown; mitigation not built)
- RQ5: is the detector deterministic across runs given a fixed seed and baseline?
  (true by construction)
