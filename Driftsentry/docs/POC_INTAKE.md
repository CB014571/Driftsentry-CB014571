# DriftSentry — POC document intake

Completed 2026-08-14 from the working tree, the git history, and this session's
verification runs. Anything not established by evidence is marked **UNKNOWN**
rather than guessed.

Companion document: `docs/CHAPTER5_FACTS.md` holds the full implementation
extraction (dependencies, schemas, code snippets, measured costs) and should be
treated as the source for anything in sections 6 and 8 below.

---

## 1. Admin / title page

| Field | Value |
|---|---|
| Project title | **DriftSentry: Behavioural Rug-Pull Detection for the Model Context Protocol** — working title, taken from the first commit message and `pyproject.toml` ("A proxy-based detector for behavioural rug-pull attacks in the Model Context Protocol"). **Confirm against the exact title on `DriftSentry_Proposal_v23.docx`** |
| Full name | Shevon Fernando |
| Student ID | CB014571 |
| Degree programme | BSc (Hons) Cyber Security |
| Supervisor | Krishnamoorthi Caucidheesan |
| Institution | Asia Pacific Institute of Information Technology (APIIT), in collaboration with the University of Staffordshire |
| Submission date | **UNKNOWN** |
| Referencing style | **UNKNOWN** — APIIT typically requires Harvard, but this has not been confirmed for this module. Do not assume |

Note: the supervisor's academic designation was flagged as a placeholder during
the proposal review and has not been corrected.

---

## 2. The problem

**Plain statement.** The Model Context Protocol lets an AI assistant call tools
hosted by third-party servers. The user approves a tool once, based on its
advertised name, description and input schema. Nothing in the protocol re-checks
that approval afterwards. A server can therefore keep its advertised definition
byte-for-byte identical while changing what the tool actually *does* — returning
altered data, copying answers to an attacker, or injecting instructions aimed at
the assistant rather than the user. This is a **behavioural rug pull**, and every
defence built on pinning the definition is blind to it by construction.

**Who is affected.**
- Developers and knowledge workers running MCP clients (Claude Desktop, Cursor,
  VS Code, Claude Code) with third-party servers installed.
- Organisations whose staff install MCP servers from aggregator platforms with no
  mandatory pre-publication review.
- MCP server registries and aggregators, who currently have no mechanism to detect
  a package that turns malicious after distribution.

**How it is currently handled, and why that is inadequate.**

| Current approach | Why it fails against this threat |
|---|---|
| Hash/signature pinning of tool definitions (mcp-scan, mcp-context-protector) | The definition never changes, so the hash never changes |
| ETDI — OAuth identity, immutable versioned definitions, policy engine | Same blind spot: everything it verifies is a property of the declaration |
| Descriptor integrity checking + LLM semantic vetting | Defines rug pull *as* a descriptor change; also puts a language model in the decision path, so the verdict is not reproducible |
| Commercial metadata pinning (MCP Manager) | Markets rug-pull protection, implemented as metadata pinning — the same gap, productised |
| One-shot runtime scanning (MCP-SandboxScan) | Answers "is this tool leaking right now", not "has it changed since you approved it". A tool clean at scan time and dirty a week later passes |
| Protocol-level re-approval | Does not exist. Measured independently: MCP forces re-approval for 0 of 8 tested tampering techniques, including under a time-of-check-to-time-of-use rug pull |

**Why it matters.** MCP tools run with the user's local privileges and the
assistant acts on their output autonomously. A compromised tool can read
credentials, alter transactions, or steer the assistant into taking actions the
user never requested — and the user's only assurance is an approval dialog they
saw once, weeks earlier.

**The research gap targeted.** Runtime behavioural analysis of MCP tools now
exists in the literature. What does not exist is any published method that
combines all five of:

1. substrate = a third-party MCP server (not model weights, not a hosted endpoint,
   not a local skill file);
2. a **post-approval** adversary — the tool was legitimate when approved;
3. **behaviour-only** signals, with the definition byte-identical;
4. a baseline **pinned at the moment of approval** and re-verified periodically
   (not a one-shot scan);
5. a decision threshold **calibrated on benign traffic that includes benign
   updates**.

Property 5 is unoccupied by every method surveyed, and it is the one that decides
whether a detector is deployable rather than merely accurate.

---

## 3. The solution

**Concept.** DriftSentry is a desktop application that sits transparently between
an MCP client and its servers. At the moment a tool is approved it fires seeded,
schema-derived canary probes at that tool, records what the tool returns and what
its process does, and learns how much that behaviour naturally varies. It then
re-fires the same probes on a schedule and raises a calibrated, attributable alert
when the tool's behaviour moves further from its approved baseline than benign
variation explains — even though the tool's advertised definition has not changed
by a single byte.

**Computing domain.** Cybersecurity — specifically runtime intrusion detection and
supply-chain security for AI agent tooling. Secondary: applied machine learning
(sentence embeddings used as a measurement instrument, not as a classifier).

**Core technology and method.**
- Transparent stdio JSON-RPC proxy (MCP Python SDK 1.28.1)
- Seeded canary probe generation from each tool's declared JSON Schema
- Sentence embeddings — `all-MiniLM-L6-v2`, 384-dim, ONNX runtime, fully local
- **Leave-one-out cross-validated variance estimation** per probe, giving an
  out-of-sample benign band rather than an in-sample fit
- Cosine distance scaled by that band, capped, and divided by a calibrated
  threshold so every tool alerts at 1.0 regardless of how noisy it is
- Differential deterministic security rules (24 regex patterns across credential
  shapes, agent-directed instruction shapes, and secret file paths) that fire only
  on behaviour *new since baseline*
- Process-level side-effect observation via `psutil` (hosts contacted, files
  opened during a probe)
- Signal combination by **maximum**, not sum, to keep correlated noise from
  accumulating into a false alarm and to keep attribution unambiguous
- Threshold calibration as a quantile of the benign drift distribution × margin,
  floored — computed on benign traffic only

**No language model sits anywhere in the decision path.** Every number is
arithmetic over stored vectors plus regular expressions. Given the same baseline
and the same responses, the score is identical on every run. That determinism is
the property the project is positioned on.

**What the POC must demonstrate to count as feasible** (specific, testable):

1. A benign and a malicious instance of the same server produce an **identical
   tool-definition hash** — establishing that the threat is real and that hash
   pinning cannot address it. *(Achieved: all six families hash to
   `6805aff88dcf676e…`, identical to benign.)*
2. The behavioural layer **detects attacks that the hash-only control misses**, on
   identical traffic through the same code path. *(Achieved in demonstration:
   hash-only 0/6 families, full detector 6/6.)*
3. A naturally noisy tool (`get_weather`, randomised temperature and condition on
   every call) **does not false-alarm** while a deterministic tool still detects
   subtle change. *(Achieved: `get_weather` is included in every run and does not
   trip.)*
4. Legitimate updates (rewording, added fields, reformatting) are **absorbed
   rather than alarmed on**, when calibration includes them.
5. The detector **recovers** — it returns to OK once the attack stops, rather than
   latching. *(Achieved: 0.05 → 2.06 alert → 0.04.)*
6. The whole loop runs **offline**, with no network egress and no external API.
   *(Achieved: local ONNX after one 79 MB fetch; `auto` backend selection never
   downloads without explicit consent.)*
7. The system reports **its own limitations** — a threshold derived from
   insufficient data is flagged `weak` and says so in the UI. *(Achieved.)*

**Feasibility / research questions.**

- **RQ1** — Can a behavioural baseline captured at approval time detect a rug pull
  that leaves the tool definition byte-identical, where definition pinning detects
  nothing?
- **RQ2** — What false-alarm rate does this incur on benign servers, including
  servers that have legitimately been updated?
- **RQ3** — How much does the behavioural layer add over a hash-only control
  measured on identical traffic?
- **RQ4** — How far does an adaptive, probe-aware adversary degrade detection, and
  how much does randomising the probe templates recover?
- **RQ5** — Does the detector remain deterministic and reproducible across runs
  given a fixed seed and baseline?

RQ1, RQ3 and RQ5 have supporting demonstration evidence. RQ2 and RQ4 are
**designed but not measured** — see section 8.

---

## 4. Scope

### Components of the full idea

| # | Component | POC status |
|---|---|---|
| 1 | Transparent stdio interception proxy with JSONL audit log | **Essential — built** |
| 2 | MCP client config ingestion, rewrite, backup, restore | **Essential — built** |
| 3 | Canary probe engine with tool-safety classification | **Essential — built** |
| 4 | Behavioural fingerprinting + leave-one-out variance modelling | **Essential — built** |
| 5 | Pluggable embedding layer (Ollama / ONNX / hashing) + ChromaDB | **Essential — built** |
| 6 | Drift scorer with 6 signals, max-combination, no LLM | **Essential — built** |
| 7 | Differential security rules | **Essential — built** |
| 8 | Process-level side-effect monitor | **Essential — built** |
| 9 | Threshold calibration on benign-only data, with provenance | **Essential — built** |
| 10 | Alerting with before/after evidence and per-cause mitigations | **Essential — built** |
| 11 | Policy store + opt-in enforcement/quarantine | Supporting — built |
| 12 | Resident daemon with scheduled re-verification | **Essential — built** |
| 13 | Loopback control API (13 endpoints) | Supporting — built |
| 14 | Desktop dashboard, 8 pages, live drift graph | Supporting — built |
| 15 | Adversarial MCP server: 6 families × 5 evasion levels | **Essential — built** |
| 16 | Attacker operator console + 18-check ground-truth self-test | Supporting — built |
| 17 | Hash-only control condition | **Essential — built** |
| 18 | Labelled evaluation corpus | **Essential — NOT BUILT** |
| 19 | Experiment runner + metrics + figures | **Essential — NOT BUILT** |
| 20 | Randomised probe templates | **Essential for RQ4 — NOT BUILT** |

### Deliberately NOT built in this POC

| Excluded | Reason |
|---|---|
| HTTP / SSE MCP transport | stdio first, matching the real MCPoison CVE which targeted a stdio-launched config. HTTP entries are reported and left untouched rather than half-handled |
| Kernel-level tracing (eBPF / ETW) | The sandbox monitor polls at 20 ms and will miss a connection opened and closed between polls. Closing that gap needs a kernel tracer; named as out of scope in `sandbox.py` |
| Containment / sandboxing of the server process | This observes, it does not contain. A tool that wants to exfiltrate is noticed, not stopped |
| Detection of servers malicious from first approval | **Fundamental, not a shortcut.** Trust On First Use: if the server is malicious when the baseline is captured, the baseline records the malice as normal. No baseline method can close this |
| LLM-based explanation or triage | An LLM may only ever appear as a secondary explainer, never as the decision, because that would destroy reproducibility |
| Multi-user / server deployment, authentication | The control API is loopback-only by design; the moment it listened on a network interface it would be an unauthenticated remote control for quarantining a user's tooling |
| Non-Windows platforms | Platform branches exist in code; no run has been performed |

---

## 5. Data

DriftSentry is **not trained on a dataset**. It is not a machine-learning
classifier; the embedding model is used as a fixed measurement instrument and is
never fine-tuned. There is therefore no training set, no labels to learn from, and
no train/validation split in the ML sense. What the project *does* need is an
evaluation corpus, and that is where the gap is.

**Data the system generates and consumes:**

| Artefact | Source | Size / format |
|---|---|---|
| Behavioural baseline | Captured live from a running MCP server | JSON, 134,169 bytes for the `acme` server; 9 probe vectors × 384 dim |
| Calibration record | Re-probes of benign servers only | JSON; currently 54 observations from 1 server |
| Proxy exchange log | Live client↔server traffic | JSONL, one record per JSON-RPC message |
| Alert log | Scored reports | JSONL, append-only, one file per server |
| Attacker ground-truth events | Written by the adversarial server itself | TSV: `timestamp \t kind \t detail` |
| Synthetic tool data | Hand-written in `server.py` | 3 customers, 5 documents, 3 orders — all fictional |

**Labels.** Ground truth is generated, not annotated. `Scenario.label()` returns
`benign`, `benign-update`, or `{family}/{level}` — giving **32 distinct labels**
(6 families × 5 levels, plus two benign classes). Labels are exact by construction
because the adversarial server declares its own behaviour, and independently
corroborated by `events.log`, which records every malicious act *regardless of
whether the detector noticed it*. That log exists specifically so a missed
detection and an attack that never fired cannot be confused.

**Preparation / cleaning.** Two guards are implemented in `calibrate_servers()`:
any run in which the definition hash moved is excluded (a calibration server must
be stable), and mixing baselines captured under different embedding backends
raises an error, because distances from different embedding spaces are not
comparable.

**Limitations and constraints:**

- **No corpus is persisted.** The 32 configurations are generable on demand;
  none has been captured, labelled and stored. `eval/` is an 8-line stub. There is
  no calibration/test split. Corpus size today is **zero stored samples**.
- **One server only.** Every baseline to date is of the project's own synthetic
  `acme` server. No community MCP server has been baselined.
- **Calibration is statistically insufficient by the tool's own standard.**
  1 server against a required minimum of 3; the record is flagged `weak: true` and
  carries its own warning text.
- All customer, document and order data is fictional. Decoy credentials are
  obvious fakes (`sk-testbed0000…`, `AKIATESTBEDFAKE00000`).

---

## 6. Build details

**Languages and frameworks.** Python only. CPython 3.14.6 (declared floor 3.11).

**Detector — direct dependencies:** `mcp` 1.28.1, `chromadb` 1.5.9, `numpy` 2.5.1,
`httpx` 0.28.1, `typer` 0.27.0 (declared, unused — the CLI is `argparse`),
`rich` 15.0.0, `psutil` 7.2.2, `fastapi` 0.140.13, `uvicorn` 0.51.0,
`pywebview` 6.2.1, `onnxruntime` 1.27.0.

**Adversarial server — direct dependencies:** `mcp` 1.28.1. One library, on
purpose: it is the clearest evidence the attacker shares no machinery with the
detector.

**Hardware and platform.** Single machine: LENOVO 83F2, AMD Ryzen 9 9955HX
(16 cores / 32 threads), 31.3 GB RAM, Windows 11 Home Single Language
10.0.26200, x64.

**External systems and APIs.** None at runtime. No cloud, no external API, no
network egress. The ONNX model downloads once (~79 MB) and runs offline
thereafter; `auto` backend selection will not trigger that download without
explicit consent. The "remote" host in the new-egress attack family is
`127.0.0.2` — loopback, deliberately not `127.0.0.1` so the beacon is
distinguishable from Python's own asyncio self-pipe.

**Built from scratch vs reused.**

| From scratch | Reused |
|---|---|
| Proxy interception + audit logging | MCP protocol handling (`mcp` SDK) |
| Probe generation from JSON Schema, seeded | Embedding inference (`all-MiniLM-L6-v2` via ChromaDB's ONNX function) |
| Response normalisation + structural signatures | Vector persistence (`chromadb`) |
| Leave-one-out variance modelling | Process introspection (`psutil`) |
| Drift scorer + weights + max-combination | HTTP serving (`fastapi`/`uvicorn`), native window (`pywebview`) |
| Security rule engine (24 patterns) | |
| Threshold calibration + provenance | |
| Alert generation + per-cause mitigations | |
| Policy + enforcement | |
| Daemon, control API, dashboard (vanilla JS, no framework) | |
| Entire adversarial server | |

Total: **9,599 lines of Python** — 5,255 in the detector (20 modules), 2,364 in
the adversary (9 modules), 1,439 in example/check scripts, 8 in the eval stub.

**Architecture — the flow in words.**

*Onboarding (once per server).* The user hands DriftSentry their MCP client's
config, or names a server in the dashboard. DriftSentry rewrites the config so the
client launches `driftsentry run` instead of the server, then connects to the real
server itself on a separate out-of-band session. It calls `tools/list`, hashes the
definitions canonically, and classifies each tool as safe-to-probe or
observation-only — using the MCP spec's own `readOnlyHint`/`destructiveHint`
annotations first, then a word-boundary keyword heuristic. For each safe tool it
generates 3 seeded probes from the declared JSON Schema and fires each 5–8 times,
while a monitor polls the server's process every 20 ms for hosts contacted and
files opened. Each response is normalised into text plus a structural signature,
embedded to 384 dimensions, and the samples are reduced to a centroid plus a
leave-one-out variance band. The result is written to JSON on disk and indexed in
ChromaDB.

*Calibration (once).* DriftSentry re-probes servers the user has approved as
benign — including legitimately *updated* versions of them — and takes the 99th
percentile of the resulting drift ratios, times a 1.25 margin, floored at 1.0.
Only benign traffic ever touches this number. The record stores how many servers
and observations produced it and flags itself `weak` if that is insufficient.

*Steady state (continuous).* The proxy sits in the live path, forwarding every
JSON-RPC message unchanged in both directions and logging it. Separately, the
daemon re-fires the stored probes on a schedule (default 20 s), out of band, one
server at a time under a lock. Each re-probe produces a measurement: cosine
distance from the stored centroid, divided by that probe's band, giving a ratio;
plus whether the response shape is one seen before, whether the tool started
erroring, and which hosts, files and content patterns are *new relative to
baseline*.

*Scoring.* The ratio is divided by the calibrated threshold and capped at 3.0.
Discrete signals get fixed weights. The tool's score is the **maximum** single
signal on its **worst** probe — never a sum and never an average, so an
intermittent attack cannot be diluted by the probes that still behave. Below 0.85
is OK, 0.85–1.00 is watch, 1.00 and above is an alert.

*Output.* On the transition into alert (not on every subsequent cycle), DriftSentry
builds an alert record naming the server and tool, the signal that crossed the
line, a concrete before/after drawn from the stored baseline excerpt, and a
mitigation list templated to the specific cause. It appends this to a JSONL log,
marks the server quarantined in the policy store, and surfaces it on the
dashboard. If — and only if — the user has opted into enforcement for that server,
the proxy begins refusing `tools/call` requests to it with a JSON-RPC `-32000`
error naming DriftSentry; `initialize` and `tools/list` are never blocked, so the
client session survives.

```
                         ┌──────────────────────────────┐
   MCP client  ──stdio──▶│  driftsentry run  (proxy)    │──stdio──▶  MCP server
              ◀──────────│  forward + log + enforce     │◀─────────
                         └──────────────┬───────────────┘
                                        │ audit log (JSONL)
                                        ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  daemon  ── out-of-band probe session ──▶ same MCP server      │
   │    │                                        │                 │
   │    │  probes ◀── baseline store (JSON + ChromaDB)             │
   │    ▼                                        ▼                 │
   │  normalise → embed → distance/band → ÷ threshold → max(...)   │
   │                          + security rules (differential)      │
   │                          + process observation (psutil)       │
   │                                        │                      │
   │                                        ▼                      │
   │                        score → verdict → alert → policy       │
   └───────────────────────────────────┬───────────────────────────┘
                                       ▼
                    loopback API (127.0.0.1) → desktop dashboard
```

---

## 7. Methodology

**Development approach.** Incremental, phase-gated. Ten phases, each with an
executable definition-of-done check that exercises the real code paths against
real processes rather than mocks. `scripts/run_all_checks.py` runs them in order
and exits non-zero if any fails. Phases 0–7 are complete; 8–10 are not.

| Phase | Content | Status |
|---|---|---|
| 0 | Stack verification, MCP client/server handshake | Complete |
| 1 | Transparent stdio proxy | Complete |
| 2 | Client config ingestion and rewriting | Complete |
| 3 | Probes, fingerprinting, variance, storage | Complete |
| 4 | Scorer, security rules, calibration | Complete |
| 5 | Alerts, policy, enforcement | Complete |
| 6 | Daemon, control API, dashboard | Complete |
| 7 | Adversarial server, 6×5 matrix, self-test | Complete |
| 8 | Labelled corpus construction | **Not started** |
| 9 | The four experiments | **Not started** |
| 10 | Analysis and write-up | **Not started** |

**Adversary-first validation.** The adversarial server was built as a separate
project with its own virtual environment and package name, and cannot import the
detector (verified: `ImportError` in both directions). Its 18-check self-test
validates the ground truth independently of the detector — including the load-
bearing assertion that all six attack families hash identically to benign.

**Alternatives considered and rejected** (each recorded in the code, with the
reason):

| Rejected | Chosen | Reason |
|---|---|---|
| In-sample variance from the probe samples | Leave-one-out cross-validated variance | In-sample bands are systematically too tight; the first honest re-probe of a noisy tool breached them. This was a real observed failure, not a theoretical one |
| Summing the signals | Combining by maximum | Embedding and structural signals read the same response and are correlated; summing lets benign noise accumulate into an alert and blurs attribution |
| Threshold at the maximum benign drift | 99th percentile × 1.25, floored at 1.0 | A deterministic tool has a near-zero band, so one flicker yields a ratio in the hundreds of thousands — a max-based threshold would silence the detector permanently |
| `MIN_BAND = 1e-6` | `MIN_BAND = 0.01` | The smaller floor implied precision the embedding does not have and produced a drift score of 263,659 |
| Probing on every live call | Out-of-band on a schedule | Keeps latency off the live path, keeps the audit log a record of what the *client* did, and gives the monitor a process tree it owns |
| A separate reimplementation of hash-only pinning | A `mode` flag inside the same scorer | Removes any incidental difference; the control sees identical traffic through identical code |
| `sentence-transformers` + `torch` | ONNX `all-MiniLM-L6-v2` via ChromaDB | ~2 GB of torch avoided; runs offline |
| `Faker` for probe values | Hand-written template pools | Fully seed-deterministic with no extra dependency |
| Enforcement on by default | Per-server opt-in, off by default | A proxy that silently blocked attacks would confound every detection measurement |

---

## 8. Evaluation

### 8.1 Metrics defined

| Metric | Definition | Instrumented? |
|---|---|---|
| Detection rate (recall) per family × level | Fraction of armed runs producing verdict `alert` | Yes — score and verdict are recorded per check |
| False-alarm rate on benign servers | Fraction of benign re-probes scoring ≥ 1.0 | Yes — `empirical_far` is computed and stored during calibration |
| False-alarm rate on **benign updates** | Same, on legitimately updated servers | Yes — via `--also-exec` |
| Hash-only control recall | Same measurement with behavioural signals discarded | Yes — `verify --hash-only` |
| Time-to-detection | Scheduled cycles between an attack arming and the first alert | Partially — `history` carries timestamped scores |
| Determinism | Byte-identical score across repeated runs on a fixed baseline and seed | Yes by construction; not yet formally measured |
| Attribution correctness | Whether `triggered_by` names the signal that actually fired | Yes — recorded per alert |

### 8.2 Experiments designed

| # | Experiment | Answers | Status |
|---|---|---|---|
| 1 | Stability — repeated re-probes of an unchanged benign server | RQ5, baseline noise | **Not run** |
| 2 | Detection vs false alarm — full 6×5 matrix against benign and benign-update controls | RQ1, RQ2 | **Not run** |
| 3 | Behavioural vs hash-only on identical traffic | RQ3 | **Not run as an experiment** (demonstrated once) |
| 4 | Adaptive attacker — L4/L5 with fixed vs randomised probe templates | RQ4 | **Not run; blocked** — randomised templates are not implemented |

### 8.3 Results

**No experiment has been run. There are no results.**

What exists is a set of **single-run demonstration measurements**, taken during
development to verify the mechanism works. These are not experimental results,
have no repetitions, no confidence intervals, and no controlled conditions. They
should appear in the POC document as *demonstration evidence*, explicitly labelled
as such, or not at all.

| Observation | Value | Provenance |
|---|---|---|
| All six families hash identically to benign | `6805aff88dcf676e…` | `attacker selftest`, check 4, 18/18 PASS |
| Live cycle: benign → content-injection → benign | 0.05, 0.05, 0.09 → **2.06, 2.06, 2.06 (alert)** → 0.04, 0.07 | Timed dashboard run, 8 scheduled checks |
| Hash-only control vs full detector | 0/6 families vs 6/6 | Single demonstration run |
| Per-level scores, content-injection | L1 2.06, L2 1.99, L3 2.06, **L4 0.09 (evades)** | Single demonstration run |
| Benign vs benign-updated | ~0.09 vs 0.79 | Single demonstration run |
| Calibrated threshold | 10.8086, from 54 observations, 1 server, **`weak: true`** | `calibration.json` |
| Attacker's probe-guess coverage | **30 of 32** template values (27 verbatim + 3 by substring rule) | Computed 2026-08-14 |
| Single tool call latency | 100.41 ms mean | Stored baseline |
| Full baseline capture | 72 tool calls, ~24–36 s | Timed API job |

**The L4 result is a negative finding and should be reported as one.** A
probe-aware adversary scores 0.09 and passes clean while L1–L3 alert at ~2.0. That
is the defence being defeated by an adversary the author built. It belongs in the
findings, not buried in limitations — reporting it is what makes the rest of the
evaluation credible.

**Performance has not been measured at all**: proxy latency overhead (the
transparency claim), memory footprint, and CPU cost during probing are all
unquantified. Do not state an overhead figure without measuring it first.

---

## 9. Risks and limitations

### Fundamental (cannot be engineered away)

| Risk | Detail |
|---|---|
| **Trust On First Use** | If a server is malicious when the baseline is captured, the baseline records the malice as normal and nothing detects it. This bounds every claim the project can make to the post-approval case |
| **Adaptive evasion is demonstrated, not hypothetical** | L4 defeats the current detector. The mitigation (randomised templates) is designed but unimplemented, so the evasion stands |
| **Max-combination has a known cost** | An attacker holding every individual signal just below the line is not caught by corroboration. This is a deliberate trade-off against false alarms |

### Technical

| Risk | Detail |
|---|---|
| Polling, not tracing | The 20 ms sandbox poll misses a connection opened and closed between polls. Closing this needs a kernel tracer, out of scope |
| Windows `open_files()` is partial | May require privileges and does not report every handle type, so file evidence is weaker than network evidence on this platform |
| Local servers only | A remote HTTP MCP server runs on someone else's machine; there is no process to observe, so side-effect signals are simply unavailable |
| Annotations are attacker-controlled | A malicious server can claim `readOnlyHint: true`. This only influences *whether* we probe it, never whether we trust the response — but it is a real limit |
| Safety heuristic can misclassify | An unusually named tool may be probed when it should not be. `--safety-policy strict` narrows this at the cost of coverage |
| Embedding model is a threat to validity | Results may vary by embedding model. Mitigated by recording backend and dimension in every baseline and refusing cross-space comparison |

### Resource and process

| Risk | Detail |
|---|---|
| **Phases 8–10 unbuilt with weeks remaining** | The single largest risk to the submission. Experiments, results and analysis all depend on work not started |
| No unit tests or CI | 5 phase checks and 18 self-test assertions substitute for a test suite; no coverage measurement |
| **`requirements.lock` does not reproduce a working install** | Missing `fastapi`, `pywebview` and four transitive deps. A marker following the documented setup gets a broken dashboard. Fast to fix, embarrassing if not |
| `pyproject.toml` under-declares four imported packages | `pip install .` yields a detector with side-effect monitoring silently disabled |
| Single machine, single developer | No redundancy |

### Security and ethical

| Risk | Detail |
|---|---|
| The project ships working attack code | Mitigated by design — see section 10 |
| The control API can quarantine a user's tooling | Mitigated by hard-coded loopback binding with no `--host` option and no OpenAPI surface |

---

## 10. Ethics and legal

**Dual-use.** The project deliberately produces a working adversarial MCP server.
Containment is designed in, not bolted on:

- **No working exploit against any third-party system.** The adversarial server
  attacks only itself; it contains no vulnerability research and no exploit code.
- **Closed loop.** "Exfiltration" appends to a file inside the attacker's own
  directory. "New egress" connects to a decoy listener the same process started,
  on `127.0.0.2`. Nothing leaves the machine.
- **Obvious fakes.** Decoy credentials are `sk-testbed0000…` and
  `AKIATESTBEDFAKE00000`. Customer records, documents and orders are fictional.
- **Explicit opt-in for the strongest capability.** Probe-awareness (L4/L5) must be
  requested explicitly; `Scenario.validate()` rejects those levels otherwise, and
  the scenario file records it in two places.

**Privacy and data protection.** No personal data is collected, processed or
stored. All test data is synthetic. All state is local to the user's machine
(`.driftsentry_data/`). No telemetry, no analytics, no external transmission.
Proxy logs truncate strings at 500 characters and stay on the local disk.

**Consent.** Not applicable — no human participants, no user study.

**Bias.** No classifier is trained, so no training-set bias exists. The nearest
analogue is the safety-classification keyword heuristic (41 destructive verbs, 24
safe verbs), which is English-only and will misclassify tools named in other
languages. This is a stated limitation.

**Intellectual property.** Both projects declare MIT in `pyproject.toml`.
**No `LICENSE` file exists in either project** — a declared-but-unfulfilled
licence. Fix before publication. Third-party dependencies are all permissively
licensed (MIT / Apache-2.0 / BSD); `all-MiniLM-L6-v2` is Apache-2.0.

**Responsible disclosure.** No third-party MCP server has been tested, so no
vulnerability disclosure obligation has arisen. If a community server is tested in
Phase 8 and found defective, standard coordinated disclosure applies.

---

## 11. Future work

Derived from the limitations above, in priority order:

1. **Randomised probe templates** — the highest-value remaining item. Converts RQ4
   from "my defence has a known hole" to "known hole, measured fix, measured cost".
2. **Build the labelled corpus and run the four experiments** — Phases 8–9.
   Everything in the results chapter depends on this.
3. **Calibrate across ≥3 servers**, clearing the `weak` flag, so a false-alarm rate
   can be quoted as a result.
4. **Baseline a real community MCP server** (`mcp-server-git` is a good candidate —
   it has genuinely destructive tools that exercise the safety classifier).
5. **Kernel-level side-effect tracing** (eBPF on Linux, ETW on Windows) to close
   the polling gap.
6. **HTTP/SSE transport support**, extending coverage to remote MCP servers — with
   the honest caveat that process-level signals are unavailable there.
7. **Cross-platform validation** on Linux and macOS.
8. **Release the adversarial server as a public benchmark**, which is the route by
   which the dataset gap becomes a citable contribution rather than a local asset.
9. **Multi-user / organisational deployment**, which would require solving the
   authentication problem the loopback-only design currently sidesteps.

---

## 12. Timeline

| Field | Value |
|---|---|
| Hard deadline | **UNKNOWN** |
| Weeks available | **UNKNOWN** |
| Existing weekly plan | **UNKNOWN** — no plan file exists in the repository |

**What is known from the git history:**

| Event | Date |
|---|---|
| First commit | 2026-07-28 |
| Most recent commit | 2026-08-02 |
| Today | 2026-08-14 |

Eleven commits across roughly one week of concentrated implementation produced
Phases 0–7. Uncommitted changes are currently present in the working tree
(`sandbox.py`, `ui/index.html`, and the new `docs/` files).

**Remaining work, with the caveat that no deadline is known:**

| Task | Rough effort |
|---|---|
| Fix `requirements.lock` and `pyproject.toml`; add `LICENSE` | Under an hour |
| Update stale `docs/TESTING.md` (10 `testbed` references) | Under an hour |
| Randomised probe templates | 1–2 days |
| Calibrate on ≥3 servers; baseline a real community server | 1–2 days |
| Build the corpus (Phase 8) | 3–5 days |
| Run the four experiments (Phase 9) | 3–5 days |
| Analysis and write-up (Phase 10) | Depends on the deadline |

---

## Summary of gaps for the document author

Flag these rather than writing around them:

1. **Submission date, weeks available, and referencing style are unknown.**
2. **The exact project title needs confirming** against `DriftSentry_Proposal_v23.docx`.
3. **There are no experimental results.** Section 8.3 lists single-run
   demonstration measurements only. Results and discussion must be placeholders.
4. **No labelled corpus exists** — `eval/` is an 8-line stub.
5. **The calibration is statistically insufficient** by the tool's own threshold
   (1 server vs a required 3) and flags itself `weak`.
6. **Randomised probe templates are unimplemented**, so Experiment 4 is blocked
   and the L4 evasion is unmitigated.
7. **No performance measurement exists** — do not state a latency-overhead figure.
8. **No real MCP client or community server has driven the system end to end.**
