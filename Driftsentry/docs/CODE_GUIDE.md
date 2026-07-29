# DriftSentry — Code Guide and Detection Logic

A complete technical account of both projects: every module, every data
structure, the detection algorithm in full, and the reasoning behind each design
choice.

Written to be read once end to end, then used as a reference. Everything
described here is code that exists and runs; where something is not built, it
says so.

**Contents**

1. [What the system is](#1-what-the-system-is)
2. [Architecture and data flow](#2-architecture-and-data-flow)
3. [The detector, module by module](#3-the-detector-module-by-module)
4. [Data structures](#4-data-structures)
5. [The detection logic in full](#5-the-detection-logic-in-full)
6. [Worked example](#6-worked-example-end-to-end-with-real-numbers)
7. [The attacker, module by module](#7-the-attacker-module-by-module)
8. [Design decisions, and the bugs behind them](#8-design-decisions-and-the-bugs-behind-them)
9. [Known limitations](#9-known-limitations)
10. [Glossary](#10-glossary)

---

## 1. What the system is

### The attack

An MCP client (Claude Desktop, Cursor) shows you a server's tools once and you
approve them. That approval is never revisited.

A **rug pull** is when an approved tool turns malicious *afterwards* while its
advertised definition — name, description, input schema — stays byte-for-byte
identical.

Documented real cases:

| Case | What happened |
|---|---|
| **postmark-mcp** | Version 1.0.16 silently began copying every email to a third party |
| **MCPoison** (CVE-2025-54136) | An edited MCP config entry that the client did not re-prompt for |
| **Invariant Labs sleeper** | Malicious code present from the start, dormant until triggered |

The delivery vector varies — a package auto-update, a compromised maintainer, a
date passing, an operator flipping a switch on a remote server. In every case the
*definition* is unchanged, which is what makes the attack work: the client has no
reason to re-ask you.

### Why existing tools miss it

Existing defences (mcp-scan, Snyk Agent Scan, mcp-context-protector) pin a
**hash of the definition**. If the definition never changes, the hash never
changes.

Worse, for a **remote** MCP server there is no file on your machine at all — the
operator changes behaviour on their end and nothing local differs. Definition
pinning has literally nothing to inspect. Behaviour is the only observable that
exists.

And a one-shot scanner cannot help either, because the attack happens *after* the
scan. This is why DriftSentry is a **resident** proxy, not a scanner.

### The two projects

| Project | Role | Size |
|---|---|---|
| `Driftsentry/` | The detector | ~5,100 lines, 20 modules |
| `mcp rug pull attack server/` | Adversarial server supplying ground truth | ~1,900 lines, 8 modules |

Neither imports the other; they have separate virtual environments and meet only
as operating-system processes speaking MCP over stdio. That separation is the
answer to the obvious objection to a project that builds both the attack and the
defence, and it is checkable:

```
"mcp rug pull attack server/.venv/Scripts/python.exe" -c "import driftsentry"  -> ImportError
"Driftsentry/.venv/Scripts/python.exe" -c "import attacker"                    -> ImportError
```

---

## 2. Architecture and data flow

```
  DATA PLANE  (in the live path - must never be slowed)

    MCP client  <--stdio-->  driftsentry run  <--stdio-->  real MCP server
                              proxy + logger
                                    |
                                    | exchange log (JSONL)
                                    v

  CONTROL PLANE  (out of band - cannot add latency to a tool call)

    probes.py -> baseline.py -> fingerprint.py -> store.py        LEARN
                                     |
                       rules.py + scorer.py + calibration.py      DECIDE
                                     |
                          alerts.py + policy.py                   RESPOND
                                     |
                        daemon.py -> api.py -> ui/                WATCH
```

Two invariants are enforced by the structure, not by convention:

**Probes never touch user traffic.** `capture_baseline()` and `reprobe()` open
their *own* connection to the server. The proxy's job is to forward and log; the
prober's job is to test. Because they are different connections, detection cannot
add latency to a real tool call, and the proxy log stays a faithful record of what
the user's client actually did rather than a mixture of real and synthetic calls.

**No detection logic lives above `scorer.py`.** The daemon calls the same
`verify_server()` the CLI uses, and the dashboard renders whatever comes back. A
UI cannot flatter results it merely displays — which matters when those results
are the thing being marked.

---

## 3. The detector, module by module

### 3.1 Data plane

#### `proxy.py` — 306 lines

DriftSentry is an MCP **server** to the client and an MCP **client** to the real
server simultaneously.

```
stdio_server()  gives (client_read, client_write)   <- facing the client
stdio_client()  gives (server_read, server_write)   <- facing the real server
```

Two async pump loops forward messages:

```python
tg.start_soon(_pump, client_read, server_write, "c2s", ...)   # client -> server
tg.start_soon(_pump, server_read, client_write, "s2c", ...)   # server -> client
```

Three transparency properties follow from this design:

- **IDs preserved.** `_pump` forwards the whole `SessionMessage` object; messages
  are never rebuilt, so a JSON-RPC `id` cannot drift.
- **Ordering preserved.** Each direction is one sequential loop.
- **Concurrency works for free.** The directions are independent, so a response
  is never blocked behind its request. Verified with 8 simultaneous in-flight
  calls.

When either side closes, the pump's `finally` cancels the task group so both ends
tear down — a half-open proxy would hang the client.

`ProxyLogger` writes structured JSONL. The non-obvious part is
**request/response correlation**: a JSON-RPC response carries only an `id`, not a
method, so the logger keeps a `_pending: {id -> (method, tool)}` map. That is how
a response can be logged as *"this answered `tools/call echo`"*, and how
`tools/list` responses get their definition hash recorded.

`_make_enforcer()` provides the opt-in blocking hook. Only `tools/call` is ever
refused — blocking `initialize` or `tools/list` would break the session outright,
and the job is to stop a dangerous *action*, not to make the client unusable.

#### `hashing.py` — 45 lines

```python
def tools_definition_hash(tools) -> str:
    identities = sorted(
        ({"name": t.get("name"),
          "description": t.get("description"),
          "inputSchema": t.get("inputSchema")} for t in tools),
        key=lambda t: (t["name"] or ""))
    canonical = json.dumps(identities, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
```

Canonicalisation matters: tools sorted by name, JSON keys sorted. Two servers
advertising the same tools in a different order must hash the same, or harmless
reordering would look like an attack. Only the three fields that form the
*contract* are hashed; runtime annotations some servers attach are ignored.

This module is simultaneously the classic-rug-pull detector **and** the
`--hash-only` control condition the evaluation benchmarks against — the same code
path, fed the same traffic, so the comparison is fair rather than a
re-implementation that might differ.

#### `paths.py` — 28 lines

All persistent state under one root, overridable via `DRIFTSENTRY_HOME`. That
override is what lets tests and the evaluation harness run in isolation rather
than stamping on real baselines.

### 3.2 Setup

#### `clientconfig.py` — 292 lines

Parses a client config (`mcpServers` for Claude/Cursor, `servers` for VS Code),
classifies each entry by transport (`command` → stdio, `url` → http), and
rewrites stdio entries to launch through the proxy:

```jsonc
// before
"shop": { "command": "python", "args": ["shop_server.py"],
          "env": { "SHOP_API_KEY": "..." } }

// after
"shop": { "command": "...\\driftsentry.exe",
          "args": ["run", "--server", "shop",
                   "--forward-env", "SHOP_API_KEY",
                   "--exec", "python", "shop_server.py"],
          "env": { "SHOP_API_KEY": "..." } }
```

Four properties, each deliberate:

- **Secrets never enter `argv`.** The obvious implementation passes
  `--env KEY=VALUE`, which publishes secrets to the process list where any user
  on the machine can read them. Instead the `env` block stays on the entry and
  only the variable *name* travels on the command line; the proxy reads the value
  from its own environment and hands it down.
- **Never overwrites by default.** Output goes to a new file; `--in-place`
  requires an explicit flag and writes a timestamped backup first.
- **Idempotent.** `is_wrapped()` detects an already-wrapped entry, so running
  `init` twice cannot nest DriftSentry inside DriftSentry (which would double
  latency and duplicate the audit log).
- **HTTP entries are skipped loudly**, not half-handled.

`default_launcher()` resolves DriftSentry by *absolute path* rather than the bare
command name, because an MCP client launches subprocesses without necessarily
inheriting your shell's `PATH`.

### 3.3 Learning what normal looks like

#### `probes.py` — 314 lines

Two responsibilities.

**Probe-safety classification.** `classify_tool_safety()` decides whether a tool
may be actively probed:

1. MCP annotations first: `destructiveHint: true` → side-effecting;
   `readOnlyHint: true` → safe. Principled when the server supplies them.
2. Otherwise word-boundary verb matching over the name and description, against
   ~50 state-changing verbs (`send`, `delete`, `write`, `order`, `pay`, `execute`,
   …) and ~25 read-only verbs (`get`, `list`, `read`, `search`, `describe`, …).
3. `--safety-policy strict` fails safe: without positive evidence of read-only
   behaviour, observe rather than probe.

Anything classified side-effecting is marked **baseline-by-observation** and
never called. You do not test a `send_email` tool by sending email.

> `_match_verb()` matches on word boundaries, allowing prefixes so "sends" and
> "deleting" still hit. A naive substring test is badly wrong here: `"put"` occurs
> inside `"input"`, so every tool documented as *"returns the input text"* would
> be misclassified as state-changing and silently denied a baseline.

**Probe generation.** `ProbeGenerator.generate()` walks a tool's JSON Schema and
produces valid, benign arguments. It handles `enum`, `const`, `default`,
`anyOf`/`oneOf`/`allOf`, integers and numbers with `minimum`/`maximum`, arrays
with `minItems`/`maxItems`, nested objects (depth-limited to 3), and strings with
`minLength`/`maxLength`.

String values come from eight template pools chosen by property name and format:

| Pool | Example values |
|---|---|
| `path` | `README.md`, `requirements.txt`, `docs/index.md` |
| `query` | `hello world`, `quarterly report`, `opening hours` |
| `text` | `The quick brown fox jumps over the lazy dog.` |
| `url` | `http://127.0.0.1:9/decoy` |
| `email` | `probe@example.invalid`, `canary@test.invalid` |
| `city` | `London`, `Colombo`, `Reykjavik` |
| `name` | `Alex Doe`, `Sam Patel` |
| `generic` | `alpha`, `bravo`, `charlie` |

Every value is inert: reserved `.invalid` addresses, a closed local port,
repository-relative read-only paths. Probes never touch a real external system.

The RNG is seeded per `(seed, server, tool, index)` using `random.seed(..., version=2)`,
which hashes the string with SHA-512 and is therefore stable across processes and
platforms — unlike `hash()`, which is randomised per run.

> **The trade-off that becomes RQ4.** Seeding makes probes reproducible, which is
> required for a replayable evaluation. But replaying the *same* values every
> check is exactly what a probe-aware (L4/L5) attacker fingerprints. Randomised
> templates are the mitigation, and Experiment 4 measures how much they recover.

#### `embeddings.py` — 201 lines

Three backends behind one protocol (`name`, `dim`, `embed(texts)`):

| Backend | Semantics | Cost |
|---|---|---|
| `OllamaEmbedding` | Real, via a local daemon (`nomic-embed-text`) | needs Ollama installed |
| `OnnxEmbedding` | Real, all-MiniLM-L6-v2, 384-dim, no torch | ~79 MB, downloaded once |
| `HashingEmbedding` | **Lexical only**, deterministic | none |

`HashingEmbedding` is the classic hashing trick: unigrams **and bigrams** are
hashed into `dim` buckets with a sign bit (signed hashing reduces collision bias),
then L2-normalised. Bigrams give some word-order sensitivity, so reordering a
response is not invisible. It captures *lexical* change, not *semantic* change —
it cannot tell that "sunny" and "clear skies" mean the same thing.

Two rules enforced in `get_backend("auto")`:

- **It never downloads.** `onnx_model_cached()` is checked first, because the
  project advertises a no-network-egress stack and silently fetching a model
  would break that promise.
- **Falling back is loud.** A `WARNING` is emitted, because baselining an entire
  evaluation with the weak lexical backend without noticing would invalidate the
  results.

Measured difference on the fixture: the noisy `weather` tool's benign band was
**~0.83 under hashing** and **~0.09 under all-MiniLM** — roughly a 9× better
signal-to-noise ratio, because the semantic model recognises that differing
temperatures are similar text.

`cosine_distance()` clamps to `[-1, 1]` before subtracting (floating-point error
can otherwise produce a distracting `-0.0000`) and returns `0.0` for two empty
responses.

#### `fingerprint.py` — 380 lines

**Normalisation.** `normalize_result()` reduces an MCP `CallToolResult` to
comparable features. It prefers the human-facing `text` blocks and falls back to
`structuredContent` only when there is no text, so a response carrying the same
value in both is not counted twice. Non-text blocks contribute their type only —
binary payloads are never embedded, but their presence is structural.

**Structural signature.** `_shape_paths()` walks the JSON and yields `path:type`
strings with **values discarded**:

```
content[].type:str | content[].text:str | isError:bool | structuredContent.result:str
```

List items are merged into a single `[]` path, so returning three results instead
of two is *not* a structural change — but an item gaining a new field is. The
signature is hashed to `shape_hash`.

> **Why text and structure are separate signals.** Many MCP tools answer with
> JSON, not prose, and embedding raw JSON is noisy: key names and punctuation
> dominate the vector, so a meaningful change to a value can be swamped while a
> harmless key reordering looks like drift. Splitting them means a payload that
> changes shape (a hidden field appearing) is caught structurally even when the
> embedding barely moves, and vice versa.

**Variance modelling.** This is the most important algorithm in the project.

```python
def leave_one_out_distances(embeddings):
    n = len(embeddings)
    if n < 3:                                  # nothing to hold out
        centroid = centroid_of(embeddings)
        return [cosine_distance(e, centroid) for e in embeddings]
    distances = []
    for i in range(n):
        others = embeddings[:i] + embeddings[i+1:]
        distances.append(cosine_distance(embeddings[i], centroid_of(others)))
    return distances
```

and then:

```python
dist_mean = fmean(distances)
dist_std  = pstdev(distances)
dist_max  = max(distances)
band = max(dist_max, dist_mean + 3.0 * dist_std, MIN_BAND)   # MIN_BAND = 0.01
```

Why not simply "distance from each sample to the centroid"? Because that centroid
is *fitted to the very samples being measured*. The distances it produces are an
in-sample fit and systematically smaller than a genuinely new call will show.
Building the band from them makes it too tight, and the first honest re-probe of a
naturally noisy tool then breaches it — a false alarm on benign behaviour, which
is the fastest way to make a detector unusable.

This was not a theoretical concern: the Phase 3 demo failed exactly this way
before the fix, with a *benign* weather tool alarming against its own baseline.

`MIN_BAND = 0.01` is an **embedding noise floor**, not a divide-by-zero guard.
Below roughly that cosine distance two responses are the same text and the
difference is numerical noise in the model. A floor of `1e-6` would technically
work but implies precision that does not exist: a deterministic tool that changed
at all then yields ratios in the hundreds of thousands, which is meaningless to a
user, unusable on a plot, and distorts calibration.

#### `sandbox.py` — 218 lines

Polls the server's process tree with psutil, collecting remote peers and open
files, then reports two views:

| View | Meaning | Used for |
|---|---|---|
| `hosts` / `files` | everything open **during** the call, including things opened earlier and still held | the drift comparison |
| `new_hosts` / `new_files` | only what appeared between start and end of this call | diagnostics |

Using the second view for drift comparison was a real bug. An exfiltration channel
opens its sink once and keeps the handle — which is what a real one does, and what
makes it observable at all — so it looked "new" on the first probe and invisible on
every probe afterwards. The attack was live the whole time; the monitor was
answering the wrong question.

Two noise filters, both load-bearing:

**Peers are compared by IP, not `IP:port`.** Ports are ephemeral, so keying on
`IP:port` would make every connection look new and fire the egress rule forever.
Worse, Python's asyncio self-pipe is a loopback TCP socketpair on Windows, so a
perfectly innocent server would appear to contact a new host on every run.

**OS and interpreter paths are excluded.** `_is_noise()` filters `.pyc`, `.pyd`,
`.dll`, `.mui`, `.cat`, `.manifest`, `.nls`, `.sys`, `.exe`, anything under
`site-packages` / `__pycache__` / `.venv`, and anything under `%SystemRoot%`,
`%ProgramFiles%`, `%ProgramData%` or the interpreter's own prefix. Which system
resource files a process holds **depends on how it was launched** — a server
started from a console holds console resources, the same server started from a
background service does not. Unfiltered, the monitor measured the *launcher*
rather than the tool, and a benign server raised `new_file_access` in the
dashboard.

**Stated limitations.** It polls (default 20 ms), so a connection opened and
closed entirely between two polls is missed; `open_files()` on Windows is partial;
and it only works for locally-launched servers, since a remote server has no
process to watch. A `stop()` call always performs one final sweep, because a call
that completes between polls would otherwise leave no trace at all and the
experiment would be measuring the poll interval rather than the detector.

#### `store.py` — 172 lines

Two stores, deliberately:

- **JSON** (`baselines/<server>.json`) is the source of truth — the whole
  baseline, human-readable and auditable. Reproducibility is a graded
  contribution, so the record that lets someone re-run your probes must not be
  locked inside a binary index.
- **ChromaDB** indexes centroid vectors for nearest-neighbour queries.

Collections are named `baselines-<backend>-<dim>`. A baseline captured with one
embedding model cannot be compared with a probe scored under another — the
vectors live in different spaces — so encoding backend and dimension in the
collection name makes mixing them *impossible* rather than merely discouraged.
`embedding_function=None` throughout: vectors are always supplied, so the store
never reaches for a model and stays offline.

#### `baseline.py` — 381 lines

Orchestration. `capture_baseline()` and `reprobe()` both open their own MCP
session, find the child process for sandbox monitoring, and drive probes.

`_find_child_pids()` returns **every** new child rather than the lowest-numbered
one. Picking a single pid was quietly unreliable: back-to-back verifications can
leave a previous server still shutting down, and pids are not ordered by launch
time, so the guess sometimes attached the monitor to the wrong process and the run
silently recorded no side effects at all.

`_call_once()` wraps a tool call with timing and sandbox observation, and converts
an exception into an error-shaped payload — a rejected probe is still a behaviour
and should be recorded, not crash the capture.

### 3.4 Deciding

#### `rules.py` — 217 lines

Five deterministic rules over 24 regex patterns.

**Content patterns** — credential-shaped output, anchored on well-known token
*formats* rather than on the word "key", so ordinary prose about API keys does not
match:

```
sk-[A-Za-z0-9_-]{16,}          openai-style
(AKIA|ASIA)[0-9A-Z]{16}        aws access key id
(ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}   github token
-----BEGIN ... PRIVATE KEY-----
eyJ[...].[...].[...]           jwt
```

**Instruction-shaped text** — content addressed to the *agent* rather than the
user, the signature of tool poisoning:

```
ignore (all)? (previous|prior|above) instructions
^\s*[\[<#]?(system|assistant)\s*(note|message)?\s*[:\]>]
(do not|don't|never) (tell|inform|reveal) ... (the )?(user|human)
(forward|send|exfiltrate) ... (credential|api key|token|password|cookie)
```

**Sensitive paths** — `.ssh/`, `id_rsa`, `*.pem`, `.env`, `.aws/`, `.npmrc`,
`.git-credentials`, browser `Login Data`, shell history.

The five rules and their weights:

| Rule | Severity | Fires when |
|---|---|---|
| `new_egress_host` | high | a peer IP not seen at baseline |
| `secret_file_read` | high | a credential-bearing path opened, not at baseline |
| `credential_shaped_output` | high | token-shaped strings new in the response |
| `new_file_access` | medium | other files opened, not at baseline |
| `instruction_shaped_output` | medium | agent-directed text new in the response |

**Every rule is differential.** `evaluate()` receives only hosts, files and flags
that were *absent at baseline*. This matters more than it sounds: a
password-manager tool legitimately emits credential-shaped output, and a
documentation tool legitimately explains how to "ignore previous instructions".
Scoring those absolutely would alarm on every check forever, and a detector that
cries wolf gets switched off. What is suspicious is a tool that never did this
before starting to do it now.

#### `scorer.py` — 401 lines

Detailed in §5.3.

#### `calibration.py` — 242 lines

Detailed in §5.4.

#### `verify.py` — 154 lines

One code path for re-probe + score, used by the CLI, the demos, the daemon and the
evaluation harness, so they cannot drift apart. `calibrate_servers()` additionally
accepts `variants` — extra benign configurations of the same server, typically a
legitimately *updated* version.

### 3.5 Responding

#### `alerts.py` — 548 lines

Builds an actionable alert. The roadmap sets the bar at four things: which server
and tool, which signal and by how much, a concrete before/after, and a mitigation.

`_CAUSE_SPECIFICITY` ranks causes from most to least specific:

```
definition_hash > rule:new_egress_host > rule:secret_file_read
> rule:credential_shaped_output > rule:instruction_shaped_output
> rule:new_file_access > behavioural_drift > structural_change
```

Severity comes from the *score*; the advice comes from the most *specific* signal
that fired. For a definition-invariant rug pull the highest-scoring signal is
almost always `behavioural_drift`, whose honest advice is the vague "look at the
before/after and decide". If a content rule also fired we know something far more
precise — and choosing the mitigation by score alone would bury the one
instruction the user most needs (*"check what your assistant did after reading
this"*) under a generic drift message.

Mitigations are templated per cause. A new-egress alert says rotate every
credential that server could have seen, because data may already have left. A
hash-change alert says the contract you approved was rewritten — force
re-approval, and do *not* re-baseline merely to silence it. Plain behavioural
drift leads with *"this is not by itself proof of an attack — a legitimate update
produces the same signal"*, because overstating weak evidence is how security
tools train users to ignore them.

Alerts render to the terminal (rich, with `box.ASCII` so any console codepage
works) and append to `alerts/<server>.jsonl` for the machine-readable record.

#### `policy.py` — 118 lines

`ServerPolicy(server, status, enforce, reason, updated_at, flagged_tools)` with
status in `trusted | watching | quarantined`.

The separation that matters: **status is what DriftSentry believes; `enforce` is
whether it may act.** A quarantined server with `enforce=false` is still fully
usable — DriftSentry has recorded its opinion and will keep saying so, but does
not interfere. Enforcement is opt-in because detection is the graded
contribution, and a proxy that silently blocked attacks would confound every
detection measurement.

### 3.6 Watching

#### `daemon.py` — ~230 lines

The resident scheduler. Holds a `ServerState` per server (status, score, history
deque of the last 120 checks, per-tool breakdown), runs a 1-second tick loop, and
re-verifies each server when its interval elapses. `scan_now()` forces a check.

Alerts are raised on the **transition** into alert, not every cycle — a sustained
attack would otherwise flood the feed and the operator would stop reading it.

Runs its event loop on a background thread so a UI can own the main one.

#### `api.py` — ~60 lines

FastAPI, bound to `127.0.0.1`. No authentication and none is appropriate: the
moment this listened on a network interface it would be an unauthenticated remote
control for quarantining a user's tooling. Endpoints: `GET /api/state`, and POST
`scan` / `quarantine` / `trust` / `enforce` / `pause`.

#### `ui/index.html`

Dark SOC-style console. Server list with status badges, a drift sparkline with the
alert threshold drawn as a dashed line, an alert feed with before/after, and
per-server actions. Polls `/api/state` every 2 seconds. No detection logic.

#### `__main__.py` — ~840 lines

The CLI: `init`, `restore`, `run`, `baseline`, `calibrate`, `verify`, `watch`,
`ui`, `report`, `quarantine`, `trust`.

`_split_command()` splits quoted command strings in **non-POSIX mode on Windows**
because `shlex` treats backslash as an escape — `C:\Users\me\python.exe` becomes
`C:Usersmepython.exe`. That bug caused a calibration to run against the wrong
server and *report success*.

---

## 4. Data structures

The shape of the data explains the design.

### Baseline (what is stored at approval time)

```
ServerBaseline
├── server, definition_hash, captured_at
├── embedding_backend, embedding_dim        # scoring must match the space
├── seed, n_probes, n_samples               # reproducibility
├── launch: {command, args, cwd}            # how to reach it again
├── tool_definitions[]                      # what was advertised
└── tools[]: ToolBaseline
    ├── tool, safety, safety_reason, probed
    └── probes[]: ProbeBaseline (18 fields)
        ├── probe_id, template_id, args     # exactly which probe
        ├── centroid[]                      # mean vector, L2-normalised
        ├── n_samples, dist_mean, dist_std, dist_max
        ├── band                            # the benign envelope
        ├── shape_hashes[]                  # every structure seen
        ├── chars_mean, chars_std, error_rate, latency_ms_mean
        ├── hosts[], files[]                # normal side effects
        ├── content_flags[]                 # patterns NORMAL for this tool
        └── excerpt                         # for the alert's "before"
```

`content_flags` is what makes the rules differential; `excerpt` is what makes an
alert show a concrete before/after rather than a number.

### Measurement (what a re-probe produces)

```
ReprobeReport(server, baseline_definition_hash, observed_definition_hash,
              embedding_backend, checks[])
└── ProbeCheck (14 fields)
    ├── tool, probe_id
    ├── distance, band, ratio, within_band
    ├── shape_known, observed_shape_hash
    ├── new_hosts[], new_files[], new_content_flags[]
    ├── observed_excerpt, baseline_excerpt
    └── became_error
```

Deliberately a measurement with **no verdict**, so it can be re-scored under a
different threshold without re-running any probes.

### Verdict (what the scorer produces)

```
DriftReport(server, scored_at, mode, threshold_ratio, calibration_source,
            embedding_backend, definition_changed, tools[])
└── ToolScore(tool, score, verdict, triggered_by, probes[], signals[])
    └── ProbeScore(probe_id, score, ratio, distance, band, signals[])
        └── Signal(name, score, severity, detail, evidence{})
```

Every number is traceable back to the probe and signal that produced it.

---

## 5. The detection logic in full

Five stages.

### 5.1 Baseline capture (approval time)

For each tool the server advertises:

1. **Classify probe safety.** Side-effecting tools are marked
   *baseline-by-observation* and never called.
2. **Generate N seeded probes** from the input schema (default 3).
3. **Call each probe M times** (default 8).
4. **Fingerprint every response**: definition hash, embedding, shape hash,
   content flags, hosts, files, latency.
5. **Learn the variance band** by leave-one-out (§3.3).

Stored to JSON + ChromaDB, keyed by server and tool.

### 5.2 Re-probe (measurement, no judgement)

Replay the stored probes. Per probe:

```
distance = max over samples of cosine_distance(sample_vector, stored_centroid)
ratio    = distance / band
```

The **worst** sample decides, not the mean. An attacker that fires on only some
calls (L2 stochastic) must not be averaged away by the calls where it behaved.

Also computed: `shape_known` (was this structure ever seen?), and the differential
sets `new_hosts`, `new_files`, `new_content_flags` — each `observed − baseline`.

### 5.3 Scoring

Three signals mapped onto **one scale where 1.0 is the alert line**:

| Signal | Score | Rationale |
|---|---|---|
| Definition hash changed | **3.0** | Not evidence of a rug pull — it *is* one class of rug pull. Needs no calibration to interpret, and is weighted clear of the line so a tight threshold cannot argue it down. |
| Security rule, high | **2.0** | Near-proof of harm: new egress, secret-file read, credential-shaped output |
| Security rule, medium | **1.1** | Suspicious with plausible benign explanations — above the line, but only just |
| Behavioural drift | `min(ratio / threshold, 3.0)` | The calibrated continuous signal |
| Structural change alone | **0.85** | Below the line *by design*: benign updates add optional fields all the time |
| Error-behaviour change | **0.4** | Informational; never raises a verdict alone |

Verdicts: `< 0.85` **OK**, `0.85 – 1.0` **WATCH**, `≥ 1.0` **ALERT**.

`WATCH_AT = 0.85` is not arbitrary. Calibration places the threshold a 1.25×
margin above the benign operating point, so ordinary benign behaviour scores up to
about `1/1.25 = 0.80`. WATCH therefore begins just above where benign traffic
normally sits. Setting it lower would put every naturally noisy tool permanently
in WATCH — alarm fatigue by construction.

#### Combination: maximum, not sum

```python
best = max(signals, key=lambda s: s.score)          # per probe
worst = max(probe_scores, key=lambda p: p.score)    # per tool
```

The score is the strongest single piece of evidence, not the accumulation of all
of it.

Summing is tempting and wrong here. The embedding and structural signals read the
*same* response and are strongly correlated, so a sum lets ordinary benign noise
on a chatty tool add up to an alert. That inflates false-alarm rate — the one
metric this project cannot afford to be sloppy about, since gap G3 is precisely
that nobody has measured it honestly. Max also keeps attribution unambiguous: the
alert names exactly the signal that caused it.

**The honest cost:** an attacker who keeps every individual signal just under the
line escapes corroboration. That is exactly the L5 mimicry case, it is conceded
rather than hidden, and Phase 9's per-level recall curve is where it gets
measured.

#### Saturation

`W_BEHAVIOURAL_MAX = 3.0`. Past a few multiples of the threshold the signal has
said everything it can — "this response is definitely not what was baselined".
Letting the number keep climbing adds no information and produces scores in the
tens of thousands for tools whose baseline was deterministic, which are unusable
in a report or on a plot. The uncapped value is kept in the signal's `evidence`
for diagnostics.

#### Determinism

Every number is arithmetic over stored vectors and regular expressions. Given the
same baseline and the same responses, the score is bit-for-bit identical on every
run. That is the property the project is positioned on against LLM-based
detectors, and it is why a language model may appear only as a secondary
*explainer* in an alert, never as the decision.

#### The hash-only control

`mode="hash-only"` discards every behavioural observation and scores the
definition hash alone — what mcp-scan and Snyk Agent Scan do. Kept inside the same
code path, fed by the same probe data, so Phase 9 measures exactly what the
behavioural layer adds rather than comparing against a re-implementation that
might differ in some incidental way.

### 5.4 Calibration

One parameter is calibrated: the drift ratio at which behaviour stops being noise.

```python
ordered         = sorted(benign_ratios)
operating_point = quantile(ordered, 1 - target_far)      # target_far = 0.01
threshold       = max(operating_point * margin, 1.0)     # margin = 1.25
empirical_far   = fraction of benign ratios >= threshold
```

**Inputs are benign only.** A threshold fitted after seeing the attacks it is meant
to catch proves nothing — the detector was told the answer. This is the property
that keeps RQ2 and RQ3 defensible.

Three deliberate choices:

**A quantile, not the maximum.** A deterministic tool has a near-zero band, so a
single flicker yields a ratio in the hundreds of thousands; a max-based threshold
would then silence the detector permanently. Allowing the top 1% to sit above the
line prevents one freak observation from dictating the threshold, and states the
accepted false-alarm rate explicitly — which RQ2 has to report anyway.

**A floor of 1.0.** A ratio of 1.0 means "exactly at the edge of the benign band
this tool measured for itself". Alerting below that would contradict the band:
those samples are, by construction, ones benign behaviour is expected to produce.

**Benign *updates* belong in the calibration set.** Real software changes:
responses get reworded, fields get added, formatting shifts. A threshold fitted to
a frozen server is far too tight and the first honest update trips it. The
`variants` parameter (`--also-exec` on the CLI) admits extra benign
configurations. This is gap G3 restated as an engineering requirement — benign
updates are part of the benign distribution, not attacks by default.

Provenance is recorded and thin evidence is flagged: `MIN_SERVERS = 3`,
`MIN_OBSERVATIONS = 30`. `active_threshold()` also refuses to reuse a threshold
calibrated under a different embedding backend, since distances from two spaces
are not comparable.

### 5.5 Alerting and response

On a threshold breach: build the alert (§3.5), append to the JSONL record, and
mark the server quarantined in policy — advisory unless enforcement was opted
into.

### 5.6 Coverage: which signal catches which family

| Family | Caught by | Where recall is honest about its limit |
|---|---|---|
| Exfiltration | file evidence (sink + credential read) | the answer is unchanged, so content signals see nothing at all |
| Silent tamper | embedding drift | a one-digit change is the hard case |
| Content injection | embedding + `instruction_shaped_output` | well-hidden text needs tighter rules |
| New egress | `new_egress_host` | near-proof when it fires; L5 could mimic baseline hosts |
| Sleeper | scheduled re-probing after it turns | long fuses need more frequent re-probes |
| Conditional | rules on the triggered behaviour | fixed probes miss it by design — randomisation is the mitigation |

Three families are caught by rules, three by embedding drift. **Neither signal
alone covers all six.** That is why the defensible claim is *a detection pathway
for every family*, never *detects every attack* — a claim the project's own
Experiment 4 is designed to falsify at L4/L5.

---

## 6. Worked example, end to end, with real numbers

Measured on the `acme` fixture with the ONNX all-MiniLM backend.

**Approval.** Five tools advertised. `send_invoice` and `search_orders` are
classified side-effecting and never probed. The other three get 3 probes × 8
samples.

Learned bands:

```
lookup_customer   0.0100  0.0100  0.0100     <- deterministic, floored at MIN_BAND
read_document     0.0100  0.0100  0.0100     <- deterministic
get_weather       0.0919  0.1048  0.0872     <- genuinely noisy, band ~9x wider
```

The detector has learned that `get_weather` varies and `lookup_customer` does not.

**Calibration** over benign + benign-updated runs, 36 observations:

```
mean 0.20   p99 8.65   max 8.65
threshold = 8.65 x 1.25 = 10.809
empirical false-alarm rate on the calibration set: 0%
```

The threshold is high because benign *updates* legitimately move responses a long
way. That is the cost of not alarming on real software updates.

**Verification, benign server:**

```
VERDICT: OK   score 0.09
```

**Verification, benign server that legitimately updated** (held-out seed, never
seen by calibration):

```
VERDICT: OK   score 0.79
```

Close to the line, correctly under it.

**Verification, six attack families at L1:**

| Family | Verdict | Score | Triggering signal |
|---|---|---|---|
| exfiltration | ALERT | 1.10 | `rule:new_file_access` |
| silent-tamper | ALERT | 2.23 | `behavioural_drift` |
| content-injection | ALERT | 2.06 | `behavioural_drift` |
| new-egress | ALERT | 2.00 | `rule:new_egress_host` |
| sleeper | ALERT | 2.06 | `behavioural_drift` |
| conditional | ALERT | 1.10 | `rule:new_file_access` |

**The same six under `--hash-only`:** all report `definition: unchanged`,
`VERDICT: OK`, `score 0.00`. **0 / 6.**

**Complexity sweep** (content-injection):

```
L1  always malicious            ALERT  2.06
L2  40% of calls                ALERT  1.99
L3  only after 2 calls          ALERT  2.06
L4  recognises the probes       OK     0.09    <- evades
```

L4 evading is the expected result. An attacker that recognises fixed probe values
behaves whenever it is watched. Randomised templates are the mitigation and
Experiment 4 measures the recovery — reporting this is worth more than a detection
rate that conceals it.

---

## 7. The attacker, module by module

### `scenario.py` — ~290 lines

The replayable unit. `Scenario(mode, family, level, seed, probe_aware, updates,
stochastic_rate, payload, trigger, notes)` serialised as JSON.

`default_home()` resolves to a **fixed per-user directory**
(`%LOCALAPPDATA%\mcp-attacker`), not a path relative to the working directory.
This is the single biggest usability decision in the project, and it was learned
the hard way: an MCP client launches servers with whatever working directory it
happens to have *and* a filtered environment, so a relative default meant the CLI
wrote one file while the running server read another. The attack then silently
never fired, which looks exactly like the detector failing to catch it — the worst
possible failure mode for a tool whose purpose is measuring detection.

Also holds `FAMILY_BRIEF`, the plain-English briefing shown when arming, and
`TOOLS_AFFECTED` / `TOOLS_UNTOUCHED`.

### `attacks.py` — 254 lines

**Family = the payload. Level = the gate.**

```python
fire, why_not = should_fire(scenario, call_index, arguments)   # LEVEL decides
if fire:
    result = _FAMILY_PAYLOADS[scenario.effective_payload()](text, scenario)  # FAMILY decides
```

Six families × five levels comes from one payload mechanism and one gating
mechanism — not thirty hand-written cases — so a level means the same thing across
families and the resulting recall matrix is comparable row to row.

The gate:

| Level | `should_fire` |
|---|---|
| L1 | always |
| L2 | `rng.random() < stochastic_rate`, seeded on `(seed, family, level, call_index)` |
| L3 | after `after_calls`, or a date, or triggering input, or `trip` |
| L4/L5 | always **except** when the input looks like a probe |

`looks_like_a_probe()` is the attacker's heuristic: the value appears in its table
of repeatedly-seen values, or ends in `.invalid`, or points at the local decoy
port. That table is written out **in the attacker's own source as a guess** — the
project does not import DriftSentry and has no access to its probe generator. This
is exactly the threat to be measured: a detector whose probes come from a small
fixed pool is defeated by a lookup table.

`apply_benign_update()` produces the false-alarm set: `reword`, `extra-field`,
`punctuation`, `verbose` — the changes a well-behaved server really does make
between versions.

### `server.py` — 185 lines

Five tools over synthetic data. **The tool definitions are fixed in the source and
never consult the scenario**, which is what makes a benign instance and a malicious
instance advertise byte-identical definitions and hash the same.

`_process()` re-reads the scenario file when its mtime changes, so
`set-family` / `set-level` / `trip` alter a **running** server on its next call —
no restart, which is exactly how a rug pull behaves.

`send_invoice` deliberately bypasses `_process()`: it is side-effecting, the
detector refuses to probe it, and so the attack never touches it.

`get_weather` is genuinely random, so the corpus always contains a naturally noisy
tool. A detector that only looks good on deterministic tools has not been tested.

### `sink.py` — ~200 lines

Closed-loop attacker infrastructure: a local file sink, a decoy credentials file
(obvious fakes), a decoy TCP listener on **127.0.0.2**, and an events log.

Two details make behaviour *observable*, which the evaluation requires — a
detector cannot be credited with catching an attack that left no trace:

- The exfil sink handle is **held open**, not opened and closed within one call. A
  short write between two polls would be missed and the experiment would measure
  the monitor's poll rate rather than the detector.
- The decoy socket is likewise kept open, so the connection is ESTABLISHED when
  the monitor looks.

Both are also realistic; a real exfiltration channel keeps its connection alive.

The decoy binds **127.0.0.2** rather than 127.0.0.1 because Python's own asyncio
self-pipe uses 127.0.0.1. Sharing it would make the attacker's beacon
indistinguishable from ordinary runtime noise, biasing the experiment in *both*
directions.

`log_event()` records every malicious act so an attack can be proven to have
happened **independently of whether the detector noticed** — otherwise a missed
detection and an attack that never fired look identical from outside.

### `selftest.py` — ~250 lines

Verifies the attacker against itself, no detector involved: definition identity
across all six families, each family producing its own *kind* of effect
(exfiltration must leave the answer untouched; injection must change it), gates
firing only when they should, probe-aware evasion working, and seed
reproducibility. 17 checks.

Every detection figure depends on this ground truth being correct, so it is
checkable rather than assumed.

### `console.py`, `menu.py`, `__main__.py`

The metasploit-style `use` / `set` / `run` console with a briefing on arming, the
numbered menu, and the CLI (`status`, `benign`, `attack`, `reset`,
`launch-command`, `configure`, `serve`, `selftest`, …).

`use` selects; `run` arms. Merging them meant browsing the options started an
attack.

---

## 8. Design decisions, and the bugs behind them

Each of these was a failing test first. They are the most useful things to be able
to explain.

| Decision | The bug it fixes |
|---|---|
| Variance estimated **leave-one-out** | In-sample fitting made bands too tight; a *benign* weather tool alarmed against its own baseline |
| Band floor **0.01**, not `1e-6` | A deterministic tool that changed at all produced six-figure scores and distorted calibration |
| Signals combined by **max** | Correlated signals summing to an alert inflates the one metric the project must defend |
| Behavioural signal **saturates at 3.0** | Scores in the tens of thousands are unusable in a report or on a plot |
| `WATCH_AT = 0.85` | Calibration's 1.25 margin puts benign traffic near 0.80; a lower watch line puts every noisy tool permanently in WATCH |
| Sandbox reports **what is open**, not what appeared | An exfil channel holds its handle open — it looked "new" once, then invisible forever |
| Peers compared by **IP**, not IP:port | Python's asyncio self-pipe is a loopback socketpair with an ephemeral port; every benign server looked like new egress |
| **OS and interpreter paths excluded** from file evidence | Which system resource files a process holds depends on how it was launched, so a baseline captured from a console and a check run from the daemon differed by files nobody opened — unfiltered, the monitor measured the launcher |
| **All** new child pids monitored, not the lowest | Back-to-back verifications leave a previous server shutting down; the guess sometimes watched the wrong process and recorded nothing |
| `_match_verb` uses **word boundaries** | `"put"` matches inside `"input"`, so every tool described as returning "the input text" was denied a baseline |
| Decoy on **127.0.0.2** | Sharing 127.0.0.1 with the interpreter's own sockets made the beacon indistinguishable from noise |
| Calibration includes **updated** servers | Fitting to a frozen server meant the first legitimate update tripped the alarm |
| Scenario at a **fixed per-user path** | A relative default meant the CLI and a launched server read different files, and the attack silently never fired |
| `_split_command` is **non-POSIX** on Windows | `shlex` ate backslashes, so a calibration ran against the wrong server and *reported success* |
| Alert advice from the **most specific** signal | Choosing by score buried the actionable instruction under a generic drift message |
| `use` selects, `run` arms | Merging them meant browsing the attack options started an attack |

That `_split_command` entry is the most instructive: it did not crash. It produced
a plausible number that was wrong. Worth citing when someone asks how you know
your results are trustworthy.

---

## 9. Known limitations

Stated plainly, because a project that names its own weaknesses is stronger than
one that hopes nobody notices.

**Probe safety relies on attacker-controlled metadata.** Tool annotations live in
the definition, so a malicious server could claim `readOnlyHint: true`. That only
affects whether a tool is probed, never whether its responses are trusted — but it
is real and belongs in threats to validity.

**Side-effect monitoring polls.** A connection opened and closed entirely between
two polls is missed, and `open_files()` on Windows is partial. A kernel-level
tracer (eBPF/ETW) would close the gap and is out of scope.

**stdio transport only.** Many real MCP servers are remote/HTTP — precisely where
definition pinning is most useless, since no local file ever changes. The largest
coverage gap.

**Calibrated on one server.** The tool says so itself; three or more are needed
before the number should be quoted as a result.

**L4/L5 defeat fixed probe templates entirely.** Reported, not hidden.

**Only ever run against servers written for this project.** Until it has faced a
real community MCP server, "works on MCP" means "works on my MCP server".

**No multi-server background service yet.** `watch` and the daemon's loop cover
one process; the full resident service is still to come.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **Rug pull** | An approved tool turning malicious after approval, definition unchanged |
| **Definition** | A tool's name, description and input schema — the contract the user approved |
| **Canary probe** | A benign, seeded test input fired at a tool to observe its behaviour |
| **Baseline** | The fingerprint of a tool's behaviour captured at approval time |
| **Band** | A probe's benign variance envelope, estimated out-of-sample |
| **Ratio** | `distance / band` — drift normalised by that tool's own noisiness |
| **Threshold** | The calibrated ratio at which drift becomes an alert |
| **Score** | Evidence in common units where 1.0 is the alert line |
| **Differential rule** | A rule that fires only on behaviour new since baseline |
| **Family** | *What* a malicious payload does (six of them) |
| **Level** | *When* a payload is allowed to fire (L1–L5) |
| **Probe-aware** | An attacker that recognises the detector's test inputs and hides |
| **Baseline-by-observation** | A side-effecting tool that is watched but never probed |
| **Hash-only** | The control condition: definition pinning alone |

---

*Every module, constant, formula and measurement described here was read from the
source or taken from a recorded run at the time of writing.*
