# DriftSentry — Code Guide and Detection Logic

A walkthrough of every module in both projects, and a full account of how
detection actually works.

Companion to the roadmap. Written to be read top to bottom once, then used as a
reference. Everything here describes code that exists and runs; where something
is not built yet, it says so.

**Contents**

1. [What the system is](#1-what-the-system-is)
2. [Architecture and data flow](#2-architecture-and-data-flow)
3. [The detector, module by module](#3-the-detector-module-by-module)
4. [The detection logic in full](#4-the-detection-logic-in-full)
5. [The attacker, module by module](#5-the-attacker-module-by-module)
6. [Design decisions, and the bugs behind them](#6-design-decisions-and-the-bugs-behind-them)
7. [Known limitations](#7-known-limitations)

---

## 1. What the system is

An MCP client (Claude Desktop, Cursor) shows you a server's tools once and you
approve them. That approval is never revisited. A **rug pull** is when an
approved tool turns malicious *afterwards* while its advertised definition —
name, description, input schema — stays byte-for-byte identical.

Existing defences pin a **hash of the definition**. If the definition never
changes, the hash never changes, and they report nothing wrong. A one-shot
scanner cannot help either, because the attack happens after the scan.

DriftSentry is therefore a **resident proxy** that learns each tool's
*behaviour* at approval time and re-verifies it on a schedule.

Two projects, deliberately independent:

| Project | Role | Size |
|---|---|---|
| `Driftsentry/` | The detector | ~5,100 lines, 20 modules |
| `mcp rug pull attack server/` | The adversarial server that supplies ground truth | ~1,900 lines, 8 modules |

Neither can import the other. They meet only as operating-system processes
speaking MCP over stdio.

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

The separation is enforced, not stylistic. Probes run on their **own** connection
to the server, never on the user's traffic, so detection cannot slow a real tool
call. And no detection logic lives above `scorer.py`, so the dashboard cannot
influence a score it displays.

---

## 3. The detector, module by module

### Data plane

**`proxy.py`** (306 lines) — The interception core. DriftSentry is an MCP
*server* to the client and an MCP *client* to the real server at the same time.
Two async pump loops forward `SessionMessage` objects **unchanged** in each
direction; messages are never rebuilt, so JSON-RPC ids and ordering survive
exactly. The two directions are independent, so concurrent in-flight calls work
naturally. Also holds the opt-in enforcement hook that can refuse a `tools/call`
to a quarantined server, and logs every exchange to JSONL.

**`hashing.py`** (45) — Canonical SHA-256 over tool definitions (name +
description + inputSchema), with tools sorted by name and JSON keys sorted, so
harmless reordering cannot look like a change. This is simultaneously the
classic-rug-pull detector **and** the `--hash-only` control condition the
evaluation benchmarks against.

**`paths.py`** (28) — All persistent state under one directory, overridable via
`DRIFTSENTRY_HOME` so tests and the harness can run isolated.

### Setup

**`clientconfig.py`** (292) — Parses Claude/Cursor/VS Code configs, rewrites each
stdio server to launch through the proxy, writes a backup, prints a diff, and can
restore. Three properties: never overwrites by default, idempotent (cannot wrap
DriftSentry inside DriftSentry), and **secrets stay in `env`** — only variable
*names* travel on the command line, so keys never appear in the process list.

### Learning what normal looks like

**`probes.py`** (314) — Generates benign canary inputs from a tool's JSON Schema.
Values are drawn from eight template pools (`path`, `query`, `text`, `url`,
`email`, `city`, `name`, `generic`) using a seeded RNG, so probes are
reproducible but not a single fixed fingerprint. Also holds the **probe-safety
classifier**: MCP `readOnlyHint` / `destructiveHint` annotations first, then
word-boundary verb heuristics. Side-effecting tools are never probed.

**`embeddings.py`** (201) — Pluggable backends, tried in order: Ollama → cached
ONNX all-MiniLM-L6-v2 → dependency-free feature hashing. `auto` never triggers a
download (protecting the no-network-egress claim) and warns loudly if it falls
back to the lexical backend, since silently baselining an evaluation with the
weak backend would invalidate the results.

**`fingerprint.py`** (380) — Response normalisation and variance maths. Splits a
response into **normalised text** (→ embedding) and an **independent structural
signature** (paths and types, values discarded), so a hidden field appearing is
caught structurally even when the prose barely moves. Computes each probe's
benign variance band.

**`sandbox.py`** (218) — Polls the server process tree with psutil for hosts
contacted and files opened during a probe. Feeds the highest-weighted signals.

**`store.py`** (172) — ChromaDB for centroid vectors, JSON as the readable source
of truth. Collections are keyed by embedding backend **and** dimension, so
baselines from different models can never be silently compared.

**`baseline.py`** (381) — Orchestrates capture and re-probe.

### Deciding

**`rules.py`** (217) — Five deterministic security rules over 24 regex patterns:
`new_egress_host`, `secret_file_read`, `new_file_access`,
`credential_shaped_output`, `instruction_shaped_output`. All **differential** — a
rule fires only if the pattern is new since baseline.

**`scorer.py`** (401) — Combines the signals into one number. Detailed in §4.

**`calibration.py`** (242) — Derives the threshold from benign servers only.
Detailed in §4.

**`verify.py`** (154) — One code path for re-probe + score, used by the CLI, the
demos, the daemon and the evaluation, so they cannot diverge.

### Responding

**`alerts.py`** (548) — Turns a score into something actionable: cause,
before/after, and mitigations templated per cause. Severity comes from the score;
the *advice* comes from the most specific signal that fired.

**`policy.py`** (118) — trusted / watching / quarantined, plus the enforcement
switch. Quarantine is advisory unless explicitly opted into.

### Watching

**`daemon.py`** (~230) — The resident scheduler. Re-verifies every server on a
timer, keeps drift history, and raises alerts on *transitions* into alert so a
sustained attack does not flood the feed.

**`api.py`** (~60) — A localhost-only FastAPI control surface. No authentication,
and bound to `127.0.0.1` deliberately: it can quarantine a user's tooling, so it
must not be network-reachable.

**`ui/index.html`** — The dashboard: server list, live drift sparkline with the
threshold drawn on it, alert feed, and Scan / Quarantine / Trust / Block actions.

**`__main__.py`** (~840) — The CLI: `init`, `restore`, `run`, `baseline`,
`calibrate`, `verify`, `watch`, `ui`, `report`, `quarantine`, `trust`.

---

## 4. The detection logic in full

This is the part that matters. Four stages.

### Stage 1 — Baseline capture (approval time)

For each tool the server advertises:

1. **Classify probe safety.** Annotations first (`readOnlyHint`,
   `destructiveHint`), then word-boundary verb matching over the name and
   description. Anything that looks side-effecting is marked
   *baseline-by-observation* and **never probed** — you do not test a
   `send_email` tool by sending email.

2. **Generate N seeded probes** from the tool's input schema. The seed is stored,
   so the exact same probes can be replayed later and by anyone reproducing the
   work.

3. **Call each probe M times** (default 3 probes × 8 samples).

4. **Fingerprint every response**:
   - `definition_hash` — canonical hash of the advertised tools
   - `embedding` — vector over the normalised response text
   - `shape_hash` — structural signature (JSON paths and types, values discarded)
   - `content_flags` — which content rules match *normally* for this tool
   - `hosts` / `files` — what the process touched during the call

5. **Learn the variance band** — how much this probe's responses naturally vary.

#### The variance band, and why it is estimated out-of-sample

A weather or search tool legitimately returns different text every call. Treating
"differs from baseline" as drift would alarm forever.

So each probe gets a band. The obvious way to compute it — distance from each
sample to the centroid of those same samples — is **wrong**: the centroid is
fitted to the very points being measured, so the distances are systematically
smaller than a genuinely new sample will show.

Instead, `leave_one_out_distances()` holds each sample out, re-centroids the
rest, and measures the held-out distance. That estimates what we actually care
about: how far a sample the model has *not* seen tends to fall.

```
band = max( worst held-out distance,
            mean + 3σ,
            MIN_BAND = 0.01 )
```

`MIN_BAND` is an **embedding noise floor**, not a divide-by-zero guard. Below
about 0.01 cosine distance two responses are the same text and the difference is
numerical noise. A floor of `1e-6` would imply precision that does not exist and
produce drift ratios in the hundreds of thousands for deterministic tools.

### Stage 2 — Re-probe (measurement, no judgement)

`reprobe()` replays the stored probes and produces, per probe:

| Field | Meaning |
|---|---|
| `distance` | cosine distance from the stored centroid, **worst** sample |
| `band` | the learned benign band |
| `ratio` | `distance / band` — the variance-normalised drift |
| `shape_known` | was this structure seen at baseline? |
| `new_hosts` / `new_files` | touched now, not at approval |
| `new_content_flags` | content patterns present now, absent at baseline |

The **worst** sample decides, not the average: an attacker that fires on only
some calls (L2 stochastic) must not be averaged away.

This stage passes no judgement. Keeping measurement separate from scoring means a
stored measurement can be re-scored under a different threshold without
re-running any probes.

### Stage 3 — Scoring

Three signals, mapped onto **one scale where 1.0 is the alert line**:

| Signal | Score | Rationale |
|---|---|---|
| Definition hash changed | **3.0** | Not evidence of a rug pull — it *is* one class of rug pull. Needs no calibration to interpret. |
| Security rule, high (`new_egress_host`, `secret_file_read`, `credential_shaped_output`) | **2.0** | Near-proof of harm |
| Security rule, medium (`new_file_access`, `instruction_shaped_output`) | **1.1** | Suspicious, with plausible benign explanations |
| Behavioural drift | `ratio / threshold`, capped at **3.0** | The calibrated continuous signal |
| Structural change alone | **0.85** | Below the line by design: benign updates add optional fields |
| Error-behaviour change | **0.4** | Informational only |

Verdict bands: `< 0.85` OK, `0.85–1.0` WATCH, `≥ 1.0` ALERT.

#### Why combine by maximum, not by sum

The score is the strongest single piece of evidence, not the accumulation of all
of it.

Summing is tempting and wrong here: the embedding and structural signals read the
*same* response and are strongly correlated, so a sum lets ordinary benign noise
on a chatty tool add up to an alert. That inflates false-alarm rate — the one
metric this project cannot afford to be sloppy about. Max also keeps attribution
unambiguous: the alert names exactly the signal that caused it.

The honest cost: an attacker who keeps every individual signal just under the
line escapes corroboration. That is precisely the L5 mimicry case, and Phase 9's
per-level recall curve is where it gets measured rather than hidden.

#### Why the behavioural signal saturates at 3.0

Past a few multiples of the threshold the signal has said all it can. Letting the
number keep climbing produces scores in the tens of thousands for tools whose
baseline was deterministic — unusable in a report or on a plot, and it distorts
calibration.

#### Why no language model

Every number is arithmetic over stored vectors and regular expressions. Given the
same baseline and the same responses, the score is bit-for-bit identical on every
run. That determinism is the property the project is positioned on against
LLM-based detectors, and it is why an LLM may appear only as a secondary
*explainer* in an alert, never as the decision.

### Stage 4 — Calibration

One parameter is calibrated: the drift ratio at which behaviour stops being noise.

**Inputs are benign only.** A threshold fitted after seeing the attacks it is
meant to catch proves nothing — the detector was told the answer.

```
operating_point = quantile(benign_ratios, 1 - target_far)     target_far = 0.01
threshold       = max(operating_point × margin, 1.0)          margin     = 1.25
```

Three deliberate choices:

- **A quantile, not the maximum.** A deterministic tool has a near-zero band, so
  a single flicker yields a ratio in the hundreds of thousands; a max-based
  threshold would silence the detector permanently. Allowing the top 1% to sit
  above the line prevents that, and states the accepted false-alarm rate
  explicitly — which RQ2 has to report anyway.

- **A floor of 1.0.** A ratio of 1.0 means "exactly at the edge of the benign band
  this tool measured for itself". Alerting below that would contradict the band.

- **Benign *updates* belong in the calibration set.** Real software changes:
  responses get reworded, fields get added. A threshold fitted to a frozen server
  is far too tight and the first honest update trips it. `--also-exec` lets extra
  benign configurations join the calibration set. This is gap G3 stated as an
  engineering requirement.

The saved record carries provenance — how many observations, from how many
servers, under which embedding backend — and warns when the evidence is too thin
to quote (`MIN_SERVERS = 3`, `MIN_OBSERVATIONS = 30`).

### Stage 5 — Alerting

Severity comes from the score. The **advice** comes from the most *specific*
signal that fired, ranked: definition hash → egress → secret file → credential
output → instruction output → new file → behavioural drift → structural.

This matters. For a definition-invariant rug pull the highest-scoring signal is
almost always `behavioural_drift`, whose honest advice is the vague "look at the
before/after and decide". If a content rule *also* fired we know something far
more precise, with a specific remedy. Choosing the mitigation by score alone
would bury the one instruction the user most needs — *"check what your assistant
did after reading this"* — under a generic drift message.

Mitigations are templated per cause: a new-egress alert says rotate the
credentials that server could have seen; a hash-change alert says force
re-approval; plain drift leads with *"this is not by itself proof of an attack"*,
because overstating a weak signal is how detectors get switched off.

### Coverage: which signal catches which family

| Family | Caught by | Honest limit |
|---|---|---|
| Exfiltration | file evidence (sink + credential read) | answer is unchanged, so content signals see nothing |
| Silent tamper | embedding drift | a one-digit change is the hard case |
| Content injection | embedding + `instruction_shaped_output` | well-hidden text needs tighter rules |
| New egress | `new_egress_host` | near-proof when it fires |
| Sleeper | scheduled re-probing after it turns | long fuses need frequent re-probes |
| Conditional | rules on the triggered behaviour | fixed probes miss it by design |

Three families are caught by rules, three by embedding drift. **Neither signal
alone covers all six.** That is why the claim is *a detection pathway for every
family* — never *detects every attack*.

---

## 5. The attacker, module by module

**`scenario.py`** (~290) — The replayable unit: mode × family × level × seed as
JSON, plus `default_home()`, the fixed per-user path that stops the CLI and a
launched server reading different files.

**`attacks.py`** (254) — Six payloads and the L1–L5 gate. **Family = what it
does; level = when it fires.** Six × five comes from one payload mechanism and
one gating mechanism, so a level means the same thing across families and the
recall matrix is comparable row to row. Also the probe-aware logic: an attacker's
*guess* at the defender's probe values, hard-coded here, never imported.

**`server.py`** (185) — The MCP server. Tool definitions are **fixed and never
consult the scenario**, which is what makes benign and malicious instances hash
identically.

**`sink.py`** (~200) — Closed-loop infrastructure: a local file sink, a decoy
listener on `127.0.0.2`, a decoy credentials file, and an events log recording
every malicious act. Handles are held open deliberately so behaviour is
*observable* — a write between two monitor polls would measure the poll rate
rather than the detector.

**`selftest.py`** (~250) — Verifies the attacker against itself, with no detector
involved: definition identity, each family producing its own kind of effect,
gates firing only when they should, probe-aware evasion, and seed
reproducibility. Every detection figure depends on this ground truth, so it is
checkable rather than assumed.

**`console.py`** (~330) — The metasploit-style `use` / `set` / `run` console,
with a briefing on arming.

**`menu.py`** (257) and **`__main__.py`** (~490) — The numbered menu and the CLI.

---

## 6. Design decisions, and the bugs behind them

Each of these was a failing test first. They are the most useful things to be
able to explain.

| Decision | The bug it fixes |
|---|---|
| Variance estimated **leave-one-out** | In-sample fitting made bands too tight; a *benign* weather tool alarmed on the first honest re-probe |
| Band floor **0.01**, not `1e-6` | A deterministic tool that changed at all produced six-figure scores, and distorted calibration |
| Signals combined by **max** | Correlated signals summing to an alert inflates the one metric the project must defend |
| Behavioural signal **saturates at 3.0** | Scores in the tens of thousands are unusable in a report or a plot |
| `WATCH_AT = 0.85` | Calibration's 1.25 margin puts benign traffic near 0.80; a lower watch line puts every noisy tool permanently in WATCH |
| Sandbox reports **what is open**, not what appeared | An exfil channel holds its handle open — it looked "new" once, then invisible forever |
| Peers compared by **IP**, not IP:port | Python's asyncio self-pipe is a loopback socketpair with an ephemeral port; every benign server looked like new egress |
| **OS and interpreter paths excluded** from file evidence | Which system resource files a process holds depends on how it was launched, so a baseline captured from a console and a check run from the daemon differed by files nobody opened — unfiltered, the monitor measured the launcher |
| Decoy on **127.0.0.2** | Sharing 127.0.0.1 with the interpreter's own sockets made the beacon indistinguishable from noise |
| Calibration includes **updated** servers | Fitting to a frozen server meant the first legitimate update tripped the alarm |
| `_split_command` is **non-POSIX** on Windows | `shlex` ate backslashes, so a calibration ran against the wrong server and *reported success* |

That last one is the most instructive: it did not crash. It produced a plausible
number that was wrong. Worth citing when someone asks how you know your results
are trustworthy.

---

## 7. Known limitations

Stated plainly, because a project that names its own weaknesses is stronger than
one that hopes nobody notices.

**Probe safety relies on attacker-controlled metadata.** Tool annotations live in
the definition, so a malicious server could claim `readOnlyHint: true`. That only
affects whether a tool is probed, never whether its responses are trusted — but
it is real, and belongs in threats to validity.

**Side-effect monitoring polls.** A connection opened and closed entirely between
two polls is missed, and `open_files()` on Windows is partial. A kernel-level
tracer (eBPF/ETW) would close the gap and is out of scope.

**stdio transport only.** Many real MCP servers are remote/HTTP — and that is
exactly where definition pinning is most useless, since no file on your machine
ever changes. The biggest coverage gap.

**The threshold is currently calibrated on one server.** The tool says so itself.
Three or more are needed before the number should be quoted as a result.

**Probe-aware attackers (L4/L5) defeat fixed templates entirely.** Reported, not
hidden: randomised templates are the mitigation and Experiment 4 measures how
much they recover.

**Only ever run against servers written for this project.** Until it has faced a
real community MCP server, "works on MCP" means "works on my MCP server".

**No scheduler beyond `watch` and the daemon's foreground loop.** The full
multi-server background service is still to come.

---

*Generated as project documentation. Every module, constant and behaviour
described here was read from the source at the time of writing, not recalled.*
