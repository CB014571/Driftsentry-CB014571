# Demonstration guide — what runs, where it is, and what to say

Every step gives the command, what appears on screen, which code executes,
and the sentence to say while it runs. Line numbers are from the working tree
on 20 September 2026. Open the named files in editor tabs *before* the viva,
in the order listed at the end, so you can click to a line while talking.

The guide's 20-minute limit gives the demo about four minutes. Steps 1 to 6
fit that. Steps 7 and 8 are for questions, or if the panel asks to see more.

---

## Before you start

Two terminals, both at `F:\fyp project`.

**Terminal A — detector:**
```
cd "F:\fyp project\Driftsentry"
.\.venv\Scripts\activate
```

**Terminal B — attacker:**
```
cd "F:\fyp project\mcp rug pull attack server"
.\.venv\Scripts\activate
```

**Clear any previous state, or step 5 will not re-fire:**
```
driftsentry trust --server acme
attacker reset
```

**Get the launch command once** — it is what every `--exec` below expands to:
```
attacker launch-command
```
It prints the attacker's Python path and entry point. Call it `<LAUNCH>` below.

**Editor tabs, in this order:** `attacker/server.py` · `attacker/attacks.py` ·
`driftsentry/baseline.py` · `driftsentry/fingerprint.py` ·
`driftsentry/scorer.py` · `driftsentry/alerts.py` ·
`driftsentry/probe_generator.py` · `eval/ground_truth.py`.

---

## Step 1 — Ground truth is sound (30 s)

**Terminal B:**
```
python -m attacker selftest
```

**What appears:** 18 checks, all passing. One line reads *all six families
hash to 6805aff88dcf676e — identical to benign*.

**What runs:**

| File | Function | Line | What it does |
|---|---|---|---|
| `attacker/selftest.py` | `main()` | 134 | Launches the server once per family, collects tool definitions, asserts every hash matches benign |
| `attacker/selftest.py` | `_definition_hash()` | 54 | SHA-256 over name + description + schema, first 16 hex chars — the same thing mcp-scan pins |
| `attacker/server.py` | `@mcp.tool()` ×5 | 119, 132, 140, 150, 163 | The five tool definitions. Fixed decorators; nothing here reads the scenario |
| `attacker/server.py` | `_process()` | 75 | The only place the scenario is consulted — *after* the definition is served |

**Say:**
> "Before I show the detector, I prove the premise. All six attack families
> advertise exactly the same tool definition as the benign server — the hash
> is identical. This is asserted on every run, so hash pinning provably cannot
> tell them apart. The attack lives in `_process`, line 75, which runs after
> the definition has already been approved."

**Click to:** `server.py:119` — a `@mcp.tool()` decorator — then `server.py:75`.

---

## Step 2 — The tests pass (15 s)

**Terminal A:**
```
python -m pytest tests\ -q
```

**What appears:** `177 passed in ~2–6s`.

**What runs:** eleven test files. The ones worth naming if asked:

| File | Locks |
|---|---|
| `tests/test_scorer_golden.py` | The scorer's output on a fixed report — written *before* the hardening changes, so the control condition cannot drift |
| `tests/test_probes_fixed_golden.py` | The exact fixed-probe values for seed 20260720 |
| `tests/test_probe_generator.py` | Keyed probes: replayable with the key, different every cycle, never escape the sandbox |
| `tests/test_redact.py` | Redaction drops cross-input distance to zero |

**Say:**
> "177 tests. Four of them are regression locks written before I changed the
> detector, so I can prove the control condition is the same code the
> experiments started with."

---

## Step 3 — Capture a baseline (60 s)

**Terminal B** — make sure the server is benign:
```
attacker benign
```

**Terminal A:**
```
driftsentry baseline --server acme --verbose --exec <LAUNCH>
```

**What appears:** five tools listed; three marked probed, two skipped as
side-effecting; for each probed tool, three probes, five samples each; then
*baseline saved*. Roughly 45 tool calls, under a minute.

**What runs, in order:**

| File | Function | Line | What it does |
|---|---|---|---|
| `driftsentry/baseline.py` | `capture_baseline()` | 105 | The whole capture: launch, list tools, probe, summarise, save |
| `driftsentry/probes.py` | safety classification | — | 46 destructive verbs, 23 safe. A tool whose name or description hits a destructive verb is never probed |
| `driftsentry/baseline.py` | `_call_once()` | 82 | One MCP `tools/call`; on exception, synthesises an `isError` result rather than crashing |
| `driftsentry/fingerprint.py` | `normalize_result()` | 117 | Text blocks joined; keys sorted; shape hash and text hash, 32 hex each |
| `driftsentry/embeddings.py` | `OnnxEmbedding.embed()` | 148 | all-MiniLM-L6-v2 → 384-dimensional vector |
| `driftsentry/fingerprint.py` | `centroid_of()` | 354 | Mean of the five sample vectors, L2-normalised |
| `driftsentry/fingerprint.py` | `leave_one_out_distances()` | 364 | Each sample's distance to the centroid of the other four — the out-of-sample variance |
| `driftsentry/fingerprint.py` | `summarize_probe()` | 394 | Band = max(worst observed, mean + 3σ, MIN_BAND 0.01). Keeps a 300-char excerpt |
| `driftsentry/fielddrift.py` | `learn_profiles()` | 165 | Learns which fields are volatile — timestamps, request IDs — so they are masked later |
| `driftsentry/store.py` | `BaselineStore.save()` | 78 | Writes `baselines/acme.json` and indexes centroids in ChromaDB |

**Say:**
> "This is Trust On First Use. The server is honest right now, and I record
> what honest looks like. For each read-only tool I generate three probes
> from its schema and call each five times. The five responses become a
> centroid, and — this is the important part — the variance is measured
> leave-one-out, so the band is what a *future* call will actually see, not
> what these five looked like to each other."

**Click to:** `fingerprint.py:364`, the four-line loop. Then `fingerprint.py:52`,
`MIN_BAND = 0.01`, and say: *"Without this floor a deterministic tool has a band
of zero, and the first change divides by nothing — I measured a score of
263,659 before adding it."*

**If asked "where is the training?":** *"There isn't any. This function is
the whole of it — it records, it does not fit."*

---

## Step 4 — Verify the benign server (30 s)

**Terminal A:**
```
driftsentry verify --server acme --exec <LAUNCH>
```

**What appears:** per-tool scores around 0.03–0.10, verdict **OK**, no alert.

**What runs:**

| File | Function | Line | What it does |
|---|---|---|---|
| `driftsentry/verify.py` | `verify_server()` | 46 | Loads the baseline, re-probes, scores, writes alerts |
| `driftsentry/baseline.py` | `reprobe()` | 448 | Two fresh samples per probe |
| `driftsentry/scorer.py` | `score_report()` | 259 | Every signal for every probe of every tool |
| `driftsentry/scorer.py` | `raw_behavioural = …` | 326 | Distance ÷ band, times comparability, capped at 3.0 |
| `driftsentry/scorer.py` | `best = max(signals…)` | 427 | Per probe: the winning signal, not the sum |
| `driftsentry/scorer.py` | `worst = max(probe_scores…)` | 440 | Per tool: the worst probe. The server is its worst tool |

**Say:**
> "Same server, a minute later. Every probe scores well inside its band — this
> is what benign variation looks like against a calibrated baseline. 1.0 is
> the alert line; we are at a twentieth of it."

**Click to:** `scorer.py:427` and `:440`. Say: *"Max, not sum. The embedding
and structure signals move together; adding them would count one change
twice. Max also means every alert names exactly one cause."*

---

## Step 5 — Arm the attack, watch it fire (60 s)

**Terminal B:**
```
attacker attack content-injection
```

**Terminal A:**
```
driftsentry verify --server acme --exec <LAUNCH>
```

**What appears:** one or more tools jump to roughly **2.0**, verdict **ALERT**.
A coloured alert block prints: server, tool, winning signal, score, threshold,
a before/after excerpt, and mitigations.

**What runs — the attacker side:**

| File | Function | Line | What it does |
|---|---|---|---|
| `attacker/scenario.py` | `Scenario` | 182 | The armed state, read from `scenario.json` on every call |
| `attacker/server.py` | `_process()` | 75 | Sees the scenario is armed, hands the honest response to the attack family |
| `attacker/attacks.py` | content-injection handler | — | Appends an instruction-shaped payload to the response text |
| `attacker/sink.py` | `log_event("inject", …)` | 70 | Writes the ground-truth line: *this attack executed, here is what it did* |

**What runs — the detector side:**

| File | Function | Line | What it does |
|---|---|---|---|
| `driftsentry/rules.py` | `content_flags()` | 97 | Instruction-shaped output → high-severity rule, 2.0 — on the *raw* text, before redaction |
| `driftsentry/scorer.py` | `W_RULE_HIGH = 2.0` | 68 | Twice the alert line: sufficient alone |
| `driftsentry/scorer.py` | `best = max(…)` | 427 | The rule wins over behavioural drift |
| `driftsentry/alerts.py` | `build_alerts()` | 390 | 18-field record: before/after, winning signal, per-cause mitigations; appended to `alerts/acme.jsonl` |
| `driftsentry/alerts.py` | `render_text()` | 474 | The terminal block. ASCII-only so it survives any console |

**Say:**
> "I've armed content injection. The tool definition has not changed — you can
> re-run the self-test and get the same hash. But the response now carries an
> injected instruction, the rule fires at 2.0, twice the alert line, and the
> alert names it. The evidence is the before and after excerpt: this is what
> the tool said at approval, this is what it says now."

**Click to:** `rules.py:97`, then `alerts.py:390`. If asked how you know the
attack really fired, show the attacker's own record. **Terminal B:**
```
type %LOCALAPPDATA%\mcp-attacker\sink\events.log
```
One tab-separated line per event — timestamp, kind (`inject`), detail.
*"The attacker's own log, written in its own process, with no knowledge of
the verdict. This is the ground truth every experiment row is judged
against."* (`attacker status` shows the armed scenario, not this log.)

---

## Step 6 — The control: hash-only sees nothing (30 s)

Server still armed. **Terminal A:**
```
driftsentry verify --server acme --hash-only --exec <LAUNCH>
```

**What appears:** every tool **OK**. Definition hash unchanged. No alert.

**What runs:**

| File | Function | Line | What it does |
|---|---|---|---|
| `driftsentry/scorer.py` | `if mode == "hash-only":` | 289 | Same scorer, same report — every signal except the definition hash is discarded |

**Say:**
> "Same armed server. Same probes, same responses, same scorer — one flag.
> This is what mcp-scan and every definition-pinning tool would report:
> nothing wrong. The only difference between this screen and the last one is
> which signals are allowed to count. That is the project in one comparison."

**Click to:** `scorer.py:289`. This is the single most important line to have
on screen. Stay on it.

Then disarm and show recovery — **Terminal B** `attacker benign`,
**Terminal A** `driftsentry verify …` — score falls back to ~0.05.

---

## Step 7 — The dashboard (if time, 45 s)

**Terminal A:**
```
driftsentry ui
```

**What appears:** a native window. Overview shows the `acme` card with its
score and a sparkline. The Drift graph page shows the history with the watch
and alert lines. The Alerts page lists the record from step 5.

**What runs:**

| File | Function | Line | What it does |
|---|---|---|---|
| `driftsentry/daemon.py` | `Daemon` | 83 | Holds state; a scheduler re-verifies every 20 s (`interval`, line 86); keeps 120 points (`HISTORY`, line 39) |
| `driftsentry/api.py` | `create_app()` | 64 | 13 FastAPI endpoints, bound to 127.0.0.1 only (`__main__.py:307`) |
| `driftsentry/ui/index.html` | `refresh()` | 677 | Polls `/api/state` every 2 s |
| `driftsentry/ui/index.html` | `driftChart()` | 360 | The SVG graph with the 0.85 and 1.0 lines |
| `driftsentry/ui/index.html` | `render()` | 522 | Server cards, badges, the alert list |

**Say:**
> "The same engine, resident. It re-probes every twenty seconds and the page
> refreshes every two. The control API is bound to loopback and cannot be
> reached from the network — it can quarantine a server, so it must not be."

---

## Step 8 — The finding: keyed probes (for questions)

The `baseline` command has no keyed-mode flag; keyed probing is reached
through the evaluation harness, which is where it was measured. Two ways to
show it.

**Option A — the record.** Open `eval_results/keyed_comparison.log`. Point at
the two lines: fixed probes, L4 attacker, *probe recognised 9 of 9, attack
never fired, score 0.063*; keyed probes, *recognised 0 of 360, attack fired,
score 2.966, detected*.

**Option B — live, six minutes.** **Terminal A:**
```
python -m eval run --experiment 2 --quick
```
Runs a tiny keyed sweep and prints the outcome table.

**What runs:**

| File | Function | Line | What it does |
|---|---|---|---|
| `attacker/attacks.py` | `looks_like_a_probe()` | 90 | The L4 attacker's check: is this input one of the fixed probe values? |
| `driftsentry/keys.py` | `get_or_create()` / `derive_experiment_key()` | 81 / 112 | 32-byte key; the harness derives one from the episode seed so keyed runs are replayable |
| `driftsentry/probe_generator.py` | `KeyedProbeGenerator._rng()` | 94 | HMAC-SHA256 over `version\|server\|tool\|template\|cycle\|index\|field` seeds the value |
| `driftsentry/probe_generator.py` | `generate()` | 286 | Draws each field's value from the seeded generator |
| `driftsentry/coverage.py` | `CoverageModel.choose()` | 162 | Picks the least-used category, so probes reach the conditional attack's trigger |
| `driftsentry/redact.py` | `redact()` | 83 | Masks the rotating value out of the response before embedding |
| `driftsentry/baseline.py` | `_reprobe_keyed()` | 362 | Fresh values per cycle — stored arguments are never replayed |
| `eval/harness.py` | `Episode.run()` | 142 | One isolated episode: baseline, arm, cycles, verdict |
| `eval/ground_truth.py` | `classify()` | 120 | detected / missed / never_triggered / benign_ok / false_alarm |

**Say:**
> "My level-four attacker reads my source and recognises every fixed probe —
> `looks_like_a_probe`, line 90. It held back on all nine and never fired, so
> the detector had nothing to detect. I replaced the fixed pool with values
> derived from a secret key and the cycle number. Recognition went from nine of
> nine to zero of three hundred and sixty, and the same attack was caught at
> 2.966. That is research question four, answered."

**Click to:** `attacks.py:90`, then `probe_generator.py:94`.

---

## Questions the demo invites, and where to click

| If they ask | Click to | Say |
|---|---|---|
| "Where's the model training?" | `baseline.py:105` | There isn't any. This records; it does not fit |
| "What's 1.0?" | `scorer.py:134` | The alert line — drift equal to the calibrated benign band |
| "Why is the hash worth 3.0?" | `scorer.py:63` | A changed definition is never ambiguous; it must alert alone |
| "How did you get 10.8086?" | `calibration.py:195` | 99th percentile × 1.25, benign only, floor 1.0, flagged weak |
| "Could the attacker just behave for probes?" | `passive.py` | Yes — that's why passive monitoring exists. Built, watch-only, next to wire |
| "How do you know the attack fired?" | `sink.py:70`, then the `events.log` file | The attacker's own log, in its own process |
| "What if the tool errors?" | `baseline.py:82` | Synthesised error result; error rate is a 0.4 signal, never an alert alone |
| "Why is this process separate?" | Two terminals | Neither project can import the other. They meet only over stdio |

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Step 5 shows OK, no alert | Server quarantined from a previous run, or still benign | `driftsentry trust --server acme` · `attacker status` must say RUG-PULL / content-injection |
| Step 3 says "no baseline" on verify | Wrong `--server` name | It must match what `baseline` stored: `acme` |
| Scores are all exactly 0.0 | Embedding backend fell back to hashing | Check the first log line names `onnx`; the ONNX cache is at `~/.cache/chroma/onnx_models` |
| `--exec` errors | `<LAUNCH>` pasted wrong | Re-run `attacker launch-command` and copy exactly |
| Dashboard blank | Port in use | `driftsentry ui --port 8766` |

Have a recording of steps 1–6 as backup. The panel will accept a recording;
they will not accept ten minutes of debugging.

---

## Timing

| Step | Seconds |
|---|---|
| 1 Self-test | 30 |
| 2 Tests | 15 |
| 3 Baseline | 60 |
| 4 Verify benign | 30 |
| 5 Arm and alert | 60 |
| 6 Hash-only control | 30 |
| **Total** | **3:45** |

Steps 7 and 8 are for questions, not the timed slot.
