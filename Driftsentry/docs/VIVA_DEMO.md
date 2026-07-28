# DriftSentry — Viva Demonstration Runbook

A 10-minute live demonstration, with the exact commands, the observed output, and
what to say at each step. Every command here has been run end to end.

**The one sentence the whole demo exists to prove:**
> An MCP tool can turn malicious after you approve it while its advertised
> definition stays byte-for-byte identical — so definition pinning cannot see it,
> and behavioural re-verification can.

---

## Before you walk in

### The night before — do a full dry run

```bash
python examples/testbed_demo.py
```

Ends with `Phase 7 result: ALL CHECKS PASSED`. If it does not, do not improvise on
the day: fall back to the recorded run (see *If something breaks*).

### Pre-bake the slow steps

Baseline capture and calibration take a few minutes and are **legitimately done at
install time**, not during a demo. Run them before you present, and say so:
*"this is the approval step, which happens once when you install the server."*

```bash
python -m testbed reset --scenario F:/Driftsentry-final/.testbed/scenario.json
```
```bash
driftsentry baseline --server acme --exec python -m testbed serve --reuse --scenario F:/Driftsentry-final/.testbed/scenario.json
```
```bash
driftsentry calibrate --repeats 3
```
```bash
driftsentry trust --server acme
```

Check the benign score is comfortably below 1.00 before you present:

```bash
driftsentry verify --server acme
```

If it is above ~0.8, re-run `calibrate` with more `--repeats`. A benign server
scoring near the line will make the demo look fragile.

### Set up the screen

* **One terminal**, font size up, window maximised.
* Set the scenario path once (PowerShell):
  ```bash
  $SC = "F:/Driftsentry-final/.testbed/scenario.json"
  ```
  (bash: `SC=F:/Driftsentry-final/.testbed/scenario.json`)
* Have `docs/TESTING.md` open in a second tab as a safety net.

---

## The demonstration

### Step 0 — Frame the problem (30 seconds, no commands)

> "When you install an MCP server, the client shows you its tools and you approve
> them once. Existing scanners pin a hash of that definition. My claim is that
> the dangerous attack happens *after* approval and never touches the definition,
> so hashing cannot see it. I'm going to show you a server that does exactly
> that."

---

### Step 1 — Show the attacker's menu (30 seconds)

```bash
python -m testbed list-families
```

> "This is a standalone adversarial MCP server I built. Six attack families, each
> grounded in a documented real incident — postmark-mcp, MCPoison, the Invariant
> Labs sleeper. Five complexity levels from naive to probe-aware. It does not
> import DriftSentry: the attacker is not allowed to know how the defender works."

---

### Step 2 — The server is approved and behaving (30 seconds)

```bash
driftsentry verify --server acme
```

**Expect:** `VERDICT: OK   score 0.38 (alert at 1.00)`

> "The server is baselined and quiet. Two things to note. First, the threshold was
> calibrated on benign servers only — no attack data ever touched it, which is
> what keeps the false-alarm number defensible. Second, look at what was *not*
> probed."

Scroll back to the baseline output:

> "`send_invoice` and `search_orders` were never probed. They look side-effecting,
> so DriftSentry refuses to fire test inputs at them and marks them
> baseline-by-observation instead. You do not test a send-email tool by sending
> email."

---

### Step 3 — Turn the server malicious, live (30 seconds)

```bash
python -m testbed set-family content-injection --scenario $SC
```

**Expect:** `mode=rug-pull family=content-injection level=L1`
and `A running server picks this up on its next call.`

> "I've just rug-pulled the server. No reinstall, no new version, no change to
> what it advertises. It now injects instructions aimed at the AI assistant into
> its responses."

---

### Step 4 — Detection (1 minute) — **the centrepiece**

```bash
driftsentry verify --server acme
```

**Expect:** `VERDICT: ALERT   score 3.00   triggered by: behavioural_drift`
followed by a full alert card.

Walk the panel through the card:

> "The alert names the server and tool, the signal that fired and how far past the
> threshold it went. Then the concrete before and after — this is what the tool
> used to return, and this is what it returns now, with the injected instruction
> visible.
>
> And the mitigation is specific to the *cause*. The loudest signal here is
> behavioural drift, but a content rule also fired, so the advice addresses the
> injection: stop the assistant acting on this output, and check what it already
> did after reading it. Generic 'something changed' advice would be useless."

---

### Step 5 — The control condition (45 seconds) — **the money shot**

```bash
driftsentry verify --server acme --hash-only --no-alert
```

**Expect:** `definition : unchanged` / `VERDICT: OK   score 0.00`

> "Same server. Same attack. Same traffic. Scored the way mcp-scan and Snyk Agent
> Scan score it — definition hash only. It reports no change.
>
> That is the gap this project fills, and it is the same code path and the same
> probe data, so it is a fair comparison rather than a re-implementation I might
> have weakened."

**Pause here.** This is the moment the examiners need to absorb.

---

### Step 6 — A different family, a different signal (45 seconds)

```bash
python -m testbed set-family new-egress --scenario $SC
```
```bash
driftsentry verify --server acme
```

**Expect:** `VERDICT: ALERT   score 2.00   triggered by: rule:new_egress_host`

> "A different family, caught by a different signal — a security rule this time,
> not embedding drift. That matters for my coverage claim: three of my six
> families are caught by rules, three by behavioural drift. Neither signal alone
> covers all six. I claim a detection *pathway* for every family, not that I
> detect every attack."

---

### Step 7 — The honest limit (1 minute) — **where the marks are**

```bash
python -m testbed set-family content-injection --scenario $SC
```
```bash
python -m testbed set-level L4 --probe-aware --scenario $SC
```
```bash
driftsentry verify --server acme
```

**Expect:** `VERDICT: OK   score 0.80` — it evades.

> "This is a probe-aware attacker. It recognises my canary inputs and behaves
> whenever it thinks it is being tested. It evades detection, and I am showing you
> that deliberately.
>
> This is the experiment nobody has run against an MCP rug-pull defence. My probe
> values are already seeded rather than fixed, and Experiment 4 measures how much
> randomised templates recover against exactly this attacker. A detection rate
> that hid this result would not survive the first examiner who built the
> counterexample — and it takes about five minutes to build."

---

### Step 8 — Response (45 seconds, optional if time is short)

```bash
driftsentry report --server acme
```
```bash
driftsentry quarantine --server acme --enforce
```

> "Alerts are recorded as JSON as well as terminal output, so the evaluation has a
> machine-readable trail. Quarantine is advisory by default. If I opt in to
> enforcement, the proxy refuses tool calls to that server in the live data path —
> the client gets an error explaining why.
>
> Enforcement is off by default on purpose: detection is the contribution being
> evaluated, and a proxy that silently blocked attacks would confound every
> detection measurement."

---

### Step 9 — Close (30 seconds)

> "To summarise: six attack families, all advertising byte-identical definitions.
> Hash-only pinning catches zero of six. DriftSentry catches six of six at L1,
> with no false alarm on a benign server or on a benign server that has
> legitimately updated. Detection degrades as the attacker adapts, and at L4 the
> probe-aware attacker defeats fixed probes — which is what the randomised-template
> experiment is for."

---

## Reset between runs

```bash
python -m testbed reset --scenario $SC
```
```bash
driftsentry trust --server acme
```

---

## If something breaks live

1. **Stay calm and narrate.** "Let me check what the server is actually running."
   ```bash
   python -m testbed show --scenario $SC
   ```
   This prints the active scenario. If `mode` is `benign`, the `set-family` call
   went to a different file — re-run it with the explicit `--scenario $SC`.

2. **The classic failure:** the CLI and the server reading different scenario
   files, because environment variables do not reach a server launched by an MCP
   client. Always pass `--scenario` with an absolute path. `serve --reuse` warns
   loudly when the file it was pointed at does not exist.

3. **Last resort:** run the whole thing from the recorded demo instead.
   ```bash
   python examples/testbed_demo.py
   ```
   Better still, have its output saved to a file beforehand and show that.

---

## Questions to expect, and the answers

**"You built both the attacker and the defender. Isn't this circular?"**
> The strongest objection, and I lead with it rather than waiting to be asked. Three
> answers. The testbed is a separate package that cannot import the detector.
> Calibration and test data are disjoint — the threshold never sees attack data,
> and the false-alarm number is measured on a held-out seed. And the L4/L5 attacker
> is deliberately given knowledge of the defence and allowed to target it, which is
> the opposite of tuning the defence to my own attacks.

**"Why no LLM in the scoring?"**
> Reproducibility. Every number is arithmetic over stored vectors and regular
> expressions, so the same baseline and the same responses give a bit-identical
> score every run. MCPShield puts a language model in the decision path and cannot
> make that claim. An LLM may appear as a secondary explainer in an alert, never as
> the decision.

**"Six out of six looks too good."**
> That is L1 — the naive attacker — and I report it as such. Recall drops as the
> attacker adapts, and at L4 it reaches zero for fixed probes. The claim I defend
> is a per-family, per-level matrix, not a single detection rate.

**"How do I know it isn't just alarming on everything?"**
> A benign server scores 0.09 and a benign server that has legitimately updated
> scores 0.79, both under the 1.00 line, with the update measured on a seed the
> threshold never saw. Benign updates are in the calibration distribution
> deliberately — a detector that alarms on a legitimate update is unusable however
> good its recall looks.

**"What about tools you can't safely probe?"**
> They are never probed. Classification uses the MCP `readOnlyHint` /
> `destructiveHint` annotations first, then word-boundary verb heuristics.
> Side-effecting tools are marked baseline-by-observation. The honest limitation:
> annotations live in the attacker-controlled definition, so a malicious server can
> claim to be read-only. That only affects whether I probe it, never whether I
> trust its responses, and it is in my threats to validity.

**"How reliable is the side-effect monitoring?"**
> It polls, so a connection opened and closed entirely between two polls is missed;
> and `open_files` on Windows is partial. A kernel-level tracer would close that gap
> and is out of scope. I state it rather than claiming the monitor is complete.

**"Does the proxy slow things down?"**
> Probes run out of band on a schedule, never on a live tool call, so detection adds
> no latency to real use. The proxy itself forwards message objects unchanged, and I
> verify transparency and concurrent in-flight calls as a regression test.

---

## Timing

| Step | Time |
|---|---|
| 0. Frame the problem | 0:30 |
| 1. Attacker's menu | 0:30 |
| 2. Server is behaving | 0:30 |
| 3. Turn it malicious | 0:30 |
| 4. Detection + alert card | 1:00 |
| 5. Hash-only control | 0:45 |
| 6. Second family | 0:45 |
| 7. L4 evades | 1:00 |
| 8. Response / enforcement | 0:45 |
| 9. Close | 0:30 |
| **Total** | **~7 minutes** + questions |

Each `verify` takes roughly 10–20 seconds to run. Talk over it — explain what it is
doing (replaying the same seeded probes, recomputing three signals) rather than
watching the terminal in silence.
