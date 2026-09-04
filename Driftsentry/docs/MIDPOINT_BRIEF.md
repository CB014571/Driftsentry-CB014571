# Midpoint evaluation brief — DriftSentry

Structured to the six points the Project Manager asked for. Every figure is from
the working tree.

**Your position:** implementation is substantially complete; evaluation is the
open work. That is a good place to be at midpoint, and the PM's framing rewards
stating it plainly.

---

## Opening statement — 30 seconds, memorise this

> DriftSentry detects behavioural rug-pull attacks in the Model Context Protocol,
> where an approved tool turns malicious while its advertised definition stays
> byte-for-byte identical.
>
> Eight of ten planned phases are complete. The detector, the adversarial server
> and the evaluation harness are all built and working — about 14,500 lines with
> 177 passing tests. What remains is running the controlled experiments and
> writing up the results.
>
> I also have a finding I did not expect: my own attacker defeated my own
> detector, and I have since closed that gap and measured the difference.

Then stop and let them direct.

---

## 1. What I have completed

### Phases 0–7 of 10, complete

| Phase | Deliverable | Evidence |
|---|---|---|
| 0 | Stack verification, MCP handshake | `check_stack.py`, `echo_client.py` pass |
| 1 | Transparent stdio proxy | Survives 8 concurrent calls, logs every exchange |
| 2 | Client config ingestion and rewrite | Working config, secrets hidden, idempotent, restores |
| 3 | Canary probes, fingerprinting, variance | Drift caught on an identical definition hash |
| 4 | Drift scorer, security rules, calibration | 8 signals, calibrated threshold with provenance |
| 5 | Alerting, policy, enforcement | Before/after evidence, per-cause mitigations |
| 6 | Daemon, control API, dashboard | 13 endpoints, 8 pages, live 2-second refresh |
| 7 | Adversarial server | 6 families × 5 levels, 18/18 self-test |

### By the numbers

| | |
|---|---|
| Detector | **9,038 lines**, 29 modules |
| Adversarial server | **2,394 lines**, 9 modules, separate project and virtual environment |
| Evaluation harness | **1,168 lines**, 7 modules |
| Test suite | **1,897 lines, 177 tests, all passing** |
| Attack configurations | 6 families × 5 levels = **30**, plus benign and benign-update |
| Detection signals | **8 active** |

### Three things worth demonstrating

**The premise holds.** All six attack families produce a tool-definition hash of
`6805aff88dcf676e…` — identical to benign. Hash pinning cannot tell them apart.
Asserted by the self-test, so it is checked on every run, not claimed once.

**The detector works.** Live cycle at the calibrated threshold: benign 0.05,
0.05, 0.09 → content-injection armed **2.06 (alert)** → disarmed 0.04, 0.07.
Detection and recovery, with the definition unchanged throughout.

**Ground truth is independent.** The adversarial server writes its own event log,
in its own process, with no knowledge of the detector's verdict. Without it, a
missed detection and an attack that never fired look identical from outside.

---

## 2. What is currently under development

Be direct about this. It is the honest centre of the midpoint.

### Experiment 1 — the control condition (~58% complete)

38 of 66 episodes ran before the machine restarted. It needs relaunching, and
takes about two hours unattended.

Interim, incomplete results at threshold 10.8086:

| Level | Detected | Missed | Never fired | Recall |
|---|---|---|---|---|
| L1 | 7 | 0 | 0 | 100% |
| L2 | 6 | 0 | 0 | 100% |
| L3 | 6 | 0 | 0 | 100% |
| L4 | 0 | 0 | 6 | **undefined** |
| L5 | 0 | 0 | 6 | **undefined** |
| benign | — | — | — | 0 false alarms of 6 |

**Always say "interim and incomplete" when you show this.** An examiner who
catches you presenting a partial run as a finished result will doubt everything
else.

L4 and L5 recall being *undefined* rather than zero is the interesting part: the
attacker recognised the probes and declined to act — 54 probe-shaped inputs held
back in one episode. A detector cannot be blamed for missing an attack that did
not happen.

### Nine detection modules built but not yet wired

Built, unit-tested, deliberately not switched on: temporal CUSUM, corroboration
scoring, differential paired probes, timing and order camouflage, tripwire
resources, and passive monitoring of live traffic.

**Say why they are not enabled:** each can raise the false-alarm rate, and
turning nine signals on at once would make any change in results unattributable.
Each needs its own calibration and its own controlled comparison.

That is a defensible engineering position, not an excuse — and stating it shows
you understand experimental design.

---

## 3. What work remains

| Task | Effort | Blocks |
|---|---|---|
| Complete Experiment 1 | ~2 h unattended | Chapter 6 results |
| Run Experiment 2 (keyed probes) | ~2 h unattended | The central comparison |
| Calibrate across ≥3 servers | 1–2 days | Quotable false-alarm rate |
| Baseline a real community MCP server | 1–2 days | External validity |
| Wire and calibrate the 9 built modules | 3–5 days | Experiments 3–6 |
| Build the labelled corpus properly | 3–5 days | Reproducibility artefact |
| Chapters 6 and 7 | Depends on deadline | Final submission |

### The three that genuinely cap the grade

1. **The experiments must actually run.** Everything else is secondary.
2. **Calibration is weak** — 54 observations from one server, and the tool flags
   it `weak: true` itself. Needs three servers minimum.
3. **No real MCP server has been tested.** Only my own synthetic one. This is the
   biggest external-validity limitation.

---

## 4. Planned testing and evaluation

### Already in place

- **177 unit tests**, including four regression-lock files written *before* any
  detector change, so the control condition cannot drift
- **18-check ground-truth self-test** on the adversarial server
- **Five executable phase checks** exercising real processes, not mocks

### The experiment design

Six controlled experiments, each varying one thing:

| # | Compares | Answers |
|---|---|---|
| 1 | Current detector, fixed probes, full matrix | Baseline vulnerability |
| 2 | Same matrix, keyed probes | Does L4/L5 detection improve? |
| 3 | Probe recognisability across probe modes | How fingerprintable are probes? |
| 4 | Active probing vs active + passive | Does passive close the gap? |
| 5 | With and without paired probes | Does differential probing help? |
| 6 | Full ablation across all configurations | What does each component contribute? |

### Metrics

Recall on attacks the attacker's independent log **proves executed**, reported
beside false-alarm rate on benign *and* benign-updated servers. Plus
time-to-detection, calls-to-detection, and runtime cost.

**The methodological rule I enforce:** an episode counts as a missed detection
only when ground truth proves the payload ran. A probabilistic or trigger-gated
attack that never fired is a separate outcome, excluded from the recall
denominator, and trigger exposure is reported separately.

### Dataset discipline

Three partitions with separate seeds: development, calibration (benign and benign
updates only), and a blind test whose thresholds are frozen before it is opened.
Every result row carries a `config_hash` of the detector configuration, so "no
tuning after seeing test data" is auditable rather than merely promised.

---

## 5. Further development and refinements

Ordered by value:

1. **Randomised probe rotation is done** — superseded by keyed generation, which
   is stronger. Probe recognition by my L4 attacker fell from **100% (9/9) to
   0% (0/360)**.
2. **Wire the temporal and corroboration scorers** — these target the low-and-slow
   and sub-threshold attackers respectively, the two evasion strategies still open.
3. **Passive monitoring into the scoring path** — currently watch-only. It is the
   only channel that can see a server which behaves for probes and attacks real
   users.
4. **Kernel-level tracing** — out of scope for this project, named as future work.

---

## 6. Other components before final submission

| Item | Status |
|---|---|
| LICENSE file | **Missing.** Both projects declare MIT; no file exists |
| Commit outstanding work | Last commit 2 August; a large body of work is uncommitted |
| `docs/TESTING.md` | Stale — 10 references to the old `testbed` name |
| Coverage measurement | No `pytest-cov` installed; no figure to quote |
| Proxy latency overhead | Unmeasured — a claimed property I have not evidenced |
| Chapters 6 and 7 | Not started, dependent on experiment results |

---

## Demonstration sequence — 10 minutes

Do this live if you get the chance. It is far more convincing than slides.

| # | Show | Command | Takeaway |
|---|---|---|---|
| 1 | Ground truth is sound | `python -m attacker selftest` | 18/18, and all six families hash identically |
| 2 | Tests pass | `python -m pytest tests\ -q` | 177 passed |
| 3 | The dashboard, normal | `driftsentry ui` | Benign server, score ~0.05 |
| 4 | Arm an attack | `attacker attack content-injection` | Score jumps to ~2.06, alert |
| 5 | The alert | Dashboard → Alerts | Before/after and mitigations |
| 6 | **Hash-only vs full** | `verify --hash-only` then `verify` | **Control sees nothing; detector alerts** |
| 7 | The harness | `python -m eval run --experiment 1 --quick` | Episodes classified against ground truth |

Step 6 is the single most important thing you can show. Same server, same
traffic, same code path — only the signals differ.

**Before demonstrating:** run `driftsentry trust --server acme` to clear any
previous quarantine, or the alert will not re-fire.

---

## The finding to lead with

If the conversation stalls, or you are asked what you learned:

> I built an attacker that defeated my own detector. My L4 probe-aware attacker
> recognised 100% of my probes and never fired — undetectable, because nothing
> happened. I then replaced fixed probes with values derived from a secret key
> and rotated every cycle. Recognition dropped to zero, and the same attack went
> from never firing to being caught at 2.966.

A student who demonstrates an evasion against their own system and then closes it
is doing security engineering. It reads far better than a system that always
worked, and it is hard to fake.

---

## Three sentences to have ready

**"How much is done?"**
> Eight of ten phases. The implementation is substantially complete; the
> controlled experiments are what remain.

**"What are your results?"**
> The full run is incomplete — 38 of 66 episodes. I have component measurements
> and one end-to-end result, and I would rather show you those than present a
> partial run as finished.

**"What worries you most?"**
> That no real community MCP server has been tested. Everything I claim is under
> controlled conditions against an adversary I wrote myself.

---

## One action before the evaluation

**Restart Experiment 1 the night before.** It runs unattended in about two hours
and would let you show a complete control condition instead of 58% of one:

```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\python.exe -m eval run --experiment 1 --seeds 2 --threshold 10.8086
```

If there is no time, the `--quick` sweep produces a complete summary table in
about six minutes and demonstrates the harness working end to end — which is what
the evaluators are actually assessing at midpoint.
