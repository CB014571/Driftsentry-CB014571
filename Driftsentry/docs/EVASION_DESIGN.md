# DriftSentry — adaptive-evasion hardening: design

Design document covering the 15 requested items, with every proposed change
classified **Must have** / **High value** / **Stretch**.

Status marks are factual: ✅ built and tested, 🔶 partly built, ⬜ not started.

---

## 0. Attacker bypass model

Every defence below traces back to one of these. Where DriftSentry cannot address
a strategy, that is stated rather than papered over.

| # | Evasion strategy | Current status | Defence | Priority |
|---|---|---|---|---|
| 1 | Exact probe-value recognition | ✅ **closed** | Keyed probes, new values per cycle | Must |
| 2 | Probe-*pattern* recognition (values look synthetic) | ✅ **closed** | Realistic grammars | Must |
| 3 | Verification-session recognition | ⬜ open | Session-fingerprint audit; partial mitigation only | High |
| 4 | Predictable probe timing | ⬜ open | Keyed interval jitter | High |
| 5 | Predictable probe order | ⬜ open | Keyed permutation | High |
| 6 | Conditional attacks (fire only on certain inputs) | 🔶 partial | Coverage-guided probing | Must |
| 7 | Sleeper / delayed attacks | 🔶 partial | Sequence probes + temporal detector | High |
| 8 | Tiny single-field change | 🔶 partial | Field-level drift; determinism signal already helps | Must |
| 9 | Identical response, hidden side effect | 🔶 partial | Side-effect fingerprinting + tripwires | Must |
| 10 | Gradual low-and-slow drift | ⬜ open | CUSUM/EWMA | High |
| 11 | All signals held just below threshold | ⬜ open | Corroboration fusion | High |
| 12 | Benign for probes, malicious for real traffic | ⬜ open | Passive monitoring + active/passive inconsistency | Must |

**Outside the observable boundary — document as limitations, do not claim:**

- A server malicious *at approval time* (Trust On First Use). The baseline records
  the malice as normal. Unfixable by any baseline method.
- Side effects invisible to a 20 ms `psutil` poll — a connection opened and closed
  between polls. Needs a kernel tracer; out of scope for this FYP.
- Anything the server does on a machine we cannot observe (remote HTTP servers).
- An attacker with filesystem read access, who can simply read the probe key.

---

## 1. Modules that must change

| Module | Change | Priority | Status |
|---|---|---|---|
| `driftsentry/baseline.py` | keyed capture/verify paths, coverage selection, sequences | Must | ✅ keyed done |
| `driftsentry/fingerprint.py` | family types, text hashes, volatile-field masking | Must | ✅ partly |
| `driftsentry/scorer.py` | comparability scaling, new signals, fusion strategy | Must | ✅ partly |
| `driftsentry/verify.py` | thread cycle/key/strategy | Must | ✅ done |
| `driftsentry/daemon.py` | jitter, cycle counter, temporal state load/save | High | ⬜ |
| `driftsentry/proxy.py` | emit `PassiveObservation` | Must | ⬜ |
| `driftsentry/calibration.py` | calibrate corroboration + temporal thresholds | High | ⬜ |
| `driftsentry/rules.py` | tripwire-token rule; shared invariant comparison | High | ⬜ |
| `driftsentry/sandbox.py` | process-creation evidence | High | ⬜ |
| `driftsentry/store.py` | persist families, temporal state | Must | ✅ families |
| `attacker/*` | ground-truth events for every family | Must | ✅ done |

## 2. New modules

| Module | Purpose | Priority | Status |
|---|---|---|---|
| `keys.py` | per-server secret, experiment key derivation | Must | ✅ |
| `probe_generator.py` | HMAC-keyed schema-valid generation | Must | ✅ |
| `probe_templates.py` | realistic safe grammars | Must | ✅ |
| `redact.py` | strip probe arguments before embedding | Must | ✅ |
| `families.py` | probe-family baselines + comparability | Must | ✅ |
| `coverage.py` | schema category model, under-tested category preference | Must | ⬜ |
| `passive.py` | `PassiveObservation`, invariant evaluation on live traffic | Must | ⬜ |
| `fielddrift.py` | per-field comparison + volatile masking | Must | ⬜ |
| `metamorphic.py` | paired probes, `probe_consistency_score` | High | ⬜ |
| `temporal.py` | CUSUM + EWMA per (server, tool) | High | ⬜ |
| `corroboration.py` | independent-evidence fusion | High | ⬜ |
| `tripwire.py` | synthetic canary resources + tokens | High | ⬜ |
| `camouflage.py` | keyed jitter, order permutation, count variation | High | ⬜ |
| `eval/*` | harness, ground truth, experiments | Must | ✅ |

## 3. Dependencies

**No new runtime dependencies.** HMAC, CSV, statistics are stdlib. `pytest` added
as a dev extra (the project had no test framework). `scikit-learn` only if the
optional ML instrument is built, imported inside `eval/` and never by
`driftsentry/` — and a 40-line numpy logistic regression avoids even that.

Already fixed: `psutil`, `fastapi`, `pywebview` were imported but undeclared;
`requirements.lock` omitted `fastapi`/`pywebview` so a lock-file install produced
a broken dashboard.

## 4. Baseline JSON schema changes

```
ServerBaseline
  + schema_version: int = 1          ✅
  + probe_mode: "fixed" | "keyed"    ✅
  + key_id: str                      ✅   identifier only, never the key
  + generator_version: str           ✅
  + families: [TemplateFamilyBaseline] ✅
  + coverage: {tool: {category: count}}  ⬜
  + volatile_fields: {tool: [json_path]} ⬜

TemplateFamilyBaseline               ✅
    family_id, tool, field_grammars, n_instances, n_samples,
    centroid, band, dist_mean/std/max, comparability,
    text_hashes, shape_hashes, hosts, files, content_flags,
    error_rate, chars_mean/std, echo_ratio, excerpt,
    instances[], generator_version, key_id, cycle
  + expected_processes: [str]        ⬜
  + field_profiles: {path: FieldProfile}  ⬜

ProbeBaseline
  + text_hashes: [str]               ✅
  + family_id                        ⬜ (currently carried via template_id)

ProbeCheck
  + determinism_break: bool          ✅
  + comparability: float             ✅
  + field_drift_score: float         ⬜
  + consistency: float               ⬜
```

## 5. Migration

Rules already implemented and tested:

- Every new field is defaulted; a v1 baseline loads unchanged as
  `probe_mode="fixed", schema_version=1, families=[]`. **Verified** against the
  real stored `acme` baseline.
- `--probe-mode keyed` against a v1 baseline fails with a clear message telling
  the user to re-baseline. Never silently degrades.
- Chroma vectors carry `probe_mode`/`family_id` in metadata so fixed and keyed
  vectors cannot be compared.
- Temporal state keyed by `baseline_id`; re-baselining resets it rather than
  carrying a stale accumulator across an intentional behaviour change.
- Nothing rewrites an existing baseline in place.

This is not politeness. The fixed path is Experiment B's control condition and
must stay byte-identical.

## 6. Keyed probe generation ✅ built

```
seed = HMAC-SHA256(key, "version|server|tool|template|cycle|index|field_path")
rng  = Random(int.from_bytes(seed))
value = grammar(rng, schema_constraints)
```

Per **field**, not per probe — two fields of one probe must not be correlated, or
a server could infer one from the other.

Supported: string, integer, number, boolean, enum, arrays of scalars, one level
of nested object. `$ref`, `allOf`, untyped arrays and unknown types raise
`UnsupportedSchema`, and the tool degrades to observation-only rather than being
baselined against a malformed probe.

**Measured:** the L4 attacker's recogniser caught 9/9 fixed probes (100%) and
0/360 keyed probes (0%).

**Limitation now documented in code:** low-cardinality fields (enums, cities)
cannot be made unpredictable — only diluted. Values that appeared in the old
fixed pool are treated as burned and excluded, since the server saw them on every
verification for the life of that generator.

## 7. Probe families ✅ built

Replaces `exact input → exact response distribution` with
`family → behavioural invariants`. Family identity comes from the schema
(`path=filename`), so it is stable for the life of the tool while every value is
new.

The enabler is **argument redaction**: a tool that echoes its input produces a
different response for every probe by construction. Stripping the probe's own
arguments before embedding removes that term.

**Measured:** two different values from one family had cosine distance 0.7561
raw, 0.0000 redacted.

`comparability` is measured per family at baseline (mean pairwise post-redaction
distance) and the scorer scales the embedding signal by it — so where a tool
genuinely returns unrelated content for unrelated inputs, the detector leans on
structure, rules and side effects instead of pretending the embedding means
something.

## 8. Passive monitoring — design (Must, ⬜)

Hooks the proxy at the point where `ProxyLogger` already correlates requests to
responses.

```
_pump(c2s) → ProxyLogger.record → PassiveMonitor.on_request(tool, args)
_pump(s2c) → ProxyLogger.record → PassiveMonitor.on_response(id, result, obs)
                                    └─ PassiveObservation
                                    └─ INVARIANTS ONLY vs family baseline
```

Never semantic distance against canary centroids. Only: unseen outbound host,
credential-file access, unexpected file access, unexpected child process, new
security-rule activation, agent-directed instruction text, unseen response-shape
class, unusual error transition.

Three hard constraints:
1. **Never blocks or delays a user call** — observation is queued off the hot path.
2. **Watch-only until calibrated** — this is the highest false-positive risk in
   the upgrade (real traffic is far more varied than canaries).
3. **Active/passive inconsistency is itself the signal** (evidence family E):
   clean under probes, dirty on real traffic *is* the signature of a probe-aware
   attacker.

## 9. Side-effect fingerprinting — design (Must, 🔶)

`Behaviour = response + structure + network + files + processes + security effects`

Per family, store expected hosts/files/processes; at verify, diff and weight by
confidence:

| Event | Weight | Rationale |
|---|---|---|
| Credential-file / tripwire read | critical | near-proof |
| New external egress | strong | primary exfiltration channel |
| Unexpected process creation | strong | new capability |
| Unexpected file access | medium | benign updates touch new files |
| Response text change | weak | ambiguous alone |

Adds process-creation evidence to `sandbox.py` (children observed during a call
that were absent at baseline). No eBPF/ETW.

**Tripwires (High, ⬜):** synthetic files under the sandbox containing
`DRIFTSENTRY-<keyed-token>`, which no honest tool has reason to read. Reading one
is high-confidence; the token reaching the exfiltration sink is near-proof.
Evaluation-environment only, never real credentials.

## 10. Field-level drift — design (Must, ⬜)

Whole-response embeddings miss `"account": "382910"` → `"382911"`.

1. Parse JSON responses; canonicalise key order.
2. Classify each leaf by type: URL, email, ID, account, money, path, hostname,
   status/permission, instruction, free text.
3. Compare per type: exact equality for IDs/accounts/URLs/emails/paths; numeric
   delta for money; normalised similarity for free text.
4. `field_drift_score` = max weighted per-field change, security-sensitive types
   weighted above free text.

Lightweight and rule-based. No general semantic understanding of arbitrary fields.

**Volatile-field masking (Must, ⬜):** during baseline sampling, any field whose
value differs across samples of the *same* probe is marked volatile
(timestamps, request IDs, UUIDs) and masked to `<VOLATILE>` before comparison.
This is what allows sensitivity to rise without the false-alarm rate rising with
it — the two changes should ship together.

## 11. Temporal detector — design (High, ⬜)

CUSUM primary, designed exactly for small sustained shifts:

```
S_n = max(0, S_{n-1} + (score_n − k))     alert if S_n > h
```

`k` = benign mean + a fraction of benign σ; `h` calibrated for a target in-control
average run length, which converts directly to a per-cycle false-alarm rate.
EWMA alongside as a smoothed trend for the dashboard, not a second alerting path.

Persisted per `(server, tool, baseline_id)` — the daemon's 120-point history is
in-memory only and lost on restart. Reset on re-baseline and on explicit trust.

**FP risk:** CUSUM accumulates without bound, so a tool sitting slightly high
forever eventually alerts. Needs bounded `S` or decay, and ARL calibration.

## 12. Corroboration formula — design (High, ⬜)

Six families, chosen so members are correlated *within* and independent *across*:

| Family | Members |
|---|---|
| A Content | embedding drift, field drift, content rules |
| B Structure | structural change, error-rate change |
| C Side effects | egress, file, process, tripwire |
| D Surface | definition hash / schema change |
| E Adaptive | paired-probe inconsistency, active/passive inconsistency |
| F Temporal | CUSUM / EWMA |

Each family score = **max** of its members (correlated within → never sum).

```
alert if  any family ≥ T_critical              (1.0)
   or     count(families ≥ T_high) ≥ 2         (~0.65, calibrated)
   or     count(families ≥ T_med)  ≥ 3         (~0.45, calibrated)
```

Family D alone is always critical. `max_only` stays the default; corroboration is
opt-in so the two are experimentally comparable.

## 13. Evaluation harness architecture ✅ built

```
eval/
  __main__.py           python -m eval run --experiment 1
  harness.py            one episode on isolated DRIFTSENTRY_HOME + ATTACKER_HOME
  scenario_control.py   drives the attacker CLI as a subprocess (never imports it)
  ground_truth.py       reads the attacker's event log; recall / FAR / exposure
  record.py             40+ column row, CSV + JSONL, config_hash
  experiments.py        sweeps and reporting
```

Outcome classification is five-way, not two: `detected`, `missed`,
`never_triggered`, `benign_ok`, `false_alarm`. **`never_triggered` is excluded
from the recall denominator** — a detector cannot be blamed for missing an attack
that did not happen. Trigger exposure is reported separately.

**Ground truth was broken and is now fixed:** `content-injection`,
`silent-tamper` and `sleeper` recorded no events at all, so "fired but missed"
and "never fired" were indistinguishable for half the attack matrix.

## 14. Tests

✅ 97 passing. Regression locks were written **before** any detector change.

| Test | Covers | Status |
|---|---|---|
| `test_scorer_golden.py` | weights, max-combination, hash-only control | ✅ 13 |
| `test_probes_fixed_golden.py` | control-condition probe values, safety classifier | ✅ 11 |
| `test_variance_math.py` | leave-one-out, MIN_BAND, cosine clamp, normalisation | ✅ 15 |
| `test_calibration_math.py` | quantile, floor, all four `weak` triggers | ✅ 14 |
| `test_probe_generator.py` | determinism, rotation, schema validity, key non-leak | ✅ 23 |
| `test_determinism_signal.py` | the sensitivity gap and its closure | ✅ 8 |
| `test_redact.py` | redaction correctness, payload survival | ✅ 13 |
| `test_families.py` | comparability, family band, invariants | ⬜ |
| `test_coverage.py` | category assignment, under-tested preference | ⬜ |
| `test_passive.py` | invariants only, never blocks, watch-only default | ⬜ |
| `test_fielddrift.py` | per-type comparison, volatile masking | ⬜ |
| `test_temporal.py` | CUSUM accumulation/reset, persistence | ⬜ |
| `test_corroboration.py` | rule table, `max()` path unchanged | ⬜ |
| `test_migration.py` | v1 baseline loads; keyed refuses it clearly | 🔶 |

## 15. False-positive risk per change

**Six of the ten remaining changes push FAR up.** This is the central risk.

| Change | FP mechanism | Mitigation |
|---|---|---|
| Keyed probes | Fresh value hits a legitimate error path never seen at baseline → new shape | Baseline ≥8 instances; admit known error shapes into `shape_classes` |
| Family bands | Wider band cuts sensitivity; may also *reduce* FAR on updates — direction unknown | Measure both; report as a trade-off curve |
| Determinism signal ✅ | A deterministic tool that legitimately updates now alerts | Weight 1.15 — alerts but dismissible; requires ≥3 identical samples |
| Coverage-guided probing | Deliberately explores unusual input classes → more novel-but-benign responses | Cap categories per cycle; admit new shapes seen during baseline coverage |
| Passive monitoring | Real traffic is far more varied than canaries | Watch-only until separately calibrated; only security-relevant novelty counts |
| Field-level drift | Volatile fields (timestamps, UUIDs) look like tampering | **Ship with volatile masking, never before it** |
| Tripwires | Backup/indexing tools legitimately read everything | Confine to the evaluation sandbox; opt-in |
| Differential probes | Naturally nondeterministic tools differ between paired calls | Compare invariant *classes* only; exclude families with unstable invariants |
| Temporal CUSUM | Unbounded accumulation | Bound/decay `S`; calibrate `h` for target ARL |
| Corroboration | Lowers the bar by design | Calibrate on benign + benign-update; report FAR cost beside recall gain |

Cross-cutting: **the calibration partition must contain benign updates**, or every
threshold above is fitted to a world that does not exist.

---

## Classification summary

**Must have** — keyed probes ✅, realistic templates ✅, probe families ✅,
redaction ✅, evaluation harness ✅, ground-truth fix ✅, coverage-guided probing ⬜,
passive monitoring ⬜, field drift + volatile masking ⬜, side-effect strengthening 🔶

**High value** — timing/order camouflage, tripwires, differential probes,
temporal CUSUM, corroboration fusion, process evidence, calibration extension

**Stretch** — sequence probes, session-fingerprint minimisation, probe-recognisability
ML instrument, Isolation Forest ablation

---

## Evidence so far

| Measurement | Before | After |
|---|---|---|
| L4 recognises probes | 100% (9/9) | **0%** (0/360) |
| Cross-input distance, one family | 0.7561 | **0.0000** |
| Deterministic probe: change needed to alert | 0.108 | **any change** |
| **content-injection/L4, end to end** | `never_triggered`, 0.063 — held back on 54 probe-shaped inputs | **`detected`, 2.966** — fired, caught |

The last row is the mechanism working end to end, with ground truth from the
attacker's independent event log rather than the detector's own opinion.

## Next, in order

1. `coverage.py` — conditional attacks (evasion #6) are the largest remaining
   Must-have gap, and cheap
2. `fielddrift.py` + volatile masking — must ship together
3. `passive.py` — closes evasion #12, the strategy keyed probes cannot reach
4. Then High-value items, then Experiments A–H
