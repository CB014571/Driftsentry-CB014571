# DriftSentry upgrade — implementation plan (v2)

Goal: make L4/L5 adaptive behavioural rug pulls substantially harder to evade,
then prove the improvement through controlled experiments. Preserve the existing
architecture and the working detector.

Plan only. No code written yet.

---

## 0. Findings from inspecting the current code

Four things found during inspection change the design. They come first because
three of them are load-bearing.

### F1 — Ground truth is missing for three of six families (BLOCKING)

The accuracy rule ("only count a false negative if the attacker's independent
event log confirms the malicious action occurred") cannot currently be applied:

| Family | Logs an event? | Why |
|---|---|---|
| `exfiltration` | yes (`exfiltrate`) | calls `sink.steal()` |
| `new-egress` | yes (`egress`) | calls `sink.beacon()` |
| `conditional` | yes | delivers the exfiltration payload |
| **`content-injection`** | **no** | `_content_injection()` never touches `sink` |
| **`silent-tamper`** | **no** | `_silent_tamper()` never touches `sink` |
| **`sleeper`** | **no** | delivers the content-injection payload |

For those three, "fired but missed" and "never fired" are indistinguishable.
**Nothing can be measured until this is fixed.** The fix is additive recording
inside the adversarial server; payload behaviour is untouched.

It also supplies the `probe_recognised` column: log the L4/L5 skip decision
(`should_fire()` already computes the reason string).

### F2 — The attacker observes baseline traffic, so probe reuse is unsafe

Under Trust On First Use the server is benign *while being baselined* and sees
every probe value fired at it. A sophisticated attacker logs them. This rules out
the cheap shortcut "baseline a larger pool, fire a random subset per cycle" —
any reused value is recognisable.

Verification must therefore use values **never fired before**, which forces
family-distribution comparison. Item 4 of the spec is a consequence of F2, not an
optional refinement.

### F3 — Unpredictability costs discriminative power (expect it in results)

An exact-argument baseline compares like with like. A family baseline compares an
unseen input against a distribution over *different* inputs, so the benign band
is wider and per-probe sensitivity drops.

**Expect keyed probes to reduce recall on L1–L3 while improving L4/L5.** That is
a legitimate finding. Experiment 2 must report the trade-off, not a single
headline number. F4 recovers much of the loss.

### F4 — Argument echo dominates cross-input variance

Two of the four probed tools echo their input into the response:

```python
return f"Document {path.strip()}: {body}"                 # read_document
return f"{city.strip()}: {temperature}C, {condition}, …"  # get_weather
```

A fresh probe value therefore changes the response *by construction*, with no
attack involved. Fix: redact the probe's own argument values out of the response
before embedding.

```
"Document security-review-2026.md: No document filed under 'security-review-2026.md'."
  → "Document <ARG:path>: No document filed under '<ARG:path>'."
```

Deterministic, cheap, and it makes family comparison nearly as sensitive as exact
comparison for echo-dominated tools. Implement it with the family baseline, not
after.

---

## 1. Existing files to modify

| File | Change | Risk |
|---|---|---|
| `attacker/attacks.py`, `attacker/sink.py` | F1: log `inject`, `tamper`, `probe-skip` events | Low — recording only |
| `driftsentry/probes.py` | Keep `ProbeGenerator` intact as the `fixed` control; extract the schema walker so the keyed generator reuses it rather than duplicating | Medium — shared with the control condition |
| `driftsentry/fingerprint.py` | `normalize_result(result, args=None)` for redaction; family dataclasses | Medium |
| `driftsentry/baseline.py` | `capture_baseline(..., probe_mode=…)`, `reprobe(..., probe_mode=…, cycle=…, paired=…)`; family capture/verify path | **High** — 8 call sites incl. 5 demo scripts |
| `driftsentry/scorer.py` | `strategy="max"\|"corroboration"`; comparability weighting; consistency + passive + temporal signals | **High** — the working detector |
| `driftsentry/store.py` | Persist families, `schema_version`, `probe_mode` in Chroma metadata | Medium |
| `driftsentry/calibration.py` | Also calibrate corroboration and temporal thresholds | Medium |
| `driftsentry/verify.py` | Thread `probe_mode` / `strategy` / cycle through | Low |
| `driftsentry/daemon.py` | Pass through; own the verification-cycle counter; load/save temporal state | Medium |
| `driftsentry/proxy.py` | Emit `PassiveObservation` (non-blocking, off by default) | Medium — live data path |
| `driftsentry/rules.py` | Expose an invariant-comparison helper reused by differential probing | Low |
| `driftsentry/__main__.py` | `--probe-mode`, `--scoring`, `--paired`, `--temporal` flags | Low |
| `pyproject.toml` | Declare `psutil`, `fastapi`, `pywebview` (currently undeclared); add `[dev]`/`[eval]` extras; regenerate `requirements.lock` | Low — fixes an existing defect |

**Backward-compatibility rule.** Every new parameter is keyword-only with a
default reproducing today's behaviour. The five `examples/` scripts and
`scripts/setup_demo.py` must keep working untouched — they are the existing
definition-of-done checks and the control condition for Experiment 1.

## 2. New modules

| Module | Purpose | ~LOC |
|---|---|---|
| `driftsentry/keys.py` | Per-server secret key: created at enrolment, stored in `.driftsentry_data/keys.json`, never placed in an MCP payload or server-visible log | 60 |
| `driftsentry/probe_generator.py` | `KeyedProbeGenerator` — HMAC-SHA256 → seeded RNG → existing schema walker | 180 |
| `driftsentry/probe_templates.py` | Realistic safe grammars (filename, phrase, identifier, email, URL, person, city, numeric id) | 220 |
| `driftsentry/redact.py` | Argument redaction before embedding (F4) | 60 |
| `driftsentry/families.py` | `TemplateFamilyBaseline`, comparability estimation, family scoring | 240 |
| `driftsentry/metamorphic.py` | Semantics-preserving transforms + `probe_consistency_score` | 200 |
| `driftsentry/passive.py` | `PassiveObservation`, passive invariant evaluation | 200 |
| `driftsentry/corroboration.py` | Evidence families A–E, deterministic corroboration rule | 160 |
| `driftsentry/temporal.py` | CUSUM + EWMA per (server, tool), persisted | 150 |
| `eval/record.py` | Result-row dataclass, CSV/JSONL writers, config hashing | 150 |
| `eval/ground_truth.py` | Parse and interpret the attacker events log | 120 |
| `eval/scenario_control.py` | Drive the attacker CLI as a subprocess | 130 |
| `eval/harness.py` | One episode: baseline → arm → cycles → collect → reset | 300 |
| `eval/splits.py` | Development / calibration / blind-test seed and lineage partitions | 90 |
| `eval/experiments.py` | Experiments 1–6 | 350 |
| `eval/probe_recognisability.py` | Logistic regression + ROC-AUC (eval only) | 180 |
| `eval/stats.py` | Recall, FAR, precision, F1, p50/p95, CPU/memory | 150 |
| `eval/__main__.py` | `python -m eval run --experiment 2 --seeds 1..20` | 120 |
| `tests/` | First unit-test suite (§12) | 600 |

## 3. Current control flow

```
ONBOARDING
  client config ──► clientconfig.rewrite ──► client launches `driftsentry run`

LIVE PATH (passive)
  client ⇄ proxy._pump ⇄ real server
              └──► ProxyLogger ──► logs/<server>.jsonl        [logged, never scored]
              └──◄ PolicyStore (only if enforce=True)

BASELINE (approval time, out of band)
  capture_baseline
    ├─ list_tools ──► tools_definition_hash
    ├─ classify_tool_safety ──► probe / observe-only
    ├─ ProbeGenerator.generate(seed)  ──► 3 fixed probes/tool
    ├─ for each probe × 8 samples:
    │     _call_once ──► SandboxMonitor(start/stop) ──► Observation
    │     normalize_result ──► embedder.embed
    └─ summarize_probe ──► leave_one_out_distances ──► band
                       ──► BaselineStore.save (JSON + Chroma)

VERIFY (every 20 s)
  daemon._check ──► verify_server ──► reprobe
      └─ replay SAME probe args ──► distance vs stored centroid
                                ──► ratio = distance / band
                                ──► ProbeCheck[]
  ──► score_report
        signals: behavioural_drift | structural | error | rules | definition_hash
        combine: max()  over signals, then max() over probes
  ──► verdict ──► build_alerts ──► AlertStore + PolicyStore
```

## 4. Revised control flow

Additions marked `»`. Nothing existing is removed.

```
ONBOARDING
  » keys.get_or_create(server)  ──► local secret key (never sent)

LIVE PATH
  client ⇄ proxy._pump ⇄ real server
              ├──► ProxyLogger ──► logs/<server>.jsonl
              » └──► PassiveMonitor ──► PassiveObservation
                        └─ invariant check only (hosts/files/flags/shape/error)
                        └─ passive_evidence[tool]           [watch-only by default]

BASELINE
  capture_baseline(probe_mode)
    ├─ fixed  : ProbeGenerator (unchanged — control condition)
    » └─ keyed : KeyedProbeGenerator(key, server, tool, template, cycle=0, field)
    »              └─ probe_templates ──► realistic values
    »  M instances per template family (not 1 exact arg)
    ├─ for each instance × N samples: call, monitor, normalize
    »     └─ redact.apply(args) BEFORE embed
    » └─ families.summarize ──► family centroid, family band,
    »                           invariant sets, comparability

VERIFY (cycle c)
  reprobe(probe_mode, cycle=c, paired=…)
    ├─ fixed : replay stored args                      (unchanged)
    » └─ keyed: generate NEW instance from same family at cycle c
    »            └─ compare vs FAMILY distribution + invariants
    » └─ paired: also fire T(x) ──► metamorphic.consistency(x, T(x))
    »                              └─ probe_consistency_score
  ──► score_report(strategy)
        signals: behavioural_drift | structural | error | rules | definition_hash
        »        + probe_consistency  + passive_inconsistency  + temporal
        » combine:  max()                      (unchanged default)
        »        OR corroboration(A,B,C,D,E)   (opt-in, calibrated)
  » ──► temporal.update(server, tool, score) ──► CUSUM/EWMA ──► temporal signal
  ──► verdict ──► alerts ──► policy
```

## 5. Data-model changes

```
ServerBaseline
  + schema_version: int = 1
  + probe_mode: str = "fixed"            # fixed | keyed
  + key_id: str = ""                     # identifies the key, never the key
  + families: list[TemplateFamilyBaseline] = []

TemplateFamilyBaseline                    (new)
    family_id, tool, template_id
    field_map: dict[str, str]             # field_path -> template kind
    instances: list[ProbeBaseline]        # M baselined values
    family_centroid: list[float]
    family_band: float
    comparability: float                  # 0–1, MEASURED (see below)
    shape_classes: set[str]               # union incl. legitimate error shapes
    invariant_hosts / invariant_files / invariant_flags: set[str]
    error_states: set[str]
    length_mean, length_std
    generation: dict                      # key_id, generator version, cycle

ProbeBaseline
  + family_id: str | None = None
  + redacted_excerpt: str = ""

ProbeCheck
  + family_id, comparability, cycle
  + consistency: float | None             # differential probing
  + paired_divergence: list[str]          # which invariants disagreed

PassiveObservation                        (new)
    tool_id, timestamp, structural_signature,
    observed_hosts, observed_files, process_evidence,
    security_flags, error_state, response_length, embedding (optional)

TemporalState                             (new, persisted)
    server, tool, cusum_s, ewma, n, last_updated, baseline_id

DriftReport
  + strategy: str = "max"
  + evidence_families: dict[str, float]   # A–E
  + temporal: dict

Calibration
  + corroboration: dict                   # per-family thresholds + rule config
  + temporal: dict                        # CUSUM k, h; EWMA alpha
```

**`comparability` is measured, not assumed.** At baseline, generate M instances
from a family and compute mean pairwise post-redaction distance. Low spread → the
tool's output is largely input-independent → the embedding signal is trustworthy
for that family. High spread → down-weight the embedding signal and lean on
structure, invariants, rules and side effects. This turns the spec's "where
semantic comparison is weak, give more importance to X" into a stored, reportable
number rather than a judgement call.

## 6. Compatibility and migration

The stored `acme` baseline has no families and is `probe_mode=fixed` — and it is
**Experiment 1's control condition**, so it must keep working byte-identically.

- `ServerBaseline.from_dict` gains defaults for every new field. Existing JSON
  loads unchanged and is treated as `schema_version=1, probe_mode="fixed"`.
- `--probe-mode keyed` against a v1 baseline fails with a clear message telling
  the user to re-baseline. It never silently degrades or half-works.
- Chroma: keep the existing per-backend collection naming; add `probe_mode` and
  `family_id` to vector metadata and filter on query, so fixed and keyed vectors
  can never be compared against each other.
- Temporal state is keyed by `baseline_id`; re-baselining resets it rather than
  carrying a stale accumulator across a behavioural change.
- No destructive migration. Nothing rewrites an existing baseline in place.

## 7. Keyed-probe design

```
seed_material = HMAC-SHA256(
    key   = server_secret_key,                    # 32 bytes, local only
    msg   = f"{generator_version}|{server_id}|{tool_id}|"
            f"{template_id}|{cycle}|{field_path}"
)
rng = random.Random(int.from_bytes(seed_material[:8], "big"))
value = probe_templates[kind].generate(rng, schema_constraints)
```

Properties this gives:

| Requirement | How it is met |
|---|---|
| Not enumerable from source | Source reveals the grammar, not the key. Future values need the key |
| Reproducible for experiments | Key is an experiment input; same key + cycle → same values |
| New values each cycle | `cycle` is in the HMAC message |
| Key never reaches the server | Key is used only to seed generation; only *outputs* are transmitted. Excluded from proxy logs, alerts and baseline JSON (only `key_id`, a hash prefix, is stored) |
| Schema-valid | Generation walks the schema; the existing `_value()` constraint logic (min/max, minLength, enum, const) is reused |
| Fail safely | Unsupported schema constructs → the tool falls back to observe-only rather than firing a malformed probe |

Supported initially: string, integer, number, boolean, enum, arrays of scalars,
one level of nested object. `$ref`, `oneOf` with complex branches,
`patternProperties`, and recursive schemas are explicitly out of scope and
degrade to observe-only.

**Honest boundary:** keyed generation stops the attacker *predicting* future
probe values. It does not stop it *recognising* a value it has already seen, so
per-cycle rotation is what carries the benefit, and reuse must be avoided (F2).

## 8. Passive-monitoring integration

The proxy already parses `tools/call` requests and correlates responses via
`ProxyLogger._pending`. Passive monitoring hooks the same point.

```
_pump(c2s) ──► ProxyLogger.record ──► [existing JSONL]
                   └─» PassiveMonitor.on_request(tool, args)
_pump(s2c) ──► ProxyLogger.record
                   └─» PassiveMonitor.on_response(id, result, observation)
                         └─ build PassiveObservation
                         └─ evaluate INVARIANTS ONLY vs the tool's baseline sets
```

What it checks (never semantic distance against canary responses):

| Check | Source of truth |
|---|---|
| New outbound destination | host ∉ family `invariant_hosts` |
| Credential / sensitive-file access | `rules.secret_paths()` on new files |
| New unexpected file access | file ∉ family `invariant_files` |
| Agent-directed instruction text | `rules.content_flags()` ∉ baseline flags |
| Previously unseen dangerous rule | any new high-severity rule hit |
| Response-shape class change | shape ∉ family `shape_classes` |
| Error-state transition | error state ∉ baseline `error_states` |

Design constraints, in order of importance:

1. **Never blocks or delays a user call.** Observation is queued and evaluated
   off the hot path; the pump is untouched apart from one non-blocking handoff.
2. **Watch-only by default.** Passive evidence contributes to evidence family C/E
   but cannot alert on its own until calibrated (see §13 — this is the highest
   false-positive risk in the whole upgrade).
3. **Kept internally distinct** from active-probe scoring, with its own record
   type and its own calibration.
4. **Active-vs-passive inconsistency is itself a signal** (family E): the tool
   behaves cleanly for canaries but shows new hosts/files/flags on real traffic.
   That is the exact signature of a probe-aware attacker and is the strongest
   argument for building this channel.

Sandbox attribution caveat: the proxy does not own the server subprocess in the
same way the probe engine does, so process-level evidence on live traffic is
weaker. Where the pid is known it is used; otherwise passive evidence is limited
to response-derived signals, and that limitation is recorded per observation.

## 9. Differential (metamorphic) probe design

For a subset of safe families, fire `x` and `T(x)` in the same cycle, where `T`
is semantics-preserving, then compare **security-relevant invariants only** —
never semantic content, which may legitimately differ.

Transforms, strongest first:

| ID | Transform | Why the relation holds |
|---|---|---|
| MR1 | Reorder object fields | JSON key order is semantically void — any behavioural difference is pure evidence |
| MR2 | Reorder tokens in a search phrase | "quarterly security review" ≡ "security review quarterly" for a search tool |
| MR3 | Case variation on free-text fields | Search/lookup tools normalise case |
| MR4 | Path alias (`docs/x.md` ≡ `./docs/x.md`) | Same sandbox-safe target |
| MR5 | Whitespace padding | Nearly all tools `.strip()` |

Compared invariants: shape class, security-flag set, observed host set, observed
file set, error state.

```
probe_consistency_score = weighted disagreement over those five,
                          0.0 = identical behaviour, 1.0 = fully divergent
```

**Why this catches an evasive server.** The attacker's recogniser is a lookup
table plus suffix rules. A token reorder or case change can fall on the other
side of that boundary, so `x` is recognised (server behaves) while `T(x)` is not
(server attacks). Divergent invariants on semantically equivalent inputs is
evidence of input-conditional behaviour — which no honest tool has a reason to
exhibit at the invariant level.

**Honest boundary, to state in the write-up:** against a *perfect* recogniser
that catches both members, consistency stays 0 and this yields nothing. It is
strong against a partial or lookup-based recogniser, which is what a realistic
attacker has. Experiment 5 measures exactly where that boundary sits.

Cost: 2× calls for paired families. Limit to two variants per relevant family.

## 10. Corroboration and temporal scoring

### Corroboration

Evidence families, chosen so members within a family are correlated and families
are largely independent:

| Family | Members |
|---|---|
| A — Semantic/content | embedding drift, content security rules |
| B — Structure/error | structural change, error-rate change |
| C — Side effects | new egress host, secret-file read, new file/process |
| D — Surface integrity | definition hash / schema change |
| E — Adaptive evasion | probe-consistency divergence, active-vs-passive inconsistency |

Each family's score is the max of its members (correlated within family → max,
never sum). The rule, with thresholds as *calibrated configuration*, not
constants:

```
alert if   any family >= T_critical            (default 1.0)
   or      count(families >= T_high) >= 2      (T_high  ~0.65, calibrated)
   or      count(families >= T_med)  >= 3      (T_med   ~0.45, calibrated)
```

Family D alone is always critical (a changed definition needs no corroboration).
`max_only` remains the default; `max_plus_corroboration` is opt-in so the two can
be compared in Experiment 6.

### Temporal

CUSUM as the primary detector — it is designed for exactly the "low and slow"
case where each observation is individually unremarkable:

```
S_n = max(0, S_{n-1} + (score_n - k))      alert if S_n > h
```

`k` (slack) calibrated as the benign mean plus a fraction of benign σ; `h`
calibrated for a target in-control average run length, which converts directly
into a per-cycle false-alarm rate. EWMA is kept alongside as a smoothed trend for
the dashboard and for reporting, not as a second alerting path.

Persisted per `(server, tool, baseline_id)` in `.driftsentry_data/temporal.json`,
because the daemon's 120-point history is in-memory only and is lost on restart.
Reset on re-baseline and on explicit trust.

## 11. Evaluation-harness structure

```
eval/
  __main__.py            python -m eval run --experiment 2 --seeds 1..20
  splits.py              dev / calibration / blind-test seed + lineage partitions
  scenario_control.py    subprocess driver for the attacker CLI
  ground_truth.py        events-log parsing -> {fired, not_fired, n/a}
  harness.py             one episode (below)
  experiments.py         Experiments 1-6
  probe_recognisability.py   logistic regression + ROC-AUC
  stats.py               recall, FAR, precision, F1, p50/p95, CPU, memory
  record.py              ExperimentRow + CSV/JSONL writers
```

One episode:

```
1  scenario_control.reset()                 # attacker -> benign, clear sink
2  ground_truth.clear()                     # truncate events.log
3  capture_baseline(probe_mode, seed, key)  # fresh baseline, isolated DRIFTSENTRY_HOME
4  scenario_control.arm(family, level, seed)
5  for cycle in 1..N:
6      t0 = perf_counter()
7      report = verify_server(..., cycle=cycle, strategy=…)
8      row = record.from_report(report, cycle, duration=perf_counter()-t0)
9      if report.verdict == "alert": break
10 fired = ground_truth.fired(family)       # independent of the detector
11 outcome = classify(fired, detected)      # detected / missed / never_triggered
12 scenario_control.reset()
13 writer.append(row)
```

`ExperimentRow` fields: `experiment_id`, `timestamp`, `seed`, `key_id`,
`server_id`, `tool_id`, `attack_family`, `attack_level`, `probe_mode`,
`scoring_mode`, `attack_fired`, `detected`, `outcome`, `final_score`,
`winning_signal`, `embedding_score`, `structure_score`, `error_score`,
`rule_score`, `sideeffect_score`, `consistency_score`, `passive_score`,
`temporal_score`, `definition_changed`, `evidence_families` (A–E),
`probe_recognised`, `verification_cycle`, `calls_to_detection`,
`time_to_detection`, `execution_duration`, `cpu_pct`, `rss_mb`,
`detector_version`, `config_hash`.

`config_hash` is a SHA-256 over the active thresholds and weights, so any row can
be traced to the exact detector configuration that produced it — which is what
makes "no threshold tuning after seeing blind-test data" auditable rather than
merely promised.

**Isolation:** every episode runs with its own `DRIFTSENTRY_HOME` (the env var
already exists in `paths.py`), so episodes cannot contaminate each other and the
developer's real `.driftsentry_data/` is never touched.

## 12. Tests required

Regression locks come first, before any refactor, because "preserve the working
detector" is the binding constraint.

| Test | Protects |
|---|---|
| `test_scorer_golden.py` | Freezes current `score_report()` output on fixed synthetic reports (benign / drifted / rule-firing / definition-changed). Any change must be deliberate |
| `test_probes_fixed_golden.py` | Freezes fixed-probe values for a known schema+seed so the control condition cannot drift |
| `test_variance_math.py` | `leave_one_out_distances`, `centroid_of`, `MIN_BAND`, cosine clamping |
| `test_calibration_math.py` | Quantile, margin, floor, `weak` on all four trigger conditions |
| `test_probe_generator.py` | Determinism given key+cycle; different values across cycles; no key material recoverable from output |
| `test_templates_schema_valid.py` | Every generated value validates against its declaring schema across all supported types; unsupported schemas degrade to observe-only |
| `test_templates_safety.py` | Only `.invalid` domains, loopback URLs, sandbox-relative paths. No external egress, no absolute paths outside the sandbox |
| `test_redact.py` | Redaction is stable, idempotent, and does not corrupt unrelated text |
| `test_families.py` | Comparability estimation; family band widens correctly; error shapes admitted |
| `test_metamorphic.py` | Each transform preserves semantics; consistency scoring on synthetic divergences |
| `test_passive.py` | Invariant evaluation; never blocks; watch-only default enforced |
| `test_corroboration.py` | Rule table fires exactly as specified; `max()` path provably unchanged |
| `test_temporal.py` | CUSUM accumulation and reset; EWMA; persistence round-trip |
| `test_ground_truth.py` | fired / not-fired / not-applicable per family — including the three fixed in F1 |
| `test_migration.py` | A v1 baseline loads unchanged; keyed mode refuses it with a clear error |

## 13. Risks of increasing false positives

This is the central risk of the whole upgrade: **five of the six additions push
the false-alarm rate up.** Each needs its own mitigation and its own calibration.

| # | Source | Mechanism | Mitigation |
|---|---|---|---|
| R1 | Family bands (F3) | Wider bands cut sensitivity — but also make benign updates *less* likely to alarm. Net direction on FAR is genuinely unknown | Measure both recall and FAR in Experiment 2; report as a trade-off curve |
| R2 | **Unseen legitimate code paths** | A fresh keyed value can hit an error path never seen at baseline ("No document filed under X") → new shape → `structural_change` fires on a benign server. **Most likely new FP source** | Baseline enough instances (M ≥ 8) to cover error paths; admit known error shapes into `shape_classes`; treat error-shape-with-known-error-state as benign |
| R3 | Passive monitoring | Real user traffic is far more varied than canaries. A user passing a genuinely new argument legitimately causes new file access | Watch-only by default; separate calibration; only *security-relevant* novelty (secret paths, new hosts, injection text) counts, not any difference |
| R4 | Differential probing | Naturally nondeterministic tools (`get_weather`) differ between paired calls for innocent reasons; input-dependent tools legitimately touch different files | Compare invariant *classes*, never content; require divergence to be security-relevant; exclude families whose baseline shows unstable invariants |
| R5 | Corroboration | Lowers the bar by design (two families at 0.65). Mechanically raises FAR | Calibrate on benign + benign-update only; report the FAR cost alongside the recall gain; keep `max_only` as default |
| R6 | Temporal CUSUM | Accumulates without bound — a tool sitting slightly high forever eventually alerts | Calibrate `h` for a target in-control run length; bound or decay `S`; reset on re-baseline |

Cross-cutting: **the calibration partition must contain benign updates**, not just
stable benign servers, or every threshold above will be fitted to a world that
does not exist. This is already implemented (`--also-exec`) and must be used.

## 14. Estimated complexity

| Priority | Change | Size | Risk to existing behaviour | Notes |
|---|---|---|---|---|
| — | F1 attacker ground truth | S | None | Blocking prerequisite |
| — | Regression locks + `pyproject` fix | S | None | Do first |
| P0 | Evaluation harness | **L** | None (additive) | Biggest single piece; nothing measurable without it |
| P1 | Keyed probe generator + keys | M | Low | Self-contained; well-tested primitive |
| P2 | Probe-family baseline + redaction | **L** | **High** | Touches baseline, fingerprint, store, scorer. The hard part of the upgrade |
| P3 | Realistic templates | M | Low | Mostly data + grammars |
| P4 | Passive monitoring | M | **Medium** | Touches the live data path — must not block |
| P5 | Differential paired probes | M | Low | Additive signal; 2× call cost on paired families |
| P6 | Corroboration scoring | S–M | Low | Opt-in; default path untouched |
| P7 | Temporal CUSUM/EWMA | S | Low | Needs new persistence |
| P8 | Experiments 1–6 + statistics | **L** | None | Time-dominated by run duration, not code |

Sequencing note: **run Experiment 1 immediately after P0**, before any detector
change. That captures the "before" numbers on genuinely untouched code, which is
impossible to reconstruct later and removes any suspicion of contamination.

Suggested order:

```
F1 → regression locks → P0 → Experiment 1 → P1 → P3 → P2 → Experiments 2,3
   → P4 → Experiment 4 → P5 → Experiment 5 → P6 → P7 → Experiment 6 → blind test
```

P3 is pulled ahead of P2 because the family baseline needs realistic templates to
baseline *from*; building families against placeholder values would mean
rebuilding them afterwards.
