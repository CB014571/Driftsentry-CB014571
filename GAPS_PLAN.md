# GAPS_PLAN.md: build plan for the new research gaps (DriftSentry FYP)

> **For Claude Code.** This file is a task list. Work through it **one task at a time, in order**.
> Before each task, read every file it lists. If the real code differs from this plan, **follow the code**, make the smallest change that meets the goal, and tell the user about the difference.
> **Stop at every CHECKPOINT** and report to the user before going on.
> Code blocks in this file are **sketches**, not tested code. Match the real names in the repo.

---

## 1. What this project is

- **DriftSentry** detects "rug-pull" attacks on MCP servers. A server is approved, and later its tools start behaving badly while their definitions stay the same.
- DriftSentry records a **baseline** (probe calls and responses) at approval. Later it **re-probes** and scores drift.
- **The attacker** is a deliberately malicious MCP server used only for the experiments.
- This is a final-year research project. **Results must be honest and reproducible.** A failed hypothesis is a valid result. Never tune anything to make a hypothesis pass.

## 2. The research gaps this plan solves

| Gap | Question | What must be built |
|---|---|---|
| Gap 2 (main) | **RQ3:** can a malicious server tell probe calls from real agent calls? Using which signals? | Record what the server sees; collect real agent sessions and probe sessions; train classifiers per signal family; build an attacker that uses the classifier |
| Gap 2 (fix) | **RQ4:** do countermeasures stop that? At what cost? | Make probes look like the real host: client name, environment, argument shape, timing, secret probe subsets |
| Gap 3 | **RQ1:** how many false alarms happen on real, harmless server upgrades? Do per-tool thresholds help? | Real-server upgrade runner; per-tool calibration, frozen before testing |
| Gap 4 | **RQ2:** is active probing better than passive monitoring and hash pinning? | Replay real traffic in each episode; score three detectors on the same episodes; statistics |

## 3. Hypotheses (pass/fail rules; do not change them)

- **H1 (RQ1):** per-tool thresholds cut false alarms on real benign upgrades by **at least half** compared with the single global threshold, without lowering detection on the attack matrix.
- **H2 (RQ2):** full DriftSentry detects more attacks than hash-only (**McNemar p < 0.05**). It also catches attacks on tools the agent never calls, which passive monitoring cannot.
- **H3 (RQ3):** at least one signal family **other than arguments** separates probes from real calls with **AUC ≥ 0.9**, and an attacker using it cuts DriftSentry's detection by **≥ 50 percentage points**.
- **H4 (RQ4):** with countermeasures, the best classifier falls to **AUC ≤ 0.6**, detection comes back to **within 10 points** of the no-evasion level, and false alarms rise by **≤ 2 points**.

## 4. Repository map (checked 31 Oct 2026)

```
F:\fyp project\
├─ Driftsentry\                      # the detector (own venv: Driftsentry\.venv)
│  ├─ driftsentry\                   # package
│  │  ├─ proxy.py                    # ProxyLogger, run_stdio_proxy (live proxy, optional passive)
│  │  ├─ baseline.py                 # capture_baseline, reprobe, _reprobe_keyed (ClientSession(read, write), no client_info)
│  │  ├─ verify.py                   # verify_server, _launch_of (env only from an explicit override)
│  │  ├─ scorer.py                   # Signal, ProbeScore, ToolScore(tool, score, verdict, triggered_by), DriftReport(definition_changed, tools, mode)
│  │  ├─ calibration.py              # Calibration, calibrate_from_ratios, _quantile, active_threshold (ONE global threshold)
│  │  ├─ passive.py                  # PassiveMonitor(server, baseline, *, enabled, alerting), on_request, on_response(rid, result, *, hosts, files, processes), summary(), inconsistency()
│  │  ├─ camouflage.py               # _rng(key, *parts), next_interval, permute, probe_count, SessionFingerprint.residual_tells()
│  │  ├─ probe_generator.py          # KeyedProbeGenerator
│  │  ├─ keys.py                     # derive_experiment_key(seed, label)
│  │  ├─ daemon.py                   # background verification (calls verify_server)
│  │  └─ __main__.py                 # CLI: run --server --cwd --forward-env --passive --enforce --exec
│  ├─ eval\                          # experiment harness
│  │  ├─ harness.py                  # EpisodeConfig, Episode.run, run_episode, _launch()
│  │  ├─ experiments.py              # SweepSpec, _configs, run_sweep, summarise, experiment_1, experiment_2, compare
│  │  ├─ record.py                   # ExperimentRow (already has passive_score, definition_changed, probe_recognised, probe_skip_count), ResultWriter
│  │  ├─ ground_truth.py             # read(), classify() -> detected | missed | never_triggered | benign_ok | false_alarm
│  │  ├─ scenario_control.py         # AttackerControl.env(), launch_command()
│  │  └─ __main__.py                 # python -m eval run --experiment {1,2} --seeds --cycles --threshold --quick
│  ├─ tests\                         # pytest suite
│  ├─ eval_results\
│  ├─ run_exp2_when_ready.py         # THRESHOLD = 10.8086
│  └─ requirements.txt / requirements-optional.txt
└─ mcp rug pull attack server\       # the attacker (own venv: "mcp rug pull attack server\.venv")
   └─ attacker\
      ├─ server.py                   # FastMCP("acme-business-tools"); tools lookup_customer, read_document, search_orders, get_weather, send_invoice; all call _process(text, arguments)
      ├─ attacks.py                  # looks_like_a_probe(arguments) (arguments only), should_fire(scenario, call_index, arguments), apply_attack
      ├─ scenario.py                 # Scenario dataclass, LEVELS (L1-L5), is_probe_aware(), validate()
      ├─ sink.py                     # SINK_DIR = default_home()/"sink", log_event, ensure_sink
      └─ selftest.py
```

**Commands (Windows, Git Bash).** Run them from the folder named:
- DriftSentry tests: `cd Driftsentry && ./.venv/Scripts/python.exe -m pytest tests/ -q`
- Harness self-test: `cd Driftsentry && ./.venv/Scripts/python.exe -m eval selftest`
- Attacker self-test: `cd "mcp rug pull attack server" && ./.venv/Scripts/python.exe -m attacker selftest`
- Quick pipeline check: `cd Driftsentry && ./.venv/Scripts/python.exe -m eval run --experiment 1 --quick --threshold 2.0`

## 5. Facts about the current code that this plan depends on

1. **Probe sessions announce themselves.** `baseline.py` opens `ClientSession(read, write)` with no `client_info`, so every probe session uses the MCP SDK's default client name. Real hosts send their own name.
2. **The environment differs between probe and agent sessions, and in the harness this difference is artificial.**
   - The installed SDK (`mcp/client/stdio/__init__.py`, line ~127) uses `{**get_default_environment(), **server.env}` when env is given, and `get_default_environment()` when it is not.
   - The proxy (`__main__ run --forward-env`) therefore gives the server the SDK default set plus the forwarded keys. The daemon gives it the default set.
   - But `eval/harness.py::_launch()` and `scenario_control.env()` pass the **full** `os.environ` to the attacker.
   - So in the harness, probe sessions have many more environment variables than proxy sessions. A classifier would learn that, and the RQ3 result would be fake.
   - **Experiments 1 and 2 are not affected,** because the L1–L5 attacker only checks arguments.
3. **Passive findings are only logged to stderr** (`run_stdio_proxy`, at close). Nothing machine-readable is saved.
4. **Calibration is one global number** (`Calibration.threshold_ratio`), set by `calibrate_from_ratios` as a quantile of benign ratios × margin.
5. **Pieces that already exist; reuse them, don't rebuild them:**
   - `passive.inconsistency()` (active/passive disagreement; currently not called anywhere);
   - `score_report(mode="hash-only")`;
   - `ExperimentRow.passive_score` and `definition_changed`;
   - `camouflage._rng` (keyed randomness);
   - `keys.derive_experiment_key`.

## 6. Ground rules (always follow)

1. **The attacker must never import DriftSentry.** It may only use what a real malicious server could see.
2. **Never store environment variable values** in logs, profiles or datasets. They can contain API keys. Names and counts only.
3. **Labels (probe or genuine) come from harness time windows,** never from anything the attacker records or infers.
4. **Never use `pid` or timestamps as classifier features.** They are for labelling and grouping only.
5. **Split by session** (GroupKFold on session/pid), never by single call.
6. **Calibration and thresholds are frozen** (SHA-256 and timestamp) **before** any test data is scored. Never re-fit after seeing test results.
7. **Don't change the default behaviour of Experiments 1 and 2.** New behaviour goes behind new options whose defaults keep the old behaviour.
8. **Keep all existing tests passing.** Add tests for every new module in the style of `tests/`.
9. **Commit after each task** with the message `T<n>: <what>`. Work on the branch `gaps-v2`.
10. **Don't start any run longer than about 10 minutes without asking the user.** Build it, run a `--quick` version, then give the user the exact full command.
11. **Tasks marked [HUMAN] need the user.** Prepare everything, then ask.

---

## PHASE 0: Setup

### T0. Branch, dependencies and a clean start
- `git status`. If there are uncommitted changes, **ask the user** before committing them. Then `git checkout -b gaps-v2`.
- Add `scikit-learn`, `statsmodels`, `scipy` and `matplotlib` to `Driftsentry/requirements-optional.txt`, and install them into `Driftsentry/.venv`.
- Run all four commands from section 4. Record the results.
- **Done when:** the branch exists, the packages import, and all existing tests pass.

---

## PHASE 1: Record what the server sees (Gap 2 foundation)

### T1. Proxy: session ID, client info, passive summary
**Read:** `driftsentry/proxy.py`.
- In `ProxyLogger.__init__`: `self.session_id = uuid.uuid4().hex[:12]`.
- In `_emit`: add `"session": self.session_id` to every record.
- In `record()`: when `method == "initialize"` (client to server), store `params.get("clientInfo")` as `rec["client"]` (name and version only).
- In `run_stdio_proxy`, at close: if a passive monitor exists, `_emit` one record `{"kind": "passive_summary", "summary": monitor.summary(), "findings": [f.to_dict() for f in monitor.findings()]}`.
- **Tests:** `tests/test_proxy_logging.py`. Feed `ProxyLogger.record` fake `initialize` and `tools/call` messages, then assert the session ID is constant, `client` is logged, and no environment values are logged.
- **Done when:** the tests pass, and `logs/<server>.jsonl` from a real session shows `session`, `client` and a final `passive_summary`.
- **[HUMAN]** Ask the user to connect Claude Desktop through the proxy once. Save the real `client` name and version to `Driftsentry/eval/host_profile.json` as `{"name": ..., "version": ...}`. Later tasks use it.

### T2. Attacker: record per-call features
**Read:** `attacker/server.py`, `attacks.py`, `sink.py`.
- **New `attacker/features.py`** (standard library only; T14 imports it from the eval side):
  - `observe(mcp, tool, arguments) -> dict` builds one row per call and appends it to `SINK_DIR/"features.jsonl"`.
  - **Raw fields:**
    - `t`, `pid` (labelling only);
    - `tool`, `args`;
    - `client_name`, `client_version`, from `mcp.get_context().session.client_params.clientInfo`, inside try/except;
    - `env_count = len(os.environ)`, `has_home`, `cwd`;
    - `parent_name` and `parent_argc`: the parent process's executable name and argument count. Use `psutil` if it's installed, else leave them blank. Don't add psutil as a hard dependency.
    - `calls_before`, `distinct_tools_before`, `proc_age_s`, `gap_s` (None for the first call).
  - `FAMILIES`: a dict mapping family name to a function `row -> dict[str, float | 1]`. The families are:
    - `argument`: length, character entropy, digit ratio, word count, has_space;
    - `client`: one-hot of `client_name` and `client_version`;
    - `environment`: env_count, has_home, one-hot cwd basename, one-hot parent_name, parent_argc;
    - `session`: calls_before, distinct_tools_before, proc_age_s;
    - `timing`: gap_s (−1 if None), is_first;
    - `all`: the union of all of them.
  - `p_probe(row, model: dict) -> float`: logistic regression with the standard library (vector in `model["feature_names"]` order, missing = 0; standardise with `mean`/`scale`; dot `coef`; add `intercept`; sigmoid).
- **`server.py`:** change `_process(text, arguments)` to `_process(text, arguments, tool)`. Call `features.observe(...)` first and pass the row on: `apply_attack(..., features=row)` and then `should_fire(..., features=row)`. Each tool passes its own name.
- **`attacks.py`:** add `features: dict | None = None` to `apply_attack` and `should_fire`. **No behaviour change yet.**
- **Tests:** in the attacker selftest or a new test, assert one row per call, all keys present, no environment values, and `p_probe` matches a hand-computed value.
- **Done when:** the attacker selftest passes and `features.jsonl` fills with one row per call.

### T3. A genuine agent
**[HUMAN] prerequisite:** Ollama installed with 3 tool-calling models pulled (for example `llama3.1:8b`, `qwen2.5:7b`, `mistral-nemo`). Ask the user which ones.
- **New `Driftsentry/eval/agent.py`:**
  - `async run_task(task, model, launch, *, client_info, system_prompt, max_steps=6) -> dict` (the transcript plus timings).
  - Open `ClientSession(read, write, client_info=types.Implementation(name=..., version=...))` using `host_profile.json`.
  - List tools and convert them to Ollama's `tools` format.
  - Loop on `POST http://localhost:11434/api/chat` (`stream: false`) with httpx. Run each `tool_calls` entry through `session.call_tool`; append tool results as `{"role": "tool", ...}`.
- **New `Driftsentry/eval/agent_tasks.json`:** 40 realistic tasks that use the attacker's 5 tools and their data (customers, documents, orders, weather, invoices). Some single-tool, some multi-step. Add 2 system-prompt styles (short, detailed).
- The agent **always connects through the proxy** (see T4).
- **Done when:** one task runs end to end and the proxy log and `features.jsonl` both show the calls.
- **[HUMAN]** Ask the user to also record about 10 sessions by hand in Claude Desktop through the proxy (the realism check). Save their time windows the same way as T5.

### T4. One place that builds launches, with environment parity
**Read:** `eval/harness.py::_launch`, `eval/scenario_control.py`, `driftsentry/verify.py::_launch_of`, `driftsentry/__main__.py` (the `run` command).
- **New `Driftsentry/eval/launch.py`** with two functions:
  - `agent_launch(atk_project, atk_home, ds_home, server_id) -> dict`: starts `Driftsentry/.venv python -m driftsentry run --server <id> --passive --forward-env ATTACKER_HOME --exec <attacker python> -m attacker serve`. Its env is `{"ATTACKER_HOME": atk_home, "DRIFTSENTRY_HOME": ds_home}` only (the SDK adds its default set). Its cwd is fixed.
  - `probe_launch(atk_project, atk_home) -> dict`: launches the attacker directly, as the daemon does. Its env is `{"ATTACKER_HOME": atk_home}` only, with **the same cwd** the proxy gives the attacker.
- **In `EpisodeConfig`,** add `launch_parity: bool = False`. When True, `_launch()` uses `probe_launch()`. When False, the old behaviour stays (Experiments 1 and 2 unchanged).
- **Test:** `tests/test_launch_parity.py`. Start the attacker both ways (through the proxy, and directly), make one call each, and read `features.jsonl`. Assert `env_count`, `has_home` and `cwd` are **equal**. If they can't be made equal, the remaining difference is a real deployment difference. Write it down and tell the user; it becomes a finding.
- **Done when:** the parity test passes or the remaining difference is documented.

### T5. Collect the RQ3 dataset
- **New `Driftsentry/eval/collect.py`** (CLI: `python -m eval collect --sessions N --models a,b,c --out eval_results/rq3`):
  1. Fresh `DRIFTSENTRY_HOME` and `ATTACKER_HOME`; the attacker in **benign** mode.
  2. `capture_baseline(..., probe_mode="keyed", key=derive_experiment_key(...))` with `probe_launch`.
  3. Alternate, **one at a time, never overlapping:** an agent session (task × model × prompt style), then one `verify_server(baseline, launch=probe_launch, cycle=i, key=key)`.
  4. Around each, write `{"label": 0|1, "start": t0, "end": t1, "task"/"cycle": ..., "model": ...}` to `windows.jsonl` (0 = genuine, 1 = probe).
  5. Copy `features.jsonl` from the sink into the output folder at the end.
- **New `Driftsentry/eval/rq3_dataset.py`:**
  - Join each feature row to the window containing `t`; drop rows outside all windows.
  - Assert **every `pid` falls in exactly one window.** Fail loudly otherwise.
  - Output `dataset.jsonl` with `label` and `group = pid`.
- **Target:** about 120 genuine sessions and 120 probe cycles. Run `--sessions 4` as the quick test.
- **Done when:** the quick run gives a dataset with both labels and no pid in two windows.

### ⛔ CHECKPOINT A
Report to the user: what changed, test results, the parity result from T4, and the exact full T5 command with an estimated run time. **Wait for approval before the full collection.**

---

## PHASE 2: RQ1, real benign upgrades (Gap 3)

### T6. Choose the real servers [HUMAN + research]
- **New `Driftsentry/eval/real_servers.json`:** a list of `{"name", "launcher": "uvx"|"npx", "package", "entry", "old", "new", "read_only_tools": [...], "needs_key": false, "licence", "label": "benign"|"benign-security-relevant", "label_reason"}`, plus a separate `"excluded": [{"name", "reason"}]`.
- **Aim for 15–25 servers** whose tool definitions or behaviour changed between two versions, and which need no paid API key.
  - Prefer Python servers (`uvx`). The sandbox monitor sees Python fully but Node only roughly; note this.
  - On Windows use `npx.cmd`.
- **Only call tools that don't write anything** (`read_only_tools`).
- **`label`:** the user decides it from the changelog. "benign-security-relevant" means the upgrade legitimately adds network, file or process access.
- **Done when:** the user approves the list.

### T7. Upgrade runner
- **New `Driftsentry/eval/real_upgrades.py`** (CLI: `python -m eval rq1 --servers eval/real_servers.json --runs 3 --out eval_results/rq1`). For each server:
  - `key = derive_experiment_key(1, name)`;
  - `capture_baseline` on the **old** version;
  - `verify_server` ×3 on **old** (normal noise) and ×3 on **new** (the upgrade).
- **One row per (server, phase, run, tool):** `score`, `verdict`, `triggered_by`, the per-signal maximum (reuse `eval/record.py::components`), `definition_changed`, and the raw ratios needed for calibration.
- **Report `definition_changed` counts.** That is the evidence that hash pinning alarms on harmless upgrades (Gap 1).
- **Done when:** `--quick` (2 servers, 1 run) works end to end.

### T8. Per-tool calibration, frozen
**Read:** `calibration.py`, `scorer.py`.
- **Important design point:**
  - A tool's own threshold comes from **that tool's own benign runs before the upgrade** (its old/old runs, which in real use happen at approval time).
  - The **calibration servers** only set the *rule*: quantile, margin, minimum observations `MIN_OBS`, and the global fallback.
  - So test servers never use data from after their upgrade.
- **In `calibration.py`:**
  - add `fit_per_tool(rows, rule) -> dict[tool, threshold]`, reusing `calibrate_from_ratios`/`_quantile`; tools with fewer than `MIN_OBS` observations use the global threshold;
  - add `freeze(obj, path)`, writing JSON with `_sha256` (of the sorted-key body) and `_frozen_at` (UTC);
  - add `verify_frozen(path)`, which fails if the hash doesn't match.
- **`scorer.score_report`:** add an optional `per_tool: dict[str, float] | None`. When a tool has an entry, use it instead of `threshold_ratio`. Default None, so old behaviour is unchanged.
- **Split:** a server is in calibration if `int(sha256(name).hexdigest(), 16) % 10 < 4`, otherwise test. Write the split to a file and freeze it **before** running test servers.
- **Tests:** freezing then verifying round-trips, tampering fails, the fallback works, and old scoring is unchanged when `per_tool=None` (golden tests still pass).

### T9. RQ1 analysis
- **New `Driftsentry/eval/rq1_analyse.py`:**
  - On **test** servers' new runs: false-alarm rate with the global threshold vs per-tool, with Wilson intervals (`eval/stats.py`, T13; build T13 first if needed).
  - Break down by signal (`triggered_by`) and by label (benign vs benign-security-relevant).
  - Re-score the existing attack matrix results with per-tool thresholds and check detection didn't fall.
  - Print H1 PASS/FAIL using the rule in section 3.

### ⛔ CHECKPOINT B
Report the server list, the frozen calibration hash, the quick results and the full-run command. Wait.

---

## PHASE 3: RQ2, active vs passive vs hash-only (Gap 4)

### T10. Replay real traffic inside each episode
- **New `Driftsentry/eval/replay.py`:** `async replay(calls, launch, client_info) -> list[(tool, args, result, latency_s)]`.
  - It takes recorded genuine calls (tool, args) from the T5 dataset and replays them **through the proxy** using `agent_launch` (with `--passive`), so the attacker sees traffic that looks genuine.
  - Read passive findings from the proxy's final `passive_summary` record (T1).
- **`EpisodeConfig`:** add `replay_sessions: int = 0`. When > 0, after each verification cycle replay that many genuine sessions.
- **`ground_truth`:** make sure attack firings **during replay** are counted as fired, so the outcome is `missed`, not `never_triggered`, when the attack hit real traffic and probes missed it.

### T11. Attacks on tools the agent never calls
- **Attacker `scenario.py`:** add `only_tools: list[str] = field(default_factory=list)`, validated against the 5 tool names.
- **`server._process`:** if `scenario.only_tools` is set and `tool` isn't in it, behave honestly.
- **Harness:** for these episodes, choose replay sessions that **never call** the targeted tool.

### T12. Experiment 5: three detectors on the same episodes
- **`record.py`:** add `hash_detected`, `passive_detected`, `full_detected` (bool), plus `proxy_latency_ms` and `cycle_seconds`.
  - `hash_detected = report.definition_changed`.
  - `full_detected` = verdict is alert.
  - `passive_detected` = the frozen passive rule. Fix this rule on **benign episodes only** first: for example "≥ 1 high-severity finding". Freeze it in a file.
- **`experiments.py`:**
  - add `experiment_5`: the full family × level matrix, plus `only_tools` variants, with `launch_parity=True` and `replay_sessions>0`. All three detectors are scored on **the same episodes**.
  - Add `5` to `--experiment` choices in `eval/__main__.py`.
- **Overhead:** per-call latency through the proxy vs direct (replay the same calls both ways), and probe-cycle seconds.

### T13. Statistics helpers
- **New `Driftsentry/eval/stats.py`:**
  - `wilson(k, n)`: statsmodels `proportion_confint(method="wilson")`;
  - `mcnemar_p(a, b)`: paired bools, exact test (statsmodels);
  - `holm(pvals)`: `multipletests(method="holm")`;
  - `bootstrap_auc(y, s, groups, n=2000, seed=0)`: resample **whole groups**;
  - `delong(y, s1, s2) -> (auc1, auc2, p)`: fast DeLong (Sun & Xu 2014). Reference sketch:

```python
def _midrank(x):
    o = np.argsort(x); xs = x[o]; n = len(x); r = np.zeros(n); i = 0
    while i < n:
        j = i
        while j < n and xs[j] == xs[i]:
            j += 1
        r[i:j] = 0.5 * (i + j - 1) + 1; i = j
    out = np.empty(n); out[o] = r; return out

def delong(y, s1, s2):
    y = np.asarray(y).astype(bool); P, N = np.where(y)[0], np.where(~y)[0]; m, n = len(P), len(N)
    aucs, v10, v01 = [], [], []
    for s in (np.asarray(s1, float), np.asarray(s2, float)):
        tx, ty, tz = _midrank(s[P]), _midrank(s[N]), _midrank(np.r_[s[P], s[N]])
        aucs.append((tz[:m].sum() - m * (m + 1) / 2) / (m * n))
        v10.append((tz[:m] - tx) / n); v01.append(1 - (tz[m:] - ty) / m)
    sx, sy = np.cov(v10), np.cov(v01)
    var = (sx[0, 0] + sx[1, 1] - 2 * sx[0, 1]) / m + (sy[0, 0] + sy[1, 1] - 2 * sy[0, 1]) / n
    if var <= 0:
        return aucs[0], aucs[1], 1.0
    return aucs[0], aucs[1], 2 * norm.sf(abs(aucs[0] - aucs[1]) / np.sqrt(var))
```
- **Tests (`tests/test_stats.py`):**
  - DeLong AUCs equal `sklearn.metrics.roc_auc_score`;
  - the same scores twice give p = 1;
  - a clearly better classifier gives p < 0.05 on a fixed synthetic set;
  - Wilson matches statsmodels;
  - McNemar on a known table gives a known p;
  - the bootstrap resamples groups, not rows.
- **New `Driftsentry/eval/rq2_analyse.py`:**
  - detection rates per detector with Wilson intervals;
  - McNemar full vs hash-only and full vs passive;
  - the result on `only_tools` episodes;
  - time to detect and overhead;
  - H2 PASS/FAIL.

### ⛔ CHECKPOINT C
Report the quick results, the frozen passive rule, and the full-run command with an estimate. Wait.

---

## PHASE 4: RQ3, can the server spot probes? (Gap 2, main result)

### T14. Distinguishability analysis
- **New `Driftsentry/eval/rq3_distinguish.py`** (CLI: `python -m eval rq3 --data eval_results/rq3/dataset.jsonl`):
  - Import `FAMILIES` from `attacker/features.py` by adding the attacker project to `sys.path`. That file is standard-library only, so this is safe. **One source of truth for features.**
  - For each family: pipeline `DictVectorizer(sparse=False) → StandardScaler → LogisticRegression(max_iter=2000)`, with `cross_val_predict(..., groups=group, cv=GroupKFold(5), method="predict_proba")`.
  - Report AUC, a bootstrap 95% interval (by group), and DeLong of each family vs `argument`, then Holm across families.
  - Fit each family on the **full** dataset and export `recogniser_<family>.json` = `{"feature_names", "mean", "scale", "coef", "intercept", "family", "trained_on": <dataset sha256>}`.
  - Save ROC points per family for the figures.
  - Print H3 (AUC part) PASS/FAIL.
- **Test:** a synthetic dataset where one feature perfectly separates the labels gives AUC ≈ 1 for its family and ≈ 0.5 for the others.

### T15. Learned evasive attacker (level L6)
- **Attacker `scenario.py`:**
  - add `"L6"` to `LEVELS` ("learned recogniser");
  - make `is_probe_aware()` include L6;
  - make `validate()` require `probe_aware` for L6;
  - add `recogniser_family: str = "all"`.
- **`attacks.should_fire`:** for L6, load `ATTACKER_HOME/recogniser.json` once (cache it). If `features is not None and features.p_probe(row, model) > 0.5`, then `sink.log_event("probe-skip", ...)` and return `(False, "learned recogniser: probe")`. Otherwise fire.
- **Rule:** the recogniser must be trained on the T5 collection dataset only, never on data from the evaluation episodes.
- **Test (attacker side):** with a tiny model JSON that flags `client_name == "probe-x"`, a call from client "probe-x" is skipped and other calls fire.

### T16. Experiment 3: detection lost to the learned attacker
- **`EpisodeConfig`:** add `recogniser: str | None`. `_prepare()` copies that JSON to `atk_home/recogniser.json`.
- **`experiment_3`:**
  - the family × level matrix at **L1** (reference) and **L6**, once per recogniser family;
  - `launch_parity=True`, and `replay_sessions > 0` (without genuine traffic an L6 attacker never fires and every episode becomes `never_triggered`).
- **Measure:** detection at L1 minus detection at L6, per family, with intervals. Also measure how often **passive** catches what probes missed.
- **Add `3` to the `--experiment` choices.** Print H3 (recall part) PASS/FAIL.

### ⛔ CHECKPOINT D
Report AUC per family, which family wins, the quick L6 result and the full-run command. Wait.

---

## PHASE 5: RQ4, countermeasures (Gap 2 fixes)

**Every countermeasure goes behind its own option** (default off) on capture and reprobe, so Experiment 4 can switch them one at a time.

### T17. Host identity mimicry (option `mimic_host`)
- **`proxy.py`:** on the first `initialize`, save `{"name", "version"}` and the server's cwd to `data_dir()/hostprofile/<server>.json`. Names only; **no environment values.**
- **`baseline.py`** (`capture_baseline` and `reprobe`): when `mimic_host`, open `ClientSession(read, write, client_info=types.Implementation(name=..., version=...))` from the profile, with the same cwd and environment rule as the proxy launch.
- **Test:** with the option on, a probe session's `client_name` in `features.jsonl` equals the host's.

### T18. Argument and timing mimicry (option `mimic_traffic`)
- **`probe_generator.py`:** add `MimicProbeGenerator`.
  - Learn only the **shape** of real arguments per tool from proxy logs: length range, character classes, word count, ID patterns.
  - Generate **new** values with the keyed random generator. **Never replay real user values.** Keep `redact.py` in the path.
- **`camouflage.py`:** gaps between probe calls drawn from recorded genuine gaps (keyed `_rng`); keep the session open for a realistic length; on some cycles skip `tools/list` and use the cached definition.
- **Update `SessionFingerprint.residual_tells()`** so it reports which clues are now removed.
- **Test:** generated arguments match the learned shape, the same key and cycle give the same output, and no generated value equals a logged real value.

### T19. Secret subsampling (option `subsample_bank`)
- **`baseline.py`** (keyed mode): when the option is on, at capture record a **bank** of about 64 probes per tool with their responses and bands.
- **`_reprobe_keyed`:** pick `m` (3–4) probes per cycle with `camouflage._rng(key, server, tool, cycle).sample(bank, m)`, and compare each with its own recorded response.
- **Test:** the same key and cycle pick the same subset, different cycles pick different subsets, and an attacker that memorised the first `m` probes is still caught on later cycles.

### T20. Experiment 4: re-run under each countermeasure
| Condition | Options on |
|---|---|
| K (current) | none |
| K + host | `mimic_host` |
| Mimic | `mimic_host` + `mimic_traffic` |
| Subsample | `subsample_bank` |
| All | all three |

For each condition:
1. re-run T5 collection, then T14 → best AUC;
2. retrain the L6 recogniser on **that condition's** collection data, then run the T16 matrix → detection recovered;
3. run benign episodes → change in false alarms;
4. record calls and seconds per cycle → cost.

- **New `eval/rq4_analyse.py`:** prints H4 PASS/FAIL. **If H4 fails, report it as a finding. Don't tune.**
- **Optional, only if the user asks:** in-session probing through `proxy.py`.

### ⛔ CHECKPOINT E
Report the results table and costs. Wait.

---

## PHASE 6: Results for the report

### T21. Tables and figures
- **New `Driftsentry/eval/report_tables.py`:** reads `eval_results/` and writes CSV tables and PNG figures to `eval_results/report/`:
  - **RQ1:** the server table; false-alarm rate per signal, global vs per-tool; `definition_changed` count.
  - **RQ2:** the three-way detection table with Wilson intervals; McNemar results; time-to-detect chart; overhead table.
  - **RQ3:** AUC per family with intervals; ROC curves; detection-loss chart.
  - **RQ4:** before/after AUC and detection per condition; cost table.
  - **Hypotheses:** H1–H4 with the numbers and PASS/FAIL.
- **Don't edit the report document.** The user writes Chapters 6–7 from these files.

---

## 7. Timeline (deadline: final submission 13 Feb 2027)
| Dates | Tasks |
|---|---|
| 1–7 Nov | T0–T5 (start full collection) |
| 8–21 Nov | T6–T9 (RQ1) |
| 22 Nov–5 Dec | T10–T13 (RQ2) |
| 6–20 Dec | T14–T16 (RQ3) |
| 21 Dec–20 Jan | T17–T20 (RQ4) |
| 20 Jan–13 Feb | T21, writing |
