# Testing DriftSentry

Every command here has been run end to end on Windows with CPython 3.14. Expected
outputs are the ones actually observed, not idealised.

Activate the environment first:

```bash
.venv\Scripts\activate
```

---

## 1. Automated: the self-verifying demos

Each demo asserts its own phase's definition of done and prints
`ALL CHECKS PASSED`. They run in temporary directories, so they never touch your
real config, baselines, or alerts.

| Command | Proves | Time |
|---|---|---|
| `python examples/echo_client.py` | The MCP loop works at all | seconds |
| `python scripts/check_stack.py` | ChromaDB + embeddings work offline | seconds |
| `python examples/proxy_demo.py` | Proxy is transparent; ids survive 8 concurrent calls | ~20s |
| `python examples/init_demo.py` | Config rewrite/restore round-trips; secrets stay out of argv | ~2m |
| `python examples/baseline_demo.py` | Probe safety, variance learning, drift caught | ~3m |
| `python examples/scorer_demo.py` | Calibration, scoring, hash-only control | ~4m |
| `python examples/alert_demo.py` | Alerts, mitigations, opt-in enforcement blocks a live call | ~4m |
| `python examples/testbed_demo.py` | **The Mid-Point demo** - six families, false alarms, L1-L4 | ~10m |

Run them all:

```bash
for d in proxy_demo init_demo baseline_demo scorer_demo alert_demo testbed_demo; do python examples/$d.py 2>&1 | grep "result:"; done
```

---

## 2. Manual: the demo you drive by hand

This is the sequence for a live demonstration. **Use an absolute `--scenario`
path** - see the gotcha at the bottom.

```bash
set SC=F:/Driftsentry-final/.testbed/scenario.json
```

**Approve a server while it is behaving.**

```bash
python -m testbed reset --scenario %SC%
```
```bash
driftsentry baseline --server acme --exec python -m testbed serve --reuse --scenario %SC%
```

Note in the output that `search_orders` and `send_invoice` are **not probed** -
they look side-effecting, so DriftSentry refuses to fire canaries at them.

**Set the alert threshold from benign behaviour only.**

```bash
driftsentry calibrate --repeats 3
```

**Confirm a healthy server is quiet.**

```bash
driftsentry verify --server acme
```
> `VERDICT: OK   score 0.82 (alert at 1.00)`

**Now turn the server malicious - without restarting it.**

```bash
python -m testbed set-family content-injection --scenario %SC%
```
```bash
driftsentry verify --server acme
```
> `VERDICT: ALERT   score 3.00   triggered by: behavioural_drift`

followed by a full alert card: cause, before/after, and mitigations.

**The comparison that is the whole thesis.** Same server, same attack, scored
the way mcp-scan and Snyk Agent Scan score it:

```bash
driftsentry verify --server acme --hash-only --no-alert
```
> `definition : unchanged` / `VERDICT: OK   score 0.00`

**Try other families.**

```bash
python -m testbed set-family new-egress --scenario %SC%
```
```bash
driftsentry verify --server acme
```
> `VERDICT: ALERT   score 2.00   triggered by: rule:new_egress_host`

**Show the honest limit (RQ4).**

```bash
python -m testbed set-level L4 --probe-aware --scenario %SC%
```
```bash
driftsentry verify --server acme
```
> `VERDICT: OK   score 0.80`

The probe-aware attacker recognises the canary inputs and behaves while watched.
This is the expected result, not a bug: it is what motivates randomised probe
templates and what Experiment 4 measures.

**Review and reset.**

```bash
driftsentry report --server acme --full
```
```bash
python -m testbed reset --scenario %SC%
```
```bash
driftsentry trust --server acme
```

---

## 3. Enforcement (optional, opt-in)

A quarantine is advisory by default. To let the proxy actually refuse calls:

```bash
driftsentry quarantine --server acme --enforce
```

Any client talking through `driftsentry run --enforce` then receives a JSON-RPC
error for that tool naming DriftSentry and how to undo it. Detection is the
graded contribution; blocking is a bonus, kept opt-in so it can never confound a
detection measurement.

---

## 4. Against a real MCP client

```bash
driftsentry init --config "%APPDATA%\Claude\claude_desktop_config.json"
```

Writes a **new** file (`*.driftsentry.json`) and captures a baseline per server;
the original is never modified unless you pass `--in-place`, which takes a
timestamped backup first. Undo with:

```bash
driftsentry restore --config <path>
```

Only stdio servers are proxied. HTTP entries are reported and left untouched.

---

## What "working" looks like

| Situation | Expected |
|---|---|
| Benign server | `OK`, comfortably under 1.00 |
| Benign server that legitimately updated | `OK` - no false alarm |
| Any family at L1 | `ALERT`, with the triggering signal named |
| The same attack under `--hash-only` | `OK` - the gap this project fills |
| L4 probe-aware | `OK` - expected evasion |

If a benign verify sits close to 1.00, the threshold was calibrated on too little
data. Re-run `driftsentry calibrate` with more `--repeats`, and across more than
one benign server - the tool warns when the evidence is too thin to quote.

---

## The one gotcha

**Environment variables do not reach an MCP server launched by a client.** The
MCP SDK passes only a filtered environment to servers it spawns, so `TESTBED_HOME`
set in your shell does *not* reach a testbed server that DriftSentry started.

If the CLI and the server end up reading different scenario files, the attack
never fires and it looks exactly like a detection failure. Always pass
`--scenario <absolute path>` to both `serve` and `set-family` / `set-level` /
`trip`. `serve --reuse` now warns loudly when the file it was pointed at does not
exist.
