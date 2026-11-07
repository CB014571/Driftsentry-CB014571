# DriftSentry - measured results

Generated 2026-11-07 from the files in `eval_results/`. Where a result has not been measured this says so and gives the command that would produce it. Nothing here is transcribed by hand.

### Table 1. Fixed against keyed probe values

Detection by attack level, same families, same seeds, same
threshold. The only variable is how probe arguments are chosen.

**NOT MEASURED.** Experiment 2 has not run: `eval_results/exp2_console.log` holds one line, `waiting for Experiment 1 to finish...`, and no result file exists. Produce it with:

    python -m eval run --experiment 2

Until then the only paired evidence is the four-episode
demonstration in Table 1b, which is not a rate.

| level | fixed probes | keyed probes |
| --- | --- | --- |
| L1 | 100.0% [0.65, 1.00] (7/7) | NOT MEASURED |
| L2 | 100.0% [0.61, 1.00] (6/6) | NOT MEASURED |
| L3 | 100.0% [0.61, 1.00] (6/6) | NOT MEASURED |
| L4 | never fired (6 held back) | NOT MEASURED |
| L5 | never fired (6 held back) | NOT MEASURED |

`never fired` is not a detection failure. A level-4 server that
recognises a fixed probe value holds back while it is being
tested and attacks only genuine traffic, so no attack occurs
during a probe cycle for the detector to catch. That is the
evasion the keyed generator exists to remove, and it is why
recall is reported over episodes where the attack fired.

### Table 1b. Paired demonstration, one seed per cell

n = 1 episode per cell, 4 cells. This is a
demonstration of the mechanism, not a rate: no interval can be
put on a single episode. Superseded by Table 1 once Experiment
2 has run.

| cell | fixed | score | keyed | score |
| --- | --- | --- | --- | --- |
| content-injection/L1 | detected | 2.061 | detected | 2.966 |
| content-injection/L4 | never_triggered | 0.063 | detected | 2.966 |
| exfiltration/L4 | never_triggered | 0.074 | detected | 1.100 |
| silent-tamper/L4 | never_triggered | 0.087 | detected | 2.228 |

### Table 2. Three detectors on the same attacks (Gap 1, Gap 4)

Each row is one sweep of the same twelve attack configurations
(six families, two seeds). The sweeps differ only in which
recogniser was copied into the attacker's home, which L1
ignores, so they are replications rather than independent
attacks - and they are reported separately for that reason.

| sweep | attacks fired | hash pinning | passive | full |
| --- | --- | --- | --- | --- |
| argument | 10 | 0/10 | 0/10 | 10/10 |
| client | 12 | 0/12 | 0/12 | 12/12 |
| session | 12 | 0/12 | 0/12 | 12/12 |
| timing | 11 | 0/11 | 0/11 | 11/11 |

Across all 4 replications, 45 episodes in which
the attack executed: hash pinning caught 0, passive monitoring 0, the full detector 45.

A single-replication interval, which is the honest one for a
design of twelve configurations:

| detector | caught (sweep `argument`) |
| --- | --- |
| definition hash (TOFU pinning) | 0.0% [0.00, 0.28] (0/10) |
| passive monitoring | 0.0% [0.00, 0.28] (0/10) |
| DriftSentry, full | 100.0% [0.72, 1.00] (10/10) |

The advertised tool definition changed in 0/45 of these
attacks. That is the mechanism of a behavioural rug pull: the
declared interface is byte-identical before and after the tool
turns, so a pinned hash has nothing to compare.

Passive monitoring was available in every episode, so its
zero is a genuine non-detection and not an absence of
monitoring.

### Table 3. Separating probe traffic from genuine traffic (RQ3)

2325 calls (165 genuine, 2160 probe) across 235 process instances; 5-fold GroupKFold on the process, so no session spans a split.

| feature family | AUC [95% CI] | vs argument (Holm) |
| --- | --- | --- |
| client | 1.000 [1.000, 1.000] | p = 6.733e-19, beats it |
| session | 0.983 [0.970, 0.993] | p = 2.911e-16, beats it |
| timing | 0.951 [0.929, 0.971] | p = 2.909e-10, beats it |
| argument | 0.763 [0.695, 0.824] | reference |
| environment | 0.500 [0.500, 0.500] | p = 5.31e-23 |
| all | 1.000 [1.000, 1.000] | - |

Intervals are bootstrapped over process instances rather than
over calls, because calls inside one process share a client, a
working directory and a session counter and are not
independent.

### Table 4. Detection lost to a learned recogniser (RQ3, H3)

The same attack matrix at L1, where the server attacks every
call, and at L6, where it scores each call against a model
fitted to traffic it observed and stays benign for anything it
believes is a probe.

| channel | AUC | L1 recall | L6 recall | drop |
| --- | --- | --- | --- | --- |
| client | 1.000 | 100.0% [0.76, 1.00] (12/12) | 0.0% [0.00, 0.28] (0/10) | -100.0pp |
| session | 0.983 | 100.0% [0.76, 1.00] (12/12) | 0.0% [0.00, 0.28] (0/10) | -100.0pp |
| timing | 0.951 | 100.0% [0.74, 1.00] (11/11) | 0.0% [0.00, 0.43] (0/5) | -100.0pp |
| argument | 0.763 | 100.0% [0.72, 1.00] (10/10) | 0.0% [0.00, 0.43] (0/5) | -100.0pp |

The drop does not track the AUC. A channel at 0.763 cost as
much detection as one at 1.000, because an attacker does not
need to classify every call correctly - it needs to be right
about the calls it would otherwise have attacked on.

The two arms have different denominators, and the difference is
itself part of the result. An L6 episode where the server
believed every call was a probe never attacks, so it is
classified `never_triggered` and excluded from recall: there
was no attack to catch. Counting those as detections would
credit the detector for an attack that did not happen, and
counting them as misses would penalise it for the same.

### Table 5. Real benign servers and real version upgrades (Gap 3)

Nothing malicious happens in any of these runs. Every alert is
a false alarm. The `same release` column changes nothing at all
between the baseline and the re-probe.

| server | same release | after upgrade | hash fired | n per cell |
| --- | --- | --- | --- | --- |
| git | 100.0% [0.44, 1.00] (3/3) | 100.0% [0.44, 1.00] (3/3) | 3/3 | 3/3 |
| time | 0.0% [0.00, 0.56] (0/3) | 100.0% [0.44, 1.00] (3/3) | 3/3 | 3/3 |

The candidate list in `eval/real_servers.json` holds 8 servers
against a target of 15 to 25, and two of the four local ones
could not be measured: `mcp-server-calculator` and
`mcp-server-sqlite` both crash on startup at their old release
with `'Server' object has no attribute 'list_resources'`. Old
releases of MCP servers do not necessarily run against a
current SDK, which bounds how far back any upgrade pair can
reach and belongs in threats to validity.

### Table 6. Countermeasures, and what they cost (RQ4, H4)

**NOT MEASURED.** Run:

    python -m eval t20 --cycles 60

Each condition collects its own probe traffic, fits a recogniser
on that traffic, and runs the L1/L6 matrix against it.

## Outstanding

- **NOT MEASURED.** Experiment 2 has not run: `eval_results/exp2_console.log` holds one line, `waiting for Experiment 1 to finish...`, and no result file exists. Produce it with:
- | L1 | 100.0% [0.65, 1.00] (7/7) | NOT MEASURED |
- | L2 | 100.0% [0.61, 1.00] (6/6) | NOT MEASURED |
- | L3 | 100.0% [0.61, 1.00] (6/6) | NOT MEASURED |
- | L4 | never fired (6 held back) | NOT MEASURED |
- | L5 | never fired (6 held back) | NOT MEASURED |
- **NOT MEASURED.** Run:
