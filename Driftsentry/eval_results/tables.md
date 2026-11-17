# DriftSentry - measured results

Generated 2026-11-17 from the files in `eval_results/`. Where a result has not been measured this says so and gives the command that would produce it. Nothing here is transcribed by hand.

### Table 1. Fixed against keyed probe values

Detection by attack level, same families, same seeds, same
threshold. The only variable is how probe arguments are chosen.

| level | fixed probes | keyed probes |
| --- | --- | --- |
| L1 | 100.0% [0.82, 1.00] (18/18) | 100.0% [0.80, 1.00] (15/15) |
| L2 | 100.0% [0.82, 1.00] (18/18) | 100.0% [0.80, 1.00] (15/15) |
| L3 | 100.0% [0.82, 1.00] (18/18) | 100.0% [0.80, 1.00] (15/15) |
| L4 | never fired (18 held back) | 100.0% [0.80, 1.00] (15/15) |
| L5 | never fired (18 held back) | 100.0% [0.80, 1.00] (15/15) |

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

### Table 2. Three detectors on the same attacks (Validation)

Each row is one sweep of the same twelve attack configurations
(six families, two seeds). The sweeps differ only in which
recogniser was copied into the attacker's home, which L1
ignores, so they are replications rather than independent
attacks - and they are reported separately for that reason.

| sweep | attacks fired | hash pinning | passive | full |
| --- | --- | --- | --- | --- |
| argument | 10 | 0/10 | 0/10 | 10/10 |
| client | 12 | 0/12 | 0/12 | 12/12 |
| environment | 11 | 0/11 | 0/11 | 11/11 |
| session | 12 | 0/12 | 0/12 | 12/12 |
| timing | 11 | 0/11 | 0/11 | 11/11 |

Across all 5 replications, 56 episodes in which
the attack executed: hash pinning caught 0, passive monitoring 0, the full detector 56.

A single-replication interval, which is the honest one for a
design of twelve configurations:

| detector | caught (sweep `argument`) |
| --- | --- |
| definition hash (TOFU pinning) | 0.0% [0.00, 0.28] (0/10) |
| passive monitoring | 0.0% [0.00, 0.28] (0/10) |
| DriftSentry, full | 100.0% [0.72, 1.00] (10/10) |

The advertised tool definition changed in 0/56 of these
attacks. That is the mechanism of a behavioural rug pull: the
declared interface is byte-identical before and after the tool
turns, so a pinned hash has nothing to compare.

Passive monitoring was available in every episode, so its
zero is a genuine non-detection and not an absence of
monitoring.

### Table 3. Separating probe traffic from genuine traffic (RQ1)

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

### Table 4. Detection lost to a learned recogniser (RQ1, H1)

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
| environment | 0.500 | 100.0% [0.74, 1.00] (11/11) | undefined (0 of 18 episodes fired) | - |

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

The environment row is that argument taken to its limit, and
it is a result rather than a gap. All 18 L6 episodes ran and
none fired, so there is no denominator: the recall is
undefined, not zero. The attacker's own log gives the reason -
it scored every single call `probe (p=0.929)`, the same value
throughout, and so stayed benign for all of them. That is what
an AUC of 0.500 does in deployment. A recogniser that cannot
separate probe traffic from genuine traffic, and guesses
`probe`, disables the attack it was built to protect. Reported
as -100.0pp it would read as perfect evasion, which is the
opposite of what happened.

### Table 5. Real benign servers and real version upgrades (RQ3b)

Nothing malicious happens in any of these runs. Every alert is
a false alarm. The `same release` column changes nothing at all
between the baseline and the re-probe.

| server | same release | after upgrade | hash fired | n per cell |
| --- | --- | --- | --- | --- |
| alchemy | 0.0% [0.00, 0.56] (0/3) | 0.0% [0.00, 0.56] (0/3) | 0/3 | 3/3 |
| git | 0.0% [0.00, 0.56] (0/3) | 100.0% [0.44, 1.00] (3/3) | 3/3 | 3/3 |
| motherduck | 0.0% [0.00, 0.56] (0/3) | 0.0% [0.00, 0.56] (0/3) | 0/3 | 3/3 |
| time | 0.0% [0.00, 0.56] (0/3) | 100.0% [0.44, 1.00] (3/3) | 3/3 | 3/3 |

The candidate list in `eval/real_servers.json` holds 8 servers
against a target of 15 to 25, and two of the four local ones
could not be measured: `mcp-server-calculator` and
`mcp-server-sqlite` both crash on startup at their old release
with `'Server' object has no attribute 'list_resources'`. Old
releases of MCP servers do not necessarily run against a
current SDK, which bounds how far back any upgrade pair can
reach and belongs in threats to validity.

### Table 6. Countermeasures, and what they cost (RQ2, H2)

```
========================================================================
  T20 - countermeasures against a learned recogniser (RQ2 / H2)
========================================================================

  condition     best AUC    recall  false alarms   cycle s   calls
  ----------------------------------------------------------------
  none             1.000      0.0%         50.0%      19.0    18.0
  host             0.994      0.0%         50.0%      19.3    18.0
  mimic            0.993     50.0%         50.0%      17.5    18.0
  subsample        1.000      0.0%         50.0%      13.3    18.0
  all              0.994     50.0%         50.0%      24.5    18.0

  condition          channel   L1 recall   L6 recall      gap
  ------------------------------------------------------------
  none                client      100.0%        0.0% -100.0pp
  host                   all      100.0%        0.0% -100.0pp
  mimic                  all      100.0%       50.0%  -50.0pp
  subsample           client      100.0%        0.0% -100.0pp
  all                    all      100.0%       50.0%  -50.0pp

  H2: FAIL
    FAIL  auc_at_or_below_ceiling
    FAIL  recall_within_tolerance
    pass  false_alarms_contained

  A failed hypothesis is a result. The countermeasures are not to be tuned until it passes.
```

### Table 7. Attacks hidden in legitimate updates (RQ3a)

Attributed detection: an alert naming a signal the hidden change causes.
Attacks that fired: 60; never fired, excluded: 12.

| condition | C0 | C1 | C2 | C3 | pooled C0-C2 |
| --- | --- | --- | --- | --- | --- |
| accept_rebaseline | 100.0% [0.80, 1.00] (15/15) | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.20] (0/15) | 33.3% [0.21, 0.48] (15/45) |
| refuse_all | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.92, 1.00] (45/45) |
| definition_diff | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.20] (0/15) | 0.0% [0.00, 0.08] (0/45) |
| new_host_only | 20.0% [0.07, 0.45] (3/15) | 20.0% [0.07, 0.45] (3/15) | 20.0% [0.07, 0.45] (3/15) | 20.0% [0.07, 0.45] (3/15) | 20.0% [0.11, 0.34] (9/45) |
| residue | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.80, 1.00] (15/15) | 100.0% [0.92, 1.00] (45/45) |

Residue against each baseline, paired, exact McNemar with Holm correction:

| baseline | only residue | only baseline | p | Holm p | significant |
| --- | --- | --- | --- | --- | --- |
| accept_rebaseline | 30 | 0 | 1.863e-09 | 1.863e-09 | yes |
| definition_diff | 45 | 0 | 5.684e-14 | 1.705e-13 | yes |
| new_host_only | 36 | 0 | 2.91e-11 | 5.821e-11 | yes |

C3, declaration widened to cover the payload: 15 fired, residue attributed 15, evaded 0; no attack evaded, so there is no share to report.

### Table 8. Synthetic benign updates: false alarms (RQ3a)

A legitimate declared change shipped with no attack. Any alert is a false alarm.

| condition | false alarms |
| --- | --- |
| accept_rebaseline | 0.0% [0.00, 0.39] (0/6) |
| refuse_all | 100.0% [0.61, 1.00] (6/6) |
| definition_diff | 100.0% [0.61, 1.00] (6/6) |
| new_host_only | 0.0% [0.00, 0.39] (0/6) |
| residue | 0.0% [0.00, 0.39] (0/6) |

### Table 9. Residue on real benign upgrades (RQ3b)

| server | runs | residue_alert | escalation | held | residue signals |
| --- | --- | --- | --- | --- | --- |
| alchemy | 3 | 0 | 0 | 0 | - |
| git | 3 | 3 | 0 | 0 | behavioural_drift, determinism_break |
| motherduck | 3 | 0 | 0 | 0 | - |
| time | 3 | 3 | 0 | 0 | behavioural_drift, determinism_break |

Upgrades leaving a residue: 50.0% [0.15, 0.85] (2/4). Labels are null by the user's decision, so this rate is reported unlabelled.

### Table 10. Hypotheses

| | hypothesis | result | basis |
| --- | --- | --- | --- |
| H1 | a non-argument family separates probes at AUC >= 0.9, and withholding drops recall >= 50pp | PASS | client (AUC 1.000, recall -100pp); session (AUC 0.983, recall -100pp); timing (AUC 0.951, recall -100pp) |
| H2 | mimicry brings AUC <= 0.6, recall within 10pp, false alarms +2pp at most | FAIL | best AUC 0.994 (needs <= 0.6), recall gap -50pp (needs within 10), false alarms +0.0pp (needs <= +2) |
| H3 | residue detects >= 80% pooled C0-C2, beats three baselines (Holm p<0.05), <= 15% of real upgrades leave residue | FAIL | on 78 episodes (60 attacks fired); residue detects 45/45 = 100.0% pooled C0-C2 (needs >= 80%): met; vs accept_rebaseline: b01=30 b10=0 p=1.863e-09 Holm p=1.863e-09: significant; vs definition_diff: b01=45 b10=0 p=5.684e-14 Holm p=1.705e-13: significant; vs new_host_only: b01=36 b10=0 p=2.91e-11 Holm p=5.821e-11: significant; 2/4 real upgrades left a residue = 50.0% (needs <= 15%): NOT met |
| Validation | Per-tool thresholds halve benign-update false alarms at equal recall | FAIL | benign-update false alarms 6/6 global vs 6/6 per-tool; recall 12/12 vs 12/12 (pre-registered, followup/validation) |
| Validation | Full DriftSentry detects significantly more than hash-only | PASS | exp3_argument_L1: full 10/10, hash 0/10, exact McNemar p=0.001953 |
| Validation | Catches attacks on tools the agent never calls, which passive cannot | PASS | full 16/16, passive 0/16, exact McNemar p=3.052e-05 (pre-registered, followup/validation) |

A FAIL is a result, not a defect; nothing was tuned to pass.

### Table 11. Follow-ups to the failed hypotheses (post-hoc, pre-registered)

Designed after H2 and H3 failed; each frozen with a sha256 before its data. H2 and H3 stay FAIL in Table 10.

| | mechanism | result | basis |
| --- | --- | --- | --- |
| H2b | in-session verification, shaped probe values | FAIL | best AUC 0.887 (all; all 0.887, argument 0.737, client 0.499, environment 0.499, session 0.532, timing 0.802); probe-earned recall L1 11/11, L6 10/10; false-alarm rise 8.333333333333336 pp |
| H3b | residue rules v1.1, judged on held-out upgrades | FAIL | held-out: 1/3 measured upgrades left residue (calculator: accepted, sqlite: residue, duckdb: accepted); synthetic re-run residue 45/45 pooled C0-C2, baselines beaten (Holm): True |

A follow-up that passes shows the weakness was fixable; it does not turn the original FAIL into a PASS.

## Outstanding

Every table above is populated.
