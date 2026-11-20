# DriftSentry test-case catalogue

869 test cases, as collected by pytest from DriftSentry 1.1.0. Every one passed in the full run captured in T_01_full_test_suite.png. Descriptions are the tests' own docstrings, or their names where they have none.

| Area | Test cases |
|---|---|
| Adversary and recogniser | 87 |
| Passive monitoring and calibration | 48 |
| Command line and demonstration | 25 |
| Evaluation integrity and statistics | 250 |
| Scoring and drift signals | 101 |
| Update checking and residue rules (Gap 2) | 166 |
| Proxy, injector, in-session, guard (Gap 1) | 103 |
| Probes: generation, keying, safety | 89 |

## Adversary and recogniser

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-001 | test_agent.py | The corpus has forty tasks with unique ids | The corpus has forty tasks with unique ids | Passed |
| TC-002 | test_agent.py | The corpus mixes single and multi tool work | A corpus of only short tasks would make the session family trivial. | Passed |
| TC-003 | test_agent.py | Every tool the server offers is exercised | Every tool the server offers is exercised | Passed |
| TC-004 | test_agent.py | Tasks are phrased as requests not as tool calls | A prompt containing the literal call would produce machine-shaped args. | Passed |
| TC-005 | test_agent.py | Both system prompt styles exist | Both system prompt styles exist | Passed |
| TC-006 | test_agent.py | An unrecorded host profile is reported as unrecorded | Silently falling back would make the client family trivially separable. | Passed |
| TC-007 | test_agent.py | A recorded profile is used | A recorded profile is used | Passed |
| TC-008 | test_agent.py | The fallback is not the sdk default | 'mcp' appears in no real host; using it would leak the label outright. | Passed |
| TC-009 | test_agent.py | Mcp tools become ollama functions | Mcp tools become ollama functions | Passed |
| TC-010 | test_agent.py | A tool without a schema still converts | A tool without a schema still converts | Passed |
| TC-011 | test_agent.py | A tool call the model chooses reaches the server | A tool call the model chooses reaches the server | Passed |
| TC-012 | test_agent.py | String encoded arguments are parsed | Several models return `arguments` as a JSON string, not an object. | Passed |
| TC-013 | test_agent.py | A task needing no tool makes no calls | A task needing no tool makes no calls | Passed |
| TC-014 | test_agent.py | Max steps stops a model that never finishes | A looping model must not stall the collection indefinitely. | Passed |
| TC-015 | test_agent.py | A failing tool call is recorded not raised | One bad call must not discard the rest of a session's traffic. | Passed |
| TC-016 | test_agent.py | An unreachable ollama is recorded as an error not a crash | The collector must be able to skip a model and carry on. | Passed |
| TC-017 | test_attacker_features.py | The six families exist | The six families exist | Passed |
| TC-018 | test_attacker_features.py | All is the union of the others | All is the union of the others | Passed |
| TC-019 | test_attacker_features.py | Every family returns plain numbers | DictVectorizer needs scalars. A nested value would fail far from here. | Passed |
| TC-020 | test_attacker_features.py | Timestamp and pid are never features | They label and group rows. As features they would leak run order. | Passed |
| TC-021 | test_attacker_features.py | A missing field does not crash a family | Rows from an older collection must still score. | Passed |
| TC-022 | test_attacker_features.py | The module imports nothing outside the standard library | psutil is allowed only because it is optional and guarded. | Passed |
| TC-023 | test_attacker_features.py | No environment value can reach a feature | No environment value can reach a feature | Passed |
| TC-024 | test_attacker_features.py | Argument features are computed from the values | Argument features are computed from the values | Passed |
| TC-025 | test_attacker_features.py | Entropy is zero for one repeated character | Entropy is zero for one repeated character | Passed |
| TC-026 | test_attacker_features.py | First call in a process is flagged rather than zeroed | gap_s of 0 would read as an instant repeat; -1 says 'no previous call'. | Passed |
| TC-027 | test_attacker_features.py | Client family is a one hot of name and version | Client family is a one hot of name and version | Passed |
| TC-028 | test_attacker_features.py | Missing parent is a sentinel not a zero | psutil is optional, so parent_argc is often unknown. 0 would be a lie. | Passed |
| TC-029 | test_attacker_features.py | P probe matches a hand computed logistic | One feature, known standardisation: the arithmetic is checkable by hand. | Passed |
| TC-030 | test_attacker_features.py | P probe treats an unseen feature as zero | A model trained elsewhere must not crash on a row that lacks a column. | Passed |
| TC-031 | test_attacker_features.py | P probe separates the class it was trained on | P probe separates the class it was trained on | Passed |
| TC-032 | test_attacker_features.py | P probe cannot overflow on a confident model | exp(1000) would raise. A saturated model must simply return 1.0 or 0.0. | Passed |
| TC-033 | test_attacker_features.py | P probe survives a zero scale | A constant feature has zero variance; dividing by it must not blow up. | Passed |
| TC-324 | test_l6_attacker.py | L6 is a known level and requires probe awareness | L6 is a known level and requires probe awareness | Passed |
| TC-325 | test_l6_attacker.py | A call the model calls a probe is skipped | A call the model calls a probe is skipped | Passed |
| TC-326 | test_l6_attacker.py | A call the model calls genuine fires | A call the model calls genuine fires | Passed |
| TC-327 | test_l6_attacker.py | Recognition is logged as ground truth | Without this, "recognised the probe" and "fired but was missed" look identical from outside, and the RQ3 recall figure would rest on an assumption rather than evidence. | Passed |
| TC-328 | test_l6_attacker.py | The decision threshold is one half | The decision threshold is one half | Passed |
| TC-329 | test_l6_attacker.py | A missing model fires rather than evading | An attacker that never fires looks like a perfect evasion. | Passed |
| TC-330 | test_l6_attacker.py | A corrupt model fires rather than evading | A corrupt model fires rather than evading | Passed |
| TC-331 | test_l6_attacker.py | A model that cannot score fires rather than evading | A malformed but parseable model must not be read as 'stay benign'. | Passed |
| TC-332 | test_l6_attacker.py | No features at all does not crash | No features at all does not crash | Passed |
| TC-333 | test_l6_attacker.py | The model is read once not on every call | Re-reading a file per call would give the server a disk-shaped timing signature, which is not the tell this level is meant to test. | Passed |
| TC-334 | test_l6_attacker.py | Lower levels ignore the recogniser entirely [L1] | Experiments 1 and 2 are the control. A model on disk must not touch them. | Passed |
| TC-335 | test_l6_attacker.py | Lower levels ignore the recogniser entirely [L2] | Experiments 1 and 2 are the control. A model on disk must not touch them. | Passed |
| TC-336 | test_l6_attacker.py | Lower levels ignore the recogniser entirely [L3] | Experiments 1 and 2 are the control. A model on disk must not touch them. | Passed |
| TC-337 | test_l6_attacker.py | Lower levels ignore the recogniser entirely [L4] | Experiments 1 and 2 are the control. A model on disk must not touch them. | Passed |
| TC-338 | test_l6_attacker.py | Lower levels ignore the recogniser entirely [L5] | Experiments 1 and 2 are the control. A model on disk must not touch them. | Passed |
| TC-339 | test_l6_attacker.py | Benign mode never consults the model | Benign mode never consults the model | Passed |
| TC-517 | test_replay.py | Sessions are grouped by the process that produced them | Sessions are grouped by the process that produced them | Passed |
| TC-518 | test_replay.py | Calls keep the order the model made them in | A multi-step session is a sequence; shuffling it changes its meaning. | Passed |
| TC-519 | test_replay.py | Probe traffic is never replayed | Replaying probes as if they were genuine would be circular. | Passed |
| TC-520 | test_replay.py | Rows without a tool or arguments are skipped | Rows without a tool or arguments are skipped | Passed |
| TC-521 | test_replay.py | A missing corpus is empty not an error | The harness warns and continues; an exception would kill the episode. | Passed |
| TC-522 | test_replay.py | The same seed picks the same sessions | The same seed picks the same sessions | Passed |
| TC-523 | test_replay.py | Different seeds pick differently | Different seeds pick differently | Passed |
| TC-524 | test_replay.py | Sessions touching an avoided tool are excluded | T11: an attack on a tool the agent never calls. | Passed |
| TC-525 | test_replay.py | Avoiding everything yields nothing rather than cheating | Avoiding everything yields nothing rather than cheating | Passed |
| TC-526 | test_replay.py | Loading is deterministic across calls | An episode seed must select the same traffic on a re-run. | Passed |
| TC-527 | test_replay.py | Passive findings come from the sidecar | Not from the shutdown record: a client disconnect terminates the proxy before it writes one. T1 has the measurement. | Passed |
| TC-528 | test_replay.py | No sidecar is reported as unavailable not as zero findings | Zero findings and no monitoring are different claims. | Passed |
| TC-529 | test_replay.py | A corrupt sidecar is unavailable rather than fatal | A corrupt sidecar is unavailable rather than fatal | Passed |
| TC-530 | test_replay.py | Replay is off by default | Experiments 1 and 2 are the control and must not gain extra traffic. | Passed |
| TC-531 | test_replay.py | A missing recogniser fails the episode loudly | An L6 episode without a model fires unconditionally, which would be recorded as 'the evasion did not work' - a false result. | Passed |
| TC-532 | test_replay.py | Sessions carry the pacing that produced them | Sessions carry the pacing that produced them | Passed |
| TC-533 | test_replay.py | Pacing is optional but on by default | Pacing is optional but on by default | Passed |
| TC-534 | test_replay.py | A recorded pause of minutes is capped | A user who walked away must not stall the sweep. | Passed |
| TC-535 | test_replay.py | Missing pacing does not block the call | Older corpora have no proc_age_s; they should replay, just unpaced. | Passed |
| TC-536 | test_replay.py | An episode has a wall clock ceiling | An episode has a wall clock ceiling | Passed |
| TC-537 | test_replay.py | A timed out episode is an error not a silent gap | It must be visible in the results, not merely absent from them. | Passed |
| TC-538 | test_replay.py | A normal episode is unaffected by the ceiling | A normal episode is unaffected by the ceiling | Passed |
| TC-644 | test_rq3_distinguish.py | The family carrying the signal is the one that scores | The family carrying the signal is the one that scores | Passed |
| TC-645 | test_rq3_distinguish.py | A confidence interval is reported for every family | A confidence interval is reported for every family | Passed |
| TC-646 | test_rq3_distinguish.py | Cross validation is grouped by process | Calls in one session must never be split across folds. | Passed |
| TC-647 | test_rq3_distinguish.py | Few groups do not crash the fold count | A quick collection can have fewer sessions than the requested folds. | Passed |
| TC-648 | test_rq3_distinguish.py | Every family is tested against argument not against chance | The attacker already discriminates on arguments; that is the bar. | Passed |
| TC-649 | test_rq3_distinguish.py | Comparisons are holm corrected | Comparisons are holm corrected | Passed |
| TC-650 | test_rq3_distinguish.py | Beating the reference requires a higher auc not just a small p | Beating the reference requires a higher auc not just a small p | Passed |
| TC-651 | test_rq3_distinguish.py | H3 reports the auc half only | H3 reports the auc half only | Passed |
| TC-652 | test_rq3_distinguish.py | H3 fails when no family separates | A failed hypothesis is a result and must be reported as one. | Passed |
| TC-653 | test_rq3_distinguish.py | The exported model reproduces sklearn exactly | If these disagree, T16 measures something the report does not describe. | Passed |
| TC-654 | test_rq3_distinguish.py | The export records which dataset it was fitted to | A recogniser trained on evaluation data would be circular. | Passed |
| TC-655 | test_rq3_distinguish.py | One recogniser is written per family | One recogniser is written per family | Passed |
| TC-656 | test_rq3_distinguish.py | The export has everything p probe needs | The export has everything p probe needs | Passed |
| TC-657 | test_rq3_distinguish.py | A single class dataset is refused | A single class dataset is refused | Passed |
| TC-658 | test_rq3_distinguish.py | Roc points are saved for the figures | Roc points are saved for the figures | Passed |
| TC-659 | test_rq3_distinguish.py | The report names the winning family | The report names the winning family | Passed |

## Passive monitoring and calibration

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-034 | test_calibration_math.py | Threshold is the quantile times the margin | Threshold is the quantile times the margin | Passed |
| TC-035 | test_calibration_math.py | One outlier cannot dictate the threshold | A max-based threshold would silence the detector permanently. | Passed |
| TC-036 | test_calibration_math.py | Threshold never drops below the floor | Alerting below ratio 1.0 would contradict the per-probe variance band. | Passed |
| TC-037 | test_calibration_math.py | Empty calibration set is refused | Empty calibration set is refused | Passed |
| TC-038 | test_calibration_math.py | Weak when too few servers | Weak when too few servers | Passed |
| TC-039 | test_calibration_math.py | Weak when too few observations | Weak when too few observations | Passed |
| TC-040 | test_calibration_math.py | Weak when the floor had to be applied | Weak when the floor had to be applied | Passed |
| TC-041 | test_calibration_math.py | Not weak with adequate evidence | Not weak with adequate evidence | Passed |
| TC-042 | test_calibration_math.py | Describe flags weakness in text | Describe flags weakness in text | Passed |
| TC-043 | test_calibration_math.py | Threshold is refused across embedding backends | Distances from two embedding spaces are not comparable. | Passed |
| TC-044 | test_calibration_math.py | Matching backend uses the stored threshold | Matching backend uses the stored threshold | Passed |
| TC-045 | test_calibration_math.py | Uncalibrated falls back to provisional | Uncalibrated falls back to provisional | Passed |
| TC-046 | test_calibration_math.py | Round trip preserves provenance | Round trip preserves provenance | Passed |
| TC-377 | test_passive.py | Invariants are unioned from the baseline | Invariants are unioned from the baseline | Passed |
| TC-378 | test_passive.py | Ordinary traffic produces no findings | Ordinary traffic produces no findings | Passed |
| TC-379 | test_passive.py | New egress host is high severity | New egress host is high severity | Passed |
| TC-380 | test_passive.py | Credential file read is high severity | Credential file read is high severity | Passed |
| TC-381 | test_passive.py | New child process is high severity | New child process is high severity | Passed |
| TC-382 | test_passive.py | Injection text on real traffic is caught | The exact payload the content-injection family appends. | Passed |
| TC-383 | test_passive.py | Credential shaped output is caught | Credential shaped output is caught | Passed |
| TC-384 | test_passive.py | Error state change is noticed | Error state change is noticed | Passed |
| TC-385 | test_passive.py | Untracked tool claims nothing | A side-effecting tool has no baseline, so there is nothing to diff. | Passed |
| TC-386 | test_passive.py | Semantic distance is never used | Real arguments produce responses nobody baselined. | Passed |
| TC-387 | test_passive.py | A malformed response cannot break the proxy | A malformed response cannot break the proxy | Passed |
| TC-388 | test_passive.py | Untracked response id is ignored | Untracked response id is ignored | Passed |
| TC-389 | test_passive.py | Disabled monitor does nothing | Disabled monitor does nothing | Passed |
| TC-390 | test_passive.py | Alerting is off by default | Real traffic is far more varied than canaries, so this is the highest false-alarm risk in the detector and does not get to alert unaided. | Passed |
| TC-391 | test_passive.py | Long responses are bounded | Long responses are bounded | Passed |
| TC-392 | test_passive.py | Agreement scores zero | Both channels saw the egress: no gap, no adaptive-evasion evidence. | Passed |
| TC-393 | test_passive.py | Clean probes but dirty traffic is evidence | The signature of probe-aware evasion, and nothing else produces it. | Passed |
| TC-394 | test_passive.py | No passive findings means no inconsistency | No passive findings means no inconsistency | Passed |
| TC-395 | test_passive.py | Summary reports what was seen | Summary reports what was seen | Passed |
| TC-396 | test_per_tool_calibration.py | A quiet tool gets a lower bar than a noisy one | The whole point. One global number is set by the noisiest tool. | Passed |
| TC-397 | test_per_tool_calibration.py | A tool with too few observations keeps the global threshold | A quantile from three points is an extrapolation, not a measurement. | Passed |
| TC-398 | test_per_tool_calibration.py | The minimum observation count is the boundary | The minimum observation count is the boundary | Passed |
| TC-399 | test_per_tool_calibration.py | A threshold never falls below the alert floor | Below 1.0 would mean alerting on drift smaller than benign variation. | Passed |
| TC-400 | test_per_tool_calibration.py | Provenance records how each threshold was reached | Provenance records how each threshold was reached | Passed |
| TC-401 | test_per_tool_calibration.py | The rule is recorded alongside the thresholds | The calibration servers fix the RULE; test servers supply their own data. | Passed |
| TC-402 | test_per_tool_calibration.py | Rows missing a tool or ratio are skipped not guessed | Rows missing a tool or ratio are skipped not guessed | Passed |
| TC-403 | test_per_tool_calibration.py | No rows gives no thresholds rather than an error | No rows gives no thresholds rather than an error | Passed |
| TC-404 | test_per_tool_calibration.py | Freeze then verify round trips | Freeze then verify round trips | Passed |
| TC-405 | test_per_tool_calibration.py | An edited threshold is refused | The failure mode this exists for: a quiet re-fit after seeing results. | Passed |
| TC-406 | test_per_tool_calibration.py | A file that was never frozen is refused | A file that was never frozen is refused | Passed |
| TC-407 | test_per_tool_calibration.py | Key order does not change the digest | Rewriting the file with keys in another order must still verify. | Passed |
| TC-408 | test_per_tool_calibration.py | The timestamp is not part of the digest | Two freezes of the same content agree, so a re-freeze is detectable as a content change rather than hidden by a changing timestamp. | Passed |
| TC-409 | test_per_tool_calibration.py | Per tool defaults to none and changes nothing | Per tool defaults to none and changes nothing | Passed |
| TC-410 | test_per_tool_calibration.py | A tool with its own threshold is judged by it | A tool with its own threshold is judged by it | Passed |
| TC-411 | test_per_tool_calibration.py | A tool absent from the map falls back to the global threshold | A tool absent from the map falls back to the global threshold | Passed |

## Command line and demonstration

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-047 | test_cli_update.py | Baseline takes a probe mode and keeps fixed as the default | Baseline takes a probe mode and keeps fixed as the default | Passed |
| TC-048 | test_cli_update.py | Verify update check is off by default | Verify update check is off by default | Passed |
| TC-049 | test_cli_update.py | The update is printed in the dashboards words | The update is printed in the dashboards words | Passed |
| TC-050 | test_cli_update.py | An explained update says so | An explained update says so | Passed |
| TC-173 | test_demo_menu.py | Every test arms a valid scenario | Every test arms a valid scenario | Passed |
| TC-174 | test_demo_menu.py | Keys are unique and numbered | Keys are unique and numbered | Passed |
| TC-175 | test_demo_menu.py | Every test starts from the demo baseline release | One baseline, approved on v1n, has to serve every test. | Passed |
| TC-176 | test_demo_menu.py | Gap 2 tests ship an update and gap 1 tests do not | Gap 2 tests ship an update and gap 1 tests do not | Passed |
| TC-177 | test_demo_menu.py | The sleeper turns on the clock not by chance | A call count resets with every fresh server process - measured: it never turned. And the L3 gate also fires on '@', 'key', 'token' or 'secret' in the input, so those are switched off. | Passed |
| TC-178 | test_demo_menu.py | The false alarm case is labelled as one | The false alarm case is labelled as one | Passed |
| TC-179 | test_demo_menu.py | Ground truth counts only events since the test was armed | Ground truth counts only events since the test was armed | Passed |
| TC-180 | test_demo_menu.py | The menu never imports driftsentry | The menu never imports driftsentry | Passed |
| TC-181 | test_demo_menu.py | A narrow base update keeps the narrow hints | Otherwise a C2 update against a v1n baseline would also read as a widened permission on every tool. | Passed |
| TC-182 | test_demo_menu.py | The evaluation is unaffected | narrow_base defaults off: C2 still ships on plain v1, as the RQ3a sweep measured it. | Passed |
| TC-183 | test_demo_menu.py | The daemon enrols with keyed probes and checks updates | The daemon enrols with keyed probes and checks updates | Passed |
| TC-184 | test_demo_menu.py | The update summary renders the scorers outcome | The update summary renders the scorers outcome | Passed |
| TC-185 | test_demo_menu.py | The dashboard has the update panel | The dashboard has the update panel | Passed |
| TC-186 | test_demo_menu.py | The dashboard names what the update declared | Measured on the live dashboard: without this the panel said UPDATE EXPLAINED without saying what the update declared - the one thing an examiner needs to see. | Passed |
| TC-187 | test_demo_menu.py | The residue outcome carries the declaration without touching the rules | The residue outcome carries the declaration without touching the rules | Passed |
| TC-188 | test_demo_menu.py | Every demo process gets the same home | Every demo process gets the same home | Passed |
| TC-189 | test_demo_menu.py | The home is outside localappdata | The home is outside localappdata | Passed |
| TC-190 | test_demo_menu.py | A baseline that launches the attacker differently is replaced | A baseline that launches the attacker differently is replaced | Passed |
| TC-191 | test_demo_menu.py | A fixed probe baseline is replaced | A fixed probe baseline is replaced | Passed |
| TC-192 | test_demo_menu.py | A backup is kept where the dashboard will not monitor it | Measured: a backup beside the baselines showed up as a second server. | Passed |
| TC-193 | test_demo_menu.py | The attacker cli takes a home | The attacker cli takes a home | Passed |

## Evaluation integrity and statistics

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-051 | test_conditions.py | The baseline condition has nothing switched on | 'none' must reproduce what RQ3 measured, or nothing is comparable. | Passed |
| TC-052 | test_conditions.py | Each condition adds one thing to the last | One variable at a time, or a change cannot be attributed. | Passed |
| TC-053 | test_conditions.py | Subsample is measured without the others | It targets memorisation, a different threat from recognition, so its contribution has to be separable rather than bundled. | Passed |
| TC-054 | test_conditions.py | The full condition has everything | The full condition has everything | Passed |
| TC-055 | test_conditions.py | Each kwargs helper matches the function it feeds | One dict served both calls and was wrong in both directions: it omitted subsample_bank, which verify_server does take, and included mimic_traffic, which capture_baseline does not. | Passed |
| TC-056 | test_conditions.py | Every condition explains itself | Every condition explains itself | Passed |
| TC-057 | test_conditions.py | H4 passes when all three hold | H4 passes when all three hold | Passed |
| TC-058 | test_conditions.py | H4 fails when the classifier still works | H4 fails when the classifier still works | Passed |
| TC-059 | test_conditions.py | H4 fails when detection does not come back | Flattening AUC by making probing useless is not a countermeasure. | Passed |
| TC-060 | test_conditions.py | H4 fails when detection returns by alarming on everything | H4 fails when detection returns by alarming on everything | Passed |
| TC-061 | test_conditions.py | Recall tolerance is two sided | Overshooting the no-evasion level is as suspicious as falling short. | Passed |
| TC-062 | test_conditions.py | An unmeasured full condition is undefined not failed | Not having run it is a different statement from having run it and lost. | Passed |
| TC-063 | test_conditions.py | The verdict says not to tune for it | The verdict says not to tune for it | Passed |
| TC-064 | test_conditions.py | The thresholds are the ones the plan states | The thresholds are the ones the plan states | Passed |
| TC-065 | test_conditions.py | Cost is reported beside benefit | A countermeasure that triples cycle time has to show that. | Passed |
| TC-066 | test_conditions.py | An unmeasured condition says so rather than showing zero | An unmeasured condition says so rather than showing zero | Passed |
| TC-067 | test_conditions.py | Verify server forwards every countermeasure [mimic_host] | Verify server forwards every countermeasure | Passed |
| TC-068 | test_conditions.py | Verify server forwards every countermeasure [mimic_traffic] | Verify server forwards every countermeasure | Passed |
| TC-069 | test_conditions.py | Verify server forwards every countermeasure [subsample_bank] | Verify server forwards every countermeasure | Passed |
| TC-070 | test_conditions.py | Reprobe forwards to the keyed path [mimic_traffic] | The keyed path is the only one T20 runs, so a flag that stops at reprobe has no effect at all. | Passed |
| TC-071 | test_conditions.py | Reprobe forwards to the keyed path [subsample_bank] | The keyed path is the only one T20 runs, so a flag that stops at reprobe has no effect at all. | Passed |
| TC-072 | test_conditions.py | The episode config carries the conditions | A condition that cannot reach an episode cannot be measured. | Passed |
| TC-073 | test_conditions.py | The sweep spec carries the conditions | The sweep spec carries the conditions | Passed |
| TC-074 | test_conditions.py | The collector collects under the condition | A recogniser fitted on unprotected traffic and tested on protected traffic measures staleness, not the countermeasure. | Passed |
| TC-075 | test_conditions.py | Recall counts only episodes where the attack fired | An attack that never triggered is not a miss, and counting it as one would understate the detector. | Passed |
| TC-076 | test_conditions.py | False alarms come from the benign arms only | False alarms come from the benign arms only | Passed |
| TC-077 | test_conditions.py | An unmeasured arm is nan rather than zero | Zero recall and no measurement are different claims. | Passed |
| TC-078 | test_conditions.py | The merge drops the genuine sources own probe windows | Unprotected probe traffic must never land in a protected condition's probe class - it would understate the countermeasure. | Passed |
| TC-079 | test_conditions.py | Mimic host without a recording raises | Mimic host without a recording raises | Passed |
| TC-080 | test_conditions.py | Imitating the sdk default is refused | Imitating the SDK's own name is imitating a probe. | Passed |
| TC-081 | test_conditions.py | Mimic traffic without startup times raises | A profile with gaps but no startup times cannot close the channel. | Passed |
| TC-082 | test_conditions.py | The committed fixtures are usable | They are real recordings, and the comparison cannot run without them. | Passed |
| TC-083 | test_conditions.py | An episode installs what its condition needs | An episode installs what its condition needs | Passed |
| TC-084 | test_conditions.py | Startup times are learned from the handshake | first tools/call minus initialize, per session. | Passed |
| TC-085 | test_conditions.py | A startup longer than the ceiling is dropped | A user who walked away before asking for anything is not a think time. | Passed |
| TC-086 | test_conditions.py | The startup draw is keyed and repeatable | The startup draw is keyed and repeatable | Passed |
| TC-087 | test_conditions.py | No profile means no pause rather than a guess | No profile means no pause rather than a guess | Passed |
| TC-088 | test_conditions.py | The probe loop pauses before the first call | The probe loop pauses before the first call | Passed |
| TC-089 | test_conditions.py | The pause is the remainder of a target | The pause is the remainder of a target | Passed |
| TC-090 | test_conditions.py | The first call is paced against the real process age | Measured from before the process is spawned, not from the probe loop: the handshake alone is several hundred milliseconds. | Passed |
| TC-091 | test_conditions.py | No pacing without a previous call | There is no inter-arrival gap before the first call; the startup draw covers that, and applying both would double-count. | Passed |
| TC-092 | test_conditions.py | A recorded episode is not run again | A recorded episode is not run again | Passed |
| TC-093 | test_conditions.py | Resume off runs everything | Resume off runs everything | Passed |
| TC-094 | test_conditions.py | The same episode under a different config is a conflict | Two configurations under one episode_id makes the file unreadable. | Passed |
| TC-095 | test_conditions.py | A resumed run returns only what it ran | So a caller cannot mistake the fragment for the whole sweep. | Passed |
| TC-096 | test_conditions.py | Recorded reads episode ids and hashes from disk | Recorded reads episode ids and hashes from disk | Passed |
| TC-097 | test_conditions.py | Recorded is empty when nothing has run | Recorded is empty when nothing has run | Passed |
| TC-098 | test_conditions.py | Episode id matches the harness | The two are computed in different places; if they drift, resume lies. | Passed |
| TC-099 | test_conditions.py | The cost figure survives a suspended machine | The cost figure survives a suspended machine | Passed |
| TC-100 | test_conditions.py | The stall is reported not smoothed away | A stall may be a suspend, and it may be the countermeasure blocking. Either way it is worth seeing. | Passed |
| TC-101 | test_conditions.py | Ordinary variance is not called an outlier | The threshold is loose on purpose; pruning normal variance would be choosing the cost figure. | Passed |
| TC-102 | test_conditions.py | Every cycle duration is kept | So a contaminated figure can be recomputed rather than re-measured. | Passed |
| TC-103 | test_conditions.py | An even number of cycles still has a median | An even number of cycles still has a median | Passed |
| TC-104 | test_conditions.py | No cycles is zero rather than a crash | No cycles is zero rather than a crash | Passed |
| TC-105 | test_conditions.py | An arm is read back whole however many runs wrote it | An arm is read back whole however many runs wrote it | Passed |
| TC-106 | test_conditions.py | Benign and rug pull episodes are told apart | Benign and rug pull episodes are told apart | Passed |
| TC-107 | test_conditions.py | An episode counts once however many cycles it wrote | Counting rows would weight a long episode more than a short one. | Passed |
| TC-108 | test_conditions.py | A missing arm is empty not an error | A missing arm is empty not an error | Passed |
| TC-109 | test_conditions.py | The episode outcome is tables own definition | One definition of what an episode came to, so a condition row and the tables cannot disagree. | Passed |
| TC-110 | test_conditions.py | The bank is bigger than the draw | The bank is bigger than the draw | Passed |
| TC-111 | test_conditions.py | A bank equal to the draw draws everything | Which is why n_instances == DEFAULT_DRAW was a no-op, not a bug in subsample() itself. | Passed |
| TC-112 | test_conditions.py | A draw from the real bank is a strict subset | A draw from the real bank is a strict subset | Passed |
| TC-113 | test_conditions.py | Different cycles draw differently | Otherwise the bank buys nothing: an attacker sees the same few every cycle and memorising them is as good as before. | Passed |
| TC-114 | test_conditions.py | The condition passes every flag it holds | subsample_bank was missing - the fifth flag in this project accepted and dropped. | Passed |
| TC-115 | test_conditions.py | The control passes every flag off | The control passes every flag off | Passed |
| TC-194 | test_detectors.py | Hash only sees a definition change and nothing else | The premise of the project: a behavioural rug pull leaves it untouched. | Passed |
| TC-195 | test_detectors.py | The full detector is the scorer verdict | The full detector is the scorer verdict | Passed |
| TC-196 | test_detectors.py | All three read the same report object | They must not be able to differ by anything except which signals they use. | Passed |
| TC-197 | test_detectors.py | The rule fires at or above its severity floor | The rule fires at or above its severity floor | Passed |
| TC-198 | test_detectors.py | The rule counts findings | The rule counts findings | Passed |
| TC-199 | test_detectors.py | Monitoring that never ran is not a clean result | An episode where nothing was watched and one that was watched and came back clean are different claims. Conflating them would credit passive monitoring with episodes it never saw. | Passed |
| TC-200 | test_detectors.py | An unknown severity does not crash the rule | An unknown severity does not crash the rule | Passed |
| TC-201 | test_detectors.py | The weakest clean rule is chosen | Strictness here would flatter active probing. | Passed |
| TC-202 | test_detectors.py | Calibration loosens only as far as benign noise requires | Calibration loosens only as far as benign noise requires | Passed |
| TC-203 | test_detectors.py | Benign traffic that always alarms is reported not hidden | If no rule is clean, that is the finding and must be said. | Passed |
| TC-204 | test_detectors.py | Calibration records how much benign data it saw | Calibration records how much benign data it saw | Passed |
| TC-205 | test_detectors.py | A frozen rule round trips | A frozen rule round trips | Passed |
| TC-206 | test_detectors.py | A rule edited after freezing is refused | The failure this exists for: loosening the rule once results are in. | Passed |
| TC-207 | test_detectors.py | The report compares only episodes where the attack fired | An attack that never executed is not a missed detection for anyone. | Passed |
| TC-208 | test_detectors.py | The report names the paired test and its discordant counts | The report names the paired test and its discordant counts | Passed |
| TC-209 | test_detectors.py | No fired episodes says so rather than reporting zero | No fired episodes says so rather than reporting zero | Passed |
| TC-210 | test_detectors.py | False alarms are reported beside recall | False alarms are reported beside recall | Passed |
| TC-251 | test_hardening.py | Benign noise never accumulates | Benign noise never accumulates | Passed |
| TC-252 | test_hardening.py | Gradual climb is caught without any cycle alerting | The case single-point scoring cannot see. | Passed |
| TC-253 | test_hardening.py | One elevated reading does not fire | A benign update produces a single spike, not a trend. | Passed |
| TC-254 | test_hardening.py | Accumulator is bounded | Accumulator is bounded | Passed |
| TC-255 | test_hardening.py | Rebaseline resets the accumulator | Evidence gathered against the old normal must not charge the new one. | Passed |
| TC-256 | test_hardening.py | State survives a restart | A detector for slow attacks that forgets on restart would never see one. | Passed |
| TC-257 | test_hardening.py | Reset clears only the named server | Reset clears only the named server | Passed |
| TC-258 | test_hardening.py | Calibration places k above benign | Calibration places k above benign | Passed |
| TC-259 | test_hardening.py | Correlated signals do not corroborate | Embedding and structure read the same response; they are one family. | Passed |
| TC-260 | test_hardening.py | Two independent families alert | The sub-threshold case max() misses by design. | Passed |
| TC-261 | test_hardening.py | Three mildly elevated families alert | Three mildly elevated families alert | Passed |
| TC-262 | test_hardening.py | One family alone is not corroboration | One family alone is not corroboration | Passed |
| TC-263 | test_hardening.py | A single critical signal still alerts | Corroboration only ever ADDS detections; it never removes one. | Passed |
| TC-264 | test_hardening.py | Definition change is always critical | Definition change is always critical | Passed |
| TC-265 | test_hardening.py | Unmapped signals are ignored | Better silent than dumped into a family they correlate with. | Passed |
| TC-266 | test_hardening.py | Calibration reports its own false alarm rate | Calibration reports its own false alarm rate | Passed |
| TC-267 | test_hardening.py | Transforms preserve meaning | Transforms preserve meaning | Passed |
| TC-268 | test_hardening.py | Every transform preserves meaning | The property the whole signal rests on. | Passed |
| TC-269 | test_hardening.py | Identical behaviour scores zero | Identical behaviour scores zero | Passed |
| TC-270 | test_hardening.py | Divergent egress between equivalent inputs is evidence | The probe-gating signature: benign for one, malicious for the other. | Passed |
| TC-271 | test_hardening.py | Divergent security flags are evidence | Divergent security flags are evidence | Passed |
| TC-272 | test_hardening.py | Content differences alone are not evidence | Two different search phrases legitimately return different results. | Passed |
| TC-273 | test_hardening.py | Empty samples are safe | Empty samples are safe | Passed |
| TC-274 | test_hardening.py | Interval jitters but averages to the base | Interval jitters but averages to the base | Passed |
| TC-275 | test_hardening.py | Interval is reproducible from the key | Interval is reproducible from the key | Passed |
| TC-276 | test_hardening.py | Probe order varies across cycles | Probe order varies across cycles | Passed |
| TC-277 | test_hardening.py | Probe count varies but never reaches zero | Probe count varies but never reaches zero | Passed |
| TC-278 | test_hardening.py | Residual session tells are enumerated | The honest half: these are the fingerprints camouflage does NOT remove. | Passed |
| TC-279 | test_hardening.py | Planted files carry unique keyed tokens | Planted files carry unique keyed tokens | Passed |
| TC-280 | test_hardening.py | Tokens are keyed so a server cannot forge one | Tokens are keyed so a server cannot forge one | Passed |
| TC-281 | test_hardening.py | Reading a tripwire is detected | Reading a tripwire is detected | Passed |
| TC-282 | test_hardening.py | Token in the sink proves exfiltration | Opening a file might be indiscriminate scanning; the token leaving is not. | Passed |
| TC-283 | test_hardening.py | Tripwire contents are obviously synthetic | Tripwire contents are obviously synthetic | Passed |
| TC-284 | test_hardening.py | Tripwire weights rank exfiltration above reading | Tripwire weights rank exfiltration above reading | Passed |
| TC-412 | test_prereg_line_endings.py | Crlf record verifies after an lf checkout | Crlf record verifies after an lf checkout | Passed |
| TC-413 | test_prereg_line_endings.py | Lf record verifies after a crlf checkout | Lf record verifies after a crlf checkout | Passed |
| TC-414 | test_prereg_line_endings.py | A changed character still fails | A changed character still fails | Passed |
| TC-458 | test_real_envs.py | Date based versions sort newest first | The official servers use dates, so string order is nearly right and numerically wrong in exactly the places that matter. | Passed |
| TC-459 | test_real_envs.py | Semver sorts numerically not lexically | Semver sorts numerically not lexically | Passed |
| TC-460 | test_real_envs.py | A strange version does not raise | An unparseable version must not take down a run mid-sweep. | Passed |
| TC-461 | test_real_envs.py | Pips own resolution is tried first and costs nothing | For a current release pip is right, and a walk would be wasted installs. | Passed |
| TC-462 | test_real_envs.py | The walk takes the newest sdk that starts | Newest-first, because that is closest to how the release was deployed. | Passed |
| TC-463 | test_real_envs.py | The walk is bounded | An unresolved server is reported, not searched for indefinitely. | Passed |
| TC-464 | test_real_envs.py | Every attempt keeps the servers own error | The error text is what identified the SDK mismatch; a boolean hides it. | Passed |
| TC-465 | test_real_envs.py | An install failure during the walk is recorded not raised | One unbuildable SDK must not end the search for a working one. | Passed |
| TC-466 | test_real_envs.py | No sdk walk reproduces the unmeasurable result | resolve=False must fail the way the first run failed, not quietly fix it. | Passed |
| TC-467 | test_real_envs.py | A package that imports is not a server that runs | pip reporting success says nothing: the failure is at the server's own import of the SDK decorator, which is after pip is done. | Passed |
| TC-468 | test_real_envs.py | A handshake that hangs is a failure not a wait | A handshake that hangs is a failure not a wait | Passed |
| TC-469 | test_real_envs.py | The tool list comes back parsed | The tool list comes back parsed | Passed |
| TC-470 | test_real_envs.py | Tool names survives rubbish | Tool names survives rubbish | Passed |
| TC-471 | test_real_envs.py | A yanked release is not offered | Pinning a yanked version installs something nobody ships. | Passed |
| TC-472 | test_real_envs.py | The sdk walk starts at the releases own date | Measured 9 Nov: newest-first from today, bounded at eight attempts, never reached the SDK an early-2025 release was written against. | Passed |
| TC-473 | test_real_envs.py | An unknown release date falls back to every sdk | An unknown release date falls back to every sdk | Passed |
| TC-474 | test_real_run.py | The default set is the local no network one | Anything that reaches someone else's service must be chosen, not arrived at by accident. | Passed |
| TC-475 | test_real_run.py | A name that is not in the file is an error not a silent skip | A name that is not in the file is an error not a silent skip | Passed |
| TC-476 | test_real_run.py | Every candidate has both versions and an entry point | Every candidate has both versions and an entry point | Passed |
| TC-477 | test_real_run.py | Label is still the users call | The file says label is a reading of intent and therefore not mine. If one ever gets filled in by code rather than by the user, this fails. | Passed |
| TC-478 | test_real_run.py | A writing tool is withheld with the reason | git_commit must never be probed, and the write-up needs to say why. | Passed |
| TC-479 | test_real_run.py | The live tool list is used not the guess in the json | real_servers.json says its tool lists are unconfirmed guesses. A guess must not widen what gets called. | Passed |
| TC-480 | test_real_run.py | A tool the guess called safe and the classifier refuses is logged | A tool the guess called safe and the classifier refuses is logged | Passed |
| TC-481 | test_real_run.py | A server with nothing confirmed is reported not probed | Failing closed can leave nothing to probe. That is an outcome, not a reason to relax the policy. | Passed |
| TC-482 | test_real_run.py | A read only annotation is positive evidence | Some servers say so themselves, and that is the strongest signal. | Passed |
| TC-483 | test_real_run.py | A server that will not start is not silently empty | A server that will not start is not silently empty | Passed |
| TC-484 | test_real_run.py | A server that could not be built is listed not dropped | "Two of four candidates could not be installed" is part of the answer to Gap 3, not a blank in the table. | Passed |
| TC-485 | test_real_run.py | The noise phase is reported beside the upgrade | A detector that alarms on its own release has no upgrade rate to report. mcp-server-git is that case and the table must show it. | Passed |
| TC-486 | test_real_run.py | Hash pinning is counted separately | Hash pinning is counted separately | Passed |
| TC-487 | test_real_run.py | An sdk pin found by walking is named in the report | "This release needs mcp<=X" is a finding about the ecosystem, so it belongs in the output rather than only in a log line. | Passed |
| TC-488 | test_real_run.py | Nothing measured produces no pooled rate | A pooled rate over zero runs would print as a number. | Passed |
| TC-489 | test_real_run.py | A run with nothing declared takes the base detectors verdict | A run with nothing declared takes the base detectors verdict | Passed |
| TC-490 | test_real_run.py | A quiet run with nothing declared is accepted | A quiet run with nothing declared is accepted | Passed |
| TC-491 | test_real_run.py | A declared update records the checkers outcome | A declared update records the checkers outcome | Passed |
| TC-492 | test_real_run.py | The noise phase is never update checked | The same release against its own baseline declared nothing; scoring it as an update would only rename the base detector's verdict. | Passed |
| TC-493 | test_real_run.py | The default run is exactly the approved servers | The default run is exactly the approved servers | Passed |
| TC-494 | test_real_run.py | The cli default is the approved set | The cli default is the approved set | Passed |
| TC-495 | test_real_run.py | Motherduck never points at the cloud | Motherduck never points at the cloud | Passed |
| TC-496 | test_real_run.py | Placeholders fill from the fixture | Placeholders fill from the fixture | Passed |
| TC-497 | test_real_run.py | A sqlite fixture is created once and holds the seed | A sqlite fixture is created once and holds the seed | Passed |
| TC-498 | test_real_run.py | An unknown fixture kind is refused | An unknown fixture kind is refused | Passed |
| TC-499 | test_real_run.py | The launch carries only the servers own environment | The launch carries only the servers own environment | Passed |
| TC-616 | test_rq3_dataset.py | Rows are labelled from the window that contains them | Rows are labelled from the window that contains them | Passed |
| TC-617 | test_rq3_dataset.py | Group is the process not the row | Calls inside one process share a client, a cwd and a session counter. | Passed |
| TC-618 | test_rq3_dataset.py | Rows between sessions are dropped not guessed | Startup and teardown traffic belongs to no session. | Passed |
| TC-619 | test_rq3_dataset.py | Overlapping windows fail the build | Two sessions at once means rows with no defined label. | Passed |
| TC-620 | test_rq3_dataset.py | A process serving both labels fails the build | A mixed group would leak a session across a train/test split. | Passed |
| TC-621 | test_rq3_dataset.py | In session traffic may mix labels within one process | H2b: probes ride the client's own session, so one process sees both. | Passed |
| TC-622 | test_rq3_dataset.py | A row without a timestamp fails rather than being dropped | A row without a timestamp fails rather than being dropped | Passed |
| TC-623 | test_rq3_dataset.py | No windows is an error not an empty dataset | No windows is an error not an empty dataset | Passed |
| TC-624 | test_rq3_dataset.py | No feature rows is an error | No feature rows is an error | Passed |
| TC-625 | test_rq3_dataset.py | Baseline traffic is excluded by the recorded cutoff | Baselining probes once, with a different sample count. | Passed |
| TC-626 | test_rq3_dataset.py | An explicit cutoff overrides the recorded one | An explicit cutoff overrides the recorded one | Passed |
| TC-627 | test_rq3_dataset.py | A row exactly on a boundary is inside the window | A row exactly on a boundary is inside the window | Passed |
| TC-628 | test_rq3_dataset.py | Windows are not widened to catch stragglers | Widening risks swallowing a neighbour's first call. | Passed |
| TC-629 | test_rq3_dataset.py | Describe reports the shape for the checkpoint | Describe reports the shape for the checkpoint | Passed |
| TC-630 | test_rq3_dataset.py | Windows are on disk before the collection ends | Windows are on disk before the collection ends | Passed |
| TC-631 | test_rq3_dataset.py | A new run does not inherit the previous run s windows | Stale labels joined to fresh rows would mislabel silently. | Passed |
| TC-632 | test_rq3_dataset.py | A recycled pid is two processes not one | The false failure that stopped a completed 120-session collection. | Passed |
| TC-633 | test_rq3_dataset.py | Calls from one process stay in one group | The property the grouping exists for, which must still hold. | Passed |
| TC-634 | test_rq3_dataset.py | Genuinely overlapping sessions still fail | Recycling is excused; a real overlap must not be. | Passed |
| TC-635 | test_rq3_dataset.py | Process start is recovered exactly | features.py derives t and proc_age_s from one time.time() call. | Passed |
| TC-636 | test_rq3_dataset.py | Appending under a stale header is refused | Appending under a stale header is refused | Passed |
| TC-637 | test_rq3_dataset.py | The old file is kept not overwritten | The old file is kept not overwritten | Passed |
| TC-638 | test_rq3_dataset.py | A matching header appends normally | A matching header appends normally | Passed |
| TC-639 | test_rq3_dataset.py | A fresh file writes the current header | A fresh file writes the current header | Passed |
| TC-640 | test_rq3_dataset.py | A prefix header is appended to under its own columns | A prefix header is appended to under its own columns | Passed |
| TC-641 | test_rq3_dataset.py | A row with values in a column the file lacks is refused | Writing it would drop the values silently. | Passed |
| TC-642 | test_rq3_dataset.py | A prefix file keeps its rows | A prefix file keeps its rows | Passed |
| TC-643 | test_rq3_dataset.py | Every existing results file is a prefix of todays header | The property the prefix rule rests on, checked on the real files. | Passed |
| TC-660 | test_rq3u_analyse.py | A clear win passes | A clear win passes | Passed |
| TC-661 | test_rq3u_analyse.py | One of seven real upgrades with residue is within 15 percent | One of seven real upgrades with residue is within 15 percent | Passed |
| TC-662 | test_rq3u_analyse.py | Two of seven real upgrades with residue fails | Two of seven real upgrades with residue fails | Passed |
| TC-663 | test_rq3u_analyse.py | Low detection fails | Low detection fails | Passed |
| TC-664 | test_rq3u_analyse.py | No advantage over the baselines fails | Residue at 100% is not enough if the baselines detect as much. | Passed |
| TC-665 | test_rq3u_analyse.py | Missing real upgrades is not decidable not a pass | Missing real upgrades is not decidable not a pass | Passed |
| TC-666 | test_rq3u_analyse.py | Never triggered attacks leave the denominator | Never triggered attacks leave the denominator | Passed |
| TC-667 | test_rq3u_analyse.py | An episode counts once however many cycles | An episode counts once however many cycles | Passed |
| TC-668 | test_rq3u_analyse.py | A baseline beating residue is not residues significance | Direction matters: b10 > b01 must never read as residue doing better. | Passed |
| TC-669 | test_rq3u_analyse.py | C3 reports evasions that needed an escalation | C3 reports evasions that needed an escalation | Passed |
| TC-670 | test_rq3u_analyse.py | C3 is kept out of the pooled h3 figure | C3 is kept out of the pooled h3 figure | Passed |
| TC-671 | test_rq3u_analyse.py | Benign updates give a false alarm rate per condition | Benign updates give a false alarm rate per condition | Passed |
| TC-672 | test_rq3u_analyse.py | A real upgrade with any residue run counts against h3 | The strict reading: one alarm on a benign upgrade is one a user saw. | Passed |
| TC-740 | test_stats.py | Wilson matches statsmodels | Wilson matches statsmodels | Passed |
| TC-741 | test_stats.py | Wilson does not claim certainty from six observations | The reason this is not a normal-approximation interval. | Passed |
| TC-742 | test_stats.py | Wilson handles an empty sample | Wilson handles an empty sample | Passed |
| TC-743 | test_stats.py | Mcnemar on a known table | b01 = 8, b10 = 1. Exact binomial two-sided p = 2 * P(X <= 1 / 9, 0.5). | Passed |
| TC-744 | test_stats.py | Mcnemar reports the discordant counts not just a p value | A tiny p from two disagreements is not strong evidence. | Passed |
| TC-745 | test_stats.py | Identical detectors give no evidence of a difference | Identical detectors give no evidence of a difference | Passed |
| TC-746 | test_stats.py | Mcnemar rejects unpaired inputs | Mcnemar rejects unpaired inputs | Passed |
| TC-747 | test_stats.py | Symmetric disagreement is not evidence either way | Ten each way is a lot of disagreement and no reason to prefer either. | Passed |
| TC-748 | test_stats.py | Pairing finds a difference that marginals alone would miss | Why H2 is paired rather than two independent proportions. | Passed |
| TC-749 | test_stats.py | Holm matches statsmodels and keeps input order | Holm matches statsmodels and keeps input order | Passed |
| TC-750 | test_stats.py | Holm is why five families are not tested naively | Five p-values just under 0.05 are not five findings. | Passed |
| TC-751 | test_stats.py | Holm on nothing | Holm on nothing | Passed |
| TC-752 | test_stats.py | Bootstrap auc point estimate matches sklearn | Bootstrap auc point estimate matches sklearn | Passed |
| TC-753 | test_stats.py | Resampling groups gives a wider interval than resampling rows | The whole reason the signature takes `groups`. | Passed |
| TC-754 | test_stats.py | Bootstrap is reproducible from its seed | Bootstrap is reproducible from its seed | Passed |
| TC-755 | test_stats.py | Single class resamples are skipped not scored as half | Substituting 0.5 for an undefined AUC would drag the interval inward. | Passed |
| TC-756 | test_stats.py | Delong aucs equal sklearn | Delong aucs equal sklearn | Passed |
| TC-757 | test_stats.py | The same scores twice give p of one | The same scores twice give p of one | Passed |
| TC-758 | test_stats.py | A clearly better classifier is detected | A clearly better classifier is detected | Passed |
| TC-759 | test_stats.py | Two equally useless classifiers are not called different | Two equally useless classifiers are not called different | Passed |
| TC-760 | test_stats.py | Delong handles ties through midranks | Scores from a coarse model are full of ties; ranks must be averaged. | Passed |
| TC-761 | test_stats.py | Delong needs both classes | Delong needs both classes | Passed |
| TC-762 | test_stats.py | Exact mcnemar matches statsmodels without needing it | Computed directly since Application Control blocked statsmodels' pandas DLL on 9 Nov. Must give exactly what statsmodels gives. | Passed |
| TC-763 | test_stats.py | Exact mcnemar known value | Exact mcnemar known value | Passed |
| TC-764 | test_stats.py | Wilson matches statsmodels without needing it | Wilson matches statsmodels without needing it | Passed |
| TC-765 | test_stats.py | Holm matches statsmodels without needing it | Holm matches statsmodels without needing it | Passed |
| TC-785 | test_tables.py | An episode counts once however many cycles it wrote | A four-cycle episode and a one-cycle episode are one attack each. | Passed |
| TC-786 | test_tables.py | An episode detected in any cycle is detected | Detection is a property of the episode: catching it on cycle 3 is catching it. | Passed |
| TC-787 | test_tables.py | The sweeps are reported separately not pooled | The L1 sweeps differ only in a recogniser that L1 ignores, so pooling them would report an interval narrower than the design supports. | Passed |
| TC-788 | test_tables.py | The quoted interval comes from one replication | The quoted interval comes from one replication | Passed |
| TC-789 | test_tables.py | An absent file says so rather than reporting zero | An absent file says so rather than reporting zero | Passed |
| TC-790 | test_tables.py | A missing table names the command that would produce it | A missing table names the command that would produce it | Passed |
| TC-791 | test_tables.py | Experiment two is called out as never run | Its log holds one line and there is no result file. The fixed-against- keyed comparison is the detector's own contribution, so an absent arm has to be loud. | Passed |
| TC-792 | test_tables.py | The summary lists everything outstanding | The summary lists everything outstanding | Passed |
| TC-793 | test_tables.py | A populated run says so | The outstanding section must be able to come back empty, or it is decoration rather than a check. | Passed |
| TC-794 | test_tables.py | An attack that never fired is not counted as a miss | A server that held back during every probe cycle presented nothing to detect. Counting it as a miss would penalise the detector for an attack that did not happen. | Passed |
| TC-795 | test_tables.py | Held back episodes are reported not dropped | At L4 with fixed probes every episode held back. That is the evasion the keyed generator exists to remove, so it has to appear. | Passed |
| TC-796 | test_tables.py | A failed upgrade run is visible | Two servers could not be measured at all. An absent row would read as a server that was fine. | Passed |
| TC-797 | test_tables.py | Same release alarms are shown beside upgrade alarms | git alarms with nothing changed at all, which is a sharper finding than an upgrade alarm and must not be folded into one number. | Passed |
| TC-798 | test_tables.py | No result file is not measured | No result file is not measured | Passed |
| TC-799 | test_tables.py | Measured with nothing fired is undefined not missing | The environment arm: 18 episodes ran, none attacked. | Passed |
| TC-800 | test_tables.py | Measured with fired episodes is a rate | Measured with fired episodes is a rate | Passed |
| TC-801 | test_tables.py | An undefined arm produces no drop figure | Reported as -100.0pp it would read as perfect evasion, which is the opposite of what happened. | Passed |
| TC-802 | test_tables.py | The numbering map is the plans | The numbering map is the plans | Passed |
| TC-803 | test_tables.py | Relabel is one pass and leaves lookalikes alone | RQ1 -> RQ3b and RQ3 -> RQ1 must not chain into each other. | Passed |
| TC-804 | test_tables.py | No table title uses the old numbering | No table title uses the old numbering | Passed |
| TC-805 | test_tables.py | New tables say not measured rather than zero | New tables say not measured rather than zero | Passed |
| TC-806 | test_tables.py | The hypothesis table never passes on missing data | The hypothesis table never passes on missing data | Passed |

## Scoring and drift signals

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-116 | test_coverage_and_fielddrift.py | Categories respect schema constraints | Categories respect schema constraints | Passed |
| TC-117 | test_coverage_and_fielddrift.py | Enums and consts have nothing to vary | Enums and consts have nothing to vary | Passed |
| TC-118 | test_coverage_and_fielddrift.py | Numeric fields get numeric categories | Numeric fields get numeric categories | Passed |
| TC-119 | test_coverage_and_fielddrift.py | Least used category is preferred | Least used category is preferred | Passed |
| TC-120 | test_coverage_and_fielddrift.py | Coverage reaches the conditional attack trigger | The measured reason this exists. | Passed |
| TC-121 | test_coverage_and_fielddrift.py | Sensitive lookalike values contain no real secrets | It must LOOK interesting to an attacker without BEING interesting. | Passed |
| TC-122 | test_coverage_and_fielddrift.py | Coverage model round trips | Coverage model round trips | Passed |
| TC-123 | test_coverage_and_fielddrift.py | Field classification [endpoint-https://api.example.com/v1-url] | Field classification | Passed |
| TC-124 | test_coverage_and_fielddrift.py | Field classification [recipient-dana@northgate.example-email] | Field classification | Passed |
| TC-125 | test_coverage_and_fielddrift.py | Field classification [account-382910-account] | Field classification | Passed |
| TC-126 | test_coverage_and_fielddrift.py | Field classification [amount-GBP 1200.00-money] | Field classification | Passed |
| TC-127 | test_coverage_and_fielddrift.py | Field classification [ref-CUS-48217-identifier] | Field classification | Passed |
| TC-128 | test_coverage_and_fielddrift.py | Field classification [status-active-status] | Field classification | Passed |
| TC-129 | test_coverage_and_fielddrift.py | Field classification [path-docs/report.md-path] | Field classification | Passed |
| TC-130 | test_coverage_and_fielddrift.py | Field classification [summary-The quarterly review is complete.-text] | Field classification | Passed |
| TC-131 | test_coverage_and_fielddrift.py | Field classification [count-42-number] | Field classification | Passed |
| TC-132 | test_coverage_and_fielddrift.py | Field classification [enabled-True-boolean] | Field classification | Passed |
| TC-133 | test_coverage_and_fielddrift.py | Flatten collapses list indices | Flatten collapses list indices | Passed |
| TC-134 | test_coverage_and_fielddrift.py | Volatile fields are learned not listed | No allow-list of field names: volatility is observed from the tool. | Passed |
| TC-135 | test_coverage_and_fielddrift.py | Volatile movement alone scores zero | Timestamps changing must never look like tampering. | Passed |
| TC-136 | test_coverage_and_fielddrift.py | One digit account change scores maximum | One digit account change scores maximum | Passed |
| TC-137 | test_coverage_and_fielddrift.py | Recipient redirect is caught | The postmark-mcp pattern: the answer looks right, the address does not. | Passed |
| TC-138 | test_coverage_and_fielddrift.py | Prose rewording scores low | A benign update rewords text; that must not reach the alert line. | Passed |
| TC-139 | test_coverage_and_fielddrift.py | Identity change outranks prose change | Identity change outranks prose change | Passed |
| TC-140 | test_coverage_and_fielddrift.py | Masking replaces only volatile leaves | Masking replaces only volatile leaves | Passed |
| TC-141 | test_coverage_and_fielddrift.py | No profiles means no signal | A v1 baseline has no field profiles; the signal is unavailable, not wrong. | Passed |
| TC-142 | test_coverage_and_fielddrift.py | Profile round trips | Profile round trips | Passed |
| TC-211 | test_determinism_signal.py | Identical samples are marked deterministic | Identical samples are marked deterministic | Passed |
| TC-212 | test_determinism_signal.py | A varying probe is not deterministic | A varying probe is not deterministic | Passed |
| TC-213 | test_determinism_signal.py | A thin baseline is never treated as deterministic | Two identical samples prove nothing, and treating them as proof would turn every hastily captured baseline into a hair-trigger. | Passed |
| TC-214 | test_determinism_signal.py | Small change on a deterministic probe was previously missed | Without the signal, a tiny edit sits comfortably under the alert line. | Passed |
| TC-215 | test_determinism_signal.py | The same change now alerts | The same change now alerts | Passed |
| TC-216 | test_determinism_signal.py | It does not fire on a naturally varying probe | The signal is only ever set for probes that earned it, so a noisy tool is untouched - this is what keeps the false-alarm cost bounded. | Passed |
| TC-217 | test_determinism_signal.py | It stays below the strong security rules | Ordering matters: 'this changed at all' is weaker evidence than 'this contacted a host it never contacted', and the score must say so. | Passed |
| TC-218 | test_determinism_signal.py | Old baselines without text hashes never trigger it | Backward compatibility: a v1 baseline has no text hashes, so the check is simply unavailable rather than wrongly firing. | Passed |
| TC-219 | test_family_band.py | A random tool does not alarm on an honest cycle | The 100% false-alarm case, in miniature. | Passed |
| TC-220 | test_family_band.py | The band covers individual samples not averages of them | The band must be commensurable with what compare_to_family measures. | Passed |
| TC-221 | test_family_band.py | More samples does not make an honest cycle look worse | The tell that found the defect. | Passed |
| TC-222 | test_family_band.py | A real change still leaves the band | A wider band must not swallow an actual attack. | Passed |
| TC-223 | test_family_band.py | A deterministic tool keeps the noise floor | Zero scatter must not produce a zero band - that divides by nothing. | Passed |
| TC-224 | test_family_band.py | A one sample family does not crash | A one sample family does not crash | Passed |
| TC-225 | test_family_band.py | Comparability still measures input sensitivity not noise | A noisy tool whose answer does not depend on the INPUT stays comparable. | Passed |
| TC-226 | test_family_band.py | Comparability falls when the input really does change the answer | Comparability falls when the input really does change the answer | Passed |
| TC-349 | test_observed_definitions.py | An added output field does not change the definition hash | So definition_changed is False for a C2 cover change, and the residue check cannot be triggered off the hash. | Passed |
| TC-350 | test_observed_definitions.py | A widened annotation does not change the definition hash | A C3 escalation - readOnly removed, open-world added - is invisible to pinning. That is a finding for Gap 1, not only a detail for Gap 2. | Passed |
| TC-351 | test_observed_definitions.py | An input schema change does change the hash | The hash is not useless: it covers name, description and inputSchema. | Passed |
| TC-352 | test_observed_definitions.py | The report keeps the definitions it saw | The report keeps the definitions it saw | Passed |
| TC-353 | test_observed_definitions.py | The kept definitions include output schema and annotations | Both are dropped by the hash, and both are what the rules table keys on, so losing them anywhere makes residue checking impossible. | Passed |
| TC-354 | test_observed_definitions.py | A report built without the field still works | Every existing caller and test constructs ReprobeReport positionally or by keyword without this field. | Passed |
| TC-355 | test_observed_definitions.py | Two reports do not share one list | A mutable default would make every report alias the same list. | Passed |
| TC-356 | test_observed_definitions.py | The hash and the definitions can disagree about change | The case the whole task exists for: identical hash, different definitions. | Passed |
| TC-357 | test_observed_definitions.py | A baseline file written before this task still loads | The fixed-probe baseline is the control condition the whole evaluation compares against. A file that stops loading invalidates it. | Passed |
| TC-358 | test_observed_definitions.py | A baseline round trips through json with definitions | A baseline round trips through json with definitions | Passed |
| TC-359 | test_observed_definitions.py | The baseline keeps the full definition not the hashed subset | capture_baseline stores model_dump(mode='json'), so outputSchema and annotations survive. If that ever narrows to the hashed fields, residue checking loses its reference side. | Passed |
| TC-360 | test_observed_definitions.py | A real reprobe carries the definitions it saw | A real reprobe carries the definitions it saw | Passed |
| TC-361 | test_observed_definitions.py | An unset hint comes back as none not as a missing key | So the differ cannot use `in annotations` to mean "explicitly set": that would call every tool explicitly destructive. | Passed |
| TC-362 | test_observed_definitions.py | Definitions are dumped with wire names | Definitions are dumped with wire names | Passed |
| TC-363 | test_observed_definitions.py | By alias changes nothing the hash or differ read on this sdk | By alias changes nothing the hash or differ read on this sdk | Passed |
| TC-500 | test_redact.py | Echoed argument is replaced | Echoed argument is replaced | Passed |
| TC-501 | test_redact.py | Two values of one family become identical | The whole point: same template, different value, same redacted form. | Passed |
| TC-502 | test_redact.py | Redaction collapses cross input distance | Measured on the adversarial server's real response templates. | Passed |
| TC-503 | test_redact.py | Tool output is left alone | Only the input is removed. Everything the tool contributed must survive, because a change in that is exactly what the detector is looking for. | Passed |
| TC-504 | test_redact.py | An attack payload survives redaction | Redaction must not accidentally hide the thing being detected. | Passed |
| TC-505 | test_redact.py | Case and whitespace variants are handled | Tools tidy their input before echoing it - .strip() is near-universal. | Passed |
| TC-506 | test_redact.py | Path tail is matched | Path tail is matched | Passed |
| TC-507 | test_redact.py | Short values are not redacted | A two-character argument would match all over an unrelated response and destroy far more signal than the echo it removes. | Passed |
| TC-508 | test_redact.py | Nested and list arguments | Nested and list arguments | Passed |
| TC-509 | test_redact.py | Non string and empty arguments are safe [args0] | Non string and empty arguments are safe | Passed |
| TC-510 | test_redact.py | Non string and empty arguments are safe [None] | Non string and empty arguments are safe | Passed |
| TC-511 | test_redact.py | Non string and empty arguments are safe [args2] | Non string and empty arguments are safe | Passed |
| TC-512 | test_redact.py | Non string and empty arguments are safe [args3] | Non string and empty arguments are safe | Passed |
| TC-513 | test_redact.py | Non string and empty arguments are safe [args4] | Non string and empty arguments are safe | Passed |
| TC-514 | test_redact.py | Longest value is substituted first | Replacing a short value nested inside a longer one first would corrupt the longer match before it is reached. | Passed |
| TC-515 | test_redact.py | Echo ratio reflects how much was input | Echo ratio reflects how much was input | Passed |
| TC-516 | test_redact.py | Minimum value length is conservative | Minimum value length is conservative | Passed |
| TC-727 | test_scorer_golden.py | Benign scores below watch | ratio 0.5 against threshold 2.0 -> 0.25 evidence units, well clear of watch. | Passed |
| TC-728 | test_scorer_golden.py | Behavioural drift alerts and is capped | The behavioural signal saturates at W_BEHAVIOURAL_MAX. | Passed |
| TC-729 | test_scorer_golden.py | Structural change alone is watch not alert | Structure moving on its own is deliberately below the alert line. | Passed |
| TC-730 | test_scorer_golden.py | New egress host is high severity | New egress host is high severity | Passed |
| TC-731 | test_scorer_golden.py | Secret file read is high severity | Secret file read is high severity | Passed |
| TC-732 | test_scorer_golden.py | Ordinary new file is medium | Ordinary new file is medium | Passed |
| TC-733 | test_scorer_golden.py | Definition hash change dominates | Definition hash change dominates | Passed |
| TC-734 | test_scorer_golden.py | Definition change alerts even with no probeable tools | Definition change alerts even with no probeable tools | Passed |
| TC-735 | test_scorer_golden.py | Signals combine by maximum not sum | Three mid-strength signals must NOT accumulate into a higher score. | Passed |
| TC-736 | test_scorer_golden.py | Worst probe decides the tool | An attack that fires on only some inputs must not be averaged away. | Passed |
| TC-737 | test_scorer_golden.py | Hash only mode discards every behavioural signal | The control condition must see nothing but the definition hash. | Passed |
| TC-738 | test_scorer_golden.py | Hash only mode still catches a definition change | Hash only mode still catches a definition change | Passed |
| TC-739 | test_scorer_golden.py | Threshold normalises across noisy and quiet tools | A noisy tool and a deterministic one must alert at the same score. | Passed |
| TC-857 | test_variance_math.py | Identical vectors have zero distance | Identical vectors have zero distance | Passed |
| TC-858 | test_variance_math.py | Distance is clamped to non negative | Floating-point error can push cosine just outside [-1, 1]. | Passed |
| TC-859 | test_variance_math.py | Orthogonal vectors are distance one | Orthogonal vectors are distance one | Passed |
| TC-860 | test_variance_math.py | Empty vectors do not divide by zero | Empty vectors do not divide by zero | Passed |
| TC-861 | test_variance_math.py | Leave one out is wider than in sample | The bug this replaced. | Passed |
| TC-862 | test_variance_math.py | Leave one out falls back below three samples | Nothing to hold out with fewer than three; documented as optimistic. | Passed |
| TC-863 | test_variance_math.py | Identical samples give zero spread | Identical samples give zero spread | Passed |
| TC-864 | test_variance_math.py | Deterministic tool gets the noise floor not zero | A zero-width band would divide by zero in the scorer. | Passed |
| TC-865 | test_variance_math.py | Noisy tool gets a band above the floor | Noisy tool gets a band above the floor | Passed |
| TC-866 | test_variance_math.py | Band covers both worst case and sigma rule | Band covers both worst case and sigma rule | Passed |
| TC-867 | test_variance_math.py | Structure ignores values but notices new fields | Structure ignores values but notices new fields | Passed |
| TC-868 | test_variance_math.py | List length is not a structural change | List length is not a structural change | Passed |
| TC-869 | test_variance_math.py | Error flag is carried through | Error flag is carried through | Passed |

## Update checking and residue rules (Gap 2)

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-143 | test_declared_diff.py | Identical lists are empty | Identical lists are empty | Passed |
| TC-144 | test_declared_diff.py | Tool order is ignored | Tool order is ignored | Passed |
| TC-145 | test_declared_diff.py | Key order is ignored | Key order is ignored | Passed |
| TC-146 | test_declared_diff.py | An added output field is found at its path | The C2 cover change: lookup_customer gains last_contact. | Passed |
| TC-147 | test_declared_diff.py | A nested property change is found at the nested path | A nested property change is found at the nested path | Passed |
| TC-148 | test_declared_diff.py | An added required parameter | An added required parameter | Passed |
| TC-149 | test_declared_diff.py | An existing parameter becoming required | An existing parameter becoming required | Passed |
| TC-150 | test_declared_diff.py | An annotation flip true to false is an escalation | An annotation flip true to false is an escalation | Passed |
| TC-151 | test_declared_diff.py | An explicit narrow hint dropped to absent is an escalation | true -> absent is a widening too: absent defaults to false. | Passed |
| TC-152 | test_declared_diff.py | Absent to explicit default is not an escalation | Nothing a tool may do changed, so it is not even a declared change. | Passed |
| TC-153 | test_declared_diff.py | A new tool and a removed tool | A new tool and a removed tool | Passed |
| TC-154 | test_declared_diff.py | Open world added is an escalation | The C3 cover for egress families. | Passed |
| TC-155 | test_declared_diff.py | Destructive added is an escalation | Destructive added is an escalation | Passed |
| TC-156 | test_declared_diff.py | Narrowing is recorded but is not an escalation | Narrowing is recorded but is not an escalation | Passed |
| TC-157 | test_declared_diff.py | A defaulted hint can never be widened | Every default is already the permissive value. | Passed |
| TC-158 | test_declared_diff.py | Escalations are listed across the whole diff | Escalations are listed across the whole diff | Passed |
| TC-159 | test_declared_diff.py | Null hints are not explicit | Measured: unset hints arrive as null, not as missing keys. Reading `"destructiveHint" in annotations` as explicit would call every tool explicitly destructive. | Passed |
| TC-160 | test_declared_diff.py | A tool that starts declaring output reports each field added | Measured: a plain-dict tool has outputSchema null. | Passed |
| TC-161 | test_declared_diff.py | Null output on both sides is no change | Null output on both sides is no change | Passed |
| TC-162 | test_declared_diff.py | A field added inside a nested model is found through refs | Pydantic nests models as $defs plus $ref. Without following the ref both versions show the same string and the added field is invisible. | Passed |
| TC-163 | test_declared_diff.py | An optional field written two ways is the same | Optional[str] can arrive as anyOf or as a type list. | Passed |
| TC-164 | test_declared_diff.py | A reworded field title is not a declared change | It changes no behaviour, and a declared change that explains nothing would only confuse the residue checker. | Passed |
| TC-165 | test_declared_diff.py | Array members use fielddrift paths | `items[].sku`, the format fielddrift.flatten reports drift in, so the residue checker can match a declared path against a drifted one. | Passed |
| TC-166 | test_declared_diff.py | An enum change | An enum change | Passed |
| TC-167 | test_declared_diff.py | A description change | A description change | Passed |
| TC-168 | test_declared_diff.py | A self referencing schema does not hang | A self referencing schema does not hang | Passed |
| TC-169 | test_declared_diff.py | To dict is json serialisable and complete | To dict is json serialisable and complete | Passed |
| TC-170 | test_declared_diff.py | For tool returns an empty diff for an untouched tool | For tool returns an empty diff for an untouched tool | Passed |
| TC-171 | test_declared_diff.py | The differ reads a real update | v1 -> v2 of the fixture: one output field added and both hints widened. Hand-written dicts cannot show whether the SDK's real shapes - titles, null hints, $defs - are handled; this does. | Passed |
| TC-172 | test_declared_diff.py | A real server diffed against itself is empty | A real server diffed against itself is empty | Passed |
| TC-539 | test_residue.py | Row1 no declared change any drift is residue | Row1 no declared change any drift is residue | Passed |
| TC-540 | test_residue.py | Row1 no declared change no drift is accepted | Row1 no declared change no drift is accepted | Passed |
| TC-541 | test_residue.py | Row1 reduces to the base detector exactly | Every signal the full detector would alert on is residue, and nothing else is - the residue checker adds no evidence and removes none. | Passed |
| TC-542 | test_residue.py | Row2 drift confined to the declared field is explained | Row2 drift confined to the declared field is explained | Passed |
| TC-543 | test_residue.py | Row2 drift outside the declared field is residue | The masked response still drifts: something besides last_contact moved. | Passed |
| TC-544 | test_residue.py | Row2 declared output field plus new host is residue on network | The report's own example: the field is accepted, the egress is not. | Passed |
| TC-545 | test_residue.py | Row2 declared output field never explains a file write | Row2 declared output field never explains a file write | Passed |
| TC-546 | test_residue.py | Row2 declared field on another tool explains nothing here | C1: the cover change is on a different tool. | Passed |
| TC-547 | test_residue.py | Row2 masking that failed explains nothing | Row2 masking that failed explains nothing | Passed |
| TC-548 | test_residue.py | Row3 a probe that uses the changed parameter is explained | Row3 a probe that uses the changed parameter is explained | Passed |
| TC-549 | test_residue.py | Row3 a probe that does not use it is residue | Row3 a probe that does not use it is residue | Passed |
| TC-550 | test_residue.py | Row3 probe args can be passed explicitly | Row3 probe args can be passed explicitly | Passed |
| TC-551 | test_residue.py | Row4 a description change explains no behaviour | Row4 a description change explains no behaviour | Passed |
| TC-552 | test_residue.py | Row5 a new tool needs its own baseline and excuses nothing else | Row5 a new tool needs its own baseline and excuses nothing else | Passed |
| TC-553 | test_residue.py | Row6 a closed world tool never explains a new host | Row6 a closed world tool never explains a new host | Passed |
| TC-554 | test_residue.py | Row6 a read only tool never explains a file write | Row6 a read only tool never explains a file write | Passed |
| TC-555 | test_residue.py | Row7 read only removed plus new file write is an escalation | Row7 read only removed plus new file write is an escalation | Passed |
| TC-556 | test_residue.py | Row7 open world added plus new host is an escalation | The C3 cover for egress families. | Passed |
| TC-557 | test_residue.py | Row7 a widened hint is reported even with no effect | Row7 a widened hint is reported even with no effect | Passed |
| TC-558 | test_residue.py | Row7 read only removed never covers a secret read | A write permission does not cover reading ~/.ssh. | Passed |
| TC-559 | test_residue.py | Row7 an escalated tool is not offered for re baselining | Row7 an escalated tool is not offered for re baselining | Passed |
| TC-560 | test_residue.py | Row8 open world tool plus new host is held for review | Row8 open world tool plus new host is held for review | Passed |
| TC-561 | test_residue.py | Row8 holding needs a declared change on that tool | Always-residue: a tool whose definition did not change declared nothing, so nothing - not even its open-world hint - excuses a host. | Passed |
| TC-562 | test_residue.py | Row8 explicit reading a defaulted open world tool holds nothing | Every attacker tool declares no annotations, so every one is open-world by MCP default. Under the explicit reading its new host is residue. | Passed |
| TC-563 | test_residue.py | Row8 literal reading a defaulted open world tool holds its host | The other reading, kept testable so the choice is a measured one. | Passed |
| TC-564 | test_residue.py | Row8 literal reading explains response content too | Under the literal reading even unmasked drift on a defaulted open-world tool is explained - which is why the reading matters for H3. | Passed |
| TC-565 | test_residue.py | An unknown open world policy is refused | An unknown open world policy is refused | Passed |
| TC-566 | test_residue.py | A content flag inside a declared field is residue | Flags are never masked: instruction-shaped text is residue wherever it appears, including inside the field the update declared. | Passed |
| TC-567 | test_residue.py | A determinism break that survives masking is residue | A determinism break that survives masking is residue | Passed |
| TC-568 | test_residue.py | A determinism break caused by the declared field is explained | A determinism break caused by the declared field is explained | Passed |
| TC-569 | test_residue.py | Verdict order residue beats escalation beats held | Verdict order residue beats escalation beats held | Passed |
| TC-570 | test_residue.py | Signal counts and to dict | Signal counts and to dict | Passed |
| TC-571 | test_residue.py | The residue view carries the masked measurement | T25 scores this view, so it must hold what the checker decided. | Passed |
| TC-572 | test_residue.py | Mask removes the field and re renders the json text | Mask removes the field and re renders the json text | Passed |
| TC-573 | test_residue.py | Mask keeps the servers own formatting | Mask keeps the servers own formatting | Passed |
| TC-574 | test_residue.py | Mask leaves free text alone | A declared structured field never explains a change in prose. | Passed |
| TC-575 | test_residue.py | Mask without structured content explains nothing | Mask without structured content explains nothing | Passed |
| TC-576 | test_residue.py | Mask with unreproducible formatting explains nothing | Mask with unreproducible formatting explains nothing | Passed |
| TC-577 | test_residue.py | Strip nested and array paths | Strip nested and array paths | Passed |
| TC-578 | test_residue.py | A root level declaration masks nothing | Otherwise "the whole output changed" would explain everything. | Passed |
| TC-579 | test_residue.py | Mask does not touch the original | Mask does not touch the original | Passed |
| TC-580 | test_residue.py | Freeze then verify | Freeze then verify | Passed |
| TC-581 | test_residue.py | A frozen file edited afterwards is refused | A frozen file edited afterwards is refused | Passed |
| TC-582 | test_residue.py | Code whose rules moved after the freeze is refused | Code whose rules moved after the freeze is refused | Passed |
| TC-583 | test_residue.py | The open world reading is part of the frozen rules | The choice that decides H3 on this attacker is hashed with the rest. | Passed |
| TC-584 | test_residue.py | A real update is masked and checked end to end | Baseline on v1, re-probe v2: an output field added and both hints widened. The masked measurement must be taken through the real re-probe, and the residue checker must explain the field and report the widening. | Passed |
| TC-585 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-False-checks0] | Residue mode with nothing declared is full mode | Passed |
| TC-586 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-False-checks1] | Residue mode with nothing declared is full mode | Passed |
| TC-587 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-False-checks2] | Residue mode with nothing declared is full mode | Passed |
| TC-588 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-False-checks3] | Residue mode with nothing declared is full mode | Passed |
| TC-589 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-False-checks4] | Residue mode with nothing declared is full mode | Passed |
| TC-590 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-True-checks0] | Residue mode with nothing declared is full mode | Passed |
| TC-591 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-True-checks1] | Residue mode with nothing declared is full mode | Passed |
| TC-592 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-True-checks2] | Residue mode with nothing declared is full mode | Passed |
| TC-593 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-True-checks3] | Residue mode with nothing declared is full mode | Passed |
| TC-594 | test_residue_scoring.py | Residue mode with nothing declared is full mode [None-True-checks4] | Residue mode with nothing declared is full mode | Passed |
| TC-595 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-False-checks0] | Residue mode with nothing declared is full mode | Passed |
| TC-596 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-False-checks1] | Residue mode with nothing declared is full mode | Passed |
| TC-597 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-False-checks2] | Residue mode with nothing declared is full mode | Passed |
| TC-598 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-False-checks3] | Residue mode with nothing declared is full mode | Passed |
| TC-599 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-False-checks4] | Residue mode with nothing declared is full mode | Passed |
| TC-600 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-True-checks0] | Residue mode with nothing declared is full mode | Passed |
| TC-601 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-True-checks1] | Residue mode with nothing declared is full mode | Passed |
| TC-602 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-True-checks2] | Residue mode with nothing declared is full mode | Passed |
| TC-603 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-True-checks3] | Residue mode with nothing declared is full mode | Passed |
| TC-604 | test_residue_scoring.py | Residue mode with nothing declared is full mode [diff1-True-checks4] | Residue mode with nothing declared is full mode | Passed |
| TC-605 | test_residue_scoring.py | A declared output field no longer alerts | A declared output field no longer alerts | Passed |
| TC-606 | test_residue_scoring.py | The definition hash does not count against a declared update | In full mode a changed definition alerts at 3.0 by itself. | Passed |
| TC-607 | test_residue_scoring.py | Residue alerts and names the signal | The report's read_notes example: the field is accepted, the egress alerts and the alert names the network. | Passed |
| TC-608 | test_residue_scoring.py | An escalation is shown but does not alert alone | An escalation is shown but does not alert alone | Passed |
| TC-609 | test_residue_scoring.py | An escalation beside residue alerts on the residue | The only sense in which an escalation is "combined": scores take the max, so the residue decides. | Passed |
| TC-610 | test_residue_scoring.py | A held host is logged and never alerts | A held host is logged and never alerts | Passed |
| TC-611 | test_residue_scoring.py | An escalated tool with no probes is still shown | An escalated tool with no probes is still shown | Passed |
| TC-612 | test_residue_scoring.py | To dict carries the residue outcome | To dict carries the residue outcome | Passed |
| TC-613 | test_residue_scoring.py | Update check and per tool default off | Update check and per tool default off | Passed |
| TC-614 | test_residue_scoring.py | Update check turns a benign declared update from alert to watch | The whole of Gap 2 on one real update: v1 -> v2 adds an output field and widens both hints. Full mode alerts on the new field. Residue mode explains the field and shows the widening, without alerting. | Passed |
| TC-615 | test_residue_scoring.py | Update check on an unchanged server scores as full | Update check on an unchanged server scores as full | Passed |
| TC-673 | test_rules_v1_1.py | A mirrored structured block is removed | A mirrored structured block is removed | Passed |
| TC-674 | test_rules_v1_1.py | Structured content that says something else is kept | Structured content that says something else is kept | Passed |
| TC-675 | test_rules_v1_1.py | Errors are not rewritten by normalisation | The error rule explains a rewording; it does not edit the text. | Passed |
| TC-676 | test_rules_v1_1.py | Normalising never touches the input | Normalising never touches the input | Passed |
| TC-677 | test_rules_v1_1.py | V1 1 keeps every v1 0 row and never list | V1 1 keeps every v1 0 row and never list | Passed |
| TC-678 | test_rules_v1_1.py | V1 0 frozen file still matches the code | V1 0 frozen file still matches the code | Passed |
| TC-679 | test_rules_v1_1.py | Formalisation does not mask fields a tool already returned | A schema added to a schemaless tool: no masking, only the mirror goes. | Passed |
| TC-680 | test_rules_v1_1.py | An existing schema still masks declared fields | An existing schema still masks declared fields | Passed |
| TC-681 | test_rules_v1_1.py | Nothing changed means no second measurement | Nothing changed means no second measurement | Passed |
| TC-682 | test_rules_v1_1.py | V1 1 is opt in everywhere | V1 1 is opt in everywhere | Passed |
| TC-683 | test_rules_v1_1.py | An error reworded is explained under v1 1 only | An error reworded is explained under v1 1 only | Passed |
| TC-684 | test_rules_v1_1.py | A success that became an error is still residue | A success that became an error is still residue | Passed |
| TC-685 | test_rules_v1_1.py | Side effects on an error are still residue | Side effects on an error are still residue | Passed |
| TC-686 | test_rules_v1_1.py | Instructions in an error are still residue | Instructions in an error are still residue | Passed |
| TC-687 | test_rules_v1_1.py | A view that makes things worse is not used | Raw clean, framework view drifting: nothing is residue. | Passed |
| TC-688 | test_rules_v1_2.py | Hyphen to underscore is a rename | Hyphen to underscore is a rename | Passed |
| TC-689 | test_rules_v1_2.py | Case and camel case are a rename | Case and camel case are a rename | Passed |
| TC-690 | test_rules_v1_2.py | A different name is not a rename however similar | A different name is not a rename however similar | Passed |
| TC-691 | test_rules_v1_2.py | Different input fields are not a rename | Different input fields are not a rename | Passed |
| TC-692 | test_rules_v1_2.py | An ambiguous pairing is refused | An ambiguous pairing is refused | Passed |
| TC-693 | test_rules_v1_2.py | Unchanged tools are not touched | Unchanged tools are not touched | Passed |
| TC-694 | test_rules_v1_2.py | Rename back restores old names only | Rename back restores old names only | Passed |
| TC-695 | test_rules_v1_2.py | A pure rename leaves no other declared change but is not empty | A pure rename leaves no other declared change but is not empty | Passed |
| TC-696 | test_rules_v1_2.py | V1 2 is v1 1 plus only the renaming and removal rules | V1 2 is v1 1 plus only the renaming and removal rules | Passed |
| TC-697 | test_rules_v1_2.py | V1 2 freezes and verifies | V1 2 freezes and verifies | Passed |
| TC-698 | test_rules_v1_2.py | Check update accepts v1 2 | Check update accepts v1 2 | Passed |
| TC-699 | test_rules_v1_2.py | The renaming session calls the new name | The renaming session calls the new name | Passed |
| TC-700 | test_rules_v1_2.py | Design case sqlite upgrade pairs all six tools | The design data for v1.2: held-out sqlite under v1.1 renamed every tool. | Passed |
| TC-701 | test_rules_v1_2.py | A removed tool failing is explained under v1 2 only | A removed tool failing is explained under v1 2 only | Passed |
| TC-702 | test_rules_v1_2.py | Side effects during a removed tool call stay residue | Side effects during a removed tool call stay residue | Passed |
| TC-828 | test_update_conditions.py | Every family has an attribution set | Every family has an attribution set | Passed |
| TC-829 | test_update_conditions.py | The gated families take their payloads signals | The gated families take their payloads signals | Passed |
| TC-830 | test_update_conditions.py | Egress is attributed by the network signal only | Egress is attributed by the network signal only | Passed |
| TC-831 | test_update_conditions.py | Silent tamper is attributed by the signals that read changed text | Not field_drift alone: on a prose tool its score cannot reach the alert line, and the keyed path computes none. | Passed |
| TC-832 | test_update_conditions.py | No content family is attributed by a structural change | The only structural change in an update episode is the cover's field. | Passed |
| TC-833 | test_update_conditions.py | A content signal must be on the attacked tool | What keeps a C1 cover change on another tool from being credited. | Passed |
| TC-834 | test_update_conditions.py | A side effect is the process and counts on any tool | Measured: the attacker keeps its sink file and egress sockets open, so in a live C3 exfiltration the alert landed on read_document. | Passed |
| TC-835 | test_update_conditions.py | A side effect the family does not cause is still not attribution | A side effect the family does not cause is still not attribution | Passed |
| TC-836 | test_update_conditions.py | The wrong signal is not attribution | The wrong signal is not attribution | Passed |
| TC-837 | test_update_conditions.py | A benign c2 update | The false-alarm case: only refuse_all and definition_diff object. | Passed |
| TC-838 | test_update_conditions.py | C2 exfiltration to a new host | The report's example: the field is accepted, the egress is not. | Passed |
| TC-839 | test_update_conditions.py | C2 silent tamper is seen only by residue and refuse all | C2 silent tamper is seen only by residue and refuse all | Passed |
| TC-840 | test_update_conditions.py | C1 cover on another tool tamper on the attacked one | The attacked tool declared nothing, so residue applies in full. | Passed |
| TC-841 | test_update_conditions.py | C0 reduces accept rebaseline and residue to the full detector | C0 reduces accept rebaseline and residue to the full detector | Passed |
| TC-842 | test_update_conditions.py | An alert on the wrong tool is an alert but not a detection | Noise on search_orders while the attack sits on lookup_customer. | Passed |
| TC-843 | test_update_conditions.py | A benign episode is never attributed | A benign episode is never attributed | Passed |
| TC-844 | test_update_conditions.py | All five come from one measurement | Same object scored five ways - nothing re-run per condition. | Passed |
| TC-845 | test_update_conditions.py | An existing config hashes exactly as before | Adding update keys to every config would change every config_hash, and resume would refuse every half-finished sweep as a conflict. | Passed |
| TC-846 | test_update_conditions.py | An update config is hashed apart from a plain one | An update config is hashed apart from a plain one | Passed |
| TC-847 | test_update_conditions.py | Each cover gets its own episode label | Each cover gets its own episode label | Passed |
| TC-848 | test_update_conditions.py | The attacker driver passes release and cover | The attacker driver passes release and cover | Passed |
| TC-849 | test_update_conditions.py | The update matrix is family by cover by seed plus benign updates | The update matrix is family by cover by seed plus benign updates | Passed |
| TC-850 | test_update_conditions.py | An update sweep has unique episode ids | An update sweep has unique episode ids | Passed |
| TC-851 | test_update_conditions.py | Per tool reaches every update episode | Per tool reaches every update episode | Passed |
| TC-852 | test_update_conditions.py | A plain sweep is untouched by the update fields | A plain sweep is untouched by the update fields | Passed |
| TC-853 | test_update_conditions.py | Rq3u refuses to score against edited rules | Rq3u refuses to score against edited rules | Passed |
| TC-854 | test_update_conditions.py | Rq3u refuses a per tool file that was never frozen | Rq3u refuses a per tool file that was never frozen | Passed |
| TC-855 | test_update_conditions.py | A c0 row says the base detector decided | The first live C0 episode wrote residue_verdict=accepted beside alert_residue=True. With nothing declared the checker never runs and the base detector's alerts are the residue. | Passed |
| TC-856 | test_update_conditions.py | A quiet c0 row is accepted | A quiet c0 row is accepted | Passed |

## Proxy, injector, in-session, guard (Gap 1)

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-227 | test_h2c.py | Window unions overlapping sweeps and the first one after | Window unions overlapping sweeps and the first one after | Passed |
| TC-228 | test_h2c.py | Window does not wait forever for a sweep | Window does not wait forever for a sweep | Passed |
| TC-229 | test_h2c.py | An unavailable watch reports unavailable | An unavailable watch reports unavailable | Passed |
| TC-230 | test_h2c.py | Skeleton keeps classes and punctuation but no letters or digits | Skeleton keeps classes and punctuation but no letters or digits | Passed |
| TC-231 | test_h2c.py | A filled skeleton has exactly the pattern classes | A filled skeleton has exactly the pattern classes | Passed |
| TC-232 | test_h2c.py | Filled values are keyed not fixed | Filled values are keyed not fixed | Passed |
| TC-233 | test_h2c.py | Shaped string matches a drawn pattern rather than the average | Shaped string matches a drawn pattern rather than the average | Passed |
| TC-234 | test_h2c.py | Shapes without skeletons still work | Shapes without skeletons still work | Passed |
| TC-235 | test_h2c.py | Old profiles without skeletons load | Old profiles without skeletons load | Passed |
| TC-236 | test_h2c.py | An ordinary real call raises nothing | An ordinary real call raises nothing | Passed |
| TC-237 | test_h2c.py | A new host on a real call alerts | A new host on a real call alerts | Passed |
| TC-238 | test_h2c.py | A file in a never seen directory alerts | A file in a never seen directory alerts | Passed |
| TC-239 | test_h2c.py | Instruction shaped text in a real answer alerts | Instruction shaped text in a real answer alerts | Passed |
| TC-240 | test_h2c.py | Take empties the findings | Take empties the findings | Passed |
| TC-241 | test_h2c.py | A guard defect never raises | A guard defect never raises | Passed |
| TC-242 | test_h2c.py | Apply guard turns a clean report into an alert | Apply guard turns a clean report into an alert | Passed |
| TC-243 | test_h2c.py | Apply guard with no findings changes nothing | Apply guard with no findings changes nothing | Passed |
| TC-244 | test_h2c.py | The tap queues a real call once it is answered | The tap queues a real call once it is answered | Passed |
| TC-245 | test_h2c.py | The tap never queues a probe answer | The tap never queues a probe answer | Passed |
| TC-246 | test_h2c.py | Pacing runs after the window opens | Pacing runs after the window opens | Passed |
| TC-247 | test_h2c.py | A continuous watch is resolved later not during the call | A continuous watch is resolved later not during the call | Passed |
| TC-248 | test_h2c.py | Process evidence is compared server wide not per tool | Found live: an unprobed tool's empty record made the server's own loopback socket look like new egress on a clean server. | Passed |
| TC-249 | test_h2c.py | The watcher process sweeps without stalling the event loop | Measured reason for the separate process: an in-thread sweep held the GIL and turned a 5 ms sleep into ~55 ms, a timing tell of our own. | Passed |
| TC-250 | test_h2c.py | Either way recall credits probe and guard but not leftovers | Either way recall credits probe and guard but not leftovers | Passed |
| TC-285 | test_host_mimicry.py | A genuine handshake is recorded | A genuine handshake is recorded | Passed |
| TC-286 | test_host_mimicry.py | The sdk default is never recorded as a host | Otherwise a probe session teaches the detector to imitate itself. | Passed |
| TC-287 | test_host_mimicry.py | A handshake without a name is ignored | A handshake without a name is ignored | Passed |
| TC-288 | test_host_mimicry.py | A later handshake replaces an earlier one | A later handshake replaces an earlier one | Passed |
| TC-289 | test_host_mimicry.py | Profiles are kept per server | Profiles are kept per server | Passed |
| TC-290 | test_host_mimicry.py | A missing version does not produce a null | A probe announcing version null would be as distinctive as "mcp". | Passed |
| TC-291 | test_host_mimicry.py | Only name version and cwd are stored | Only name version and cwd are stored | Passed |
| TC-292 | test_host_mimicry.py | No environment value can reach the profile | Written on every proxied session, so a leak here would be routine. | Passed |
| TC-293 | test_host_mimicry.py | A corrupt profile reads as absent rather than raising | A corrupt profile reads as absent rather than raising | Passed |
| TC-294 | test_host_mimicry.py | An unseen server yields no identity | The caller must fall back, not invent. See the module docstring. | Passed |
| TC-295 | test_host_mimicry.py | A recorded server yields the host identity | A recorded server yields the host identity | Passed |
| TC-296 | test_host_mimicry.py | The identity is never the sdk default once a host is known | The identity is never the sdk default once a host is known | Passed |
| TC-297 | test_host_mimicry.py | Mimic host is off by default | Experiments 1, 2 and 3's L1 arm must keep announcing the SDK default, or the condition they measure changes underneath them. | Passed |
| TC-298 | test_host_mimicry.py | With the option off no identity is sent even if one is known | With the option off no identity is sent even if one is known | Passed |
| TC-299 | test_host_mimicry.py | With the option on but nothing recorded it falls back | With the option on but nothing recorded it falls back | Passed |
| TC-300 | test_host_mimicry.py | With the option on and a profile the host identity is used | With the option on and a profile the host identity is used | Passed |
| TC-301 | test_injector.py | Client ids are renumbered and restored | Client ids are renumbered and restored | Passed |
| TC-302 | test_injector.py | The server sees one gap free sequence with probes inside | The server sees one gap free sequence with probes inside | Passed |
| TC-303 | test_injector.py | A probe answer never reaches the client | A probe answer never reaches the client | Passed |
| TC-304 | test_injector.py | A client cancellation names the id the server knows | A client cancellation names the id the server knows | Passed |
| TC-305 | test_injector.py | Server requests and unknown messages pass untouched | Server requests and unknown messages pass untouched | Passed |
| TC-306 | test_injector.py | Initialized only after the handshake answer | Initialized only after the handshake answer | Passed |
| TC-307 | test_injector.py | Probe traffic is never learned as genuine | traffic.learn reads only client-to-server requests; probes log as 'probe'. | Passed |
| TC-308 | test_insession.py | No shapes means exactly the old values | No shapes means exactly the old values | Passed |
| TC-309 | test_insession.py | Shaped values are keyed and reproducible | Shaped values are keyed and reproducible | Passed |
| TC-310 | test_insession.py | Shaped values follow the genuine lengths | Shaped values follow the genuine lengths | Passed |
| TC-311 | test_insession.py | Shaping never sends an empty value unless users did | Shaping never sends an empty value unless users did | Passed |
| TC-312 | test_insession.py | Shapes record lengths not values | Shapes record lengths not values | Passed |
| TC-313 | test_insession.py | Every genuine call is sent exactly once in order | Every genuine call is sent exactly once in order | Passed |
| TC-314 | test_insession.py | Interleaving is keyed | Interleaving is keyed | Passed |
| TC-315 | test_insession.py | Probes are not always first or last | Probes are not always first or last | Passed |
| TC-316 | test_insession.py | Genuine calls are sent before the probe window opens | prepare_probe runs before the sandbox starts; call_tool is the probe only. | Passed |
| TC-317 | test_insession.py | Expected probe calls counts the subsampled draw | Expected probe calls counts the subsampled draw | Passed |
| TC-318 | test_insession.py | An event is attributed to the call it fell inside | An event is attributed to the call it fell inside | Passed |
| TC-319 | test_insession.py | The attacker stamps events finely enough to attribute | The attacker stamps events finely enough to attribute | Passed |
| TC-320 | test_insession.py | A changed preregistration is refused | A changed preregistration is refused | Passed |
| TC-321 | test_insession.py | The genuine halves do not overlap | The genuine halves do not overlap | Passed |
| TC-322 | test_insession.py | In session leaves earlier config hashes alone | In session leaves earlier config hashes alone | Passed |
| TC-323 | test_insession.py | H2b uses h2s thresholds unchanged | H2b uses h2s thresholds unchanged | Passed |
| TC-340 | test_launch_parity.py | Probe launch passes only the forwarded variable | Probe launch passes only the forwarded variable | Passed |
| TC-341 | test_launch_parity.py | Agent launch starts the proxy not the attacker | Agent launch starts the proxy not the attacker | Passed |
| TC-342 | test_launch_parity.py | The proxy forwards by name so values never hit the command line | A forwarded value could be a secret. Only the NAME may be an argument. | Passed |
| TC-343 | test_launch_parity.py | The attacker never learns where the detector keeps its state | The attacker never learns where the detector keeps its state | Passed |
| TC-344 | test_launch_parity.py | Both paths agree on the working directory | cwd reaches the feature row as cwd_base. One definition, used twice. | Passed |
| TC-345 | test_launch_parity.py | The artefact being corrected is real and large | Documents the gap, so the write-up can quote it from a test run. | Passed |
| TC-346 | test_launch_parity.py | Probe and agent launches look identical to the attacker | The parity claim itself, measured rather than assumed. | Passed |
| TC-347 | test_launch_parity.py | Parity reproduces the expected environment exactly | Not just equal to each other - equal to what was intended. | Passed |
| TC-348 | test_launch_parity.py | The old launch really did differ | Guards the premise: without parity the gap is large and learnable. | Passed |
| TC-448 | test_proxy_logging.py | Every record carries one stable session id | Every record carries one stable session id | Passed |
| TC-449 | test_proxy_logging.py | Two proxies on one server get different sessions | The log is append-only and shared, so the id is what separates runs. | Passed |
| TC-450 | test_proxy_logging.py | Client identity is captured from the handshake | Client identity is captured from the handshake | Passed |
| TC-451 | test_proxy_logging.py | A handshake without client info does not break logging | A handshake without client info does not break logging | Passed |
| TC-452 | test_proxy_logging.py | No environment values are ever logged | The log becomes a dataset. An API key must not be able to reach it. | Passed |
| TC-453 | test_proxy_logging.py | Capabilities are not copied into the client record | Only name and version. The handshake carries more; we do not want it. | Passed |
| TC-454 | test_proxy_logging.py | Passive summary is written as a record not just stderr | Passive summary is written as a record not just stderr | Passed |
| TC-455 | test_proxy_logging.py | Passive verdict survives a process that is killed | The sidecar, not the shutdown record, is what readers must rely on. | Passed |
| TC-456 | test_proxy_logging.py | Sidecar tracks the latest verdict | Sidecar tracks the latest verdict | Passed |
| TC-457 | test_proxy_logging.py | No sidecar when passive is off | No sidecar when passive is off | Passed |
| TC-807 | test_traffic_mimicry.py | Sessions and gaps are learned from the proxy log | Sessions and gaps are learned from the proxy log | Passed |
| TC-808 | test_traffic_mimicry.py | Only client tool calls are counted | Responses and handshakes are not user actions. | Passed |
| TC-809 | test_traffic_mimicry.py | A long gap is a user who walked away not a model thinking | A long gap is a user who walked away not a model thinking | Passed |
| TC-810 | test_traffic_mimicry.py | Too few sessions is not usable | Imitating an accident is its own fingerprint. | Passed |
| TC-811 | test_traffic_mimicry.py | Enough sessions is usable | Enough sessions is usable | Passed |
| TC-812 | test_traffic_mimicry.py | A missing log gives an empty profile | A missing log gives an empty profile | Passed |
| TC-813 | test_traffic_mimicry.py | A corrupt line does not discard the rest | A corrupt line does not discard the rest | Passed |
| TC-814 | test_traffic_mimicry.py | Argument shapes are learned without keeping the values | Replaying a user's arguments would send their data to a server that may be hostile - the detector's probes would become the exfiltration channel for the traffic they protect. | Passed |
| TC-815 | test_traffic_mimicry.py | Shape records character mix not content | Shape records character mix not content | Passed |
| TC-816 | test_traffic_mimicry.py | A profile round trips | A profile round trips | Passed |
| TC-817 | test_traffic_mimicry.py | Without a profile the current behaviour is unchanged | One session of every probe. The control condition must not move. | Passed |
| TC-818 | test_traffic_mimicry.py | With a profile a cycle is split into realistic sessions | With a profile a cycle is split into realistic sessions | Passed |
| TC-819 | test_traffic_mimicry.py | The split removes what made session separable | calls_before above five occurred only in probe traffic. After splitting, the longest probe session matches the longest real one. | Passed |
| TC-820 | test_traffic_mimicry.py | A plan is reproducible from its key and cycle | A plan is reproducible from its key and cycle | Passed |
| TC-821 | test_traffic_mimicry.py | Different cycles give different plans | A constant split would become a fingerprint of its own. | Passed |
| TC-822 | test_traffic_mimicry.py | No probes means no sessions | No probes means no sessions | Passed |
| TC-823 | test_traffic_mimicry.py | Gaps are drawn from observed gaps | Gaps are drawn from observed gaps | Passed |
| TC-824 | test_traffic_mimicry.py | Without a profile there is no pause | Without a profile there is no pause | Passed |
| TC-825 | test_traffic_mimicry.py | Gaps are reproducible and vary by index | Gaps are reproducible and vary by index | Passed |
| TC-826 | test_traffic_mimicry.py | The fingerprint names both newly measured tells | The fingerprint names both newly measured tells | Passed |
| TC-827 | test_traffic_mimicry.py | Turning the countermeasures on removes those two tells | Turning the countermeasures on removes those two tells | Passed |

## Probes: generation, keying, safety

| ID | File | Test case | What it checks | Result |
|---|---|---|---|---|
| TC-364 | test_only_tools.py | An empty list targets every tool | The default must not quietly disarm the attacker. | Passed |
| TC-365 | test_only_tools.py | Only the named tool is targeted | Only the named tool is targeted | Passed |
| TC-366 | test_only_tools.py | Several tools can be named | Several tools can be named | Passed |
| TC-367 | test_only_tools.py | A misspelled tool is refused at arm time | Otherwise it arms cleanly, never fires, and looks like a clean evasion. | Passed |
| TC-368 | test_only_tools.py | An advertised but unreachable tool is still refused | Being a real tool name is necessary but not sufficient. | Passed |
| TC-369 | test_only_tools.py | The declared tool names match the server | If the server gains a tool and this list does not, targeting it fails. | Passed |
| TC-370 | test_only_tools.py | The server consults targets before attacking | _process must return the honest text for an untargeted tool. | Passed |
| TC-371 | test_only_tools.py | Replay can avoid the targeted tool | The other half: traffic the user would plausibly produce, minus the tool under attack. Without it the 'user never calls it' premise is only asserted. | Passed |
| TC-372 | test_only_tools.py | The episode config carries avoid tools | The episode config carries avoid tools | Passed |
| TC-373 | test_only_tools.py | A tool no payload can reach is refused | A tool no payload can reach is refused | Passed |
| TC-374 | test_only_tools.py | Every attackable tool validates | Every attackable tool validates | Passed |
| TC-375 | test_only_tools.py | Attackable is a subset of advertised | Attackable is a subset of advertised | Passed |
| TC-376 | test_only_tools.py | The unreachable tool really does bypass the scenario | Guards the premise: if send_invoice ever routes through _process, this restriction becomes wrong and should be removed rather than carried. | Passed |
| TC-415 | test_probe_generator.py | Same key and cycle reproduce exactly | Same key and cycle reproduce exactly | Passed |
| TC-416 | test_probe_generator.py | A different key gives different values | A different key gives different values | Passed |
| TC-417 | test_probe_generator.py | Experiment keys are derivable and stable | Experiment keys are derivable and stable | Passed |
| TC-418 | test_probe_generator.py | Each cycle produces new values | Each cycle produces new values | Passed |
| TC-419 | test_probe_generator.py | Probes within one cycle do not collide | The fixed generator wastes a third of its budget on duplicates. | Passed |
| TC-420 | test_probe_generator.py | Family id is stable across cycles | The family is what a baseline is captured against, so it must not move. | Passed |
| TC-421 | test_probe_generator.py | Values depend on server and tool | Values depend on server and tool | Passed |
| TC-422 | test_probe_generator.py | No key material appears in generated output | Everything generated here is transmitted to the monitored server. | Passed |
| TC-423 | test_probe_generator.py | Key id does not reveal the key | Key id does not reveal the key | Passed |
| TC-424 | test_probe_generator.py | Key round trip through the store | Key round trip through the store | Passed |
| TC-425 | test_probe_generator.py | Supported scalar types are generated correctly | Supported scalar types are generated correctly | Passed |
| TC-426 | test_probe_generator.py | Arrays and nested objects | Arrays and nested objects | Passed |
| TC-427 | test_probe_generator.py | Length constraints are respected | Length constraints are respected | Passed |
| TC-428 | test_probe_generator.py | Const is passed through | Const is passed through | Passed |
| TC-429 | test_probe_generator.py | Unsupported schemas fail safely [bad0] | Refuse rather than improvise. | Passed |
| TC-430 | test_probe_generator.py | Unsupported schemas fail safely [bad1] | Refuse rather than improvise. | Passed |
| TC-431 | test_probe_generator.py | Unsupported schemas fail safely [bad2] | Refuse rather than improvise. | Passed |
| TC-432 | test_probe_generator.py | Unsupported schemas fail safely [bad3] | Refuse rather than improvise. | Passed |
| TC-433 | test_probe_generator.py | Generated values are not obviously synthetic | 'probe_918273' is unpredictable and still announces itself as a test. | Passed |
| TC-434 | test_probe_generator.py | Emails use only reserved domains | Emails use only reserved domains | Passed |
| TC-435 | test_probe_generator.py | Urls stay on loopback | Urls stay on loopback | Passed |
| TC-436 | test_probe_generator.py | Filenames are relative and sandbox safe | Filenames are relative and sandbox safe | Passed |
| TC-437 | test_probe_generator.py | Generator version is recorded | Generator version is recorded | Passed |
| TC-438 | test_probes_fixed_golden.py | Fixed probes match the stored baseline | Same seed, same server, same tool -> byte-identical arguments. | Passed |
| TC-439 | test_probes_fixed_golden.py | Read document probes match the stored baseline | Read document probes match the stored baseline | Passed |
| TC-440 | test_probes_fixed_golden.py | Generation is stable across generator instances | Values must not depend on process state. | Passed |
| TC-441 | test_probes_fixed_golden.py | Probe values depend on server and tool | Keying includes server and tool, so the same seed does not collide. | Passed |
| TC-442 | test_probes_fixed_golden.py | Fixed generator collides across indices | Documents a real weakness of the fixed generator. | Passed |
| TC-443 | test_probes_fixed_golden.py | Side effecting tools are never probed | Side effecting tools are never probed | Passed |
| TC-444 | test_probes_fixed_golden.py | Read only verbs are probed | Read only verbs are probed | Passed |
| TC-445 | test_probes_fixed_golden.py | Word boundary matching does not misfire on substrings | 'put' occurs inside 'input'. | Passed |
| TC-446 | test_probes_fixed_golden.py | Annotations take precedence over keywords | Annotations take precedence over keywords | Passed |
| TC-447 | test_probes_fixed_golden.py | Strict policy requires positive evidence | Strict policy requires positive evidence | Passed |
| TC-703 | test_safety_policy.py | A real write tool is never probed [git_commit-Records changes to the repository] | A real write tool is never probed | Passed |
| TC-704 | test_safety_policy.py | A real write tool is never probed [git_add-Adds file contents to the staging area] | A real write tool is never probed | Passed |
| TC-705 | test_safety_policy.py | A real write tool is never probed [git_reset-Unstages all staged changes] | A real write tool is never probed | Passed |
| TC-706 | test_safety_policy.py | A real write tool is never probed [git_create_branch-Creates a new branch from an optional base branch] | A real write tool is never probed | Passed |
| TC-707 | test_safety_policy.py | A real write tool is never probed [git_checkout-Switches branches] | A real write tool is never probed | Passed |
| TC-708 | test_safety_policy.py | A real read only tool is still probed [git_status-Shows the working tree status] | Failing closed must not cost every tool on a server with a write path. | Passed |
| TC-709 | test_safety_policy.py | A real read only tool is still probed [git_log-Shows the commit logs] | Failing closed must not cost every tool on a server with a write path. | Passed |
| TC-710 | test_safety_policy.py | A real read only tool is still probed [git_diff-Shows differences between branches or commits] | Failing closed must not cost every tool on a server with a write path. | Passed |
| TC-711 | test_safety_policy.py | A real read only tool is still probed [git_show-Shows the contents of a commit] | Failing closed must not cost every tool on a server with a write path. | Passed |
| TC-712 | test_safety_policy.py | A real read only tool is still probed [git_branch-List Git branches] | Failing closed must not cost every tool on a server with a write path. | Passed |
| TC-713 | test_safety_policy.py | The name outweighs the description | git_log is "Shows the commit logs" - commit is a noun here. | Passed |
| TC-714 | test_safety_policy.py | A destructive description still counts when the name says nothing | A destructive description still counts when the name says nothing | Passed |
| TC-715 | test_safety_policy.py | A read only description counts when the name says nothing | A read only description counts when the name says nothing | Passed |
| TC-716 | test_safety_policy.py | An unrecognised tool is not probed by default | A verb list is a list of the cases someone thought of. The next real server will have a tool nobody thought of. | Passed |
| TC-717 | test_safety_policy.py | The permissive policy is still reachable for reproduction | Results recorded under the old default have to stay reproducible. | Passed |
| TC-718 | test_safety_policy.py | An explicit annotation still wins | An explicit annotation still wins | Passed |
| TC-719 | test_safety_policy.py | The adversarial server classifies exactly as before [lookup_customer-Look up a customer record by account identifier.-True] | Checked before the default was changed, and asserted here so it stays true: Experiments 1 to 3 probe the same three tools they always did. | Passed |
| TC-720 | test_safety_policy.py | The adversarial server classifies exactly as before [read_document-Read a document from the internal reference library.-True] | Checked before the default was changed, and asserted here so it stays true: Experiments 1 to 3 probe the same three tools they always did. | Passed |
| TC-721 | test_safety_policy.py | The adversarial server classifies exactly as before [get_weather-Report the current weather for a city.-True] | Checked before the default was changed, and asserted here so it stays true: Experiments 1 to 3 probe the same three tools they always did. | Passed |
| TC-722 | test_safety_policy.py | The adversarial server classifies exactly as before [search_orders-Search recent orders and return the matching lines.-False] | Checked before the default was changed, and asserted here so it stays true: Experiments 1 to 3 probe the same three tools they always did. | Passed |
| TC-723 | test_safety_policy.py | The adversarial server classifies exactly as before [send_invoice-Send an invoice to a customer by email.-False] | Checked before the default was changed, and asserted here so it stays true: Experiments 1 to 3 probe the same three tools they always did. | Passed |
| TC-724 | test_safety_policy.py | The real read only servers remain probeable [get_current_time-Get current time in a specific timezone] | Strict must not make a whole server unprobeable - calculate was the calculator server's only tool and briefly fell off the list. | Passed |
| TC-725 | test_safety_policy.py | The real read only servers remain probeable [convert_time-Convert time between timezones] | Strict must not make a whole server unprobeable - calculate was the calculator server's only tool and briefly fell off the list. | Passed |
| TC-726 | test_safety_policy.py | The real read only servers remain probeable [calculate-Calculates the result of an expression] | Strict must not make a whole server unprobeable - calculate was the calculator server's only tool and briefly fell off the list. | Passed |
| TC-766 | test_subsampling.py | The same key and cycle draw the same probes | A run has to be replayable from its key. | Passed |
| TC-767 | test_subsampling.py | Different cycles draw differently | Repetition is the thing being removed. | Passed |
| TC-768 | test_subsampling.py | Different tools draw differently | Different tools draw differently | Passed |
| TC-769 | test_subsampling.py | A different key draws differently | Without the key the next draw cannot be narrowed from the last. | Passed |
| TC-770 | test_subsampling.py | A draw never repeats a probe within a cycle | A draw never repeats a probe within a cycle | Passed |
| TC-771 | test_subsampling.py | Indices stay inside the bank | Indices stay inside the bank | Passed |
| TC-772 | test_subsampling.py | A draw larger than the bank takes the whole bank | A draw larger than the bank takes the whole bank | Passed |
| TC-773 | test_subsampling.py | An empty bank draws nothing | An empty bank draws nothing | Passed |
| TC-774 | test_subsampling.py | Exposure grows with cycles and is stated not implied | A bank is exhaustible. The write-up should say how fast. | Passed |
| TC-775 | test_subsampling.py | A bigger bank lasts longer | A bigger bank lasts longer | Passed |
| TC-776 | test_subsampling.py | A bigger draw burns the bank faster | The cost of covering more probes per cycle, made visible. | Passed |
| TC-777 | test_subsampling.py | Cycles until matches exposure after | Cycles until matches exposure after | Passed |
| TC-778 | test_subsampling.py | The default bank survives a realistic deployment | At a 20-second schedule, 15 cycles is five minutes. The default is not a strong guarantee, and the number is here so nobody assumes otherwise. | Passed |
| TC-779 | test_subsampling.py | Degenerate inputs do not raise | Degenerate inputs do not raise | Passed |
| TC-780 | test_subsampling.py | An attacker that memorised early cycles still meets new probes | The point of the bank, as a simulation rather than an assertion. | Passed |
| TC-781 | test_subsampling.py | Without a bank every cycle reuses the same probe | The pre-T19 behaviour, which is what makes memorising work. | Passed |
| TC-782 | test_subsampling.py | The loop asks for a bank when subsampling | The loop asks for a bank when subsampling | Passed |
| TC-783 | test_subsampling.py | Drawing from the bank sends the same number of calls | Which is why the feature-row count cannot detect this bug, and why the cost dimension for this condition should come out level with the control. | Passed |
| TC-784 | test_subsampling.py | A bank the size of the draw is the bug being guarded against | A bank the size of the draw is the bug being guarded against | Passed |
