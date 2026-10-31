# Midpoint viva — 80 questions and the answers to give

Built around the Project Manager's six required points. Every number is from the
working tree on 18 September 2026. Where something is incomplete, the answer
says so — the PM's message is explicit that partial progress presented honestly
is what is being assessed.

**The frame to hold all the way through:** *implementation is substantially
complete; evaluation is the open work.* Say it early, say it plainly, and every
other answer hangs off it.

---

## A. Opening — 3 questions

**1. Tell us what your project is, in one minute.**
> DriftSentry detects behavioural rug-pull attacks in the Model Context Protocol.
> A user approves a tool once, based on its name, description and schema. A
> malicious server can later change what the tool *does* while keeping that
> definition byte-for-byte identical, so every existing defence — which pins the
> definition — is blind to it. DriftSentry sits as a proxy between client and
> server, captures a behavioural baseline at approval time using canary probes,
> re-probes on a schedule, and alerts when behaviour drifts. It's evaluated
> against an adversarial server I built that produces the attacks with ground
> truth, and against a hash-only control on identical traffic.

**2. Where are you, overall?**
> Eight of ten phases complete. The detector, the adversarial server and the
> evaluation harness are all built and working — about 12,600 lines across the
> three, with 177 passing tests. What remains is running the controlled
> experiments to completion and writing up the results. Experiment one is at 38
> of 66 episodes; experiment two has not started.

**3. What's the single most important thing you've found so far?**
> That my own attacker defeated my own detector. The probe-aware level recognised
> 100% of my fixed probes and simply declined to act — undetectable, because
> nothing happened. I replaced fixed probes with values derived from a secret key
> and rotated every cycle. Recognition fell to 0 of 360, and the same attack went
> from never firing to being caught at a score of 2.966.

---

## B. What you have completed — 12 questions

**4. List what is finished.**
> Phases 0 to 7: stack verification and MCP handshake; the transparent stdio
> proxy; client configuration ingestion and rewrite; canary-probe baseline
> capture with variance measurement; the drift scorer with eight signals and
> benign-only threshold calibration; alerting, policy and optional enforcement;
> the resident daemon with a 13-endpoint control API and 8-view dashboard; and
> the adversarial server with six attack families across five levels.

**5. How big is the implementation?**
> Detector 9,038 lines across 33 modules. Adversarial server 2,394 lines in a
> separate project with its own virtual environment. Evaluation harness 1,168
> lines across 7 modules. Test suite 1,897 lines, 177 tests, all passing.

**6. Does the core detection actually work end to end?**
> Yes. Live cycle at the calibrated threshold: benign server scores 0.05, 0.05,
> 0.09. Arm content-injection: 2.06, alert. Disarm: 0.04, 0.07. Detection and
> recovery, with the tool-definition hash unchanged throughout. I can show this.

**7. Does the premise hold — that hash pinning really misses these?**
> All six attack families produce a tool-definition hash of `6805aff88dcf676e…`,
> identical to the benign server. The adversarial server's self-test asserts this
> on every run — 18 of 18 checks — so it's verified continuously, not claimed
> once.

**8. What signals does the scorer use?**
> Eight active: definition hash, high and medium security rules, behavioural
> drift from embedding distance, field-level drift, determinism break, structural
> change, and error-rate change. They combine by maximum, never by sum, because
> several are correlated and summing them inflated false alarms.

**9. What is the calibrated threshold and how was it set?**
> 10.8086, derived as the 99th percentile of benign drift ratios times a 1.25
> margin, with a floor of 1.0. It was set on benign and benign-update servers
> only, before any attack was scored. It's from one server and 54 observations,
> and the tool flags itself as weak — I'll come to that under limitations.

**10. What does the adversarial server do?**
> It's a standalone MCP server with five tools whose definitions never change. A
> scenario file arms one of six attack families — content injection, silent
> tamper, exfiltration, sleeper, conditional, and new-egress — at one of five
> levels from always-malicious up to probe-aware. It writes its own event log,
> so ground truth comes from the attacker, not from the detector.

**11. Why are the detector and attacker separate projects?**
> So the separation is demonstrable, not asserted. Separate environments, no
> shared code, neither can import the other. They meet only as operating-system
> processes speaking MCP over stdio — exactly how DriftSentry would meet any
> third-party server.

**12. What did the evasion-hardening work add?**
> Thirteen modules. The three that matter most: keyed probe generation, where
> values derive from HMAC-SHA256 over a secret key and the cycle number; argument
> redaction, so the embedding doesn't measure my own probe generator; and
> field-level drift with learned volatile masking, so a one-digit account change
> scores 1.0 while a moving timestamp scores 0.0.

**13. Is there a user interface?**
> A desktop dashboard with eight views: overview, drift graph, servers, alerts,
> add-server, MCP clients, calibration, and activity. Live refresh every two
> seconds. It's built on FastAPI with a native window.

**14. Are there tests?**
> 177, all passing, running in under six seconds. Four files are regression locks
> written before the detector changes, so the control condition can't drift
> underneath the experiments.

**15. Is the code published?**
> Yes — github.com/CB014571/Driftsentry-CB014571, public, MIT licence, with a
> lock file pinning 99 dependencies.

---

## C. What is currently under development — 8 questions

**16. What are you working on right now?**
> Experiment one, the control condition — fixed probes against the full attack
> matrix. It's at 38 of 66 episodes. It stopped when the machine restarted and
> needs relaunching; about two hours unattended.

**17. What does the partial run show?**
> At threshold 10.8086: levels one to three, 19 of 19 detected, 100% recall.
> Levels four and five, 0 detected, 0 missed, 12 never fired — recall undefined.
> Benign, 0 false alarms of 6. I present this as interim and incomplete.

**18. Why is L4/L5 recall "undefined" and not zero?**
> Because the attack didn't execute. The attacker recognised the probes and held
> back — 54 probe-shaped inputs declined in one episode. An episode counts as a
> missed detection only when ground truth proves the payload ran. That's a
> methodological rule I enforce, not an excuse.

**19. What else is in progress?**
> The labelled corpus. 91 rows across 37 episodes exist, but it's not yet a
> released artefact with a documented calibration/test split. That's phase 8.

**20. There are six detection modules built but not wired in. Why?**
> Passive monitoring, temporal CUSUM, corroboration, metamorphic probes,
> camouflage detection, and tripwires. Each can raise the false-alarm rate, and
> enabling six at once would make any change in results unattributable. Each
> needs its own calibration and its own controlled comparison.

**21. Is that a defensible engineering position or an excuse?**
> Defensible. The experiment is designed to measure false alarms. If I switch on
> six uncalibrated signals, I lose the ability to say which one caused what. I'd
> rather have a clean measurement of eight signals than a muddy one of fourteen.

**22. What's the state of calibration?**
> The mechanism is complete. The data is one server and 54 observations. The
> tool rates itself weak on four criteria: fewer than three servers, fewer than
> thirty observations per server, and so on. It needs at least three servers
> before I can quote a false-alarm rate with confidence.

**23. When will experiment one be complete?**
> The night before the final submission window at the latest, but I intend to
> run it this week. It's a two-hour unattended job.

---

## D. What work still remains — 8 questions

**24. List everything left.**
> Complete experiment one. Run experiment two — keyed probes, the central
> comparison. Calibrate across at least three servers. Baseline one real
> community MCP server. Wire and calibrate the six built-but-unwired signals.
> Release the corpus with a documented split. Chapters six and seven.

**25. Which of those genuinely caps the grade?**
> Three. The experiments must actually run — everything else is secondary.
> Calibration is weak and needs three servers. And no real MCP server has been
> tested — only my own synthetic one.

**26. How long will the remaining work take?**
> Experiments one and two: about two hours each, unattended. Multi-server
> calibration: one to two days. A real community server: one to two days. Wiring
> the six modules: three to five days. Corpus release: three to five days.
> Chapters six and seven depend on the deadline.

**27. What are experiments three to six?**
> Defined in the design, not built in code. Three: probe recognisability across
> probe modes. Four: active-only versus active plus passive. Five: with and
> without paired probes. Six: full ablation. They depend on the six unwired
> modules being calibrated first.

**28. Will you get to all six?**
> Honestly, one and two are essential and I will complete them. Three to six are
> scoped as stretch goals. If time forces a cut, I cut six-down and report what
> was and wasn't done.

**29. What's the plan if experiment two shows keyed probes don't help?**
> I report it. The component measurements already show recognition dropping to
> zero, so I expect L4 recall to become defined and positive. If the end-to-end
> number disagrees, that's a finding about the gap between component and system
> performance, and it goes in the write-up.

**30. What's the biggest risk to finishing?**
> Time. The remaining work is well-defined and none of it is technically
> blocked. The risk is running out of days, which is why experiments one and two
> are scheduled first.

**31. Have you started writing chapters six and seven?**
> Not yet. Chapter six depends on results I don't have. Chapter five is written
> and describes the system as built, including seventeen documented divergences
> from the proposal.

---

## E. Planned testing and evaluation — 12 questions

**32. Describe your evaluation design.**
> Six controlled experiments, each varying one thing. Every episode is a fresh
> baseline of a benign server, one scenario armed, a fixed number of
> verification cycles, and a verdict compared against the attacker's own event
> log. Episodes run in isolated home directories so nothing leaks between them.

**33. What are the metrics?**
> Recall on attacks the ground truth proves executed. False-alarm rate on benign
> and benign-updated servers. Time-to-detection and calls-to-detection. Runtime
> cost — CPU and memory are recorded per row, though not yet analysed.

**34. How do you get ground truth?**
> From the adversarial server's own event log, written in its own process, with
> no knowledge of the detector's verdict. Without it, a missed detection and an
> attack that never fired look identical from outside.

**35. How do you classify an episode?**
> Five ways: detected, missed, never-triggered, benign-ok, false-alarm.
> Never-triggered is excluded from the recall denominator, and trigger exposure
> is reported separately.

**36. How do you prevent tuning to the test set?**
> Three partitions with separate seeds: development, calibration — benign and
> benign-updates only — and a blind test whose thresholds are frozen before it's
> opened. Every result row carries a hash of the detector configuration, so "no
> tuning after seeing test data" is auditable, not promised.

**37. What is the comparison baseline?**
> Hash-only pinning — what mcp-scan does. It's a flag in the same scorer, same
> code path, same traffic. Only the signals differ. Six of six attacks detected
> by DriftSentry, zero of six by hash-only.

**38. What does "benign update" mean and why does it matter?**
> A legitimate server that changes its behaviour for honest reasons — reworded
> output, a new field. It's the hard false-alarm case. If I only calibrated on a
> server that never changes, the threshold would be meaningless. Benign updates
> are in the calibration set specifically to prevent that.

**39. What seeds do you use?**
> 20260720 for fixed probe selection, recorded in every baseline. 1234 for the
> attacker's default scenario. Episode seeds 1, 2, 3 for attacks; 101 to 103 for
> benign controls; 201 to 203 for benign updates. All recorded in every result
> row.

**40. Is the evaluation reproducible?**
> Yes, by design. Two virtual environments from a lock file, seeds in every row,
> configuration hash in every row, and the attacker's scenario file is JSON.
> Anyone can rerun an episode and get the same ground truth.

**41. What have you measured about performance?**
> Per-call latency: minimum 100.4, mean 115.7, maximum 129.9 milliseconds across
> nine probes. A verification cycle of three tools, three probes, two samples is
> twelve to fourteen seconds. A full episode is about 110 seconds.

**42. What have you NOT measured?**
> The proxy's inline delay on a real call — I have no figure. Memory and CPU are
> recorded but not analysed. Test coverage — no coverage tool is installed.

**43. What would a negative result look like, and would you report it?**
> Keyed probes not recovering L4 recall, or false alarms rising on benign
> updates. Yes. A student who reports a negative result honestly demonstrates
> more than one who hides it, and the harness writes every row before I see it.

---

## F. Further development and refinements — 6 questions

**44. What's the next refinement after the experiments?**
> Wire the temporal and corroboration scorers. They target the two evasion
> strategies still open — low-and-slow, and sub-threshold attacks that stay
> under the line on every individual probe.

**45. What about passive monitoring?**
> It's built and watch-only. It's the only channel that can see a server which
> behaves for probes and attacks real users. Moving it into the scoring path is
> the most valuable refinement, and it needs its own false-alarm calibration
> first.

**46. Randomised probe rotation was in your proposal. Where is it?**
> Superseded by keyed generation, which is stronger. Randomisation within a
> fixed pool is still enumerable by reading the source. Keying removes the pool
> entirely — the adversary can't precompute what it's never seen.

**47. What would you add with more time?**
> Kernel-level tracing for side effects, replacing poll-based observation.
> Support for HTTP transport, not just stdio. And a proper corpus release with
> versioning.

**48. What have you decided NOT to do?**
> No deep learning, no LLM judge in the detection path, no reinforcement
> learning. The method is deterministic on purpose: the same evidence always
> gives the same verdict, and a defender can attribute every alert to a signal.

**49. Would you change the architecture if starting again?**
> No. Every one of the seventeen divergences from the proposal was a mechanism
> replaced after measurement, not an architectural change. The proxy, baseline,
> scorer and alerting layers are where they were designed to be.

---

## G. Other components before final submission — 6 questions

**50. What non-code items are outstanding?**
> Chapters six and seven. The corpus as a released, versioned artefact. Test
> coverage measurement. A measured figure for proxy overhead. `docs/TESTING.md`
> has stale references to an old name. Validation on a platform other than
> Windows — conditional branches exist but have never executed.

**51. Is there a licence?**
> Yes, MIT. It was declared in both project configurations from the start; the
> file itself was added when the repository was published this month.

**52. Is everything committed?**
> Yes, as of this month. The public repository is at the current working state
> with a clean tree.

**53. Have you got a reproducibility package?**
> Partially. Lock file, seeds, and configuration hashes are there. What's
> missing is the documented corpus split and a one-command "rerun everything"
> script — that's the last part of phase 8.

**54. What's your plan for the final demonstration?**
> Seven steps: self-test proving ground truth; the test suite; the dashboard on
> a benign server; arm an attack and watch the score jump; the alert with
> before/after evidence; hash-only versus full on the same armed server; and the
> harness classifying episodes. Step six is the whole project in one screen.

**55. What documentation exists?**
> A code guide covering every module and the detection logic. A testing guide. A
> viva demo runbook. Chapter five as a factual account of what was built. And
> the design document for the evasion-hardening work.

---

## H. Progress relative to the original proposal — 8 questions

**56. How does what you've built compare with what you proposed?**
> The four components — proxy, baseline capture, drift scorer, alerting — are
> all built where they were designed. Seventeen mechanisms inside them differ
> from the proposal. All seventeen are documented in a table with the reason for
> each.

**57. Give three examples of divergence.**
> Signals added together, proposed; highest signal taken, built — because
> correlated signals inflated false alarms. Threshold at the maximum benign
> drift, proposed; 99th percentile with margin, built — because one outlier
> would silence the detector permanently. Fixed seeded probe pool, proposed;
> HMAC-keyed derivation, built — because the adversary recognised the whole
> pool.

**58. Are any divergences omissions rather than improvements?**
> Two. Typer was declared as the command framework but argparse was used and
> Typer is unused — no reason recorded, and I'd rather say that than invent one.
> And HTTP transport was proposed; only stdio is built, which limits
> applicability and is stated in the evaluation.

**59. Did you deliver the nine research objectives?**
> RO1 to RO5 fully. RO6, the labelled dataset, partially — rows exist, split not
> documented. RO7, threshold calibration, partially — mechanism done, data weak.
> RO8 and RO9, the comparisons, are the experiments in progress.

**60. Are you ahead or behind your schedule?**
> On implementation, ahead — the daemon and dashboard were scheduled later and
> are done. On evaluation, behind — the experiments were meant to be complete by
> now and are not, because the evasion finding forced a redesign of probe
> generation mid-way. I judged fixing the detector before measuring it to be the
> right call.

**61. Was that redesign in scope?**
> It's RQ4 — "how does detection weaken when a probe-aware attacker knows about
> canary inputs, and does randomising probes help." The redesign is the answer
> to that question. It was always in scope; it just cost more time than planned.

**62. What did the original proposal underestimate?**
> How completely a probe-aware attacker would win. The proposal treated it as one
> level among five. It turned out to be a full evasion, and fixing it needed
> thirteen new modules, not a template shuffle.

**63. If the evaluators had to grade you on the proposal alone, what would be
missing?**
> Results. The proposal promised a comparison; I have interim numbers and a
> harness that produces them, not a finished table. That's the gap, and I've
> said so.

---

## I. Technical questions on the demonstration — 9 questions

**64. What is a canary probe?**
> A benign, harmless input sent to a tool purely to observe how it responds.
> Generated from the tool's own JSON schema, so it fits any tool. Only sent to
> tools classified as read-only — 46 destructive and 23 safe verbs govern that.

**65. What does the embedding model do?**
> all-MiniLM-L6-v2, run locally through ONNX. It turns a tool's response into a
> 384-dimensional vector so two responses can be compared by cosine distance.
> Meaning-aware, so a reworded benign answer stays close while an injected
> instruction moves away.

**66. Why not just compare the text directly?**
> Because benign servers vary — timestamps, ordering, rewording. Exact match
> would alarm on every honest call. Embedding distance tolerates that; the
> security rules and field drift catch what it doesn't.

**67. What is the noise floor and why does it exist?**
> MIN_BAND, 0.01. Without it a perfectly deterministic probe has a benign band
> of zero, and any change at all divides by nearly zero — I measured a score of
> 263,659 before adding it.

**68. How does keyed probe generation work?**
> HMAC-SHA256 over the key and a message containing version, server, tool,
> template, cycle, index and field path. The digest seeds a random generator,
> which draws the value. Same key and cycle, same probe — replayable. Different
> cycle, different probe — unrecognisable.

**69. Why redact arguments before embedding?**
> Tools echo their input. If the probe says "security-review-2026.md" and the
> response says "opened security-review-2026.md", the embedding measures my own
> probe generator, not the tool. Redaction dropped cross-input distance from
> 0.7561 to zero.

**70. Why leave-one-out variance?**
> Bands measured across all samples at once are too tight — the first honest
> re-probe of a variable tool exceeded them. Leaving each sample out and
> measuring its distance to the rest gives the out-of-sample variance the
> re-probe will actually see.

**71. What does the dashboard show when an attack fires?**
> The server card turns red, the drift graph crosses the alert line, and the
> alert record shows the winning signal, the score, before and after excerpts,
> and per-cause mitigations — quarantine, block, trust.

**72. What does `verify --hash-only` prove?**
> Same armed server, same probes, same scorer — behavioural signals discarded.
> It reports nothing wrong. Then the full verify on the same server alerts. Same
> traffic, different conclusion, and the only difference is the signals.

---

## J. Hostile and stress questions — 8 questions

**73. You built the attack and the defence. Isn't this circular?**
> It's the standard objection and the separation exists to answer it. Separate
> projects, no shared code, ground truth from the attacker's own log. But the
> honest answer is: yes, this is a lower bound. My attacker is one adversary. A
> real one may be different. That's why baselining a real community server is
> on the remaining list.

**74. Your results are on 38 of 66 episodes. Why should we trust them?**
> You shouldn't treat them as final, and I've labelled them interim on every
> slide. What you can trust is the harness that produces them — it's built,
> tested, and wrote every row before I looked at it. The remaining 28 episodes
> are a two-hour job.

**75. Fifty-four observations from one server is not a calibration.**
> Agreed. The tool says so itself — it flags the threshold as weak. It's enough
> to demonstrate the mechanism and produce interim results. It is not enough to
> quote a false-alarm rate, and I won't until three servers are in.

**76. A synthetic dataset. What does this tell us about the real world?**
> Less than a real one would, and there isn't a real one — that's research gap
> three. The attack families are each based on a documented incident: postmark-
> mcp, MCPoison, the Invariant Labs sleeper. The synthetic server is the only
> way to get ground truth. I report it as a lower bound.

**77. What if the attacker just behaves honestly for every probe?**
> Then active probing alone cannot see it, and I say so. That's why passive
> monitoring exists — it watches real traffic, not probes. It's built, it's
> watch-only, and wiring it into scoring is the highest-value remaining
> refinement.

**78. Isn't this just anomaly detection with a new name?**
> The measurement is anomaly detection. The contribution is where it's applied —
> at approval time, on an MCP tool, with deterministic probes — and that it's
> been tested against an attacker who knows it exists. No existing MCP defence
> does both.

**79. You changed seventeen things from the proposal. Did you plan anything?**
> I planned the architecture, and it held. What changed were mechanisms inside
> it, each one replaced after measurement showed the simpler version failed.
> Every change has a documented reason. I'd be more worried about a project
> where nothing changed on contact with data.

**80. Will you finish?**
> Yes. The remaining work is well-defined, none of it is technically blocked,
> and the two essential experiments are two hours each. What I can't promise is
> experiments three to six. If time forces a cut, I cut from the end and report
> what was done.

---

## The three answers to have automatic

**"How much is done?"** — Eight of ten phases. Implementation is substantially
complete; the controlled experiments are what remain.

**"What are your results?"** — Interim. 38 of 66 episodes. Levels one to three
at 100%, four and five undefined because the attacker never fired, zero false
alarms of six. I'd rather show you the component measurements and one
end-to-end result than present a partial run as finished.

**"What worries you most?"** — That no real MCP server has been tested.
Everything I claim is under controlled conditions against an adversary I wrote.

## The one trap

Never let "undefined" become "zero" under pressure. If an evaluator says "so
your detector got 0% on L4", the answer is: "It got no chances. The attack did
not execute in any of those twelve episodes. That's a different outcome, and
it's why probe generation was redesigned."
