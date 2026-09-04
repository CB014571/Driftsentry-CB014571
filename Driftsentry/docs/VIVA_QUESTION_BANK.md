# DriftSentry — viva question bank

Every question an examiner is likely to ask, with the answer from your code.
Answers use real numbers from the working tree.

**Danger markers:** 🔴 you are currently weak here — prepare the honest answer.
🟢 your strongest ground — steer towards these.

---

## A. Opening and framing

**1. What is your project about?** — one sentence, then stop.
> DriftSentry detects behavioural rug-pull attacks in the Model Context Protocol,
> where an approved tool starts behaving maliciously while its advertised
> definition stays byte-for-byte identical — so every existing defence, which pins
> that definition, is blind to it.

**2. What is MCP, in one sentence?**
> An open standard that lets an AI assistant discover and call tools hosted by
> external servers, over JSON-RPC.

**3. What is a rug pull?**
> A tool that is benign when the user approves it and turns malicious afterwards.
> The classic form edits the tool's description; the behavioural form leaves the
> description untouched and changes only what the code does.

**4. Who is this for?**
> Developers and organisations running MCP clients — Claude Desktop, Cursor,
> VS Code — with third-party servers installed from aggregators that have no
> mandatory pre-publication review.

**5. Why does this matter?**
> MCP tools run with the user's local privileges and the assistant acts on their
> output autonomously. The user's only assurance is an approval dialog they saw
> once, weeks ago.

---

## B. Problem and motivation

**6. Give me a real-world example.**
> The postmark-mcp incident: an approved email tool silently began copying
> messages to an attacker's address. The Invariant Labs sleeper rug pull. The
> MCPoison CVE, which targeted a stdio-launched config.

**7. Why can't hash pinning solve this?**
> Because it verifies the declaration. My adversarial server's six attack families
> all hash to `6805aff88dcf676e…` — identical to benign. My self-test asserts this.

**8. Isn't this just prompt injection?**
> No. Prompt injection puts hostile text into content the model reads. This is the
> tool's own implementation changing behaviour after approval. Content injection
> is one of my six families, but exfiltration and silent-tamper leave the response
> unchanged entirely.

**9. Why not just read the source of every MCP server?** 🟢
> Most are installed as packages and updated automatically. Users cannot audit
> every update, and a study of MCP aggregators found users could not reliably
> identify malicious servers even when asked to try.

**10. Why not sandbox the server instead of detecting?**
> Containment is a different control and a valid one. My contribution is
> detection — knowing that behaviour changed. DriftSentry observes; it does not
> contain. That is stated as a boundary.

**11. How common is this attack?** 🔴
> I have no prevalence data. Documented incidents exist, and the two most-cited
> MCP security papers name rug pull as a core threat, but I cannot claim a rate.

**12. Why is this a security problem and not a software-quality problem?**
> Because the change is adversarial and deliberately concealed. A quality
> regression does not try to look like the previous version.

**13. What happens if you don't solve it?**
> Approval becomes meaningless. The user's one moment of consent protects nothing
> after the first update.

---

## C. Literature and research gap

**14. What is your research gap?** 🟢
> No published method pins a per-tool behavioural baseline at the point of human
> approval, re-verifies it with deterministic probes over the live session, and
> thresholds against benign traffic that includes benign updates. That
> combination — not runtime analysis in general — is the gap.

**15. Surely someone has done runtime analysis of MCP tools?**
> Yes, and I cite them. MCP-SandboxScan runs tools in a WASM sandbox, but as a
> one-shot scan with no temporal baseline — a tool clean when scanned and dirty a
> week later passes. Runtime Skill Audit does runtime probing but for agent
> skills, and classifies rather than compares against an approval-time baseline.

**16. What about ETDI?**
> ETDI is the flagship anti-rug-pull proposal for MCP, using OAuth identity,
> immutable versioned definitions and a policy engine. Every one of those verifies
> a property of the *declaration*. A server that keeps its signed definition
> identical and changes only the function body satisfies ETDI completely.

**17. How is this different from anomaly detection generally?**
> The substrate and the threat model. The baseline is captured at a specific
> security-relevant moment — human approval — and the adversary is adaptive and
> can observe the detector's probes.

**18. Which paper is closest to yours?**
> Behavioural Fingerprints for LLM Endpoint Stability. It fingerprints an endpoint
> with a fixed prompt set and tests for distribution shift over time —
> structurally my loop. It targets model endpoints, has no adversary, and uses a
> statistical test rather than a calibrated threshold.

**19. Has the gap narrowed since you started?** 🟢
> Yes, and I should say so. Two 2026 papers moved into adjacent space. That is why
> I narrowed my claim rather than restating "nobody has done this".

**20. How many sources have you reviewed?** 🔴
> *Know your own count before you walk in.*

**21. What is the most important paper you cite and why?**
> Beyond the Protocol — the first systematic study of MCP attack vectors. It
> establishes rug pull as one of four categories and shows aggregator audits do
> not catch malicious servers.

**22. Why should anyone believe your gap is real?**
> Because a commercial product markets rug-pull protection implemented as metadata
> pinning. If behavioural verification were solved, that product would not ship
> the blind spot.

---

## D. Design decisions

**23. Why a proxy and not a plugin in the client?** 🟢
> A proxy works with any MCP client without modifying it, and it is where
> mcp-scan's proxy mode sits, so the deployment story is proven. A client plugin
> would need one implementation per client.

**24. Why stdio only?**
> Phase scope, matching the real MCPoison CVE, which targeted a stdio-launched
> config. HTTP entries are detected and reported, never half-handled. A remote
> server also gives no process to observe, so side-effect signals disappear.

**25. Why probe out of band instead of inspecting live calls?**
> Three reasons in the code: probing on the live path would add latency to real
> tool calls; it keeps the audit log a record of what the user's client actually
> did; and it gives the sandbox monitor a process tree it owns, so file and
> network evidence is attributable.

**26. Why max() and not sum?** 🟢
> The embedding and structural signals read the same response — they are
> correlated. Summing lets benign noise on a chatty tool accumulate into an alert.
> Max also keeps attribution unambiguous.

**27. What's the cost of max()?**
> An attacker holding every signal just below the line is not caught. I built a
> corroboration scorer for that; it is not yet calibrated, so max remains default.

**28. Why is enforcement off by default?** 🟢
> Detection is the contribution being evaluated. A proxy that silently blocked
> attacks would confound every detection measurement — the attack would never get
> to happen.

**29. Why leave-one-out variance?** 🟢
> Measuring spread against a centroid fitted to the same samples is an in-sample
> estimate, systematically too tight. The first honest re-probe of a noisy tool
> breached the band and a benign server false-alarmed. Leaving each sample out
> measures how far an *unseen* sample falls — the quantity the band must cover.

**30. Why is the threshold above the band, not at it?**
> The band already estimates benign spread, so roughly half of future benign
> samples land near ratio 1.0 by construction. Alerting there would fire on
> healthy tools constantly.

**31. Why a quantile and not the maximum benign value?**
> A deterministic tool has a near-zero band, so one flicker yields a ratio in the
> hundreds of thousands. A max-based threshold would then silence the detector
> permanently. The quantile also states the accepted false-alarm rate explicitly.

**32. Why must calibration include benign updates?** 🟢
> Calibrating only against a frozen server measures a world that does not exist.
> Real deployments update. A threshold fitted to a never-changing server is too
> tight, so the first honest update trips it.

**33. Why no LLM in the decision?** 🟢
> Reproducibility. Given the same baseline and responses the score is bit-for-bit
> identical every run. An LLM judge could not be audited or replayed, and it can
> hallucinate. An LLM may only ever appear as a secondary explainer.

**34. Why keyed probes rather than random ones?** 🟢
> Random still has to be reproducible for experiments. HMAC keying gives both: the
> key is an input so a run replays exactly, while the server cannot predict the
> next value. The pool is also no longer enumerable from the source.

---

## E. Implementation — the constants

**35. What does `MIN_BAND = 0.01` mean?** 🟢
> The embedding noise floor. A deterministic tool has zero variance and the scorer
> divides by the band, so a floor is needed. I first used `1e-6`, which implies
> six decimal places of precision the embedding does not have, and produced a
> drift score of **263,659**.

**36. `BAND_SIGMA = 3.0`?**
> The band is the wider of the worst held-out sample and mean + 3σ — covering both
> a tight noisy tool and one with rare outliers.

**37. Why is `W_STRUCTURAL` 0.85, below the alert line?**
> Benign updates add optional fields constantly. Structure alone produces a watch,
> not an alert. It becomes decisive only when the embedding signal is also up.

**38. Why `W_DEFINITION_HASH = 3.0`?**
> A changed definition is not *evidence* of a rug pull, it *is* one class of rug
> pull. Weighted well clear of the line so a tight threshold cannot argue it down.

**39. Why cap the behavioural signal at 3.0?**
> Past a few multiples of the threshold the signal has said everything it can.
> Uncapped it produced scores in the tens of thousands, unusable in a report.

**40. What is `WATCH_AT = 0.85`?**
> Calibration places the threshold 1.25× above the benign operating point, so
> benign behaviour scores up to about 0.80. Watch begins just above that.

**41. How many dimensions?** — 384.

**42. How many samples per probe?** — 8 at baseline in the stored record
(default 5), 2 when re-checking. 3 probes per tool. 72 calls in one capture.

**43. What is your seed and why does it matter?**
> `20260720`, stored in every baseline. Seeded from a *string* with `version=2`,
> which hashes with SHA-512, because Python randomises `hash()` per process — a
> per-run seed would make the control condition irreproducible.

**44. Why 20-second checks?**
> A default balancing detection latency against load. Configurable via
> `--interval`.

**45. How does the sandbox monitor work, and what does it miss?**
> psutil polls the server's process tree every 20 ms for open files and
> established connections. It misses anything opened and closed between two polls.
> Closing that needs a kernel tracer — out of scope, and stated.

**46. Why compare hosts by IP and not IP:port?** 🟢
> Ports are ephemeral. Keying on address:port made every connection look new and
> fired the egress rule forever. Python's asyncio self-pipe is also a loopback
> socketpair on Windows, so an innocent server appeared to contact a new host each
> run.

**47. What is the differential rule design?**
> Every security rule fires only when a pattern is present now and absent at
> baseline. A password manager legitimately emits credential-shaped output; what is
> suspicious is a tool that never did and now does.

**48. How many rules and patterns?**
> 24 patterns across three families — 9 credential shapes, 6 instruction shapes,
> 9 secret file paths.

**49. What is `field_drift` for?** 🟢
> Whole-response embeddings are blind to one-digit edits. Measured: changing an
> account number from 382910 to 382911 moves the embedding 0.1367, and scores 1.0
> on field drift.

---

## F. The machine-learning question

**50. Is this machine learning?** 🟢
> It uses a pre-trained neural embedding as a **fixed feature extractor**. Nothing
> is trained, fine-tuned or fitted. There is no classifier. The decision layer is
> arithmetic and regular expressions.

**51. Prove it.**
> No PyTorch, scikit-learn or TensorFlow in the environment. `scorer.py` imports
> only `dataclasses`, `datetime`, `typing` and my rules module — not even numpy.

**52. Why didn't you train a classifier?**
> It would need the labelled corpus that does not exist for this attack — that is
> gap G3 — and it would sacrifice the determinism the project is positioned on.

**53. Why all-MiniLM-L6-v2 over alternatives?**
> Compared three. `sentence-transformers` + torch rejected at ~2 GB. Ollama
> supported but needs a separate native daemon. ONNX chosen: real semantics, ships
> with ChromaDB, no torch, offline after one 90 MB fetch. Hashing kept as a
> dependency-free fallback.

**54. Can the model hallucinate?**
> No. Hallucination is a property of generative models. An embedding model
> produces a fixed vector from fixed input — same input, same output. It can be
> imprecise, which is a threat to validity, but it cannot invent.

**55. What is your accuracy?**
> Accuracy is the wrong metric — the classes are imbalanced and a detector that
> never alerts would score well. I report recall on attacks that verifiably
> executed, and false-alarm rate on benign servers including updates.

---

## G. Adversary and threat model

**56. What is your threat model?**
> A third-party MCP server, benign at approval, that turns malicious afterwards.
> It can observe every probe it receives, and may know how DriftSentry works. It
> cannot read the user's filesystem — if it could, it would have the key.

**57. Why did you build your own attacker?**
> No labelled corpus exists for this attack, so ground truth had to be
> constructed. Building malicious MCP servers for evaluation is what Beyond the
> Protocol did too.

**58. Isn't testing against your own attacker circular?** 🔴
> Partly, and I say so. Two mitigations: the six families map onto published
> taxonomies rather than being invented, and my L4 attacker **defeats** my own
> detector — which is not what you would build if you were rigging the result.

**59. Describe your six families.**
> exfiltration (copies the answer, response unchanged), silent-tamper (rewrites one
> detail), content-injection (appends instructions to the assistant), new-egress
> (opens a held connection to a decoy host), sleeper (gate-only, fires after a
> trigger), conditional (gate-only, fires on interesting input).

**60. And the five levels?**
> L1 naive, fires every call. L2 stochastic. L3 trigger-gated. L4 probe-aware —
> behaves normally when it recognises a canary. L5 mimicry — probe-aware plus
> payloads shaped to minimise measurable drift.

**61. Why separate families from levels?**
> Six families × five levels is thirty attacks from two mechanisms, not thirty
> hand-written cases. The levels mean the same thing across families, so the
> recall matrix is comparable row to row.

**62. How do you know the attack actually happened?** 🟢
> The attacker writes its own event log, in its own process, with no knowledge of
> the detector's verdict. Without it, a missed detection and an attack that never
> fired look identical.

**63. Was that always the case?** — No. Three of six families recorded nothing
until I fixed it. Until then, half the matrix was unmeasurable.

**64. Can your system be evaded?** 🟢
> Yes, and I demonstrated it. My L4 attacker recognised **100%** of my fixed
> probes (9/9) and never fired. After keyed generation, recognition was **0%**
> (0/360), and the same attack went from `never_triggered` to `detected` at 2.966.

**65. What if the attacker knows about keyed probes?**
> It knows the grammar, not the key. It cannot predict the next value. It can
> still recognise a value it has already seen, which is why values rotate every
> cycle and are never reused.

**66. What if the server is malicious from the start?** 🔴
> Undetectable. Trust On First Use — the baseline records the malice as normal.
> That bounds every claim I make to the post-approval case, and no baseline method
> can close it.

---

## H. Evaluation and results

**67. What are your results?** 🔴
> The full experiment is **incomplete** — 38 of 66 episodes. I have component-level
> measurements and one end-to-end result. I do not yet have a finished evaluation,
> and I am not going to present partial numbers as final.

**68. What do you have?**
> Interim control condition at threshold 10.8086: L1, L2, L3 all 100% recall on
> attacks that executed; L4 and L5 undefined because nothing fired; false alarms
> 0 of 6 benign episodes.

**69. Why is L4 recall "undefined" and not zero?** 🟢
> Because nothing executed. The attacker recognised the probes and declined to act
> — 54 probe-shaped inputs held back in one episode. A detector cannot be blamed
> for missing an attack that did not happen. That is why trigger exposure is
> reported separately.

**70. How do you compare against existing tools?**
> A hash-only control implemented as a `mode` flag **inside the same scorer**, fed
> by identical traffic. Not a reimplementation of mcp-scan that might differ
> incidentally — my own detector with the behavioural signals switched off.

**71. What is your headline metric?**
> Recall against attacks the attacker's independent log proves executed, reported
> beside false-alarm rate on benign and benign-updated servers.

**72. How many tests?** — 177, passing, in 1.7 seconds.

**73. What do the tests actually protect?**
> The first four files are regression locks written *before* any detector change:
> the scorer's weights and max-combination, the fixed probe values that form the
> control condition, the variance maths, and all four `weak` triggers.

**74. Is your threshold trustworthy?** 🔴
> Not yet. 54 observations, one server. My own tool flags it `weak: true` because
> my minimum is three servers and thirty observations.

**75. Have you tested a real MCP server?** 🔴
> No. Only my own synthetic server. It is the most significant remaining
> limitation.

**76. What is your false-alarm rate?**
> 0 of 6 benign episodes in the interim run, at the calibrated threshold. Too few
> episodes to quote as a rate.

**77. How long does verification take?**
> About 12–14 seconds per cycle for 3 tools × 3 probes × 2 samples. A single tool
> call averages 100.41 ms. A full episode including baseline is about 110 seconds.

**78. What is the proxy's latency overhead?** 🔴
> Unmeasured. I will not quote a figure I have not measured.

---

## I. Limitations

**79. What are your main limitations?**
> Trust On First Use. Polling rather than tracing. stdio only. One synthetic
> server. Weak calibration. Windows only. Incomplete experiment.

**80. Which limitation worries you most?**
> The absence of a real community server. Everything I claim is under controlled
> conditions with an adversary I wrote.

**81. Does the embedding model threaten validity?**
> Yes. Results may vary by model. Mitigated by recording the backend and dimension
> in every baseline and refusing to reuse a threshold across embedding spaces.

**82. What about Windows-only testing?**
> Platform branches exist in the code, but no run has been performed on Linux or
> macOS. `psutil.open_files()` is also partial on Windows, so file evidence is
> weaker than network evidence there.

**83. Could a benign update trigger an alert?**
> Yes — a legitimate update produces the same signal as a subtle attack. That is
> why calibration includes benign updates, and why the ambiguous-cause mitigation
> says "compare the before and after and decide" rather than "you were attacked".

**84. Where could this fail silently?**
> If the embedding backend falls back to lexical hashing unnoticed. I made that
> fallback emit a warning, because capturing a whole evaluation with the weak
> backend and never noticing would invalidate every result.

---

## J. Ethics, legal, social, professional

**85. You built working attack code. Justify that.** 🟢
> It contains no exploit against any third-party system — it attacks only itself.
> Exfiltration writes to a file in its own directory. New egress connects to a
> decoy listener the same process started, on 127.0.0.2. Nothing leaves the
> machine.

**86. What about the credentials in it?**
> Obvious fakes — `sk-testbed0000…`, `AKIATESTBEDFAKE00000`. Synthetic by design
> and recognisable as such to any reader.

**87. Could someone weaponise your attacker?**
> They would gain nothing. It attacks only its own synthetic tools. Anyone capable
> of writing a malicious MCP server does not need my code to do it.

**88. Any personal data?**
> None. All test data is synthetic. All state is local. No telemetry, no
> analytics, no external transmission.

**89. What if you found a vulnerability in a real server?**
> Coordinated disclosure. No third-party server has been tested, so the
> obligation has not yet arisen.

**90. BCS Code of Conduct — which clauses?**
> Public interest — the closed-loop design. Professional competence — stating what
> I have not measured. Duty to the profession — reporting a negative result
> against my own system.

**91. Licensing?** 🔴
> Both projects declare MIT in `pyproject.toml`, but **no LICENSE file exists**. A
> declared but unfulfilled licence. It needs fixing.

**92. Any bias concerns?**
> No classifier is trained, so no training-set bias. The nearest analogue is the
> safety-classification keyword heuristic, which is English-only and would
> misclassify tools named in other languages.

---

## K. Project management

**93. What methodology did you follow?**
> Incremental and phase-gated. Ten phases, each with an executable
> definition-of-done check that exercises real code paths against real processes,
> not mocks.

**94. How do you know a phase is done?**
> `scripts/run_all_checks.py` runs five phase checks in order and exits non-zero
> if any fails.

**95. Version control?** 🔴
> One private Git repository, two top-level folders. Last commit 2 August; a large
> body of work is currently uncommitted and needs committing.

**96. What went wrong during development?** 🟢
> Several things worth naming: in-sample variance false-alarming on a benign
> weather tool; `MIN_BAND` producing a score of 263,659; `"put"` matching inside
> `"input"` and denying baselines to `echo`; ephemeral ports making every
> connection look new; and a child process inheriting DriftSentry's own log handle
> so the detector accused a benign server of opening its file.

**97. How did you find those?**
> All only visible when running for real, against a real process, for long enough.
> None was findable by reasoning about the code.

**98. What is left to do?**
> Complete Experiment 1, run Experiment 2, calibrate across three servers,
> baseline a real community server, and wire the nine built-but-unwired signals.

---

## L. Hostile and stress questions

**99. This looks like a lot of code that does very little. Convince me.**
> The detector is 9,000 lines because behaviour has many surfaces. The
> contribution is not the volume — it is that a definition-identical attack scores
> 2.06 while the hash-only control scores nothing on the same traffic.

**100. Your attacker is trivially simple compared to a real one.**
> Agreed for L1. L4 is not: it recognised 100% of my probes and defeated my own
> detector. That is a realistic capability, and it beat me before I fixed it.

**101. Aren't you just detecting that text changed?**
> No. Text change is the weakest of eight signals and is deliberately scaled by
> each tool's own learned variance. Exfiltration changes no text at all and is
> caught by side-effect evidence.

**102. Why should I believe 100% recall on L1–L3?**
> You should not treat it as final — the run is incomplete and it is my own
> attacker under controlled conditions. What it establishes is that when an attack
> executes, the detector currently sees it.

**103. Your calibration is from one server. Isn't the whole evaluation invalid?** 🔴
> The threshold is not yet quotable as a result, and my tool says so. The relative
> comparisons — full detector versus hash-only, fixed versus keyed probes — hold
> because both conditions use the same threshold.

**104. What if I told you a simple regex would catch these attacks?**
> For content injection, partly — and I have those rules. It catches nothing for
> exfiltration or silent-tamper, where the visible response is unchanged or
> differs by one character.

**105. Could a determined attacker still beat this?** 🟢
> Yes. An attacker that recognises probes perfectly, or attacks only real user
> traffic, or was malicious from the start. I do not claim otherwise. The
> contribution is raising the cost of evasion and measuring what that costs.

**106. What is the weakest part of your work?**
> The evaluation. The mechanism is built and tested; the measurement is
> incomplete.

**107. If you had another month?**
> Finish both experiments, calibrate on three servers, baseline `mcp-server-git`,
> and wire the temporal and corroboration scorers.

**108. What would you do differently from the start?**
> Build the evaluation harness first. I built the detector before I could measure
> it, so several design decisions were made without evidence.

---

## M. Closing

**109. What is your single most important finding?** 🟢
> That fixed probes are enumerable and an adaptive attacker exploits it. My L4
> attacker recognised every probe and never fired — undetectable because nothing
> happened. Keyed probes dropped recognition to zero and the same attack was
> caught at 2.966.

**110. What is your contribution?**
> Three things: a working behavioural detector for a threat that definition
> pinning cannot see; an adversarial server generating ground-truth-labelled
> attacks across six families and five evasion levels; and a measured negative
> result showing a probe-aware attacker defeats fixed-probe verification.

**111. Is your project finished?**
> The implementation is. The evaluation is not — 38 of 66 episodes, and the
> comparison run has not been executed.

**112. Anything you want to add?** — Have one sentence ready. Suggest the negative
result: it is the most credible thing you have, precisely because it makes you
look worse before it makes you look better.

---

## The three answers to rehearse until automatic

1. **"263,659."** The `MIN_BAND` story. It proves you debugged your own numbers.
2. **"100% to 0%."** Probe recognition before and after keyed generation.
3. **"My own tool flags it weak."** Say the calibration limitation before they find it.

## The one trap to avoid

Do not present the interim numbers — L1–L3 at 100%, FAR 0/6 — as results. They
come from an incomplete run of 38 of 66 episodes. Say "interim, incomplete" every
single time you mention them. An examiner who catches you quoting a partial run as
a finished result will doubt everything else you said.
