# H2b amendment 1 (15 Nov 2026, after collection, before any fit)

**What failed.** `python -m eval h2b fit` stopped in `eval.rq3_dataset.build`
with `LabelError: 60 process instance(s) served BOTH genuine and probe traffic`.

**Why.** That purity check was written for the original RQ1/RQ2 collection,
where probes ran in their own session: there, a process serving both labels
could only mean two sessions overlapped. H2b's mechanism is the opposite by
design - probes are interleaved into the client's own session, so every one of
the 60 sessions is one server process serving both kinds of call.

**Change.** `build(..., mixed_groups=True)` skips that one check for H2b only.
Nothing else changes: the pre-registered "5-fold GroupKFold by process" still
holds, each session's process stays whole on one side of every split, the
window-overlap check still runs, and the bootstrap still resamples by group.
No hypothesis, threshold, seed, family, or collected data was changed, and no
AUC had been computed when this was written.

**Consequence for reading the result.** Within a group, genuine and probe rows
now share process-level features (client, env, cwd, process start). That is the
point of in-session verification, and it makes those families uninformative by
construction; the timing and argument families carry whatever signal remains.
