# H2c amendment 1 (15 Nov 2026, after a failed collection, before any AUC)

**What happened.** Two copies of the H2c collection ran at the same time.
An earlier queue script (`run_h2c.sh`) was stopped with the harness's task
stop, but on Windows that ended only its wrapper: the bash process kept
waiting and, when H2b finished at 20:05:39, started `h2c collect` at
20:05:57. The overnight queue started its own `h2c collect` at 20:08:39.
Both wrote to `followup/h2c/collection` and used the same workspace.

**How it was caught.** `h2c fit` refused the data: `LabelError: 8 row(s)
fall inside more than one window ... overlapping windows mean the collector
ran two at once`. Session spans in `windows.jsonl` confirm it (sessions
3-25 span ~170 s to ~57 min and overlap one another).

**What was computed from it.** Nothing. No dataset was built, no recogniser
was fitted, no AUC exists. The data is kept, unused, in
`collection_INVALID_two_collectors_2026-11-15/` (with its logs) for the
record.

**Change.** None to the hypothesis, thresholds, procedure, seeds, split or
code. The collection is re-run from scratch, alone on the machine, under a
lock that refuses to start a second copy.

**Responsibility.** A process-management error by the experimenter's
tooling, not a property of the detector or of the data.
