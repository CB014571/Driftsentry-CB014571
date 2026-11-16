# H2b amendment 2 (15 Nov 2026, after the matrix, correcting a misreading)

**What happened.** In the H2b matrix (`logs/h2b_matrix.log`, 15 Nov 18:54-19:57),
14 of 36 episodes ended in `error` before any probing: the attacker control
command failed to start with Windows exit code 3221225794 (0xC0000142,
STATUS_DLL_INIT_FAILED). They were every L6 attack episode (12) and two L6
benign-update episodes. The L1 arm (18 episodes) and the control (6) had no
errors. The cause of the process-start failure was not established.

**What was wrong.** `verdict.json` reports L6 `fired: 0` because errored
episodes write no row. That was read, and written in the commit message of
5a356bc and in the updated mid-point report, as "the L6 adversary never
attacked in any episode". That reading was wrong: the L6 arm was never run.

**What is unaffected.** H2b fails on its first criterion regardless: best AUC
0.887 against a 0.6 ceiling (fit on the collection, which had no errors).

**Change.** None to hypothesis, thresholds, seeds, recogniser or code. The
errored episodes are re-run with the same frozen main-tree code once the
machine is free (the sweep resumes and skips recorded episodes), and the
verdict is recomputed. Both the original and re-run logs are kept.
