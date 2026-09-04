"""Evaluation harness — controlled experiments over the detector.

Builds labelled episodes by driving the adversarial server, runs verification
cycles against a freshly captured baseline, and scores the outcome against the
attacker's own event log rather than against the detector's opinion of itself.

The rule that shapes everything here: an episode counts as a missed detection
only when the attacker's independent record proves the malicious action actually
executed. A probabilistic or trigger-gated attack that never fired is a separate
outcome and is excluded from the recall denominator.

Layout
    record.py            one row of evidence, plus CSV/JSONL writers
    ground_truth.py      reads the attacker's event log; recall / FAR / exposure
    scenario_control.py  drives the attacker CLI as a subprocess
    harness.py           one episode, on isolated home directories
    experiments.py       the experiment definitions
"""

__version__ = "0.1.0"
