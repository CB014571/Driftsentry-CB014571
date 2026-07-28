"""MCP Rug-Pull Attack Server - a standalone adversarial MCP server.

This is the *attacker* half of the project. It exists to generate ground-truth
rug pulls, so that a behavioural detector can be measured honestly:

  * without a real attack there is nothing to detect, so detection rate is
    unmeasurable;
  * without benign and benign-UPDATE modes there is nothing to be wrong about,
    so false-alarm rate is unmeasurable - and that is exactly the gap in the
    literature this project set out to close.

Independence is the point
    This is a separate project with its own environment. It does not import
    DriftSentry, cannot see DriftSentry's probe generator, and shares no code
    with it. The two only ever meet as operating-system processes speaking MCP
    over stdio - the same way DriftSentry meets any third-party server.

    That separation is what answers the obvious objection to a project that
    builds both the attack and the defence. The one deliberate exception is the
    `--probe-aware` opt-in (complexity levels L4 and L5), where the attacker is
    explicitly handed a guess at what the defender's test inputs look like, so
    that an adaptive attacker can be evaluated at all.

Safety
    Closed-loop by construction. No working exploit against any third-party
    system, no real network destination, synthetic data only. "Exfiltration"
    appends to a file in a local scratch directory; "new egress" connects to a
    decoy listener this same process started on 127.0.0.2. Nothing leaves the
    machine.
"""

__version__ = "0.1.0"
