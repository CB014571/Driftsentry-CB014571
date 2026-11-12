"""The command line can do what the dashboard does: keyed enrolment and
update checking. Measured end to end against the attack server before these
were written: menu test 10 verified with --update-check gave ALERT with a
new_file residue on lookup_customer, and test 9 gave OK with UPDATE EXPLAINED
(WATCH 0.85 without the option)."""
from __future__ import annotations

from driftsentry.__main__ import _print_update, build_parser


def test_baseline_takes_a_probe_mode_and_keeps_fixed_as_the_default():
    p = build_parser()
    base = ["baseline", "--server", "s", "--exec", "python", "x.py"]
    assert p.parse_args(base).probe_mode == "fixed"
    assert p.parse_args(base[:3] + ["--probe-mode", "keyed"] + base[3:]).probe_mode == "keyed"


def test_verify_update_check_is_off_by_default():
    p = build_parser()
    ns = p.parse_args(["verify", "--server", "s"])
    assert ns.update_check is False and ns.cycle == 1
    ns = p.parse_args(["verify", "--server", "s", "--update-check", "--cycle", "7"])
    assert ns.update_check is True and ns.cycle == 7


def test_the_update_is_printed_in_the_dashboards_words(capsys):
    outcome = {"verdict": "residue_alert", "escalations": [],
               "items": [{"tool": "lookup_customer", "signal": "new_file",
                          "classification": "residue",
                          "reason": "no declared change explains it"}],
               "explained_tools": [], "tools_needing_baseline": [],
               "declared": {"tools_added": [], "tools_removed": [], "tools": {
                   "lookup_customer": {"output_changes": [{"path": "last_contact",
                                                           "kind": "added"}]}}}}
    _print_update(outcome)
    out = capsys.readouterr().out
    assert "UNDECLARED BEHAVIOUR" in out
    assert "declared   lookup_customer: output added last_contact" in out
    assert "RESIDUE    lookup_customer: new_file" in out


def test_an_explained_update_says_so(capsys):
    _print_update({"verdict": "accepted", "items": [], "escalations": [],
                   "explained_tools": ["lookup_customer"],
                   "tools_needing_baseline": [], "declared": {}})
    out = capsys.readouterr().out
    assert "UPDATE EXPLAINED" in out
    assert "safe to re-baseline: lookup_customer" in out
