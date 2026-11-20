"""Table 11 reports every follow-up that has results, H2c and H3c included.

Found on 20 Nov 2026: tables.md listed H2b and H3b only, although H2c and
H3c had verdicts, so the generated results file disagreed with the report.
"""
from eval import tables


def test_h2c_row_comes_from_its_verdict_and_fails_as_measured():
    row = tables._h2c_row()
    assert row.startswith("| H2c |")
    assert "| FAIL |" in row
    assert "best AUC 0.782" in row
    assert "caught L1 10/10, L6 10/10" in row
    assert "false alarms 9/12 in-session against 3/6 control" in row


def test_h3c_row_fails_on_its_held_out_half_and_says_what_was_not_run():
    row = tables._h3c_row()
    assert row.startswith("| H3c |")
    assert "| FAIL |" in row
    assert "held-out: 1/3 measured upgrades left residue" in row
    assert "tree-sitter: residue" in row
    assert "weak test" in row
    assert "synthetic re-run under v1.2: not run" in row


def test_table_11_lists_all_four_follow_ups():
    text = tables.table_followups()
    for name in ("| H2b |", "| H3b |", "| H2c |", "| H3c |"):
        assert name in text
