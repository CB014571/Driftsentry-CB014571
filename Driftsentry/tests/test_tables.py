"""The result tables, and the ways a table can lie.

This module exists because four harness artefacts in this project each
produced a number that looked like a finding, and every one was caught by
comparing what the code did against what a table claimed. A table built from
the result files can still mislead in three specific ways, and each gets a
test:

    by counting rows instead of episodes, which weights a long episode more
    heavily than a short one and is not a rate over attacks at all;

    by pooling replications, which treats the same twelve configurations run
    four times as forty-five independent attacks and reports an interval
    narrower than the design supports;

    by printing a zero where nothing was measured, which is a different
    claim from a measured zero.
"""
from __future__ import annotations

import json

import pytest

from eval import tables


@pytest.fixture
def results(tmp_path, monkeypatch):
    monkeypatch.setattr(tables, "RESULTS", tmp_path)
    return tmp_path


def _csv(path, rows):
    header = ["episode_id", "attack_level", "attack_family", "mode", "outcome",
              "hash_detected", "passive_detected", "full_detected",
              "passive_available", "definition_changed"]
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(str(row.get(k, "")) for k in header))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Episodes, not rows
# --------------------------------------------------------------------------- #
def test_an_episode_counts_once_however_many_cycles_it_wrote(results):
    """A four-cycle episode and a one-cycle episode are one attack each."""
    _csv(results / "exp3_client_L1.csv", [
        {"episode_id": "a", "attack_level": "L1", "outcome": "missed",
         "full_detected": "false", "passive_available": "true"},
        {"episode_id": "a", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
        {"episode_id": "a", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
        {"episode_id": "b", "attack_level": "L1", "outcome": "missed",
         "full_detected": "false", "passive_available": "true"},
    ])
    table = tables.table_three_way()
    # Two attacks, one caught - not four rows with three detections.
    assert "| client | 2 | 0/2 | 0/2 | 1/2 |" in table


def test_an_episode_detected_in_any_cycle_is_detected(results):
    """Detection is a property of the episode: catching it on cycle 3 is
    catching it."""
    _csv(results / "exp3_client_L1.csv", [
        {"episode_id": "a", "attack_level": "L1", "outcome": "missed"},
        {"episode_id": "a", "attack_level": "L1", "outcome": "detected"},
    ])
    assert "| client | 1 | 0/1 | 0/1 | 0/1 |" in tables.table_three_way()


# --------------------------------------------------------------------------- #
# Replications are not independent attacks
# --------------------------------------------------------------------------- #
def test_the_sweeps_are_reported_separately_not_pooled(results):
    """The L1 sweeps differ only in a recogniser that L1 ignores, so pooling
    them would report an interval narrower than the design supports."""
    for family in ("client", "session"):
        _csv(results / f"exp3_{family}_L1.csv", [
            {"episode_id": f"{family}-1", "attack_level": "L1",
             "outcome": "detected", "full_detected": "true",
             "passive_available": "true"},
        ])
    table = tables.table_three_way()
    assert "| client | 1 |" in table and "| session | 1 |" in table
    # The pooled total is stated, but the interval is not put on it.
    assert "Across all 2 replications, 2 episodes" in table
    assert "(2/2)" not in table, "an interval was placed on pooled replications"


def test_the_quoted_interval_comes_from_one_replication(results):
    _csv(results / "exp3_client_L1.csv", [
        {"episode_id": "c1", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
        {"episode_id": "c2", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
    ])
    _csv(results / "exp3_session_L1.csv", [
        {"episode_id": "s1", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
    ])
    table = tables.table_three_way()
    # The smallest sweep, so the interval is not the most flattering one.
    assert "sweep `session`" in table
    assert "(1/1)" in table


# --------------------------------------------------------------------------- #
# A missing result is not a zero
# --------------------------------------------------------------------------- #
def test_an_absent_file_says_so_rather_than_reporting_zero(results):
    for table in (tables.table_three_way(), tables.table_rq3_auc(),
                  tables.table_real_upgrades(), tables.table_countermeasures()):
        assert tables.MISSING in table


def test_a_missing_table_names_the_command_that_would_produce_it(results):
    assert "python -m eval t20" in tables.table_countermeasures()
    assert "eval collect" in tables.table_rq3_auc()


def test_experiment_two_is_called_out_as_never_run(results):
    """Its log holds one line and there is no result file. The fixed-against-
    keyed comparison is the detector's own contribution, so an absent arm has
    to be loud."""
    _csv(results / "exp1_fixed_probes.csv", [
        {"episode_id": "a", "attack_level": "L1", "outcome": "detected"},
    ])
    table = tables.table_probe_modes()
    assert tables.MISSING in table
    assert "python -m eval run --experiment 2" in table


def test_the_summary_lists_everything_outstanding(results):
    text = tables.build()
    assert "## Outstanding" in text
    assert tables.MISSING in text.split("## Outstanding")[1]


def test_a_populated_run_says_so(results, monkeypatch):
    """The outstanding section must be able to come back empty, or it is
    decoration rather than a check."""
    monkeypatch.setattr(tables, "TABLES", (lambda: "### Table X\n\nall good\n",))
    text = tables.build()
    assert "Every table above is populated." in text


# --------------------------------------------------------------------------- #
# Attacks that never fired
# --------------------------------------------------------------------------- #
def test_an_attack_that_never_fired_is_not_counted_as_a_miss(results):
    """A server that held back during every probe cycle presented nothing to
    detect. Counting it as a miss would penalise the detector for an attack
    that did not happen."""
    _csv(results / "exp3_client_L1.csv", [
        {"episode_id": "a", "attack_level": "L1", "outcome": "never_triggered"},
        {"episode_id": "b", "attack_level": "L1", "outcome": "detected",
         "full_detected": "true", "passive_available": "true"},
    ])
    assert "| client | 1 |" in tables.table_three_way()


def test_held_back_episodes_are_reported_not_dropped(results):
    """At L4 with fixed probes every episode held back. That is the evasion
    the keyed generator exists to remove, so it has to appear."""
    _csv(results / "exp1_fixed_probes.csv", [
        {"episode_id": f"e{i}", "attack_level": "L4",
         "outcome": "never_triggered"} for i in range(6)
    ])
    assert "never fired (6 held back)" in tables.table_probe_modes()


# --------------------------------------------------------------------------- #
# Gap 3
# --------------------------------------------------------------------------- #
def test_a_failed_upgrade_run_is_visible(results):
    """Two servers could not be measured at all. An absent row would read as
    a server that was fine."""
    rq1 = results / "rq1"
    rq1.mkdir()
    (rq1 / "rq1_sqlite.jsonl").write_text("\n".join(json.dumps(r) for r in [
        {"server": "sqlite", "phase": "old", "run": 1,
         "error": "AttributeError: 'Server' object has no attribute 'list_resources'"},
    ]) + "\n", encoding="utf-8")

    table = tables.table_real_upgrades()
    assert "failed runs" in table
    assert "list_resources" in table


def test_same_release_alarms_are_shown_beside_upgrade_alarms(results):
    """git alarms with nothing changed at all, which is a sharper finding
    than an upgrade alarm and must not be folded into one number."""
    rq1 = results / "rq1"
    rq1.mkdir()
    (rq1 / "rq1_git.jsonl").write_text("\n".join(json.dumps(r) for r in [
        {"server": "git", "phase": "old", "run": 1, "alerted": True},
        {"server": "git", "phase": "new", "run": 1, "alerted": True,
         "definition_changed": True},
    ]) + "\n", encoding="utf-8")

    table = tables.table_real_upgrades()
    assert "same release" in table
    assert table.count("(1/1)") >= 2
