"""The Gap 3 driver: what it probes, and what it refuses to probe.

The expensive mistake this file guards against has already happened once in
this project. Introspecting the real mcp-server-git found twelve tools, five
of which write, and the classifier of the day called git_commit and git_add
"safe - no state-changing signal found". The default failed open, so the
detector would have staged files and created commits in a real repository.

The classifier now fails closed. These tests check the driver actually uses
it, on the live tool list rather than on the guess in real_servers.json, and
that a server with nothing confirmed read-only is reported rather than
probed anyway.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval import real_run
from eval.real_run import ServerRun, ToolsUnconfirmed, confirm_read_only, load_specs, report
from eval.real_upgrades import UpgradeResult


# --------------------------------------------------------------------------- #
# The candidate list
# --------------------------------------------------------------------------- #
def test_the_default_set_is_the_local_no_network_one():
    """Anything that reaches someone else's service must be chosen, not
    arrived at by accident."""
    specs = load_specs(only=("time", "calculator", "git", "sqlite"))
    assert len(specs) == 4
    assert all(not s.get("network") for s in specs)


def test_a_name_that_is_not_in_the_file_is_an_error_not_a_silent_skip():
    with pytest.raises(KeyError):
        load_specs(only=("time", "nonexistent-server"))


def test_every_candidate_has_both_versions_and_an_entry_point():
    for spec in load_specs():
        assert spec["old"] and spec["new"] and spec["entry"]
        assert spec["old"] != spec["new"], spec["name"]


def test_label_is_still_the_users_call():
    """The file says label is a reading of intent and therefore not mine. If
    one ever gets filled in by code rather than by the user, this fails."""
    for spec in load_specs():
        assert spec["label"] is None, (
            f"{spec['name']} has a label; that field is the user's to set")


# --------------------------------------------------------------------------- #
# What may be probed
# --------------------------------------------------------------------------- #
def _stub_server(monkeypatch, offered, schemas=None):
    monkeypatch.setattr(real_run, "starts_and_lists",
                        lambda p, e, cwd=None: (True, json.dumps(offered)))
    monkeypatch.setattr(real_run, "_tool_schemas",
                        lambda p, e, cwd=None: schemas or {})


def test_a_writing_tool_is_withheld_with_the_reason(monkeypatch):
    """git_commit must never be probed, and the write-up needs to say why."""
    _stub_server(monkeypatch, ["git_log", "git_commit"])
    probed, withheld = confirm_read_only(Path("py"), ["-m", "x"])
    assert "git_commit" in withheld
    assert withheld["git_commit"]
    assert "git_commit" not in probed


def test_the_live_tool_list_is_used_not_the_guess_in_the_json(monkeypatch):
    """real_servers.json says its tool lists are unconfirmed guesses. A guess
    must not widen what gets called."""
    _stub_server(monkeypatch, ["git_log"])
    probed, _ = confirm_read_only(
        Path("py"), ["-m", "x"],
        declared=["git_log", "git_diff", "git_status", "git_show"])
    assert probed == ["git_log"]


def test_a_tool_the_guess_called_safe_and_the_classifier_refuses_is_logged(
        monkeypatch, caplog):
    _stub_server(monkeypatch, ["download_paper"])
    with caplog.at_level("WARNING"):
        with pytest.raises(ToolsUnconfirmed):
            confirm_read_only(Path("py"), ["-m", "x"],
                              declared=["download_paper"])
    assert any("download_paper" in r.getMessage() for r in caplog.records)


def test_a_server_with_nothing_confirmed_is_reported_not_probed(monkeypatch):
    """Failing closed can leave nothing to probe. That is an outcome, not a
    reason to relax the policy."""
    _stub_server(monkeypatch, ["write_query", "create_table"])
    with pytest.raises(ToolsUnconfirmed):
        confirm_read_only(Path("py"), ["-m", "x"])


def test_a_read_only_annotation_is_positive_evidence(monkeypatch):
    """Some servers say so themselves, and that is the strongest signal."""
    _stub_server(monkeypatch, ["mystery_tool"],
                 {"mystery_tool": {"name": "mystery_tool",
                                   "annotations": {"readOnlyHint": True}}})
    probed, withheld = confirm_read_only(Path("py"), ["-m", "x"])
    assert probed == ["mystery_tool"] and not withheld


def test_a_server_that_will_not_start_is_not_silently_empty(monkeypatch):
    from eval.real_envs import EnvError
    monkeypatch.setattr(real_run, "starts_and_lists",
                        lambda p, e, cwd=None: (False, "AttributeError: ..."))
    with pytest.raises(EnvError):
        confirm_read_only(Path("py"), ["-m", "x"])


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
def _run(name, noise, alarms, runs=3, changed=0, error=None, tools=2):
    out = ServerRun(name=name, old_version="1.0", new_version="2.0",
                    error=error, probed_tools=[f"t{i}" for i in range(tools)])
    if error:
        return out
    for i in range(runs):
        out.results.append(UpgradeResult(server=name, phase="old", run=i + 1,
                                         alerted=i < noise))
    for i in range(runs):
        out.results.append(UpgradeResult(server=name, phase="new", run=i + 1,
                                         alerted=i < alarms,
                                         definition_changed=i < changed))
    return out


def test_a_server_that_could_not_be_built_is_listed_not_dropped():
    """"Two of four candidates could not be installed" is part of the answer
    to Gap 3, not a blank in the table."""
    text = report([_run("time", 0, 3), _run("sqlite", 0, 0, error="old release: boom")])
    assert "NOT MEASURED" in text
    assert "sqlite" in text
    assert "boom" in text


def test_the_noise_phase_is_reported_beside_the_upgrade():
    """A detector that alarms on its own release has no upgrade rate to
    report. mcp-server-git is that case and the table must show it."""
    text = report([_run("git", 3, 3)])
    assert "3/3" in text


def test_hash_pinning_is_counted_separately():
    text = report([_run("time", 0, 3, changed=3)])
    lines = [l for l in text.splitlines() if l.strip().startswith("time")]
    assert lines and "3/3" in lines[0]


def test_an_sdk_pin_found_by_walking_is_named_in_the_report():
    """"This release needs mcp<=X" is a finding about the ecosystem, so it
    belongs in the output rather than only in a log line."""
    run = _run("calculator", 0, 1)
    run.environments = [{"version": "0.1.2", "sdk_version": "1.2.0",
                         "sdk_resolved_by": "walk"}]
    text = report([run])
    assert "mcp==1.2.0" in text
    assert "0.1.2" in text


def test_nothing_measured_produces_no_pooled_rate():
    """A pooled rate over zero runs would print as a number."""
    text = report([_run("sqlite", 0, 0, error="nope")])
    assert "pooled" not in text
