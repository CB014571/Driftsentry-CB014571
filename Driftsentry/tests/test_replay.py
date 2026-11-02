"""Replaying recorded genuine traffic inside an episode.

Why an episode needs real user traffic at all, and not just probes:

    RQ2 scores passive monitoring, which watches real calls. With no real
    calls it has nothing to watch and scores zero by construction - a number
    that would look like a finding and be an artefact of the experiment.

    RQ3's recall half scores an L6 attacker, which stays benign for anything
    it believes is a probe. In a probe-only episode it never fires, every
    episode classifies as never_triggered, and recall is undefined exactly
    where the question is.

The properties under test are about faithfulness. A replayed session has to
look like the session that produced it - same calls, same order, same shape -
because the session feature family reads calls_before and
distinct_tools_before, and a session of the wrong shape resembles nothing a
model actually produced.
"""
from __future__ import annotations

import json

import pytest

from eval.replay import GENUINE, choose_sessions, load_sessions, passive_findings


def _corpus(tmp_path, rows):
    path = tmp_path / "dataset.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return path


def _row(group, tool, args, t, label=GENUINE):
    return {"group": group, "tool": tool, "args": args, "t": t, "label": label}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_sessions_are_grouped_by_the_process_that_produced_them(tmp_path):
    path = _corpus(tmp_path, [
        _row("a", "lookup_customer", {"customer_id": "C-1001"}, 1.0),
        _row("a", "get_weather", {"city": "Leeds"}, 2.0),
        _row("b", "read_document", {"path": "docs/index.md"}, 3.0),
    ])
    sessions = load_sessions(path)
    assert len(sessions) == 2
    assert sorted(len(s) for s in sessions) == [1, 2]


def test_calls_keep_the_order_the_model_made_them_in(tmp_path):
    """A multi-step session is a sequence; shuffling it changes its meaning."""
    path = _corpus(tmp_path, [
        _row("a", "third", {}, 30.0),
        _row("a", "first", {}, 10.0),
        _row("a", "second", {}, 20.0),
    ])
    assert [c["tool"] for c in load_sessions(path)[0]] == ["first", "second", "third"]


def test_probe_traffic_is_never_replayed(tmp_path):
    """Replaying probes as if they were genuine would be circular."""
    path = _corpus(tmp_path, [
        _row("a", "lookup_customer", {"customer_id": "C-1"}, 1.0, label=GENUINE),
        _row("b", "lookup_customer", {"customer_id": "probe"}, 2.0, label=1),
    ])
    sessions = load_sessions(path)
    assert len(sessions) == 1
    assert sessions[0][0]["args"] == {"customer_id": "C-1"}


def test_rows_without_a_tool_or_arguments_are_skipped(tmp_path):
    path = _corpus(tmp_path, [
        _row("a", "lookup_customer", {"customer_id": "C-1"}, 1.0),
        {"group": "b", "tool": None, "args": {}, "t": 2.0, "label": GENUINE},
        {"group": "c", "tool": "x", "args": "not-a-dict", "t": 3.0, "label": GENUINE},
    ])
    assert len(load_sessions(path)) == 1


def test_a_missing_corpus_is_empty_not_an_error(tmp_path):
    """The harness warns and continues; an exception would kill the episode."""
    assert load_sessions(tmp_path / "nothing.jsonl") == []


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
def test_the_same_seed_picks_the_same_sessions(tmp_path):
    sessions = [[{"tool": f"t{i}", "args": {}}] for i in range(20)]
    assert (choose_sessions(sessions, 5, seed=7)
            == choose_sessions(sessions, 5, seed=7))


def test_different_seeds_pick_differently(tmp_path):
    sessions = [[{"tool": f"t{i}", "args": {}}] for i in range(20)]
    assert choose_sessions(sessions, 5, seed=1) != choose_sessions(sessions, 5, seed=2)


def test_sessions_touching_an_avoided_tool_are_excluded():
    """T11: an attack on a tool the agent never calls.

    Probing reaches that tool; passive monitoring cannot, because the user
    never goes near it. That difference is the measurement, so the replayed
    traffic has to genuinely avoid the tool.
    """
    sessions = [
        [{"tool": "lookup_customer", "args": {}}],
        [{"tool": "send_invoice", "args": {}}],
        [{"tool": "lookup_customer", "args": {}}, {"tool": "send_invoice", "args": {}}],
    ]
    picked = choose_sessions(sessions, 5, seed=0, avoid_tools={"send_invoice"})
    assert picked
    assert all(c["tool"] != "send_invoice" for s in picked for c in s)


def test_avoiding_everything_yields_nothing_rather_than_cheating():
    sessions = [[{"tool": "only_tool", "args": {}}]]
    assert choose_sessions(sessions, 3, seed=0, avoid_tools={"only_tool"}) == []


def test_loading_is_deterministic_across_calls(tmp_path):
    """An episode seed must select the same traffic on a re-run."""
    rows = [_row(f"g{i}", "t", {"q": str(i)}, float(i)) for i in range(10)]
    path = _corpus(tmp_path, rows)
    assert load_sessions(path) == load_sessions(path)


# --------------------------------------------------------------------------- #
# Passive findings
# --------------------------------------------------------------------------- #
def test_passive_findings_come_from_the_sidecar(tmp_path):
    """Not from the shutdown record: a client disconnect terminates the proxy
    before it writes one. T1 has the measurement."""
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    (logs / "srv.passive.json").write_text(json.dumps({
        "summary": {"calls_seen": 4, "findings": 1, "high_severity": 1},
        "findings": [{"tool": "lookup_customer", "kind": "new_egress_host",
                      "severity": "high", "detail": "x"}],
    }), encoding="utf-8")

    out = passive_findings(tmp_path, "srv")
    assert out["available"] is True
    assert out["summary"]["calls_seen"] == 4
    assert out["findings"][0]["kind"] == "new_egress_host"


def test_no_sidecar_is_reported_as_unavailable_not_as_zero_findings(tmp_path):
    """Zero findings and no monitoring are different claims.

    Reporting the second as the first would let an episode where passive
    monitoring never ran count as one where it ran and saw nothing clean.
    """
    out = passive_findings(tmp_path, "srv")
    assert out["available"] is False
    assert out["findings"] == []


def test_a_corrupt_sidecar_is_unavailable_rather_than_fatal(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    (logs / "srv.passive.json").write_text("{broken", encoding="utf-8")
    assert passive_findings(tmp_path, "srv")["available"] is False


# --------------------------------------------------------------------------- #
# The harness contract
# --------------------------------------------------------------------------- #
def test_replay_is_off_by_default():
    """Experiments 1 and 2 are the control and must not gain extra traffic."""
    from eval.harness import EpisodeConfig

    cfg = EpisodeConfig(experiment_id="x")
    assert cfg.replay_sessions == 0
    assert cfg.recogniser is None
    assert cfg.avoid_tools == ()


def test_a_missing_recogniser_fails_the_episode_loudly(tmp_path):
    """An L6 episode without a model fires unconditionally, which would be
    recorded as 'the evasion did not work' - a false result."""
    from eval.harness import Episode, EpisodeConfig

    cfg = EpisodeConfig(experiment_id="x", level="L6",
                        recogniser=str(tmp_path / "absent.json"))
    attacker = type("A", (), {"project_dir": tmp_path, "python": tmp_path})()
    episode = Episode.__new__(Episode)
    episode.cfg = cfg
    episode.workspace = tmp_path
    episode.episode_id = "e"
    episode.ds_home = tmp_path / "ds"
    episode.atk_home = tmp_path / "atk"
    episode.attacker = attacker

    with pytest.raises(FileNotFoundError, match="recogniser"):
        episode._prepare()
