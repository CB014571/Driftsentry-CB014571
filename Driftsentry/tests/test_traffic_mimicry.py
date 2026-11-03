"""Learning the shape of genuine traffic, and probing in that shape (T18).

T17 closed the client channel. RQ3 left three open, and none of them is
about what a probe contains:

    session   AUC 1.000. A cycle makes all eighteen probes in one process in
              about 0.2 seconds; a real session makes one to six over
              seconds. calls_before above five occurs only in probe traffic.
    timing    AUC 0.817. Probe calls arrive back to back.
    argument  AUC 0.786. Keyed values are unpredictable but still unlike the
              things a user asks for.

All three are properties of the schedule, so no amount of value
randomisation touches them. These tests cover learning the shape and probing
in it - and, as much as anything, the two ways that goes wrong: imitating a
shape nobody has, and carrying a user's data into it.
"""
from __future__ import annotations

import json

import pytest

from driftsentry.camouflage import SessionFingerprint, gap_from_profile, session_plan
from driftsentry.traffic import MAX_GAP_S, MIN_SESSIONS, TrafficProfile, learn

KEY = bytes(range(32))


def _log(tmp_path, records):
    path = tmp_path / "acme.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return path


def _call(session, ts, tool="lookup_customer", args=None):
    return {"dir": "c2s", "kind": "request", "method": "tools/call",
            "session": session, "ts": ts, "tool": tool,
            "args": args if args is not None else {"customer_id": "C-1001"}}


def _profile(**kw):
    base = dict(server="acme", n_sessions=20,
                calls_per_session=[1] * 12 + [2] * 5 + [3] * 2 + [5],
                gaps_s=[0.4, 0.9, 1.6, 2.3, 0.7])
    base.update(kw)
    return TrafficProfile(**base)


# --------------------------------------------------------------------------- #
# Learning
# --------------------------------------------------------------------------- #
def test_sessions_and_gaps_are_learned_from_the_proxy_log(tmp_path):
    path = _log(tmp_path, [
        _call("s1", "2026-11-03T10:00:00+00:00"),
        _call("s1", "2026-11-03T10:00:02+00:00"),
        _call("s2", "2026-11-03T10:01:00+00:00"),
    ])
    profile = learn(path, "acme")
    assert profile.n_sessions == 2
    assert sorted(profile.calls_per_session) == [1, 2]
    assert profile.gaps_s == [2.0]


def test_only_client_tool_calls_are_counted(tmp_path):
    """Responses and handshakes are not user actions."""
    path = _log(tmp_path, [
        _call("s1", "2026-11-03T10:00:00+00:00"),
        {"dir": "s2c", "kind": "response", "session": "s1", "ts": "2026-11-03T10:00:01+00:00"},
        {"dir": "c2s", "kind": "request", "method": "tools/list", "session": "s1",
         "ts": "2026-11-03T10:00:02+00:00"},
    ])
    assert learn(path, "acme").n_calls == 1


def test_a_long_gap_is_a_user_who_walked_away_not_a_model_thinking(tmp_path):
    path = _log(tmp_path, [
        _call("s1", "2026-11-03T10:00:00+00:00"),
        _call("s1", "2026-11-03T10:10:00+00:00"),      # ten minutes
    ])
    profile = learn(path, "acme")
    assert profile.gaps_s == [], f"a {MAX_GAP_S}s cap should have excluded it"


def test_too_few_sessions_is_not_usable(tmp_path):
    """Imitating an accident is its own fingerprint."""
    path = _log(tmp_path, [_call(f"s{i}", "2026-11-03T10:00:00+00:00")
                           for i in range(MIN_SESSIONS - 1)])
    assert learn(path, "acme").usable is False


def test_enough_sessions_is_usable(tmp_path):
    path = _log(tmp_path, [_call(f"s{i}", "2026-11-03T10:00:00+00:00")
                           for i in range(MIN_SESSIONS)])
    assert learn(path, "acme").usable is True


def test_a_missing_log_gives_an_empty_profile(tmp_path):
    assert learn(tmp_path / "absent.jsonl", "acme").usable is False


def test_a_corrupt_line_does_not_discard_the_rest(tmp_path):
    path = tmp_path / "acme.jsonl"
    path.write_text("{broken\n" + json.dumps(_call("s1", "2026-11-03T10:00:00+00:00")),
                    encoding="utf-8")
    assert learn(path, "acme").n_calls == 1


# --------------------------------------------------------------------------- #
# Shapes, not values
# --------------------------------------------------------------------------- #
def test_argument_shapes_are_learned_without_keeping_the_values(tmp_path):
    """Replaying a user's arguments would send their data to a server that may
    be hostile - the detector's probes would become the exfiltration channel
    for the traffic they protect."""
    secret = "ACCOUNT-99887766-dana-whitfield"
    path = _log(tmp_path, [
        _call(f"s{i}", "2026-11-03T10:00:00+00:00", args={"customer_id": secret})
        for i in range(MIN_SESSIONS)
    ])
    profile = learn(path, "acme")
    shape = profile.tool_shapes["lookup_customer"]
    assert shape.median_len == len(secret)
    assert secret not in json.dumps(profile.to_dict()), "the value itself must not be kept"


def test_shape_records_character_mix_not_content(tmp_path):
    path = _log(tmp_path, [
        _call(f"s{i}", "2026-11-03T10:00:00+00:00", args={"q": "order 8801 refund"})
        for i in range(MIN_SESSIONS)
    ])
    shape = learn(path, "acme").tool_shapes["lookup_customer"]
    assert shape.space_ratio > 0
    assert 0 < shape.digit_ratio < 1


def test_a_profile_round_trips(tmp_path):
    profile = _profile()
    restored = TrafficProfile.from_dict(profile.to_dict())
    assert restored.calls_per_session == profile.calls_per_session
    assert restored.usable == profile.usable


# --------------------------------------------------------------------------- #
# Session shaping - the channel at 1.000
# --------------------------------------------------------------------------- #
def test_without_a_profile_the_current_behaviour_is_unchanged():
    """One session of every probe. The control condition must not move."""
    assert session_plan(KEY, "acme", 1, 18) == [18]
    assert session_plan(KEY, "acme", 1, 18, _profile(n_sessions=1)) == [18]


def test_with_a_profile_a_cycle_is_split_into_realistic_sessions():
    plan = session_plan(KEY, "acme", 1, 18, _profile())
    assert sum(plan) == 18, "no probe may be dropped or duplicated"
    assert len(plan) > 1
    assert max(plan) <= 5, "no session longer than any real one"


def test_the_split_removes_what_made_session_separable():
    """calls_before above five occurred only in probe traffic. After
    splitting, the longest probe session matches the longest real one."""
    profile = _profile()
    plan = session_plan(KEY, "acme", 1, 18, profile)
    assert max(plan) <= max(profile.calls_per_session)


def test_a_plan_is_reproducible_from_its_key_and_cycle():
    assert (session_plan(KEY, "acme", 1, 18, _profile())
            == session_plan(KEY, "acme", 1, 18, _profile()))


def test_different_cycles_give_different_plans():
    """A constant split would become a fingerprint of its own."""
    assert (session_plan(KEY, "acme", 1, 18, _profile())
            != session_plan(KEY, "acme", 2, 18, _profile()))


def test_no_probes_means_no_sessions():
    assert session_plan(KEY, "acme", 1, 0, _profile()) == []


# --------------------------------------------------------------------------- #
# Timing - the channel at 0.817
# --------------------------------------------------------------------------- #
def test_gaps_are_drawn_from_observed_gaps():
    profile = _profile()
    gap = gap_from_profile(KEY, "acme", 1, 0, profile)
    assert gap in profile.gaps_s, "a parametric guess would miss a bimodal habit"


def test_without_a_profile_there_is_no_pause():
    assert gap_from_profile(KEY, "acme", 1, 0, None) == 0.0


def test_gaps_are_reproducible_and_vary_by_index():
    a = [gap_from_profile(KEY, "acme", 1, i, _profile()) for i in range(6)]
    b = [gap_from_profile(KEY, "acme", 1, i, _profile()) for i in range(6)]
    assert a == b
    assert len(set(a)) > 1, "a constant pause is as distinctive as none"


# --------------------------------------------------------------------------- #
# Honesty about what remains
# --------------------------------------------------------------------------- #
def test_the_fingerprint_names_both_newly_measured_tells():
    tells = " ".join(SessionFingerprint().residual_tells())
    assert "AUC 1.000" in tells, "the session tell should cite its measurement"
    assert "stops to think" in tells


def test_turning_the_countermeasures_on_removes_those_two_tells():
    before = SessionFingerprint()
    after = SessionFingerprint(uniform_session_length=False, back_to_back_calls=False)
    assert len(after.residual_tells()) == len(before.residual_tells()) - 2
    # ...and the structural ones are still admitted.
    assert any("own stdio session" in t for t in after.residual_tells())
