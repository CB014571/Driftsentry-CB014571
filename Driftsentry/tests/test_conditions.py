"""The countermeasure conditions, and the hypothesis they are judged by.

RQ4 asks whether realistic probes restore detection and at what cost. It is
only answerable if the conditions differ in one thing at a time, which is
why the countermeasures were built and left switched off rather than turned
on as they were finished.

The tests here are mostly about H4 refusing to pass for the wrong reason. A
countermeasure can flatten AUC by making probing so slow that detection
collapses, or restore detection by alarming on everything. Either would look
like success in a single number, so H4 takes all three conditions together
and these tests check each one can fail on its own.
"""
from __future__ import annotations

import pytest

from pathlib import Path

from eval.conditions import BY_NAME, CONDITIONS, Condition, cost_table, h4_verdict


# --------------------------------------------------------------------------- #
# The ladder
# --------------------------------------------------------------------------- #
def test_the_baseline_condition_has_nothing_switched_on():
    """'none' must reproduce what RQ3 measured, or nothing is comparable."""
    none = BY_NAME["none"]
    assert not (none.mimic_host or none.mimic_traffic or none.subsample_bank)


def test_each_condition_adds_one_thing_to_the_last():
    """One variable at a time, or a change cannot be attributed."""
    host, mimic = BY_NAME["host"], BY_NAME["mimic"]
    assert host.mimic_host and not host.mimic_traffic
    assert mimic.mimic_host and mimic.mimic_traffic and not mimic.subsample_bank


def test_subsample_is_measured_without_the_others():
    """It targets memorisation, a different threat from recognition, so its
    contribution has to be separable rather than bundled."""
    sub = BY_NAME["subsample"]
    assert sub.subsample_bank
    assert not sub.mimic_host and not sub.mimic_traffic


def test_the_full_condition_has_everything():
    full = BY_NAME["all"]
    assert full.mimic_host and full.mimic_traffic and full.subsample_bank


def test_probe_kwargs_only_carry_what_the_probe_path_accepts():
    """subsample_bank is handled at capture, not passed to verify_server."""
    kwargs = BY_NAME["all"].probe_kwargs()
    assert set(kwargs) == {"mimic_host", "mimic_traffic"}
    assert all(kwargs.values())


def test_every_condition_explains_itself():
    for cond in CONDITIONS:
        assert cond.note, cond.name
        assert cond.describe()


# --------------------------------------------------------------------------- #
# H4 - all three, never any
# --------------------------------------------------------------------------- #
def _results(**overrides):
    base = {
        "none": {"best_auc": 1.0, "recall_pct": 0.0, "false_alarm_pct": 8.0},
        "all": {"best_auc": 0.55, "recall_pct": 95.0, "false_alarm_pct": 9.0,
                "recall_gap_pp": -5.0},
    }
    base["all"].update(overrides)
    return base


def test_h4_passes_when_all_three_hold():
    out = h4_verdict(_results())
    assert out["verdict"] == "PASS"
    assert all(out["checks"].values())


def test_h4_fails_when_the_classifier_still_works():
    out = h4_verdict(_results(best_auc=0.85))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["auc_at_or_below_ceiling"] is False


def test_h4_fails_when_detection_does_not_come_back():
    """Flattening AUC by making probing useless is not a countermeasure."""
    out = h4_verdict(_results(recall_gap_pp=-40.0))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["recall_within_tolerance"] is False


def test_h4_fails_when_detection_returns_by_alarming_on_everything():
    out = h4_verdict(_results(false_alarm_pct=30.0))
    assert out["verdict"] == "FAIL"
    assert out["checks"]["false_alarms_contained"] is False


def test_recall_tolerance_is_two_sided():
    """Overshooting the no-evasion level is as suspicious as falling short."""
    assert h4_verdict(_results(recall_gap_pp=+40.0))["verdict"] == "FAIL"


def test_an_unmeasured_full_condition_is_undefined_not_failed():
    """Not having run it is a different statement from having run it and lost."""
    out = h4_verdict({"none": {"best_auc": 1.0}})
    assert out["verdict"] == "UNDEFINED"
    assert "not been measured" in out["reason"]


def test_the_verdict_says_not_to_tune_for_it():
    assert "not to be tuned" in h4_verdict(_results())["note"]


def test_the_thresholds_are_the_ones_the_plan_states():
    out = h4_verdict(_results())
    assert out["thresholds"] == {"auc_ceiling": 0.6, "recall_within": 10.0,
                                 "false_alarm_rise": 2.0}


# --------------------------------------------------------------------------- #
# Cost
# --------------------------------------------------------------------------- #
def test_cost_is_reported_beside_benefit():
    """A countermeasure that triples cycle time has to show that."""
    table = cost_table({
        "none": {"best_auc": 1.0, "recall_pct": 0.0, "false_alarm_pct": 8.0,
                 "cycle_seconds": 17.4, "calls_per_cycle": 18},
        "all": {"best_auc": 0.55, "recall_pct": 95.0, "false_alarm_pct": 9.0,
                "cycle_seconds": 41.2, "calls_per_cycle": 18},
    })
    assert "17.4" in table and "41.2" in table
    assert "cycle s" in table


def test_an_unmeasured_condition_says_so_rather_than_showing_zero():
    table = cost_table({"none": {"best_auc": 1.0, "recall_pct": 0.0,
                                 "false_alarm_pct": 8.0, "cycle_seconds": 17.4,
                                 "calls_per_cycle": 18}})
    assert "not measured" in table


# --------------------------------------------------------------------------- #
# The plumbing
#
# verify_server accepted mimic_host and mimic_traffic and forwarded neither;
# reprobe accepted mimic_traffic and forwarded nothing to the keyed path. Run
# as it stood, every T20 condition would have been byte-identical to the
# control and the comparison would have reported that no countermeasure
# changes anything. Fourth defect of this shape, after launch parity (T4),
# replay pacing (T10) and the collection sandbox - so it gets a test rather
# than a fix.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("flag", ["mimic_host", "mimic_traffic", "subsample_bank"])
def test_verify_server_forwards_every_countermeasure(flag, monkeypatch):
    import asyncio

    from driftsentry import verify as verify_mod

    seen = {}

    async def fake_reprobe(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here; the forwarding is the test")

    monkeypatch.setattr(verify_mod, "reprobe", fake_reprobe)
    monkeypatch.setattr(verify_mod, "_launch_of", lambda *a: ("python", [], None, None))

    with pytest.raises(RuntimeError):
        asyncio.run(verify_mod.verify_server(object(), **{flag: True}))

    assert seen.get(flag) is True, f"verify_server dropped {flag}"


@pytest.mark.parametrize("flag", ["mimic_traffic", "subsample_bank"])
def test_reprobe_forwards_to_the_keyed_path(flag):
    """The keyed path is the only one T20 runs, so a flag that stops at
    reprobe has no effect at all."""
    import inspect

    from driftsentry.baseline import _reprobe_keyed, reprobe

    assert flag in inspect.signature(_reprobe_keyed).parameters
    assert f"{flag}={flag}" in inspect.getsource(reprobe)


def test_the_episode_config_carries_the_conditions():
    """A condition that cannot reach an episode cannot be measured."""
    from eval.harness import EpisodeConfig

    cfg = EpisodeConfig(experiment_id="x")
    assert not (cfg.mimic_host or cfg.mimic_traffic or cfg.subsample_bank)
    # In the config hash, so two conditions can never share a row's identity.
    assert "mimic_host" in cfg.as_config()


def test_the_sweep_spec_carries_the_conditions():
    from eval.experiments import SweepSpec, _configs

    spec = SweepSpec(experiment_id="x", mimic_host=True, subsample_bank=True,
                     families=("sleeper",), levels=("L1",), seeds=(1,))
    assert all(c.mimic_host and c.subsample_bank and not c.mimic_traffic
               for c in _configs(spec))


def test_the_collector_collects_under_the_condition(tmp_path):
    """A recogniser fitted on unprotected traffic and tested on protected
    traffic measures staleness, not the countermeasure."""
    from eval.collect import Collector

    c = Collector(tmp_path, tmp_path, tmp_path, mimic_host=True, mimic_traffic=True)
    assert c.mimic_host and c.mimic_traffic and not c.subsample_bank


# --------------------------------------------------------------------------- #
# T20's own arithmetic
# --------------------------------------------------------------------------- #
def _episode(mode, outcome):
    cfg = type("C", (), {"mode": mode})()
    return type("R", (), {"config": cfg, "outcome": outcome})()


def test_recall_counts_only_episodes_where_the_attack_fired():
    """An attack that never triggered is not a miss, and counting it as one
    would understate the detector."""
    from eval.t20 import _rates

    rate, hits, n = _rates([
        _episode("rug-pull", "detected"),
        _episode("rug-pull", "missed"),
        _episode("rug-pull", "never_triggered"),
    ])
    assert (hits, n) == (1, 2)
    assert rate == 50.0


def test_false_alarms_come_from_the_benign_arms_only():
    from eval.t20 import _false_alarms

    rate, bad, n = _false_alarms([
        _episode("benign", "benign_ok"),
        _episode("benign", "false_alarm"),
        _episode("rug-pull", "detected"),
    ])
    assert (bad, n) == (1, 2)
    assert rate == 50.0


def test_an_unmeasured_arm_is_nan_rather_than_zero():
    """Zero recall and no measurement are different claims."""
    import math

    from eval.t20 import _rates

    rate, _, n = _rates([])
    assert n == 0 and math.isnan(rate)


def test_the_merge_drops_the_genuine_sources_own_probe_windows(tmp_path):
    """Unprotected probe traffic must never land in a protected condition's
    probe class - it would understate the countermeasure."""
    import json

    from eval.t20 import merge_with_genuine

    genuine = tmp_path / "rq3"
    probes = tmp_path / "cond"
    for d in (genuine, probes):
        d.mkdir()
    (genuine / "windows.jsonl").write_text(
        json.dumps({"label": 0, "start": 1.0, "end": 2.0}) + "\n"
        + json.dumps({"label": 1, "start": 3.0, "end": 4.0}) + "\n", encoding="utf-8")
    (genuine / "features.jsonl").write_text(
        json.dumps({"t": 1.5, "pid": 1, "proc_age_s": 0.5}) + "\n", encoding="utf-8")
    (probes / "windows.jsonl").write_text(
        json.dumps({"label": 1, "start": 100.0, "end": 101.0}) + "\n", encoding="utf-8")
    (probes / "features.jsonl").write_text(
        json.dumps({"t": 100.5, "pid": 2, "proc_age_s": 0.5}) + "\n", encoding="utf-8")

    merged = merge_with_genuine(probes, genuine)
    windows = [json.loads(l) for l in
               (merged / "windows.jsonl").read_text(encoding="utf-8").splitlines() if l]
    assert [w["label"] for w in windows] == [0, 1]
    assert [w["start"] for w in windows] == [1.0, 100.0]


# --------------------------------------------------------------------------- #
# The data the countermeasures imitate
#
# Every episode runs in a fresh DRIFTSENTRY_HOME, which has no recorded host
# profile and no learned traffic profile. Both countermeasures then fall back
# with a warning the evaluation CLI silences, and run as the control. The
# first T20 smoke run did exactly that: the 'all' condition, everything on,
# still had `client` as its strongest channel at AUC 1.000. Reported, that
# would have read as "the countermeasures do not work".
# --------------------------------------------------------------------------- #
def test_mimic_host_without_a_recording_raises(tmp_path, monkeypatch):
    from eval import profiles

    monkeypatch.setattr(profiles, "HOST_PROFILE", tmp_path / "absent.json")
    with pytest.raises(profiles.ProfileMissing, match="recorded host identity"):
        profiles.install("srv", mimic_host=True)


def test_imitating_the_sdk_default_is_refused(tmp_path, monkeypatch):
    """Imitating the SDK's own name is imitating a probe."""
    import json

    from eval import profiles

    path = tmp_path / "host.json"
    path.write_text(json.dumps({"name": "mcp", "version": "1.0"}), encoding="utf-8")
    monkeypatch.setattr(profiles, "HOST_PROFILE", path)
    with pytest.raises(profiles.ProfileMissing, match="SDK"):
        profiles.install("srv", mimic_host=True)


def test_mimic_traffic_without_startup_times_raises(tmp_path, monkeypatch):
    """A profile with gaps but no startup times cannot close the channel."""
    import json

    from eval import profiles

    path = tmp_path / "traffic.json"
    path.write_text(json.dumps({
        "server": "x", "n_sessions": 50, "n_calls": 50,
        "calls_per_session": [1] * 50, "gaps_s": [0.005] * 20,
        "startup_s": [], "tool_shapes": {},
    }), encoding="utf-8")
    monkeypatch.setattr(profiles, "TRAFFIC_PROFILE", path)
    with pytest.raises(profiles.ProfileMissing, match="startup"):
        profiles.install("srv", mimic_traffic=True)


def test_the_committed_fixtures_are_usable():
    """They are real recordings, and the comparison cannot run without them."""
    import json

    from eval.profiles import HOST_PROFILE, TRAFFIC_PROFILE
    from driftsentry.traffic import TrafficProfile

    host = json.loads(HOST_PROFILE.read_text(encoding="utf-8"))
    assert host["name"] and host["name"] != "mcp"

    profile = TrafficProfile.from_dict(
        json.loads(TRAFFIC_PROFILE.read_text(encoding="utf-8")))
    assert profile.usable
    # 115 genuine sessions from the RQ3 proxy log.
    assert profile.n_sessions >= 100
    # The think time that matters, not the 5ms inter-call gap.
    assert 1.0 < profile.median_startup() < 30.0


def test_an_episode_installs_what_its_condition_needs(tmp_path, monkeypatch):
    from eval.harness import Episode, EpisodeConfig

    seen = {}
    import eval.profiles as profiles_mod

    monkeypatch.setattr(profiles_mod, "install",
                        lambda server, **kw: seen.update({"server": server, **kw}))

    episode = Episode.__new__(Episode)
    episode.cfg = EpisodeConfig(experiment_id="x", mimic_host=True,
                                mimic_traffic=True)
    episode.ds_home = tmp_path / "ds"
    episode.atk_home = tmp_path / "atk"
    episode._prepare()

    assert seen == {"server": episode.cfg.server_id,
                    "mimic_host": True, "mimic_traffic": True}


# --------------------------------------------------------------------------- #
# Startup pacing - the pause the timing family actually keys on
# --------------------------------------------------------------------------- #
def test_startup_times_are_learned_from_the_handshake(tmp_path):
    """first tools/call minus initialize, per session."""
    import json

    from driftsentry.traffic import learn

    log = tmp_path / "srv.jsonl"
    log.write_text("\n".join(json.dumps(r) for r in [
        {"dir": "c2s", "kind": "request", "method": "initialize",
         "session": "a", "ts": "2026-11-03T04:57:00+00:00"},
        {"dir": "c2s", "kind": "request", "method": "tools/call", "tool": "t",
         "args": {}, "session": "a", "ts": "2026-11-03T04:57:03+00:00"},
    ]) + "\n", encoding="utf-8")

    profile = learn(log, server="srv")
    assert profile.startup_s == [3.0]


def test_a_startup_longer_than_the_ceiling_is_dropped(tmp_path):
    """A user who walked away before asking for anything is not a think time."""
    import json

    from driftsentry.traffic import learn

    log = tmp_path / "srv.jsonl"
    log.write_text("\n".join(json.dumps(r) for r in [
        {"dir": "c2s", "kind": "request", "method": "initialize",
         "session": "a", "ts": "2026-11-03T04:00:00+00:00"},
        {"dir": "c2s", "kind": "request", "method": "tools/call", "tool": "t",
         "args": {}, "session": "a", "ts": "2026-11-03T04:05:00+00:00"},
    ]) + "\n", encoding="utf-8")

    assert learn(log, server="srv").startup_s == []


def test_the_startup_draw_is_keyed_and_repeatable():
    from driftsentry.camouflage import startup_from_profile
    from driftsentry.traffic import TrafficProfile

    profile = TrafficProfile(server="srv", n_sessions=50, n_calls=50,
                             calls_per_session=[1] * 50,
                             startup_s=[1.5, 3.0, 4.5, 9.0])
    key = b"k" * 32
    first = startup_from_profile(key, "srv", 1, profile)
    assert first == startup_from_profile(key, "srv", 1, profile)
    assert first in profile.startup_s
    # A different cycle is a different draw, or the pause is a fingerprint.
    draws = {startup_from_profile(key, "srv", c, profile) for c in range(1, 12)}
    assert len(draws) > 1


def test_no_profile_means_no_pause_rather_than_a_guess():
    from driftsentry.camouflage import startup_from_profile

    assert startup_from_profile(b"k" * 32, "srv", 1, None) == 0.0


def test_the_probe_loop_pauses_before_the_first_call():
    import inspect

    from driftsentry.baseline import _reprobe_keyed

    source = inspect.getsource(_reprobe_keyed)
    startup_at = source.index("startup_from_profile")
    loop_at = source.index("for tool in baseline.tools")
    assert startup_at < loop_at, "the pause must happen before any probing"


# --------------------------------------------------------------------------- #
# Pacing to a target, not by adding a pause
#
# The first implementation slept the drawn value before each call. A probe
# call takes about a second of its own and the genuine gaps have a median of
# 5 milliseconds, so adding a drawn pause on top moved probe gaps FURTHER
# from genuine ones - measured at 1.09s against 0.005s. The feature recorded
# is the arrival time, not how long the detector chose to wait, so the wait
# has to be the remainder.
# --------------------------------------------------------------------------- #
def test_the_pause_is_the_remainder_of_a_target():
    import inspect

    from driftsentry.baseline import _reprobe_keyed

    source = inspect.getsource(_reprobe_keyed)
    assert "remaining = target - (time.monotonic() - last_call_at)" in source
    assert "remaining = target - (time.monotonic() - process_started)" in source


def test_the_first_call_is_paced_against_the_real_process_age():
    """Measured from before the process is spawned, not from the probe loop:
    the handshake alone is several hundred milliseconds."""
    import inspect

    from driftsentry.baseline import reprobe

    source = inspect.getsource(reprobe)
    spawn_at = source.index("stdio_client(params)")
    clock_at = source.index("process_started = time.monotonic()")
    assert clock_at < spawn_at
    assert "process_started=process_started" in source


def test_no_pacing_without_a_previous_call():
    """There is no inter-arrival gap before the first call; the startup draw
    covers that, and applying both would double-count."""
    import inspect

    from driftsentry.baseline import _reprobe_keyed

    assert ("if profile is not None and last_call_at is not None:"
            in inspect.getsource(_reprobe_keyed))


# --------------------------------------------------------------------------- #
# Resuming a sweep that died
# --------------------------------------------------------------------------- #
# A sweep is hours long and the process does not always survive it. The
# environment arm of Experiment 3 died after 13 of 18 episodes, leaving a
# results file that ResultWriter would happily append a second copy of those
# 13 to. These cover the three ways that goes wrong: re-running what is
# already measured, recording one episode under two configurations, and
# reporting a recall figure over the fragment a resumed run executed.
def _spec(tmp_path, **kw):
    from eval.experiments import SweepSpec
    return SweepSpec(experiment_id="exp_resume_test",
                     families=("exfiltration",), levels=("L1",), seeds=(1, 2),
                     benign_seeds=(), benign_update_seeds=(), **kw)


def _write_rows(out_dir, spec, configs):
    """Put real rows on disk for the given configs, as a dead run would leave."""
    from eval.record import ExperimentRow, ResultWriter, config_hash, now
    from eval.experiments import _episode_id
    with ResultWriter(out_dir, spec.experiment_id) as writer:
        for cfg in configs:
            writer.append(ExperimentRow(
                experiment_id=spec.experiment_id,
                episode_id=_episode_id(cfg),
                timestamp=now(),
                seed=cfg.seed,
                server_id="s", tool_id="t",
                attack_family=cfg.family or "", attack_level=cfg.level or "",
                probe_mode=cfg.probe_mode, scoring_mode=cfg.scoring_mode,
                partition=cfg.partition,
                outcome="detected", detected=True,
                config_hash=config_hash(cfg.as_config()),
            ))


def test_a_recorded_episode_is_not_run_again(tmp_path):
    from eval.experiments import _configs, run_sweep
    spec = _spec(tmp_path)
    configs = _configs(spec)
    _write_rows(tmp_path, spec, configs[:1])

    ran = []

    def fake_run_episode(cfg, attacker, workspace):
        ran.append(cfg.seed)
        raise AssertionError("should not have been reached in this test")

    import eval.experiments as mod
    real = mod.run_episode
    mod.run_episode = lambda cfg, a, w: fake_run_episode(cfg, a, w)
    try:
        with pytest.raises(AssertionError):
            run_sweep(spec, "atk", tmp_path / "ws", tmp_path, progress=False)
    finally:
        mod.run_episode = real
    # The first config was on disk, so the attempt landed on the second.
    assert ran == [configs[1].seed]


def test_resume_off_runs_everything(tmp_path):
    from eval.experiments import _configs, run_sweep
    spec = _spec(tmp_path)
    configs = _configs(spec)
    _write_rows(tmp_path, spec, configs[:1])

    ran = []
    import eval.experiments as mod
    real = mod.run_episode

    def boom(cfg, a, w):
        ran.append(cfg.seed)
        raise AssertionError("stop")

    mod.run_episode = boom
    try:
        with pytest.raises(AssertionError):
            run_sweep(spec, "atk", tmp_path / "ws", tmp_path,
                      progress=False, resume=False)
    finally:
        mod.run_episode = real
    assert ran == [configs[0].seed]


def test_the_same_episode_under_a_different_config_is_a_conflict(tmp_path):
    """Two configurations under one episode_id makes the file unreadable."""
    from eval.experiments import ResumeConflict, _configs, run_sweep
    spec = _spec(tmp_path)
    _write_rows(tmp_path, spec, _configs(spec)[:1])

    # Same episode ids, different detector configuration.
    moved = _spec(tmp_path, n_probes=spec.n_probes + 1)
    with pytest.raises(ResumeConflict):
        run_sweep(moved, "atk", tmp_path / "ws", tmp_path, progress=False)


def test_a_resumed_run_returns_only_what_it_ran(tmp_path):
    """So a caller cannot mistake the fragment for the whole sweep."""
    from eval.experiments import _configs, run_sweep
    spec = _spec(tmp_path)
    configs = _configs(spec)
    _write_rows(tmp_path, spec, configs)  # everything already done

    import eval.experiments as mod
    real = mod.run_episode
    mod.run_episode = lambda cfg, a, w: pytest.fail("nothing left to run")
    try:
        results = run_sweep(spec, "atk", tmp_path / "ws", tmp_path,
                            progress=False)
    finally:
        mod.run_episode = real
    assert results == []


def test_recorded_reads_episode_ids_and_hashes_from_disk(tmp_path):
    from eval.experiments import _configs, _episode_id, _recorded
    spec = _spec(tmp_path)
    configs = _configs(spec)
    _write_rows(tmp_path, spec, configs)
    found = _recorded(tmp_path, spec.experiment_id)
    assert set(found) == {_episode_id(c) for c in configs}
    assert all(len(h) == 1 for h in found.values())


def test_recorded_is_empty_when_nothing_has_run(tmp_path):
    from eval.experiments import _recorded
    assert _recorded(tmp_path, "never_run") == {}


def test_episode_id_matches_the_harness(tmp_path):
    """The two are computed in different places; if they drift, resume lies."""
    from eval.experiments import _configs, _episode_id
    from eval.harness import Episode
    from eval.__main__ import DEFAULT_ATTACKER
    if not Path(DEFAULT_ATTACKER).is_dir():
        pytest.skip("the attacker project is not checked out here")
    cfg = _configs(_spec(tmp_path))[0]
    episode = Episode(cfg, DEFAULT_ATTACKER, tmp_path / "ws")
    assert _episode_id(cfg) == episode.episode_id
