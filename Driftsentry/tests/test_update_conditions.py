"""T27. Update episodes: attribution, the five conditions, the harness config.

The five conditions are scored from one re-probe, so they are tested here on
constructed measurements - every case H3 turns on, without running a server.
One live episode per cover is the plan's "done when" and runs separately.
"""
from __future__ import annotations

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from eval import ground_truth
from eval.update_conditions import CONDITIONS, score_update

T = 1.5
ATTACKED = "lookup_customer"
CLEAN = {"distance": 0.0, "band": 0.01, "ratio": 0.0, "within_band": True,
         "shape_known": True, "determinism_break": False, "field_drift": 0.0,
         "field_changes": [], "comparability": 1.0}
OUT_V1 = {"type": "object", "properties": {"result": {"type": "string"}}}
OUT_C2 = {"type": "object", "properties": {"result": {"type": "string"},
                                           "last_contact": {"type": "string"}}}


def defn(name, outputs=OUT_V1, annotations=None):
    return {"name": name, "description": f"{name}.",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
            "outputSchema": outputs, "annotations": annotations}


V1 = [defn("lookup_customer"), defn("search_orders")]
C1 = [defn("lookup_customer"), defn("search_orders", outputs=OUT_C2)]
C2 = [defn("lookup_customer", outputs=OUT_C2), defn("search_orders")]


def probe(tool=ATTACKED, pid="p1", **kw):
    base = dict(tool=tool, probe_id=pid, distance=0.0, band=0.01, ratio=0.0,
                within_band=True, shape_known=True, arg_names=["q"])
    base.update(kw)
    return ProbeCheck(**base)


def score(new_defs, checks, family=""):
    m = ReprobeReport(server="s", baseline_definition_hash="h",
                      observed_definition_hash="h", checks=checks,
                      embedding_backend="hash", observed_definitions=new_defs)
    return score_update(m, V1, threshold_ratio=T, family=family,
                        attacked_tool=ATTACKED).conditions


def flags(conds):
    return {c: (conds[c].alert, conds[c].attributed) for c in CONDITIONS}


# --------------------------------------------------------------------------- #
# Attribution (ground_truth.py)
# --------------------------------------------------------------------------- #
def test_every_family_has_an_attribution_set():
    for family in ("exfiltration", "new-egress", "silent-tamper",
                   "content-injection", "sleeper", "conditional"):
        assert ground_truth.attribution_signals(family), family


def test_the_gated_families_take_their_payloads_signals():
    assert (ground_truth.attribution_signals("sleeper")
            == ground_truth.attribution_signals("content-injection"))
    assert (ground_truth.attribution_signals("conditional")
            == ground_truth.attribution_signals("exfiltration"))
    assert (ground_truth.attribution_signals("sleeper", payload="new-egress")
            == {"new_egress_host"})


def test_egress_is_attributed_by_the_network_signal_only():
    assert ground_truth.attribution_signals("new-egress") == {"new_egress_host"}


def test_silent_tamper_is_attributed_by_the_signals_that_read_changed_text():
    """Not field_drift alone: on a prose tool its score cannot reach the alert
    line, and the keyed path computes none."""
    sigs = ground_truth.attribution_signals("silent-tamper")
    assert {"determinism_break", "behavioural_drift", "field_drift"} <= sigs


def test_no_content_family_is_attributed_by_a_structural_change():
    """The only structural change in an update episode is the cover's field."""
    for family in ("silent-tamper", "content-injection"):
        assert "structural_change" not in ground_truth.attribution_signals(family)


def test_attribution_requires_the_attacked_tool():
    signals = {"search_orders": {"new_egress_host"}}
    assert not ground_truth.attributed(signals, attacked_tool=ATTACKED,
                                       family="new-egress")
    signals[ATTACKED] = {"new_egress_host"}
    assert ground_truth.attributed(signals, attacked_tool=ATTACKED,
                                   family="new-egress")


def test_the_wrong_signal_is_not_attribution():
    assert not ground_truth.attributed({ATTACKED: {"content_flag"}},
                                       attacked_tool=ATTACKED, family="new-egress")


# --------------------------------------------------------------------------- #
# The five conditions
# --------------------------------------------------------------------------- #
def test_a_benign_c2_update():
    """The false-alarm case: only refuse_all and definition_diff object."""
    f = flags(score(C2, [probe(masked=dict(CLEAN))]))
    assert f == {"accept_rebaseline": (False, False), "refuse_all": (True, False),
                 "definition_diff": (True, False), "new_host_only": (False, False),
                 "residue": (False, False)}


def test_c2_exfiltration_to_a_new_host():
    """The report's example: the field is accepted, the egress is not."""
    f = flags(score(C2, [probe(masked=dict(CLEAN), new_hosts=["x.invalid"])],
                    family="new-egress"))
    assert f["accept_rebaseline"] == (False, False)      # absorbed
    assert f["refuse_all"] == (True, True)
    assert f["definition_diff"] == (True, False)         # never attributes
    assert f["new_host_only"] == (True, True)
    assert f["residue"] == (True, True)


def test_c2_silent_tamper_is_seen_only_by_residue_and_refuse_all():
    tamper = dict(determinism_break=True, distance=0.05, ratio=5.0, within_band=False)
    f = flags(score(C2, [probe(masked=dict(CLEAN, **tamper), **tamper)],
                    family="silent-tamper"))
    assert f["accept_rebaseline"] == (False, False)
    assert f["new_host_only"] == (False, False)
    assert f["residue"] == (True, True)
    assert f["refuse_all"] == (True, True)


def test_c1_cover_on_another_tool_tamper_on_the_attacked_one():
    """The attacked tool declared nothing, so residue applies in full."""
    tamper = dict(determinism_break=True, distance=0.05, ratio=5.0, within_band=False)
    f = flags(score(C1, [probe(**tamper), probe("search_orders", "p2",
                                                masked=dict(CLEAN))],
                    family="silent-tamper"))
    assert f["residue"] == (True, True)
    assert f["accept_rebaseline"] == (False, False)


def test_c0_reduces_accept_rebaseline_and_residue_to_the_full_detector():
    tamper = dict(determinism_break=True, distance=0.05, ratio=5.0, within_band=False)
    f = flags(score(V1, [probe(**tamper)], family="silent-tamper"))
    assert f["accept_rebaseline"] == f["residue"] == (True, True)
    assert f["definition_diff"] == (False, False)


def test_an_alert_on_the_wrong_tool_is_an_alert_but_not_a_detection():
    """Noise on search_orders while the attack sits on lookup_customer."""
    f = flags(score(V1, [probe(), probe("search_orders", "p2",
                                       determinism_break=True)],
                    family="silent-tamper"))
    assert f["residue"] == (True, False)


def test_a_benign_episode_is_never_attributed():
    tamper = dict(determinism_break=True)
    f = flags(score(V1, [probe(**tamper)], family=""))
    assert f["residue"] == (True, False)


def test_all_five_come_from_one_measurement():
    """Same object scored five ways - nothing re-run per condition."""
    from eval.update_conditions import score_update as su
    m = ReprobeReport(server="s", baseline_definition_hash="h",
                      observed_definition_hash="h", checks=[probe()],
                      embedding_backend="hash", observed_definitions=C2)
    out = su(m, V1, threshold_ratio=T, attacked_tool=ATTACKED)
    assert set(out.conditions) == set(CONDITIONS)
    assert out.residue.residue is not None and out.full.residue is None


# --------------------------------------------------------------------------- #
# The harness configuration
# --------------------------------------------------------------------------- #
def test_an_existing_config_hashes_exactly_as_before():
    """Adding update keys to every config would change every config_hash, and
    resume would refuse every half-finished sweep as a conflict."""
    from eval.harness import EpisodeConfig
    from eval.record import config_hash
    cfg = EpisodeConfig("exp1_fixed_probes", seed=1)
    assert "update_check" not in cfg.as_config()
    assert config_hash(cfg.as_config()) == "cfg:11146f0cd8d6e4d8"


def test_an_update_config_is_hashed_apart_from_a_plain_one():
    from eval.harness import EpisodeConfig
    from eval.record import config_hash
    plain = EpisodeConfig("x", seed=1)
    upd = EpisodeConfig("x", seed=1, update_cover="C2")
    assert upd.as_config()["update_check"] is True
    assert config_hash(plain.as_config()) != config_hash(upd.as_config())


def test_each_cover_gets_its_own_episode_label():
    from eval.harness import EpisodeConfig
    labels = {EpisodeConfig("x", update_cover=c).label() for c in ("C0", "C1", "C2", "C3")}
    assert len(labels) == 4
    assert EpisodeConfig("x").label() == "content-injection/L1"


def test_the_attacker_driver_passes_release_and_cover():
    from eval.scenario_control import _release_args
    assert _release_args(None, None) == []
    assert _release_args("v2", "C3") == ["--release", "v2", "--cover", "C3"]


# --------------------------------------------------------------------------- #
# T28: the sweep, and the refusal to score against unverified rules
# --------------------------------------------------------------------------- #
def _spec(**kw):
    from eval.experiments import SweepSpec
    base = dict(experiment_id="rq3u_L1", probe_mode="keyed",
                families=("exfiltration", "new-egress"), levels=("L1",),
                seeds=(1, 2), benign_seeds=(), benign_update_seeds=(),
                update_covers=("C0", "C1", "C2", "C3"),
                benign_update_covers=("C1", "C2"))
    base.update(kw)
    return SweepSpec(**base)


def test_the_update_matrix_is_family_by_cover_by_seed_plus_benign_updates():
    from eval.experiments import _configs
    configs = _configs(_spec())
    attacks = [c for c in configs if c.mode == "rug-pull"]
    benign = [c for c in configs if c.mode == "benign"]
    assert len(attacks) == 2 * 4 * 2
    assert len(benign) == 2 * 2
    assert all(c.update_cover for c in configs), "no plain episodes in an update sweep"
    assert {c.update_cover for c in benign} == {"C1", "C2"}


def test_an_update_sweep_has_unique_episode_ids():
    from eval.experiments import _configs, _episode_id
    ids = [_episode_id(c) for c in _configs(_spec())]
    assert len(ids) == len(set(ids))


def test_per_tool_reaches_every_update_episode():
    from eval.experiments import _configs
    configs = _configs(_spec(per_tool={"lookup_customer": 2.0}))
    assert all(c.per_tool == {"lookup_customer": 2.0} for c in configs)


def test_a_plain_sweep_is_untouched_by_the_update_fields():
    from eval.experiments import SweepSpec, _configs
    configs = _configs(SweepSpec("exp1_fixed_probes", seeds=(1,)))
    assert not any(c.update_cover for c in configs)
    assert any(c.mode == "benign" and not c.updates for c in configs)


def test_rq3u_refuses_to_score_against_edited_rules(tmp_path, monkeypatch, capsys):
    import json

    import eval.__main__ as cli
    from driftsentry.residue import freeze_rules
    rules = tmp_path / "rules.json"
    freeze_rules(rules)
    data = json.loads(rules.read_text(encoding="utf-8"))
    data["rules"]["open_world"] = "default_counts"
    rules.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(cli, "RQ3U_RULES", rules)
    assert cli.main(["rq3u", "--quick"]) == 2
    assert "refusing to score" in capsys.readouterr().err


def test_rq3u_refuses_a_per_tool_file_that_was_never_frozen(tmp_path, capsys):
    import json

    import eval.__main__ as cli
    loose = tmp_path / "per_tool.json"
    loose.write_text(json.dumps({"thresholds": {"lookup_customer": 1.0}}),
                     encoding="utf-8")
    assert cli.main(["rq3u", "--quick", "--per-tool", str(loose)]) == 2
    assert "do not verify" in capsys.readouterr().err
