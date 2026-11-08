"""T25. Residue mode in the scorer, and update_check in verify_server.

Two properties matter most. With nothing declared, residue mode must score
exactly as full mode does - every existing experiment depends on the scorer
not moving. And with something declared, the changed definition must stop
counting against the update, because it is the declaration under test.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from driftsentry.baseline import ProbeCheck, ReprobeReport
from driftsentry.declared_diff import DeclaredDiff, diff_definitions
from driftsentry.scorer import W_ESCALATION, score_report

T = 1.5
CLEAN = {"distance": 0.0, "band": 0.01, "ratio": 0.0, "within_band": True,
         "shape_known": True, "determinism_break": False, "field_drift": 0.0,
         "field_changes": [], "comparability": 1.0}
OUT_V1 = {"type": "object", "properties": {"result": {"type": "string"}}}
OUT_V2 = {"type": "object", "properties": {"result": {"type": "string"},
                                           "last_contact": {"type": "string"}}}


def defn(name="lookup_customer", outputs=OUT_V1, annotations=None, description="d"):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object",
                            "properties": {"customer_id": {"type": "string"}}},
            "outputSchema": outputs, "annotations": annotations}


def probe(tool="lookup_customer", probe_id="p1", **kw):
    base = dict(tool=tool, probe_id=probe_id, distance=0.0, band=0.01, ratio=0.0,
                within_band=True, shape_known=True, arg_names=["customer_id"])
    base.update(kw)
    return ProbeCheck(**base)


def report(checks, new=None, changed=False):
    return ReprobeReport(server="s", baseline_definition_hash="a",
                         observed_definition_hash="b" if changed else "a",
                         checks=checks, embedding_backend="hash",
                         observed_definitions=new or [defn()])


def _fingerprint(drift):
    return [(t.tool, round(t.score, 6), t.verdict, t.triggered_by,
             [(p.probe_id, round(p.score, 6), [(s.name, round(s.score, 6))
                                               for s in p.signals])
              for p in t.probes])
            for t in drift.tools]


# --------------------------------------------------------------------------- #
# Nothing declared: identical to full
# --------------------------------------------------------------------------- #
CASES = [
    [probe()],
    [probe(distance=0.1, ratio=10.0, within_band=False, shape_known=False)],
    [probe(new_hosts=["x.invalid"], new_content_flags=["instruction:override"])],
    [probe(determinism_break=True, field_drift=0.8, field_changes=["a (x): 1 -> 2"])],
    [probe(), probe("search_orders", "p2", ratio=4.0, within_band=False)],
]


@pytest.mark.parametrize("checks", CASES)
@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("diff", [None, DeclaredDiff()])
def test_residue_mode_with_nothing_declared_is_full_mode(checks, changed, diff):
    r = report(checks, changed=changed)
    full = score_report(r, threshold_ratio=T, mode="full")
    res = score_report(r, threshold_ratio=T, mode="residue", declared_diff=diff)
    assert _fingerprint(res) == _fingerprint(full)
    assert res.verdict == full.verdict
    assert res.residue is None


# --------------------------------------------------------------------------- #
# Something declared
# --------------------------------------------------------------------------- #
def test_a_declared_output_field_no_longer_alerts():
    checks = [probe(distance=0.1, ratio=10.0, within_band=False, shape_known=False,
                    masked=dict(CLEAN))]
    new = [defn(outputs=OUT_V2)]
    r = report(checks, new=new)
    full = score_report(r, threshold_ratio=T, mode="full")
    res = score_report(r, threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions([defn()], new))
    assert full.verdict == "alert"
    assert res.verdict == "ok"
    assert res.residue["verdict"] == "accepted"


def test_the_definition_hash_does_not_count_against_a_declared_update():
    """In full mode a changed definition alerts at 3.0 by itself."""
    new = [defn(description="Look up a customer record.")]
    r = report([probe()], new=new, changed=True)
    full = score_report(r, threshold_ratio=T, mode="full")
    res = score_report(r, threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions([defn()], new))
    assert full.triggered_by == "definition_hash"
    assert res.verdict == "ok"
    assert all(s.name != "definition_hash"
               for t in res.tools for p in t.probes for s in p.signals)


def test_residue_alerts_and_names_the_signal():
    """The report's read_notes example: the field is accepted, the egress
    alerts and the alert names the network."""
    checks = [probe(distance=0.1, ratio=10.0, within_band=False, shape_known=False,
                    masked=dict(CLEAN), new_hosts=["exfil.invalid"])]
    new = [defn(outputs=OUT_V2)]
    res = score_report(report(checks, new=new), threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions([defn()], new))
    assert res.verdict == "alert"
    assert res.triggered_by == "rule:new_egress_host"
    assert res.residue["verdict"] == "residue_alert"


def test_an_escalation_is_shown_but_does_not_alert_alone():
    new = [defn(annotations={"readOnlyHint": False})]
    res = score_report(report([probe()], new=new), threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions(
                           [defn(annotations={"readOnlyHint": True})], new))
    assert res.verdict == "watch"
    assert res.triggered_by == "declaration_escalation"
    assert res.score == W_ESCALATION


def test_an_escalation_beside_residue_alerts_on_the_residue():
    """The only sense in which an escalation is "combined": scores take the
    max, so the residue decides."""
    new = [defn(annotations={"readOnlyHint": False})]
    checks = [probe(new_content_flags=["instruction:override"])]
    res = score_report(report(checks, new=new), threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions(
                           [defn(annotations={"readOnlyHint": True})], new))
    assert res.verdict == "alert"
    assert res.triggered_by == "rule:instruction_shaped_output"


def test_a_held_host_is_logged_and_never_alerts():
    open_ = {"openWorldHint": True}
    new = [defn(outputs=OUT_V2, annotations=open_)]
    checks = [probe(new_hosts=["news.example.invalid"], masked=dict(CLEAN))]
    res = score_report(report(checks, new=new), threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions([defn(annotations=open_)], new))
    assert res.verdict == "ok"
    held = [s for t in res.tools for p in t.probes for s in p.signals
            if s.name == "held_for_review"]
    assert len(held) == 1 and held[0].score == 0.0
    assert res.residue["verdict"] == "held_for_review"


def test_an_escalated_tool_with_no_probes_is_still_shown():
    old = [defn(), defn("send_invoice", annotations={"destructiveHint": False})]
    new = [defn(), defn("send_invoice", annotations={"destructiveHint": True})]
    res = score_report(report([probe()], new=new), threshold_ratio=T,
                       mode="residue", declared_diff=diff_definitions(old, new))
    shown = {t.tool: t for t in res.tools}
    assert shown["send_invoice"].triggered_by == "declaration_escalation"


def test_to_dict_carries_the_residue_outcome():
    import json
    new = [defn(outputs=OUT_V2)]
    checks = [probe(masked=dict(CLEAN), new_hosts=["exfil.invalid"])]
    res = score_report(report(checks, new=new), threshold_ratio=T, mode="residue",
                       declared_diff=diff_definitions([defn()], new))
    data = json.loads(json.dumps(res.to_dict()))
    assert data["residue"]["verdict"] == "residue_alert"


# --------------------------------------------------------------------------- #
# verify_server
# --------------------------------------------------------------------------- #
def test_update_check_and_per_tool_default_off():
    import inspect

    from driftsentry.verify import verify_server
    params = inspect.signature(verify_server).parameters
    assert params["update_check"].default is False
    assert params["per_tool"].default is None


FIXTURE = Path(__file__).parent / "fixtures" / "tiny_server.py"


@pytest.mark.live
def test_update_check_turns_a_benign_declared_update_from_alert_to_watch():
    """The whole of Gap 2 on one real update: v1 -> v2 adds an output field
    and widens both hints. Full mode alerts on the new field. Residue mode
    explains the field and shows the widening, without alerting."""
    import anyio

    from driftsentry.baseline import capture_baseline
    from driftsentry.verify import verify_server

    def launch(release):
        return dict(command=sys.executable, args=[str(FIXTURE)],
                    env=dict(os.environ, DS_TINY_RELEASE=release))

    async def go():
        v1 = launch("v1")
        base = await capture_baseline("tiny", v1["command"], v1["args"],
                                      env=v1["env"], n_probes=1, n_samples=2,
                                      monitor_sandbox=False)
        full = await verify_server(base, launch=launch("v2"), samples_per_probe=1,
                                   monitor_sandbox=False, threshold_ratio=T)
        res = await verify_server(base, launch=launch("v2"), samples_per_probe=1,
                                  monitor_sandbox=False, threshold_ratio=T,
                                  update_check=True)
        return full, res

    full, res = anyio.run(go)
    assert full.mode == "full" and full.verdict == "alert"
    assert res.mode == "residue"
    assert res.verdict == "watch", res.to_dict()
    assert res.triggered_by == "declaration_escalation"
    assert res.residue["verdict"] == "escalation"
    assert {e for _, e in res.residue["escalations"]} == {"openWorld_added",
                                                          "readOnly_removed"}


@pytest.mark.live
def test_update_check_on_an_unchanged_server_scores_as_full():
    import anyio

    from driftsentry.baseline import capture_baseline
    from driftsentry.verify import verify_server

    env = dict(os.environ, DS_TINY_RELEASE="v1")
    launch = dict(command=sys.executable, args=[str(FIXTURE)], env=env)

    async def go():
        base = await capture_baseline("tiny", launch["command"], launch["args"],
                                      env=env, n_probes=1, n_samples=2,
                                      monitor_sandbox=False)
        return await verify_server(base, launch=launch, samples_per_probe=1,
                                   monitor_sandbox=False, threshold_ratio=T,
                                   update_check=True)

    res = anyio.run(go)
    assert res.mode == "full"
    assert res.residue is None
    assert res.verdict == "ok"
