"""H2b: in-session verification, shaped probe values, and probe-earned attribution.

Measured before these were written (smoke run, 15 Nov 2026): one in-session
cycle against a benign server scored OK 0.18; against an L1 exfiltration
server it alerted on rule:new_file_access, and all 18 attacker events fell
inside exactly one call window (9 probe, 9 genuine).
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace as NS

import pytest

from driftsentry.insession import CallRecord, InSessionChannel, expected_probe_calls
from driftsentry.probe_generator import KeyedProbeGenerator, shaped_string
from driftsentry.traffic import ToolShape

KEY = b"k" * 32
TOOL = {"name": "lookup_customer",
        "inputSchema": {"type": "object", "required": ["customer_id"],
                        "properties": {"customer_id": {"type": "string"}}}}


# --------------------------------------------------------------------------- #
# Shaped values
# --------------------------------------------------------------------------- #
def test_no_shapes_means_exactly_the_old_values():
    old = KeyedProbeGenerator(KEY, cycle=3).generate("s", TOOL, count=5)
    new = KeyedProbeGenerator(KEY, cycle=3, shapes=None).generate("s", TOOL, count=5)
    assert [p.args for p in old] == [p.args for p in new]


def test_shaped_values_are_keyed_and_reproducible():
    shape = ToolShape(lengths=[6, 6, 6, 7], digit_ratio=0.5, space_ratio=0.0)
    a = KeyedProbeGenerator(KEY, cycle=1, shapes={"lookup_customer": shape}).generate("s", TOOL, 6)
    b = KeyedProbeGenerator(KEY, cycle=1, shapes={"lookup_customer": shape}).generate("s", TOOL, 6)
    c = KeyedProbeGenerator(b"x" * 32, cycle=1, shapes={"lookup_customer": shape}).generate("s", TOOL, 6)
    assert [p.args for p in a] == [p.args for p in b]
    assert [p.args for p in a] != [p.args for p in c]


def test_shaped_values_follow_the_genuine_lengths():
    shape = ToolShape(lengths=[6] * 10, digit_ratio=0.46, space_ratio=0.0)
    gen = KeyedProbeGenerator(KEY, cycle=2, shapes={"lookup_customer": shape})
    lengths = [len(p.args["customer_id"]) for p in gen.generate("s", TOOL, 12)]
    assert sum(abs(n - 6) <= 1 for n in lengths) >= 10


def test_shaping_never_sends_an_empty_value_unless_users_did():
    import random
    shape = ToolShape(lengths=[5, 6, 7], digit_ratio=0.3)
    for i in range(50):
        _, v = shaped_string("identifier", shape, random.Random(i))
        assert v != ""
    _, v = shaped_string("identifier", ToolShape(lengths=[0]), random.Random(1))
    assert v == ""


def test_shapes_record_lengths_not_values():
    shape = ToolShape(lengths=[3, 9])
    assert set(vars(shape)) >= {"lengths"} and not any(
        isinstance(v, str) for v in shape.lengths)


# --------------------------------------------------------------------------- #
# The channel
# --------------------------------------------------------------------------- #
class _FakeSession:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return NS(tools=[])

    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        return NS(content=[NS(text="ok")], isError=False)


def _run_channel(key=KEY, cycle=1, probes=6):
    genuine = [{"tool": "get_weather", "args": {"city": f"c{i}"}} for i in range(6)]
    session = _FakeSession()
    ch = InSessionChannel(session, genuine, key=key, server="s", cycle=cycle,
                          profile=None, expected_probes=probes)

    async def go():
        for i in range(probes):
            await ch.prepare_probe("lookup_customer")
            await ch.call_tool("lookup_customer", {"customer_id": f"p{i}"})
        await ch.finish()

    asyncio.run(go())
    return session, ch


def test_every_genuine_call_is_sent_exactly_once_in_order():
    session, ch = _run_channel()
    sent = [a["city"] for t, a in session.calls if t == "get_weather"]
    assert sent == [f"c{i}" for i in range(6)]
    assert sum(1 for r in ch.records if r.kind == "probe") == 6


def test_interleaving_is_keyed():
    order = lambda s: "".join("g" if t == "get_weather" else "P" for t, _ in s.calls)
    a, _ = _run_channel()
    b, _ = _run_channel()
    c, _ = _run_channel(cycle=9)
    assert order(a) == order(b)
    assert order(a) != order(c), "a new cycle reorders the session"


def test_probes_are_not_always_first_or_last():
    firsts, lasts = set(), set()
    for cycle in range(40):
        s, _ = _run_channel(cycle=cycle)
        firsts.add(s.calls[0][0])
        lasts.add(s.calls[-1][0])
    assert firsts == {"get_weather", "lookup_customer"}
    assert lasts == {"get_weather", "lookup_customer"}


def test_genuine_calls_are_sent_before_the_probe_window_opens():
    """prepare_probe runs before the sandbox starts; call_tool is the probe only."""
    from driftsentry.baseline import _call_once

    seen = []

    class _Monitor:
        def start(self):
            seen.append(("start", len(session.calls)))

        def stop(self):
            seen.append(("stop", len(session.calls)))
            return NS(hosts=set(), files=set())

    genuine = [{"tool": "get_weather", "args": {"city": "x"}}] * 3
    session = _FakeSession()
    ch = InSessionChannel(session, genuine, key=KEY, server="s", cycle=4,
                          profile=None, expected_probes=1)
    asyncio.run(_call_once(ch, "lookup_customer", {"customer_id": "p"}, _Monitor()))
    started, stopped = seen[0][1], seen[1][1]
    assert stopped - started == 1, "only the probe is inside the window"


def test_expected_probe_calls_counts_the_subsampled_draw():
    tools = [NS(tool=t, probed=True) for t in ("a", "b", "c")] + [NS(tool="d", probed=False)]
    baseline = NS(tools=tools, family_for=lambda t: NS(n_instances=8))
    assert expected_probe_calls(baseline, 1, True) == 9
    assert expected_probe_calls(baseline, 2, False) == 48


# --------------------------------------------------------------------------- #
# Attribution and the pre-registration
# --------------------------------------------------------------------------- #
def test_an_event_is_attributed_to_the_call_it_fell_inside():
    from eval.followup import events_in_windows

    records = [CallRecord("genuine", "t", {}, start=10.0, end=10.5),
               CallRecord("probe", "t", {}, start=11.0, end=11.4)]
    events = [("1970-01-01T00:00:10.200000+00:00", "exfiltrate", ""),
              ("1970-01-01T00:00:11.100000+00:00", "exfiltrate", ""),
              ("1970-01-01T00:00:12.000000+00:00", "exfiltrate", "")]
    assert events_in_windows(events, records, "probe") == 1
    assert events_in_windows(events, records, "genuine") == 1


def test_the_attacker_stamps_events_finely_enough_to_attribute():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "mcp rug pull attack server"
           / "attacker" / "sink.py")
    if not src.is_file():
        pytest.skip("attacker project not present")
    assert 'timespec="microseconds"' in src.read_text(encoding="utf-8")


def test_a_changed_preregistration_is_refused(tmp_path, monkeypatch):
    from eval import followup

    monkeypatch.setattr(followup, "OUT", tmp_path)
    monkeypatch.setattr(followup, "PREREG", tmp_path / "preregistration.json")
    monkeypatch.setattr(followup, "PROFILE_A", tmp_path / "profile_split_a.json")
    followup.preregister()
    followup.verify_preregistration()
    with pytest.raises(FileExistsError):
        followup.preregister()
    doc = json.loads(followup.PREREG.read_text(encoding="utf-8"))
    doc["thresholds"]["auc_ceiling"] = 0.9
    followup.PREREG.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(RuntimeError):
        followup.verify_preregistration()


def test_the_genuine_halves_do_not_overlap():
    from eval.followup import _session_key, genuine_split

    a = {_session_key(s) for s in genuine_split("A")}
    b = {_session_key(s) for s in genuine_split("B")}
    if not (a or b):
        pytest.skip("no genuine corpus")
    assert not (a & b)


def test_in_session_leaves_earlier_config_hashes_alone():
    from eval.harness import EpisodeConfig

    assert "in_session" not in EpisodeConfig("x").as_config()
    assert EpisodeConfig("x", in_session=True).as_config()["in_session"] is True


def test_h2b_uses_h2s_thresholds_unchanged():
    from eval import conditions, followup

    defaults = conditions.h4_verdict.__kwdefaults__
    assert followup.AUC_CEILING == defaults["auc_ceiling"]
    assert followup.RECALL_WITHIN_PP == defaults["recall_within"]
    assert followup.FALSE_ALARM_RISE_PP == defaults["false_alarm_rise"]
