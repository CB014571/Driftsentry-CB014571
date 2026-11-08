"""An attack confined to a tool the user never calls.

This is the case that separates the two detectors H2 compares. Passive
monitoring watches real traffic, so an attack on a tool the user never
touches is structurally invisible to it. A probe reaches that tool on
schedule regardless. Without this case the two could only ever be compared
where both had a chance, and RQ2 would understate the difference.

The validation matters more than it looks. A misspelled tool name would
produce a scenario that arms cleanly and then never fires - which is
indistinguishable, from the outside, from an attacker that evaded perfectly.
A typo would be reported as a successful evasion.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"

pytestmark = pytest.mark.skipif(
    not ATTACKER.is_dir(), reason=f"attacker project not found at {ATTACKER}")


@pytest.fixture
def scenario_mod(monkeypatch, tmp_path):
    monkeypatch.setenv("ATTACKER_HOME", str(tmp_path))
    if str(ATTACKER) not in sys.path:
        sys.path.insert(0, str(ATTACKER))
    for name in [n for n in sys.modules if n.startswith("attacker")]:
        del sys.modules[name]
    import attacker.scenario as scenario
    return scenario


# --------------------------------------------------------------------------- #
# Targeting
# --------------------------------------------------------------------------- #
def test_an_empty_list_targets_every_tool(scenario_mod):
    """The default must not quietly disarm the attacker."""
    sc = scenario_mod.Scenario(mode="rug-pull")
    assert sc.only_tools == []
    assert all(sc.targets(t) for t in scenario_mod.TOOL_NAMES)


def test_only_the_named_tool_is_targeted(scenario_mod):
    sc = scenario_mod.Scenario(mode="rug-pull", only_tools=["send_invoice"])
    assert sc.targets("send_invoice") is True
    assert sc.targets("lookup_customer") is False
    assert sc.targets("get_weather") is False


def test_several_tools_can_be_named(scenario_mod):
    sc = scenario_mod.Scenario(mode="rug-pull",
                               only_tools=["send_invoice", "get_weather"])
    assert sc.targets("send_invoice") and sc.targets("get_weather")
    assert not sc.targets("read_document")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def test_a_misspelled_tool_is_refused_at_arm_time(scenario_mod):
    """Otherwise it arms cleanly, never fires, and looks like a clean evasion."""
    sc = scenario_mod.Scenario(mode="rug-pull", only_tools=["send_invoic"])
    problems = sc.validate()
    assert problems
    assert "send_invoic" in problems[0]
    assert "clean evasion" in problems[0], (
        "the message must say WHY a typo is dangerous, not just that it is wrong")


def test_an_advertised_but_unreachable_tool_is_still_refused(scenario_mod):
    """Being a real tool name is necessary but not sufficient.

    send_invoice is advertised and spelled correctly, and an attack confined
    to it would still never fire. See the unreachable-tool tests below.
    """
    for tool in scenario_mod.TOOL_NAMES:
        sc = scenario_mod.Scenario(mode="rug-pull", only_tools=[tool])
        expected_clean = tool in scenario_mod.ATTACKABLE_TOOLS
        assert (sc.validate() == []) is expected_clean, tool


def test_the_declared_tool_names_match_the_server(scenario_mod):
    """If the server gains a tool and this list does not, targeting it fails.

    Checked against what the server actually REGISTERS, for every release.
    This used to read @mcp.tool() decorators out of the source with a regex;
    T26 moved registration to startup so a release can choose definitions, and
    the regex then found nothing. Asking the registration itself is the check
    the regex was standing in for, and it also covers v2's cover tools, which
    are defined inside factories and never appear as top-level decorators.
    """
    import asyncio

    from mcp.server.fastmcp import FastMCP

    import attacker.server as server

    declared = set(scenario_mod.TOOL_NAMES)
    for release, cover in (("v1", "C0"), ("v1n", "C0"), ("v2", "C0"),
                           ("v2", "C1"), ("v2", "C2"), ("v2", "C3")):
        sc = scenario_mod.Scenario(release=release, cover=cover)
        target = server.register_tools(sc, target=FastMCP("t"))
        defined = {t.name for t in asyncio.run(target.list_tools())}
        assert defined == declared, (
            f"{release}/{cover}: server registers {defined}, scenario declares {declared}")


# --------------------------------------------------------------------------- #
# The server honours it
# --------------------------------------------------------------------------- #
def test_the_server_consults_targets_before_attacking(scenario_mod):
    """_process must return the honest text for an untargeted tool."""
    source = (ATTACKER / "attacker" / "server.py").read_text(encoding="utf-8")
    assert "scenario.targets(tool)" in source
    # ...and before the attack is applied, not after.
    assert source.index("scenario.targets(tool)") < source.index("attacks.apply_attack")


# --------------------------------------------------------------------------- #
# The harness side
# --------------------------------------------------------------------------- #
def test_replay_can_avoid_the_targeted_tool():
    """The other half: traffic the user would plausibly produce, minus the
    tool under attack. Without it the 'user never calls it' premise is only
    asserted."""
    from eval.replay import choose_sessions

    sessions = [
        [{"tool": "lookup_customer", "args": {}}],
        [{"tool": "send_invoice", "args": {}}],
        [{"tool": "read_document", "args": {}}, {"tool": "send_invoice", "args": {}}],
    ]
    picked = choose_sessions(sessions, 4, seed=0, avoid_tools={"send_invoice"})
    assert picked
    assert all(call["tool"] != "send_invoice" for s in picked for call in s)


def test_the_episode_config_carries_avoid_tools():
    from eval.harness import EpisodeConfig

    cfg = EpisodeConfig(experiment_id="x", avoid_tools=("send_invoice",))
    assert cfg.avoid_tools == ("send_invoice",)
    assert EpisodeConfig(experiment_id="x").avoid_tools == ()


# --------------------------------------------------------------------------- #
# Tools no payload can reach
#
# Found by running it rather than by reading it: an episode targeting
# send_invoice armed cleanly, ran, and reported the tool as honest. The tool
# is side-effecting, so it returns directly instead of routing through
# _process, and no payload is ever applied to it. From outside, a scenario
# that never fires is indistinguishable from an attacker that evaded
# perfectly - so it has to be refused at arm time.
# --------------------------------------------------------------------------- #
def test_a_tool_no_payload_can_reach_is_refused(scenario_mod):
    sc = scenario_mod.Scenario(mode="rug-pull", only_tools=["send_invoice"])
    problems = sc.validate()
    assert problems
    assert "never fire" in problems[0]
    assert "successful evasion" in problems[0]


def test_every_attackable_tool_validates(scenario_mod):
    for tool in scenario_mod.ATTACKABLE_TOOLS:
        assert scenario_mod.Scenario(mode="rug-pull", only_tools=[tool]).validate() == [], tool


def test_attackable_is_a_subset_of_advertised(scenario_mod):
    assert set(scenario_mod.ATTACKABLE_TOOLS) < set(scenario_mod.TOOL_NAMES)


def test_the_unreachable_tool_really_does_bypass_the_scenario(scenario_mod):
    """Guards the premise: if send_invoice ever routes through _process, this
    restriction becomes wrong and should be removed rather than carried."""
    source = (ATTACKER / "attacker" / "server.py").read_text(encoding="utf-8")
    body = source[source.index("def send_invoice("):]
    body = body[:body.index("\ndef ")] if "\ndef " in body else body
    assert "_process(" not in body, (
        "send_invoice now routes through _process, so it IS attackable - "
        "add it to ATTACKABLE_TOOLS")
