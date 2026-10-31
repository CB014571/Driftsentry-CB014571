"""Do probe calls and agent calls look the same to the attacker?

This is the test that decides whether RQ3 measures anything real.

The attacker records `env_count`, `has_home` and `cwd` on every call, and the
environment feature family is built from them. If probe cycles and genuine
agent traffic reach the server through launches that differ in those fields,
a classifier separates the two classes on the harness rather than on anything
a real adversary could exploit, and the headline RQ3 number is an artefact.

So the two launches are started for real, one call is made down each, and the
rows the attacker wrote are compared. Nothing is mocked: a mocked environment
would be the one thing this test cannot afford to assume.

The slow tests are marked `live` and launch actual processes.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from eval.launch import (
    FORWARDED,
    agent_launch,
    attacker_cwd,
    describe_parity,
    expected_child_env,
    probe_launch,
)

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"

pytestmark = pytest.mark.skipif(
    not ATTACKER.is_dir(), reason=f"attacker project not found at {ATTACKER}")


# --------------------------------------------------------------------------- #
# The shape of the two launches, without starting anything
# --------------------------------------------------------------------------- #
def test_probe_launch_passes_only_the_forwarded_variable(tmp_path):
    launch = probe_launch(ATTACKER, tmp_path / "atk")
    assert set(launch["env"]) == set(FORWARDED)
    assert launch["env"]["ATTACKER_HOME"] == str(tmp_path / "atk")


def test_agent_launch_starts_the_proxy_not_the_attacker(tmp_path):
    launch = agent_launch(ATTACKER, tmp_path / "atk", tmp_path / "ds", "target")
    assert launch["args"][:4] == ["-m", "driftsentry", "run", "--server"]
    assert "--passive" in launch["args"]
    # --exec must be last: it consumes the remainder of the command line.
    assert "--exec" in launch["args"]
    tail = launch["args"][launch["args"].index("--exec") + 1:]
    assert tail[-2:] == ["-m", "attacker"] or tail[-3:] == ["-m", "attacker", "serve"]


def test_the_proxy_forwards_by_name_so_values_never_hit_the_command_line(tmp_path):
    """A forwarded value could be a secret. Only the NAME may be an argument."""
    secret_home = tmp_path / "super-secret-home"
    launch = agent_launch(ATTACKER, secret_home, tmp_path / "ds")
    for key in FORWARDED:
        assert key in launch["args"], "the name is passed to --forward-env"
    assert str(secret_home) not in " ".join(launch["args"]), \
        "the VALUE must travel in the environment, not in argv"
    assert launch["env"]["ATTACKER_HOME"] == str(secret_home)


def test_the_attacker_never_learns_where_the_detector_keeps_its_state(tmp_path):
    launch = agent_launch(ATTACKER, tmp_path / "atk", tmp_path / "ds")
    assert "DRIFTSENTRY_HOME" in launch["env"], "the proxy needs it for the baseline"
    assert "DRIFTSENTRY_HOME" not in FORWARDED, "...and must not pass it down"


def test_both_paths_agree_on_the_working_directory(tmp_path):
    """cwd reaches the feature row as cwd_base. One definition, used twice."""
    probe = probe_launch(ATTACKER, tmp_path / "atk")
    agent = agent_launch(ATTACKER, tmp_path / "atk", tmp_path / "ds")
    assert probe["cwd"] == attacker_cwd(ATTACKER)
    assert agent["args"][agent["args"].index("--cwd") + 1] == attacker_cwd(ATTACKER)


def test_the_artefact_being_corrected_is_real_and_large():
    """Documents the gap, so the write-up can quote it from a test run."""
    facts = describe_parity("/tmp/x")
    assert facts["sdk_default_vars"] < facts["full_environ_vars"], (
        "if these were equal there would have been no artefact to fix")
    assert facts["parity_child_vars"] == facts["sdk_default_vars"] + 1


# --------------------------------------------------------------------------- #
# The real thing: start both, compare what the attacker wrote down
# --------------------------------------------------------------------------- #
def _run_one_call(launch: dict, tool: str, args: dict) -> None:
    from mcp import ClientSession, types
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go():
        params = StdioServerParameters(
            command=launch["command"], args=launch["args"],
            cwd=launch["cwd"], env=launch["env"])
        async with stdio_client(params, errlog=sys.stderr) as (r, w):
            async with ClientSession(r, w, client_info=types.Implementation(
                    name="parity-check", version="1.0.0")) as session:
                await session.initialize()
                await session.call_tool(tool, args)

    asyncio.run(go())


def _rows(atk_home: Path) -> list[dict]:
    path = atk_home / "sink" / "features.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.live
def test_probe_and_agent_launches_look_identical_to_the_attacker(tmp_path):
    """The parity claim itself, measured rather than assumed."""
    probe_home = tmp_path / "probe-home"
    agent_home = tmp_path / "agent-home"
    ds_home = tmp_path / "ds-home"
    for d in (probe_home, agent_home, ds_home):
        d.mkdir(parents=True, exist_ok=True)

    _run_one_call(probe_launch(ATTACKER, probe_home),
                  "lookup_customer", {"customer_id": "CUS-1"})
    _run_one_call(agent_launch(ATTACKER, agent_home, ds_home, "parity"),
                  "lookup_customer", {"customer_id": "CUS-1"})

    probe_rows, agent_rows = _rows(probe_home), _rows(agent_home)
    assert probe_rows, "the direct launch wrote no feature rows"
    assert agent_rows, "the proxied launch wrote no feature rows"

    probe, agent = probe_rows[0], agent_rows[0]
    differences = {
        field: (probe.get(field), agent.get(field))
        for field in ("env_count", "has_home", "cwd")
        if probe.get(field) != agent.get(field)
    }
    assert not differences, (
        "probe and agent launches differ in what the attacker can see: "
        f"{differences}. Any field listed here is a label leak for RQ3 - either "
        "make the launches agree, or record it as a real deployment difference "
        "and exclude the field from the environment family."
    )


@pytest.mark.live
def test_parity_reproduces_the_expected_environment_exactly(tmp_path):
    """Not just equal to each other - equal to what was intended."""
    home = tmp_path / "atk"
    home.mkdir(parents=True, exist_ok=True)
    _run_one_call(probe_launch(ATTACKER, home),
                  "read_document", {"path": "docs/index.md"})

    rows = _rows(home)
    assert rows
    assert rows[0]["env_count"] == len(expected_child_env(home)), (
        "the child environment is not the SDK default set plus ATTACKER_HOME")


@pytest.mark.live
def test_the_old_launch_really_did_differ(tmp_path):
    """Guards the premise: without parity the gap is large and learnable.

    If this ever stops failing to differ, the artefact has gone away on its
    own and `launch_parity` has become unnecessary - which would be worth
    knowing rather than silently carrying.
    """
    from eval.scenario_control import AttackerControl

    legacy_home = tmp_path / "legacy"
    parity_home = tmp_path / "parity"
    for d in (legacy_home, parity_home):
        d.mkdir(parents=True, exist_ok=True)

    control = AttackerControl.discover(ATTACKER, home=legacy_home)
    legacy = {"command": control.launch_command()[0],
              "args": control.launch_command()[1],
              "cwd": str(control.project_dir),
              "env": control.env()}

    _run_one_call(legacy, "lookup_customer", {"customer_id": "CUS-1"})
    _run_one_call(probe_launch(ATTACKER, parity_home),
                  "lookup_customer", {"customer_id": "CUS-1"})

    legacy_count = _rows(legacy_home)[0]["env_count"]
    parity_count = _rows(parity_home)[0]["env_count"]
    assert legacy_count > parity_count, (
        f"expected the full-environment launch to be larger: "
        f"legacy={legacy_count} parity={parity_count}")
