"""The genuine-traffic agent, tested without Ollama installed.

``run_task`` is the loop that produces the negative class for RQ3, so a defect
here does not crash anything - it quietly yields a corpus of genuine traffic
that is thinner, or shorter, or more uniform than real agent traffic, and the
classifier separates the classes on that instead of on probing. The failure is
silent and the result still looks like a result, which is exactly the kind of
thing that has to be tested rather than observed.

Only the Ollama HTTP turn is injected. Everything else - the MCP session, the
proxy, the attacker - is real in the live tests, because the traffic those
produce is the measurement.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from eval.agent import (
    FALLBACK_CLIENT,
    SYSTEM_PROMPTS,
    load_host_profile,
    load_tasks,
    run_task,
    to_ollama_tools,
)

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"


# --------------------------------------------------------------------------- #
# The task corpus
# --------------------------------------------------------------------------- #
def test_the_corpus_has_forty_tasks_with_unique_ids():
    tasks = load_tasks()
    assert len(tasks) == 40
    assert len({t["id"] for t in tasks}) == 40
    assert all(t.get("prompt") for t in tasks)


def test_the_corpus_mixes_single_and_multi_tool_work():
    """A corpus of only short tasks would make the session family trivial.

    calls_before and distinct_tools_before are features; if genuine traffic
    were uniformly one call long, the classifier would split on length.
    """
    tasks = load_tasks()
    single = [t for t in tasks if len(t.get("expect", [])) == 1]
    multi = [t for t in tasks if len(t.get("expect", [])) > 1]
    none = [t for t in tasks if not t.get("expect")]
    assert len(single) >= 15, "not enough single-tool tasks"
    assert len(multi) >= 8, "not enough multi-step tasks"
    assert len(none) >= 2, "no tasks that may need no tool at all"


def test_every_tool_the_server_offers_is_exercised():
    expected = set()
    for task in load_tasks():
        expected |= set(task.get("expect", []))
    assert expected == {"lookup_customer", "read_document", "search_orders",
                        "get_weather", "send_invoice"}


def test_tasks_are_phrased_as_requests_not_as_tool_calls():
    """A prompt containing the literal call would produce machine-shaped args."""
    for task in load_tasks():
        prompt = task["prompt"]
        assert "(" not in prompt or ")" not in prompt, f"{task['id']}: looks like code"
        assert not prompt.startswith(("lookup_customer", "read_document",
                                      "search_orders", "get_weather")), task["id"]


def test_both_system_prompt_styles_exist():
    assert set(SYSTEM_PROMPTS) == {"short", "detailed"}
    assert len(SYSTEM_PROMPTS["detailed"]) > len(SYSTEM_PROMPTS["short"])


# --------------------------------------------------------------------------- #
# Host identity
# --------------------------------------------------------------------------- #
def test_an_unrecorded_host_profile_is_reported_as_unrecorded(monkeypatch, tmp_path):
    """Silently falling back would make the client family trivially separable."""
    monkeypatch.setattr("eval.agent.HOST_PROFILE", tmp_path / "missing.json")
    profile, recorded = load_host_profile()
    assert recorded is False
    assert profile == FALLBACK_CLIENT


def test_a_recorded_profile_is_used(monkeypatch, tmp_path):
    path = tmp_path / "host_profile.json"
    path.write_text(json.dumps({"name": "claude-ai", "version": "0.14.2"}),
                    encoding="utf-8")
    monkeypatch.setattr("eval.agent.HOST_PROFILE", path)
    profile, recorded = load_host_profile()
    assert recorded is True
    assert profile == {"name": "claude-ai", "version": "0.14.2"}


def test_the_fallback_is_not_the_sdk_default():
    """'mcp' appears in no real host; using it would leak the label outright."""
    assert FALLBACK_CLIENT["name"] != "mcp"


# --------------------------------------------------------------------------- #
# Tool translation
# --------------------------------------------------------------------------- #
class _Tool:
    def __init__(self, name, description, schema):
        self.name, self.description, self.inputSchema = name, description, schema


def test_mcp_tools_become_ollama_functions():
    out = to_ollama_tools([
        _Tool("lookup_customer", "Look up a customer record.",
              {"type": "object", "properties": {"customer_id": {"type": "string"}}}),
    ])
    assert out[0]["type"] == "function"
    assert out[0]["function"]["name"] == "lookup_customer"
    assert out[0]["function"]["parameters"]["properties"]["customer_id"]["type"] == "string"


def test_a_tool_without_a_schema_still_converts():
    out = to_ollama_tools([_Tool("x", None, None)])
    assert out[0]["function"]["parameters"]["type"] == "object"
    assert out[0]["function"]["description"] == ""


# --------------------------------------------------------------------------- #
# The loop, against a stubbed Ollama and the real attacker
# --------------------------------------------------------------------------- #
def _launch():
    from eval.launch import probe_launch
    return probe_launch(ATTACKER, Path(__file__).resolve().parent / "_agent_tmp")


def _scripted(*turns):
    """A fake Ollama that replays the given turns in order."""
    seq = list(turns)

    async def chat(payload, timeout):
        assert payload["stream"] is False, "the loop must not stream"
        assert payload["tools"], "tools must be offered to the model"
        return seq.pop(0) if seq else {"message": {"role": "assistant", "content": "done"}}

    return chat


@pytest.mark.live
@pytest.mark.skipif(not ATTACKER.is_dir(), reason="attacker project not found")
def test_a_tool_call_the_model_chooses_reaches_the_server(tmp_path):
    from eval.launch import probe_launch

    chat = _scripted(
        {"message": {"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "lookup_customer",
                          "arguments": {"customer_id": "C-1001"}}}]}},
        {"message": {"role": "assistant", "content": "Dana Whitfield."}},
    )
    record = asyncio.run(run_task(
        {"id": "t01", "prompt": "Who is customer C-1001?"},
        model="stub", launch=probe_launch(ATTACKER, tmp_path / "atk"),
        client_info={"name": "claude-ai", "version": "0.14.2"}, chat=chat))

    assert record["error"] is None, record["error"]
    assert record["n_calls"] == 1
    call = record["tool_calls"][0]
    assert call["tool"] == "lookup_customer"
    assert call["failed"] is False
    assert call["latency_s"] > 0
    assert record["duration_s"] > 0


@pytest.mark.live
@pytest.mark.skipif(not ATTACKER.is_dir(), reason="attacker project not found")
def test_string_encoded_arguments_are_parsed(tmp_path):
    """Several models return `arguments` as a JSON string, not an object."""
    from eval.launch import probe_launch

    chat = _scripted(
        {"message": {"role": "assistant", "tool_calls": [
            {"function": {"name": "read_document",
                          "arguments": "{\"path\": \"docs/index.md\"}"}}]}},
        {"message": {"role": "assistant", "content": "Billing and shipping."}},
    )
    record = asyncio.run(run_task(
        {"id": "t07", "prompt": "Open docs/index.md"},
        model="stub", launch=probe_launch(ATTACKER, tmp_path / "atk"), chat=chat))

    assert record["error"] is None
    assert record["tool_calls"][0]["args"] == {"path": "docs/index.md"}


@pytest.mark.live
@pytest.mark.skipif(not ATTACKER.is_dir(), reason="attacker project not found")
def test_a_task_needing_no_tool_makes_no_calls(tmp_path):
    from eval.launch import probe_launch

    chat = _scripted({"message": {"role": "assistant", "content": "You're welcome."}})
    record = asyncio.run(run_task(
        {"id": "t36", "prompt": "Thanks for your help earlier."},
        model="stub", launch=probe_launch(ATTACKER, tmp_path / "atk"), chat=chat))

    assert record["error"] is None
    assert record["n_calls"] == 0
    assert len(record["steps"]) == 1


@pytest.mark.live
@pytest.mark.skipif(not ATTACKER.is_dir(), reason="attacker project not found")
def test_max_steps_stops_a_model_that_never_finishes(tmp_path):
    """A looping model must not stall the collection indefinitely."""
    from eval.launch import probe_launch

    async def always_calls(payload, timeout):
        return {"message": {"role": "assistant", "tool_calls": [
            {"function": {"name": "get_weather", "arguments": {"city": "Leeds"}}}]}}

    record = asyncio.run(run_task(
        {"id": "t18", "prompt": "What's the weather in Leeds?"},
        model="stub", launch=probe_launch(ATTACKER, tmp_path / "atk"),
        max_steps=3, chat=always_calls))

    assert record["error"] is None
    assert len(record["steps"]) == 3
    assert record["n_calls"] == 3


@pytest.mark.live
@pytest.mark.skipif(not ATTACKER.is_dir(), reason="attacker project not found")
def test_a_failing_tool_call_is_recorded_not_raised(tmp_path):
    """One bad call must not discard the rest of a session's traffic."""
    from eval.launch import probe_launch

    chat = _scripted(
        {"message": {"role": "assistant", "tool_calls": [
            {"function": {"name": "no_such_tool", "arguments": {}}}]}},
        {"message": {"role": "assistant", "content": "I could not do that."}},
    )
    record = asyncio.run(run_task(
        {"id": "tXX", "prompt": "Do something impossible."},
        model="stub", launch=probe_launch(ATTACKER, tmp_path / "atk"), chat=chat))

    assert record["error"] is None
    assert record["tool_calls"][0]["failed"] is True


def test_an_unreachable_ollama_is_recorded_as_an_error_not_a_crash(tmp_path):
    """The collector must be able to skip a model and carry on."""
    async def refuse(payload, timeout):
        raise ConnectionError("ollama is not running")

    record = asyncio.run(run_task(
        {"id": "t01", "prompt": "Who is customer C-1001?"},
        model="absent",
        launch={"command": "python", "args": ["-c", "pass"], "cwd": None, "env": {}},
        chat=refuse))

    assert record["error"] is not None
    assert record["n_calls"] == 0
