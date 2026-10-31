"""A genuine LLM agent calling the server, so RQ3 has a real negative class.

RQ3 compares probe traffic against genuine traffic. The genuine half cannot be
synthesised by the harness: a scripted sequence of calls would share whatever
regularities the script author happened to introduce, and a classifier would
separate the classes on those rather than on anything about probing. So the
negative class is produced by an actual model choosing actual tool calls.

Local models through Ollama, for three reasons. A hosted API would send the
attacker's synthetic customer records off the machine, which the ethics
position rules out. Costs would scale with the collection size. And three
different models give three different calling styles, so the result is not a
description of one model's habits.

What makes the traffic genuine rather than merely automated
    * the model decides which tool to call and with what arguments;
    * calls arrive through the proxy, exactly as a real host's would
      (see eval/launch.py::agent_launch);
    * the session announces itself with the real host's client_info, read from
      host_profile.json, so the client family cannot separate the classes on a
      name the harness invented.

The labels do NOT come from here. The collector records time windows around
each session and the dataset builder joins on them - see T5. Nothing in this
module tells the attacker what it is.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

OLLAMA_CHAT = "http://localhost:11434/api/chat"
HOST_PROFILE = Path(__file__).resolve().parent / "host_profile.json"

#: Used only when no host profile has been recorded yet. The SDK's own default
#: would be worse: "mcp" appears in no real host, so the client family would
#: separate the classes perfectly and RQ3 would be meaningless. This value is a
#: placeholder that at least looks like a host, and the collector warns loudly.
FALLBACK_CLIENT = {"name": "claude-ai", "version": "0.0.0-unrecorded"}

SYSTEM_PROMPTS = {
    # Two styles, because prompt verbosity changes how many tools a model calls
    # and in what order. Fixing one style would make the session and timing
    # families describe that style rather than agent traffic in general.
    "short": "You are an operations assistant. Use the available tools to answer.",
    "detailed": (
        "You are an operations assistant for Acme Business Tools. You have "
        "tools for customer records, the internal document library, recent "
        "orders, weather, and invoicing. Call a tool whenever it would help "
        "answer accurately; prefer looking something up to guessing. When you "
        "have what you need, answer in one or two sentences."
    ),
}


def load_host_profile() -> tuple[dict[str, str], bool]:
    """The real host's client identity, and whether it was actually recorded.

    Returns (profile, recorded). When ``recorded`` is False the caller is
    using the fallback, which is a measurement defect rather than a detail:
    the client feature family would be trivially separable.
    """
    try:
        data = json.loads(HOST_PROFILE.read_text(encoding="utf-8"))
        if data.get("name"):
            return ({"name": data["name"],
                     "version": data.get("version") or "unknown"}, True)
    except Exception:
        pass
    return (dict(FALLBACK_CLIENT), False)


# --------------------------------------------------------------------------- #
# Tool translation
# --------------------------------------------------------------------------- #
def to_ollama_tools(mcp_tools: Any) -> list[dict[str, Any]]:
    """Convert MCP tool definitions into Ollama's function-calling schema."""
    out = []
    for tool in mcp_tools:
        schema = getattr(tool, "inputSchema", None) or {"type": "object", "properties": {}}
        out.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": (getattr(tool, "description", "") or "").strip(),
                "parameters": schema,
            },
        })
    return out


def _result_text(result: Any) -> str:
    """Flatten a CallToolResult into the string a chat model can consume."""
    parts = []
    for block in (getattr(result, "content", None) or []):
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts) if parts else "(no textual content)"


async def _post_chat(payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """One non-streaming turn against Ollama."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(OLLAMA_CHAT, json=payload)
        response.raise_for_status()
        return response.json()


async def run_task(
    task: dict[str, Any],
    model: str,
    launch: dict[str, Any],
    *,
    client_info: dict[str, str] | None = None,
    system_prompt: str = "short",
    max_steps: int = 6,
    timeout: float = 180.0,
    chat: Callable[[dict[str, Any], float], Awaitable[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Run one task to completion, returning the transcript and timings.

    ``chat`` is injectable so the loop can be tested without Ollama running.
    Nothing else about the path is stubbed: the MCP session, the proxy and the
    attacker are all real, because the traffic they produce is the point.
    """
    from mcp import ClientSession, types
    from mcp.client.stdio import StdioServerParameters, stdio_client

    post = chat or _post_chat
    profile = dict(client_info or FALLBACK_CLIENT)
    prompt = SYSTEM_PROMPTS.get(system_prompt, SYSTEM_PROMPTS["short"])

    record: dict[str, Any] = {
        "task_id": task.get("id"),
        "task": task.get("prompt"),
        "model": model,
        "system_prompt": system_prompt,
        "client_info": profile,
        "started": time.time(),
        "steps": [],
        "tool_calls": [],
        "error": None,
    }

    params = StdioServerParameters(
        command=launch["command"], args=launch["args"],
        cwd=launch.get("cwd"), env=launch.get("env"))

    try:
        async with stdio_client(params, errlog=None) as (read, write):
            async with ClientSession(read, write, client_info=types.Implementation(
                    name=profile["name"], version=profile["version"])) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools = to_ollama_tools(listed.tools)

                messages: list[dict[str, Any]] = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": task["prompt"]},
                ]

                for step in range(max_steps):
                    t0 = time.perf_counter()
                    reply = await post({"model": model, "messages": messages,
                                        "tools": tools, "stream": False}, timeout)
                    think_s = time.perf_counter() - t0

                    message = reply.get("message") or {}
                    calls = message.get("tool_calls") or []
                    messages.append(message)
                    record["steps"].append({
                        "step": step,
                        "think_s": think_s,
                        "n_tool_calls": len(calls),
                        "content": (message.get("content") or "")[:500],
                    })

                    if not calls:
                        break                      # the model answered

                    for call in calls:
                        fn = call.get("function") or {}
                        name = fn.get("name")
                        args = fn.get("arguments") or {}
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {}

                        t1 = time.perf_counter()
                        try:
                            result = await session.call_tool(name, args)
                            text = _result_text(result)
                            # A server reports a bad call by setting isError on
                            # the RESULT, not by raising: FastMCP answers an
                            # unknown tool name with isError true and a message.
                            # Treating only exceptions as failures would record
                            # those calls as successful.
                            failed = bool(getattr(result, "isError", False))
                        except Exception as exc:
                            text, failed = f"tool error: {exc}", True
                        call_s = time.perf_counter() - t1

                        record["tool_calls"].append({
                            "step": step, "tool": name, "args": args,
                            "latency_s": call_s, "failed": failed,
                        })
                        # Ollama expects tool output back as a tool-role turn.
                        messages.append({"role": "tool", "name": name,
                                         "content": text[:4000]})
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"

    record["finished"] = time.time()
    record["duration_s"] = record["finished"] - record["started"]
    record["n_calls"] = len(record["tool_calls"])
    return record


def load_tasks(path: str | Path | None = None) -> list[dict[str, Any]]:
    """The task corpus, as a list."""
    target = Path(path) if path else Path(__file__).resolve().parent / "agent_tasks.json"
    data = json.loads(Path(target).read_text(encoding="utf-8"))
    return data["tasks"] if isinstance(data, dict) else data


async def probe_models(timeout: float = 10.0) -> list[str]:
    """Which models Ollama currently has. Empty when it is not running."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get("http://localhost:11434/api/tags")
            response.raise_for_status()
            return [m["name"] for m in response.json().get("models", [])]
    except Exception:
        return []
