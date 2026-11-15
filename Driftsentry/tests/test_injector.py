"""The proxy's probe injector: one id sequence, nothing leaks to the client,
and probes are not learned as genuine traffic."""
from __future__ import annotations

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import (JSONRPCMessage, JSONRPCNotification, JSONRPCRequest,
                       JSONRPCResponse)

from driftsentry.injector import ProbeInjector


def _req(i, method="tools/call", params=None):
    return SessionMessage(JSONRPCMessage(JSONRPCRequest(
        jsonrpc="2.0", id=i, method=method, params=params or {"name": "t", "arguments": {}})))


def _resp(i, result=None):
    return SessionMessage(JSONRPCMessage(JSONRPCResponse(
        jsonrpc="2.0", id=i, result=result or {"content": [], "isError": False})))


class _Sink:
    def __init__(self):
        self.sent = []

    async def send(self, item):
        self.sent.append(item)


def test_client_ids_are_renumbered_and_restored():
    inj = ProbeInjector(_Sink())
    out = inj.client_to_server(_req("abc"))
    assert out.message.root.id == 0
    back = inj.server_to_client(_resp(0))
    assert back.message.root.id == "abc"


def test_the_server_sees_one_gap_free_sequence_with_probes_inside():
    sink = _Sink()
    inj = ProbeInjector(sink)

    async def go():
        seen = [inj.client_to_server(_req(1)).message.root.id]
        async with anyio.create_task_group() as tg:
            tg.start_soon(inj.call_tool, "lookup", {"id": "x"})
            await anyio.sleep(0.01)
            seen.append(sink.sent[-1].message.root.id)
            seen.append(inj.client_to_server(_req(2)).message.root.id)
            assert inj.server_to_client(_resp(seen[1])) is None    # answer to the probe
        return seen

    assert anyio.run(go) == [0, 1, 2]


def test_a_probe_answer_never_reaches_the_client():
    sink = _Sink()
    inj = ProbeInjector(sink)

    async def go():
        result = {}

        async def probe():
            result["r"] = await inj.call_tool("t", {})

        async with anyio.create_task_group() as tg:
            tg.start_soon(probe)
            await anyio.sleep(0.01)
            forwarded = inj.server_to_client(_resp(sink.sent[-1].message.root.id))
        return forwarded, result["r"]

    forwarded, result = anyio.run(go)
    assert forwarded is None
    assert result.isError is False


def test_a_client_cancellation_names_the_id_the_server_knows():
    inj = ProbeInjector(_Sink())
    inj.client_to_server(_req(7))
    cancel = SessionMessage(JSONRPCMessage(JSONRPCNotification(
        jsonrpc="2.0", method="notifications/cancelled", params={"requestId": 7})))
    out = inj.client_to_server(cancel)
    assert out.message.root.params["requestId"] == 0


def test_server_requests_and_unknown_messages_pass_untouched():
    inj = ProbeInjector(_Sink())
    note = SessionMessage(JSONRPCMessage(JSONRPCNotification(
        jsonrpc="2.0", method="notifications/progress", params={})))
    assert inj.server_to_client(note) is note
    assert inj.client_to_server(note) is note


def test_initialized_only_after_the_handshake_answer():
    inj = ProbeInjector(_Sink())
    inj.client_to_server(_req(0, method="initialize", params={}))
    assert not inj.initialized
    inj.server_to_client(_resp(0, {"protocolVersion": "x", "capabilities": {},
                                    "serverInfo": {"name": "s", "version": "1"}}))
    assert inj.initialized


def test_probe_traffic_is_never_learned_as_genuine(tmp_path):
    """traffic.learn reads only client-to-server requests; probes log as 'probe'."""
    import json

    from driftsentry.traffic import learn

    log = tmp_path / "s.jsonl"
    rows = [{"dir": "c2s", "kind": "request", "method": "initialize", "session": "a",
             "ts": "2026-11-15T10:00:00+00:00"},
            {"dir": "c2s", "kind": "request", "method": "tools/call", "tool": "t",
             "args": {"q": "hello"}, "session": "a", "ts": "2026-11-15T10:00:03+00:00"},
            {"dir": "probe", "kind": "response", "id": 5}]
    log.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    profile = learn(log, "s")
    assert profile.n_calls == 1
