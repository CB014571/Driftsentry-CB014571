"""Probing inside the client's own session, from the proxy (H2b, deployment).

The proxy already sits in the user's live MCP session. ``ProbeInjector``
lets verification send its probes through that session instead of opening a
separate one, so the client identity, process, environment and session
counters a probe carries are the user's own (see insession.py for why).

Three guarantees, each tested:

One id sequence
    The proxy renumbers every request the client sends and gives injected
    probes the next number from the SAME counter. The server sees one gap-free
    sequence of ids, so an injected request cannot be spotted by its id - a
    client that counts 0, 1, 2 next to probes numbered "probe-1" would be a
    tell. Responses are renumbered back before the client sees them, and a
    client's cancellation is translated to the id the server knows.

The client never sees a probe
    A response to an injected request is taken out of the server-to-client
    stream and handed to verification. Nothing is forwarded.

Probes are not learned as genuine traffic
    Injected exchanges are logged under their own direction, so
    traffic.learn() - which reads only client-to-server requests - never
    mistakes a probe for something the user did.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import anyio
from mcp import types
from mcp.shared.message import SessionMessage
from mcp.types import (JSONRPCError, JSONRPCMessage, JSONRPCNotification,
                       JSONRPCRequest, JSONRPCResponse)

log = logging.getLogger("driftsentry.injector")

#: Longest a probe waits for its answer before verification gives up on it.
PROBE_TIMEOUT_S = 60.0


class InjectedError(RuntimeError):
    """The server answered an injected request with a JSON-RPC error."""


class ProbeInjector:
    """Owns the id space between client and server, and injects requests."""

    def __init__(self, server_write: Any) -> None:
        self._server_write = server_write
        self._next = 0
        self._to_client_id: dict[int, Any] = {}       # proxy id -> client id
        self._from_client_id: dict[Any, int] = {}     # client id -> proxy id
        self._pending: dict[int, list[Any]] = {}      # proxy id -> [Event, root]
        self.opened = time.monotonic()
        self.last_call: float | None = None           # any tools/call, either side
        self.client_calls = 0
        self.initialized = False

    # -- the two pumps call these ------------------------------------------
    def client_to_server(self, item: SessionMessage) -> SessionMessage:
        """Renumber a client request; translate a client cancellation."""
        root = item.message.root
        if isinstance(root, JSONRPCRequest):
            proxy_id = self._take_id()
            self._to_client_id[proxy_id] = root.id
            self._from_client_id[root.id] = proxy_id
            if root.method == "tools/call":
                self.client_calls += 1
                self.last_call = time.monotonic()
            return SessionMessage(JSONRPCMessage(root.model_copy(update={"id": proxy_id})),
                                  metadata=item.metadata)
        if isinstance(root, JSONRPCNotification) and root.method == "notifications/cancelled":
            params = dict(root.params or {})
            if params.get("requestId") in self._from_client_id:
                params["requestId"] = self._from_client_id[params["requestId"]]
                return SessionMessage(JSONRPCMessage(root.model_copy(update={"params": params})),
                                      metadata=item.metadata)
        return item

    def server_to_client(self, item: SessionMessage) -> SessionMessage | None:
        """Divert answers to probes; renumber answers to the client back."""
        root = item.message.root
        if isinstance(root, (JSONRPCResponse, JSONRPCError)):
            slot = self._pending.get(root.id)
            if slot is not None:
                slot[1] = root
                slot[0].set()
                return None
            client_id = self._to_client_id.pop(root.id, None)
            if client_id is not None:
                self._from_client_id.pop(client_id, None)
                if isinstance(root, JSONRPCResponse) and not self.initialized:
                    self.initialized = True
                return SessionMessage(JSONRPCMessage(root.model_copy(update={"id": client_id})),
                                      metadata=item.metadata)
        return item

    def is_probe_response(self, item: SessionMessage) -> bool:
        root = item.message.root
        return isinstance(root, (JSONRPCResponse, JSONRPCError)) and root.id in self._pending

    # -- verification calls these -------------------------------------------
    async def request(self, method: str, params: dict[str, Any],
                      timeout: float = PROBE_TIMEOUT_S) -> dict[str, Any]:
        proxy_id = self._take_id()
        slot = [anyio.Event(), None]
        self._pending[proxy_id] = slot
        try:
            await self._server_write.send(SessionMessage(JSONRPCMessage(JSONRPCRequest(
                jsonrpc="2.0", id=proxy_id, method=method, params=params))))
            if method == "tools/call":
                self.last_call = time.monotonic()
            with anyio.fail_after(timeout):
                await slot[0].wait()
        finally:
            self._pending.pop(proxy_id, None)
        root = slot[1]
        if isinstance(root, JSONRPCError):
            raise InjectedError(f"{root.error.code}: {root.error.message}")
        return dict(root.result or {})

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        result = await self.request("tools/call", {"name": name, "arguments": arguments or {}})
        self.last_call = time.monotonic()        # gaps are measured from the end
        return types.CallToolResult.model_validate(result)

    async def list_tools(self) -> Any:
        return types.ListToolsResult.model_validate(await self.request("tools/list", {}))

    def _take_id(self) -> int:
        proxy_id = self._next
        self._next += 1
        return proxy_id


class LiveSessionChannel:
    """The session surface verification uses, paced against live traffic.

    Unlike the evaluation's InSessionChannel there is no queue of genuine
    calls to interleave: the user makes them, in real time. Before each probe
    this waits until a gap drawn from genuine traffic has passed since the
    last call (or, before any call, a startup delay drawn the same way), so a
    probe lands where a user's call could have.
    """

    def __init__(self, injector: ProbeInjector, *, key: bytes, server: str,
                 cycle: int, profile: Any = None, max_wait_s: float = 30.0) -> None:
        self.injector = injector
        self.key, self.server, self.cycle, self.profile = key, server, cycle, profile
        self.max_wait_s = max_wait_s
        self._index = 0

    async def list_tools(self) -> Any:
        return await self.injector.list_tools()

    async def prepare_probe(self, tool: str) -> None:
        """Nothing to send first: the user makes their own calls, live."""

    async def pace_probe(self, tool: str) -> None:
        from driftsentry.camouflage import gap_from_profile, startup_from_profile

        if self.injector.last_call is None:
            wanted = startup_from_profile(self.key, self.server, self.cycle, self.profile)
            since = self.injector.opened
        else:
            wanted = gap_from_profile(self.key, self.server, self.cycle, self._index,
                                      self.profile)
            since = self.injector.last_call
        remaining = float(wanted or 0.0) - (time.monotonic() - since)
        if remaining > 0:
            await anyio.sleep(min(remaining, self.max_wait_s))

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        self._index += 1
        return await self.injector.call_tool(name, arguments)
