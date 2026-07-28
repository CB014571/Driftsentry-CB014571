"""Phase 1 — the interception proxy core.

A *transparent* stdio proxy. The MCP client is configured to launch DriftSentry
instead of the real server; DriftSentry in turn launches the real server and
shuttles every JSON-RPC message between them, unchanged, in both directions,
logging each exchange. Correctness first: at this phase the client must not be
able to tell the proxy is there (identical behaviour, only added latency). The
probe engine and drift scorer that make use of these logs arrive in later phases.

How it is wired
    client  <--stdio-->  [ driftsentry run ]  <--stdio-->  real MCP server
                          (this module)

    * Toward the client we are an MCP *server*: ``stdio_server()`` gives us a
      read stream of the client's messages and a write stream back to it.
    * Toward the real server we are an MCP *client*: ``stdio_client()`` launches
      the server as a subprocess and gives us its read/write streams.
    * Two independent "pump" tasks forward messages. Because a response is never
      blocked on its request, multiple in-flight calls proxy correctly.

Transparency guarantees
    * We forward the whole ``SessionMessage`` object without rebuilding it, so
      JSON-RPC ids and field order survive exactly.
    * Ordering within each direction is preserved because each direction is a
      single sequential loop.
    * The real server's stderr is routed to our log file, never to our stdout —
      our stdout carries JSON-RPC frames to the client and must stay clean.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

import anyio
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

from driftsentry.hashing import tools_definition_hash
from driftsentry.paths import logs_dir

log = logging.getLogger("driftsentry.proxy")

# Truncate long strings in logged args/results so the audit log stays readable
# and never balloons on a tool that returns megabytes.
_MAX_FIELD_CHARS = 500


# --------------------------------------------------------------------------- #
# Message inspection (for logging only — never mutates the forwarded message)
# --------------------------------------------------------------------------- #
def _classify(root: Any) -> str:
    """Classify a JSON-RPC message from the fields present on it."""
    if getattr(root, "method", None) is not None:
        return "request" if getattr(root, "id", None) is not None else "notification"
    if getattr(root, "error", None) is not None:
        return "error"
    return "response"


def _truncate(value: Any) -> Any:
    """Shorten oversized strings inside logged structures, recursively."""
    if isinstance(value, str):
        return value if len(value) <= _MAX_FIELD_CHARS else value[:_MAX_FIELD_CHARS] + "...(truncated)"
    if isinstance(value, dict):
        return {k: _truncate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v) for v in value[:20]]
    return value


class ProxyLogger:
    """Writes a structured audit record for every proxied message.

    Two sinks: a JSONL file (machine-readable audit trail and, later, a passive
    drift signal) and a concise human line on stderr. It also correlates each
    response with the request id that produced it, so a response — which in
    JSON-RPC carries no method — can be logged against the call it answered, and
    ``tools/list`` responses get their definition hash recorded.
    """

    def __init__(self, server_name: str) -> None:
        self.server_name = server_name
        self.path: Path = logs_dir() / f"{server_name}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")
        # request id -> (method, tool_name); lets us name responses.
        self._pending: dict[Any, tuple[str, str | None]] = {}

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # pragma: no cover - best effort on shutdown
            pass

    def _emit(self, record: dict[str, Any]) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), "server": self.server_name, **record}
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        # Human-readable summary on stderr.
        bits = [record["dir"], record["kind"]]
        if record.get("method"):
            bits.append(record["method"])
        if record.get("tool"):
            bits.append(f"tool={record['tool']}")
        if record.get("outcome"):
            bits.append(record["outcome"])
        log.info("%s", " ".join(str(b) for b in bits))

    def record(self, message: SessionMessage, direction: str, blocked: str | None = None) -> None:
        """Log one message. ``direction`` is 'c2s' (client→server) or 's2c'."""
        root = message.message.root
        kind = _classify(root)
        rec: dict[str, Any] = {"dir": direction, "kind": kind}
        if blocked:
            rec["blocked"] = blocked

        if kind in {"request", "notification"}:
            method = getattr(root, "method", None)
            params = getattr(root, "params", None) or {}
            rec["method"] = method
            if kind == "request":
                rec["id"] = getattr(root, "id", None)
            if method == "tools/call":
                tool = params.get("name")
                rec["tool"] = tool
                rec["args"] = _truncate(params.get("arguments"))
                if kind == "request":
                    self._pending[rec["id"]] = (method, tool)
            elif kind == "request":
                self._pending[rec["id"]] = (method, None)

        else:  # response or error — correlate back to the originating request
            rid = getattr(root, "id", None)
            rec["id"] = rid
            method, tool = self._pending.pop(rid, (None, None))
            if method:
                rec["method"] = method
            if tool:
                rec["tool"] = tool
            if kind == "error":
                err = getattr(root, "error", None)
                rec["outcome"] = "error"
                rec["error"] = _truncate(getattr(err, "message", str(err)))
            else:
                rec["outcome"] = "ok"
                result = getattr(root, "result", {}) or {}
                # tools/list carries the tool definitions: record their hash.
                # This is the classic-rug-pull surface; the *check* lands in Phase 4.
                if method == "tools/list" and isinstance(result, dict) and "tools" in result:
                    tools = result.get("tools") or []
                    rec["tools"] = [t.get("name") for t in tools]
                    rec["definition_hash"] = tools_definition_hash(tools)
                else:
                    rec["result"] = _truncate(result)

        self._emit(rec)


# --------------------------------------------------------------------------- #
# The proxy
# --------------------------------------------------------------------------- #
def _blocked_response(request, server_name: str, reason: str) -> SessionMessage:
    """Build the JSON-RPC error the client receives when a call is enforced against.

    The client sees an ordinary error for that one call and carries on; the
    session is not torn down. Being explicit in the message matters - a user
    staring at a failed tool call should learn that DriftSentry refused it and
    why, not be left guessing at a mystery failure.
    """
    from mcp.types import ErrorData, JSONRPCError, JSONRPCMessage

    error = JSONRPCError(
        jsonrpc="2.0",
        id=request.id,
        error=ErrorData(
            code=-32000,
            message=(
                f"DriftSentry blocked this call: server '{server_name}' is quarantined. {reason} "
                f"Run `driftsentry report {server_name}` for the alert, or "
                f"`driftsentry trust --server {server_name}` to re-enable it."
            ),
        ),
    )
    return SessionMessage(JSONRPCMessage(error))


async def _pump(
    source,
    dest,
    direction: str,
    plog: ProxyLogger,
    cancel_scope: anyio.CancelScope,
    *,
    reply_to=None,
    enforcer=None,
) -> None:
    """Forward every message from ``source`` to ``dest``, logging as it goes.

    When ``source`` closes (the client sent EOF, or the server exited) we cancel
    the whole proxy so the other side is torn down too — a half-open proxy would
    hang the client.

    ``enforcer`` is only supplied on the client→server direction. If it refuses a
    tool call, the request is never forwarded and an error is written straight
    back to the client on ``reply_to``.
    """
    try:
        async for item in source:
            # The read streams yield exceptions in-band on malformed frames.
            if isinstance(item, Exception):
                log.warning("%s: dropping malformed message: %r", direction, item)
                continue

            if enforcer is not None and reply_to is not None:
                refusal = enforcer(item)
                if refusal is not None:
                    plog.record(item, direction, blocked=refusal)
                    await reply_to.send(_blocked_response(item.message.root, plog.server_name, refusal))
                    continue

            plog.record(item, direction)
            await dest.send(item)
    finally:
        cancel_scope.cancel()


def _make_enforcer(server_name: str):
    """Return a callable that decides whether to refuse a client message.

    Policy is consulted per call rather than cached, so quarantining a server
    from another terminal takes effect on the very next tool call instead of
    requiring the client to be restarted.

    Enforcement is deliberately narrow: only ``tools/call`` is ever refused.
    Blocking ``initialize`` or ``tools/list`` would break the client's session
    outright, and DriftSentry's job is to stop a dangerous *action*, not to make
    the client unusable.
    """
    from driftsentry.policy import PolicyStore

    store = PolicyStore()

    def enforce(message: SessionMessage) -> str | None:
        root = message.message.root
        if getattr(root, "method", None) != "tools/call" or getattr(root, "id", None) is None:
            return None
        tool = (getattr(root, "params", None) or {}).get("name")
        policy = store.get(server_name)
        if policy.blocks(tool):
            reason = policy.reason or "quarantined after a drift alert."
            log.warning("BLOCKED tools/call %s on quarantined server %r", tool, server_name)
            return reason
        return None

    return enforce


async def run_stdio_proxy(
    server_name: str,
    command: str,
    args: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    enforce: bool = False,
) -> None:
    """Run the transparent proxy for one stdio MCP server until either end closes.

    Parameters mirror what a rewritten client config supplies (Phase 2): a name
    for the server (used for the log file) and the real server's launch command.

    With ``enforce=True`` the proxy additionally refuses tool calls to a server
    the policy store has quarantined. This is off by default and opt-in per
    server: detection is the contribution being evaluated, and a proxy that
    silently blocked attacks would confound every detection measurement.
    """
    plog = ProxyLogger(server_name)
    log.info("proxying server %r via: %s %s", server_name, command, " ".join(args))
    log.info("exchange log: %s", plog.path)
    if enforce:
        log.warning("enforcement ENABLED for %r: calls to a quarantined server will be refused", server_name)

    server_params = StdioServerParameters(command=command, args=args, cwd=cwd, env=env)
    try:
        # Toward the client (our stdin/stdout).
        async with stdio_server() as (client_read, client_write):
            # Toward the real server. Its stderr goes to our stderr (a log sink),
            # never to our stdout, which carries JSON-RPC to the client.
            async with stdio_client(server_params, errlog=sys.stderr) as (server_read, server_write):
                enforcer = _make_enforcer(server_name) if enforce else None
                async with anyio.create_task_group() as tg:
                    tg.start_soon(
                        partial(
                            _pump, client_read, server_write, "c2s", plog, tg.cancel_scope,
                            reply_to=client_write, enforcer=enforcer,
                        )
                    )
                    tg.start_soon(_pump, server_read, client_write, "s2c", plog, tg.cancel_scope)
    finally:
        plog.close()
        log.info("proxy for %r stopped", server_name)
