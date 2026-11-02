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
import uuid
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

    def __init__(self, server_name: str, passive: Any | None = None,
                 server_cwd: str | None = None) -> None:
        self.server_name = server_name
        # Recorded alongside the client identity: a probe that announces the
        # right name from the wrong directory is still distinguishable.
        self.server_cwd = server_cwd
        # One id per proxy process, stamped on every record. The log is
        # append-only and shared by every run against this server, so without
        # it two interleaved sessions are indistinguishable after the fact -
        # and RQ3 labels traffic by session, not by call.
        self.session_id = uuid.uuid4().hex[:12]
        self.path: Path = logs_dir() / f"{server_name}.jsonl"
        # Passive verdict, rewritten as findings arrive rather than written
        # once at shutdown. Measured reason: a client that disconnects causes
        # the MCP SDK to TERMINATE this process, so the shutdown handler does
        # not run and the verdict is simply lost. An experiment that reads the
        # passive result cannot depend on a clean exit it does not control.
        self.passive_path: Path = logs_dir() / f"{server_name}.passive.json"
        self._fh = self.path.open("a", encoding="utf-8")
        # request id -> (method, tool_name); lets us name responses.
        self._pending: dict[Any, tuple[str, str | None]] = {}
        # Optional passive monitor. It only ever reads: it is handed a copy of
        # what was already parsed for the audit log, and every call into it is
        # wrapped so that a defect there cannot reach the forwarding path.
        self._passive = passive

    def passive_snapshot(self) -> dict[str, Any] | None:
        """Current passive verdict, or None when nothing is monitoring."""
        if self._passive is None:
            return None
        return {
            "server": self.server_name,
            "session": self.session_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "summary": self._passive.summary(),
            "findings": [f.to_dict() for f in self._passive.findings()],
        }

    def _write_passive_snapshot(self) -> None:
        """Overwrite the sidecar. Small, bounded, and safe to lose a race on."""
        snap = self.passive_snapshot()
        if snap is None:
            return
        try:
            tmp = self.passive_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(snap, default=str, indent=2), encoding="utf-8")
            tmp.replace(self.passive_path)
        except Exception as exc:  # pragma: no cover - never break forwarding
            log.debug("could not write passive snapshot: %s", exc)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # pragma: no cover - best effort on shutdown
            pass

    def _emit(self, record: dict[str, Any]) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(),
                  "server": self.server_name, "session": self.session_id, **record}
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
                    if self._passive is not None:
                        self._passive.on_request(rec["id"], tool, params.get("arguments") or {})
            else:
                if method == "initialize" and isinstance(params, dict):
                    # Who the server thinks it is talking to. Name and version
                    # only: the rest of the handshake carries capabilities we
                    # have no reason to record, and nothing here may ever hold
                    # an environment value.
                    info = params.get("clientInfo") or {}
                    if isinstance(info, dict):
                        rec["client"] = {"name": info.get("name"),
                                         "version": info.get("version")}
                        # The proxy is the only component that ever sees a
                        # genuine handshake, so it is the only place this can
                        # be learned. Probes later borrow it, which closes the
                        # channel RQ3 measured at AUC 1.000.
                        from driftsentry.hostprofile import record
                        record(self.server_name, rec["client"], self.server_cwd)
                if kind == "request":
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
                    # Passive evaluation of a REAL call. The untruncated result is
                    # passed, because a content rule that only ever saw the first
                    # 500 characters would miss a payload appended to the end -
                    # which is exactly where the injection family puts it.
                    if self._passive is not None and isinstance(result, dict):
                        self._passive.on_response(rid, result)
                        self._write_passive_snapshot()

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
    passive: bool = False,
) -> None:
    """Run the transparent proxy for one stdio MCP server until either end closes.

    Parameters mirror what a rewritten client config supplies (Phase 2): a name
    for the server (used for the log file) and the real server's launch command.

    With ``enforce=True`` the proxy additionally refuses tool calls to a server
    the policy store has quarantined. This is off by default and opt-in per
    server: detection is the contribution being evaluated, and a proxy that
    silently blocked attacks would confound every detection measurement.
    """
    monitor = None
    if passive:
        # Watch real traffic for security invariants the active probes cannot
        # reach: a server that behaves for canaries and misbehaves for the user.
        from driftsentry.passive import PassiveMonitor
        from driftsentry.store import BaselineStore

        baseline = BaselineStore().load(server_name)
        if baseline is None:
            log.warning("passive monitoring requested for %r but it has no baseline; "
                        "there is nothing to compare real traffic against", server_name)
        else:
            monitor = PassiveMonitor(server_name, baseline)
            log.info("passive monitoring enabled for %r (watch-only)", server_name)

    plog = ProxyLogger(server_name, passive=monitor, server_cwd=cwd)
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
        # The summary record goes in BEFORE the handle closes. Until now the
        # passive result existed only as stderr lines, which no experiment can
        # read; RQ2 scores passive monitoring against the same episodes as the
        # other detectors, so it has to survive in the log as data.
        if monitor is not None:
            summary = monitor.summary()
            # Best effort only. On a normal client disconnect the SDK
            # terminates this process and nothing below here runs, which is
            # why the sidecar is refreshed per call and is what readers use.
            try:
                plog._write_passive_snapshot()
                plog._emit({
                    "dir": "internal",
                    "kind": "passive_summary",
                    "summary": summary,
                    "findings": [f.to_dict() for f in monitor.findings()],
                })
            except Exception as exc:  # pragma: no cover - never break shutdown
                log.debug("could not write passive summary: %s", exc)
            log.info("passive: %d call(s) observed, %d finding(s), %d high severity",
                     summary["calls_seen"], summary["findings"], summary["high_severity"])
            for finding in monitor.findings():
                log.warning("passive finding: %s/%s - %s", finding.tool, finding.kind, finding.detail)
        plog.close()
        log.info("proxy for %r stopped", server_name)
