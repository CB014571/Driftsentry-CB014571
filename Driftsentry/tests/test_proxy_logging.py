"""What the proxy writes down about a session.

RQ3 asks whether a malicious server can tell probe traffic from genuine agent
traffic. Answering it needs the audit log to carry three things it did not
carry before: which session a record belongs to, who the client claimed to be
at the handshake, and the passive monitor's verdict as data rather than as
stderr prose.

The fourth test here is a safety rule, not a feature: environment variable
VALUES must never reach the log. They routinely hold API keys, and this log is
copied into datasets.
"""
from __future__ import annotations

import json

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from driftsentry.proxy import ProxyLogger


def _request(rid, method, params):
    return SessionMessage(JSONRPCMessage(
        JSONRPCRequest(jsonrpc="2.0", id=rid, method=method, params=params)))


def _response(rid, result):
    return SessionMessage(JSONRPCMessage(
        JSONRPCResponse(jsonrpc="2.0", id=rid, result=result)))


def _read(logger) -> list[dict]:
    return [json.loads(line) for line in
            logger.path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _drive(logger):
    """One ordinary session: handshake, list, call, reply."""
    logger.record(_request(1, "initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "claude-ai", "version": "0.14.2"},
        "capabilities": {},
    }), "c2s")
    logger.record(_response(1, {"protocolVersion": "2024-11-05"}), "s2c")
    logger.record(_request(2, "tools/call", {
        "name": "lookup_customer", "arguments": {"customer_id": "CUS-48217"},
    }), "c2s")
    logger.record(_response(2, {
        "content": [{"type": "text", "text": "Dana Whitfield, active"}],
    }), "s2c")


def test_every_record_carries_one_stable_session_id():
    logger = ProxyLogger("acme")
    try:
        _drive(logger)
    finally:
        logger.close()

    records = _read(logger)
    assert len(records) == 4
    ids = {r.get("session") for r in records}
    assert ids == {logger.session_id}, "session id must be on every record and constant"
    assert len(logger.session_id) == 12


def test_two_proxies_on_one_server_get_different_sessions():
    """The log is append-only and shared, so the id is what separates runs."""
    first, second = ProxyLogger("acme"), ProxyLogger("acme")
    try:
        _drive(first)
        _drive(second)
    finally:
        first.close()
        second.close()

    assert first.session_id != second.session_id
    assert first.path == second.path                      # same file
    sessions = {r["session"] for r in _read(first)}
    assert sessions == {first.session_id, second.session_id}


def test_client_identity_is_captured_from_the_handshake():
    logger = ProxyLogger("acme")
    try:
        _drive(logger)
    finally:
        logger.close()

    init = [r for r in _read(logger) if r.get("method") == "initialize"
            and r["dir"] == "c2s"]
    assert len(init) == 1
    assert init[0]["client"] == {"name": "claude-ai", "version": "0.14.2"}


def test_a_handshake_without_client_info_does_not_break_logging():
    logger = ProxyLogger("acme")
    try:
        logger.record(_request(1, "initialize", {"protocolVersion": "2024-11-05"}), "c2s")
    finally:
        logger.close()

    record = _read(logger)[0]
    assert record["method"] == "initialize"
    assert record.get("client") in (None, {"name": None, "version": None})


def test_no_environment_values_are_ever_logged(monkeypatch):
    """The log becomes a dataset. An API key must not be able to reach it."""
    secret = "sk-live-must-never-appear-in-any-log-line"
    monkeypatch.setenv("DRIFTSENTRY_TEST_SECRET", secret)

    logger = ProxyLogger("acme")
    try:
        _drive(logger)
    finally:
        logger.close()

    raw = logger.path.read_text(encoding="utf-8")
    assert secret not in raw
    for record in _read(logger):
        assert "env" not in record
        assert "environ" not in json.dumps(record).lower()


def test_capabilities_are_not_copied_into_the_client_record():
    """Only name and version. The handshake carries more; we do not want it."""
    logger = ProxyLogger("acme")
    try:
        logger.record(_request(1, "initialize", {
            "clientInfo": {"name": "claude-ai", "version": "0.14.2",
                           "extra": "should-not-be-copied"},
            "capabilities": {"roots": {"listChanged": True}},
        }), "c2s")
    finally:
        logger.close()

    client = _read(logger)[0]["client"]
    assert set(client) == {"name", "version"}
    assert "should-not-be-copied" not in json.dumps(client)


# --------------------------------------------------------------------------- #
# The passive summary record
#
# Before this, the passive monitor's verdict existed only as stderr lines at
# shutdown. RQ2 scores passive monitoring against the same episodes as the
# other two detectors, so the verdict has to be readable by a program.
# --------------------------------------------------------------------------- #
def test_passive_summary_is_written_as_a_record_not_just_stderr():
    from tests.test_passive import _Baseline, _result
    from driftsentry.passive import PassiveMonitor

    monitor = PassiveMonitor("acme", _Baseline())
    logger = ProxyLogger("acme", passive=monitor)
    try:
        logger.record(_request(1, "tools/call", {
            "name": "lookup_customer", "arguments": {"customer_id": "CUS-1"},
        }), "c2s")
        logger.record(_response(1, _result("baseline answer")), "s2c")

        # What run_stdio_proxy's finally block does, before closing the handle.
        summary = monitor.summary()
        logger._emit({"dir": "internal", "kind": "passive_summary",
                      "summary": summary,
                      "findings": [f.to_dict() for f in monitor.findings()]})
    finally:
        logger.close()

    records = _read(logger)
    final = records[-1]
    assert final["kind"] == "passive_summary"
    assert final["session"] == logger.session_id
    assert final["summary"]["calls_seen"] == 1
    assert isinstance(final["findings"], list)
    # It must be the LAST record, so a reader can take it as the session verdict.
    assert [r["kind"] for r in records].count("passive_summary") == 1


def test_passive_verdict_survives_a_process_that_is_killed():
    """The sidecar, not the shutdown record, is what readers must rely on.

    Measured on Windows: when a client disconnects, the MCP SDK terminates the
    proxy process, so `run_stdio_proxy`'s finally block never runs. A clean
    stdin EOF does not end the process either. Either way a shutdown-only
    record is lost, so the verdict is refreshed on every evaluated response.
    """
    from tests.test_passive import _Baseline, _result
    from driftsentry.passive import PassiveMonitor

    monitor = PassiveMonitor("acme", _Baseline())
    logger = ProxyLogger("acme", passive=monitor)

    logger.record(_request(1, "tools/call", {
        "name": "lookup_customer", "arguments": {"customer_id": "CUS-1"},
    }), "c2s")
    logger.record(_response(1, _result("baseline answer")), "s2c")

    # No close(), no shutdown hook - the process "died" here.
    assert logger.passive_path.is_file(), "sidecar must exist without a clean exit"
    snap = json.loads(logger.passive_path.read_text(encoding="utf-8"))
    assert snap["session"] == logger.session_id
    assert snap["summary"]["calls_seen"] == 1
    assert isinstance(snap["findings"], list)


def test_sidecar_tracks_the_latest_verdict():
    from tests.test_passive import _Baseline, _result
    from driftsentry.passive import PassiveMonitor

    logger = ProxyLogger("acme", passive=PassiveMonitor("acme", _Baseline()))
    seen = []
    for i in range(3):
        logger.record(_request(i, "tools/call", {
            "name": "lookup_customer", "arguments": {"customer_id": f"CUS-{i}"},
        }), "c2s")
        logger.record(_response(i, _result(f"answer {i}")), "s2c")
        seen.append(json.loads(
            logger.passive_path.read_text(encoding="utf-8"))["summary"]["calls_seen"])
    logger.close()
    assert seen == [1, 2, 3], "each evaluated response must refresh the sidecar"


def test_no_sidecar_when_passive_is_off():
    logger = ProxyLogger("acme")
    try:
        _drive(logger)
    finally:
        logger.close()
    assert logger.passive_snapshot() is None
    assert not logger.passive_path.exists()
