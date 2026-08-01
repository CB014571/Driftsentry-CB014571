"""Phase 6 - the local control API the dashboard talks to.

Bound to 127.0.0.1 only. There is no authentication and none is appropriate:
the moment this listened on a network interface it would be an unauthenticated
remote control for quarantining a user's tooling, so it is kept to the loopback
interface where the only reachable caller is the desktop app on the same machine.

The API is deliberately thin - it reads daemon state and forwards commands. It
computes nothing about drift, because a UI layer that could influence a score
would undermine the evaluation it is meant to display.

Long operations run as background JOBS
    Baselining a server takes minutes. Holding an HTTP request open for that long
    would time out and leave the user staring at a spinner with no idea whether
    anything was happening, so connect and calibrate start a job, return an id
    immediately, and the dashboard follows progress through /api/state.
"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from driftsentry.daemon import Daemon

UI_FILE = Path(__file__).resolve().parent / "ui" / "index.html"


def _split(command: str) -> list[str]:
    """Split a command string, keeping Windows backslashes intact.

    POSIX-mode shlex treats a backslash as an escape, which silently mangles
    C:\\Users\\... into C:Users... - the command then fails, or worse succeeds
    against the wrong path.
    """
    import os

    tokens = shlex.split(command, posix=(os.name != "nt"))
    out = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        out.append(token)
    return out


class ConnectRequest(BaseModel):
    name: str
    command: str                 # full launch command, e.g. python -m attacker serve
    cwd: str | None = None
    probes: int = 3
    samples: int = 8


class ConfigRequest(BaseModel):
    path: str
    in_place: bool = False


def create_app(daemon: Daemon) -> FastAPI:
    app = FastAPI(title="DriftSentry", docs_url=None, redoc_url=None)

    # -- read ---------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return UI_FILE.read_text(encoding="utf-8")

    @app.get("/api/state")
    def state() -> JSONResponse:
        return JSONResponse(daemon.snapshot())

    # -- connect a server ---------------------------------------------------
    @app.post("/api/connect")
    def connect(req: ConnectRequest) -> JSONResponse:
        tokens = _split(req.command)
        if not tokens:
            return JSONResponse({"ok": False, "error": "empty command"}, status_code=400)
        name = req.name.strip()
        if not name:
            return JSONResponse({"ok": False, "error": "a name is required"}, status_code=400)
        if name in daemon.servers:
            return JSONResponse(
                {"ok": False, "error": f"{name!r} is already connected"}, status_code=400)

        job = daemon.start_job("connect", f"connecting {name}")
        daemon.submit(daemon.connect_server(
            job, name, tokens[0], tokens[1:], req.cwd, req.probes, req.samples))
        return JSONResponse({"ok": True, "job": job})

    @app.post("/api/disconnect/{server}")
    def disconnect(server: str) -> JSONResponse:
        daemon.store.delete(server)
        daemon.servers.pop(server, None)
        return JSONResponse({"ok": True})

    # -- inspect / wire up an MCP client ------------------------------------
    @app.post("/api/client/inspect")
    def inspect_client(req: ConfigRequest) -> JSONResponse:
        """Read a client config and report what could be protected."""
        from driftsentry.clientconfig import parse_config, rewrite_config

        path = Path(req.path).expanduser()
        if not path.is_file():
            return JSONResponse({"ok": False, "error": f"not found: {path}"}, status_code=400)
        try:
            parsed = parse_config(path)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

        _new, report = rewrite_config(parsed)
        servers = []
        for name, entry in parsed.servers.items():
            servers.append({
                "name": name,
                "transport": entry.transport,
                "command": entry.command or entry.url or "",
                "args": entry.args,
                "wrapped": entry.wrapped,
                "action": report.actions.get(name, "unknown"),
                "note": report.notes.get(name, ""),
            })
        return JSONResponse({"ok": True, "path": str(path),
                             "key": parsed.servers_key, "servers": servers})

    @app.post("/api/client/protect")
    def protect_client(req: ConfigRequest) -> JSONResponse:
        """Rewrite a client config so its servers run through the proxy."""
        from driftsentry.clientconfig import (
            diff_text, make_backup, parse_config, rewrite_config, write_config,
        )

        path = Path(req.path).expanduser()
        if not path.is_file():
            return JSONResponse({"ok": False, "error": f"not found: {path}"}, status_code=400)
        parsed = parse_config(path)
        new_data, report = rewrite_config(parsed)
        if not report.wrapped_servers:
            return JSONResponse({"ok": False,
                                 "error": "nothing to protect (already wrapped, or no stdio servers)"},
                                status_code=400)

        diff = diff_text(parsed.data, new_data, label=path.name)
        if req.in_place:
            backup = str(make_backup(path))
            write_config(path, new_data)
            target = str(path)
        else:
            backup = None
            target = str(path.with_name(f"{path.stem}.driftsentry{path.suffix}"))
            write_config(Path(target), new_data)

        return JSONResponse({"ok": True, "written": target, "backup": backup,
                             "protected": report.wrapped_servers, "diff": diff})

    @app.get("/api/client/discover")
    def discover_clients() -> JSONResponse:
        """Look for MCP client configs in their usual locations."""
        import os

        candidates = [
            ("Claude Desktop", Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"),
            ("Claude Desktop (macOS)", Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
            ("Cursor", Path.home() / ".cursor" / "mcp.json"),
            ("VS Code", Path(os.environ.get("APPDATA", "")) / "Code" / "User" / "mcp.json"),
            ("Claude Code", Path.home() / ".claude.json"),
        ]
        found = []
        for label, path in candidates:
            if path.is_file():
                count = None
                try:
                    from driftsentry.clientconfig import parse_config

                    count = len(parse_config(path).servers)
                except Exception:
                    count = None
                found.append({"client": label, "path": str(path), "servers": count})
        return JSONResponse({"ok": True, "found": found})

    # -- calibration --------------------------------------------------------
    @app.post("/api/calibrate")
    def calibrate(repeats: int = 3) -> JSONResponse:
        if not daemon.servers:
            return JSONResponse({"ok": False, "error": "connect a server first"},
                                status_code=400)
        job = daemon.start_job("calibrate", "calibrating the alert threshold")
        daemon.submit(daemon.calibrate(job, repeats))
        return JSONResponse({"ok": True, "job": job})

    # -- per-server actions -------------------------------------------------
    @app.post("/api/scan/{server}")
    def scan(server: str) -> JSONResponse:
        daemon.scan_now(server)
        return JSONResponse({"ok": True, "queued": server})

    @app.post("/api/quarantine/{server}")
    def quarantine(server: str) -> JSONResponse:
        daemon.set_policy(server, "quarantined")
        return JSONResponse({"ok": True})

    @app.post("/api/trust/{server}")
    def trust(server: str) -> JSONResponse:
        daemon.set_policy(server, "trusted", enforce=False)
        return JSONResponse({"ok": True})

    @app.post("/api/enforce/{server}")
    def enforce(server: str, on: bool = True) -> JSONResponse:
        current = daemon.servers[server].policy_status if server in daemon.servers else "trusted"
        daemon.set_policy(server, current, enforce=on)
        return JSONResponse({"ok": True})

    @app.post("/api/pause")
    def pause() -> JSONResponse:
        return JSONResponse({"paused": daemon.toggle_pause()})

    return app
