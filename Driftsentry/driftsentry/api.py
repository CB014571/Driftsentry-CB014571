"""Phase 6 - the local control API the dashboard talks to.

Bound to 127.0.0.1 only. There is no authentication and none is appropriate:
the moment this listened on a network interface it would be an unauthenticated
remote control for quarantining a user's tooling, so it is kept to the loopback
interface where the only reachable caller is the desktop app on the same machine.

The API is deliberately thin - it reads daemon state and forwards commands. It
computes nothing about drift, because a UI layer that could influence a score
would undermine the evaluation it is meant to display.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from driftsentry.daemon import Daemon

UI_FILE = Path(__file__).resolve().parent / "ui" / "index.html"


def create_app(daemon: Daemon) -> FastAPI:
    app = FastAPI(title="DriftSentry", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return UI_FILE.read_text(encoding="utf-8")

    @app.get("/api/state")
    def state() -> JSONResponse:
        return JSONResponse(daemon.snapshot())

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
        daemon.set_policy(server, daemon.servers[server].policy_status, enforce=on)
        return JSONResponse({"ok": True})

    @app.post("/api/pause")
    def pause() -> JSONResponse:
        return JSONResponse({"paused": daemon.toggle_pause()})

    return app
