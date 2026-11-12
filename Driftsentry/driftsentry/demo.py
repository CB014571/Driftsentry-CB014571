"""`driftsentry demo` - the whole demonstration from one command.

Opens two windows that never talk to each other:

    the attacker's test menu   where you arm an attack (pick 1-12)
    the DriftSentry dashboard  which has to find it by probing

DriftSentry still never IMPORTS the attacker. It starts the attacker's own
command-line program as a separate process - the same way an MCP client
starts a server - so the separation the whole evaluation rests on holds in
the demonstration too.

What it sets up, in order:

  1. The attacker is reset and set to the clean server on the v1n release,
     the release every menu test is defined against.

  2. The server is enrolled with KEYED probes and its own secret key. An
     existing baseline is reused only if it is already keyed and launches
     this attacker; a fixed-probe baseline left from before keyed enrolment
     is backed up and replaced, because a probe-aware server can recognise
     fixed probes and the dashboard would be blind to it.

  3. The menu opens in its own console window.

  4. The dashboard opens.

One attacker home, given explicitly to every process
    The server the dashboard launches, the menu and the setup steps all get
    the same `--home` folder, inside the attacker's own project. They used to
    share the attacker's DEFAULT home instead, under %LOCALAPPDATA%, and that
    was measured to fail: processes started by a packaged Windows app have
    their %LOCALAPPDATA% writes redirected to a private copy
    (AppData/Local/Packages/<app>/LocalCache), so the dashboard's server read
    one scenario file while the menu armed another. Every check came back OK
    with the attack armed - which looks exactly like a missed detection. A
    folder named outright cannot be redirected and cannot be disagreed about.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"
DEFAULT_NAME = "acme"
HOME_DIR = ".demo_home"          # inside the attacker project


def demo_home(project: Path) -> Path:
    """The one attacker home every demo process shares."""
    return project / HOME_DIR


class DemoError(RuntimeError):
    """The demo cannot be set up, with what to do about it."""


def find_attacker(project: str | Path | None = None) -> tuple[Path, Path]:
    """The attacker project and its interpreter."""
    root = Path(project) if project else DEFAULT_ATTACKER
    for python in (root / ".venv" / "Scripts" / "python.exe",
                   root / ".venv" / "bin" / "python"):
        if python.is_file():
            return root.resolve(), python
    raise DemoError(f"no attacker found at {root} (expected a .venv inside it). "
                    f"Pass --attacker with the attack server's folder.")


def attacker_env() -> dict[str, str]:
    """This environment without ATTACKER_HOME - see the module docstring."""
    env = dict(os.environ)
    env.pop("ATTACKER_HOME", None)
    return env


def _attacker(python: Path, project: Path, *args: str) -> str:
    done = subprocess.run([str(python), "-m", "attacker", "--home",
                           str(demo_home(project)), *args], cwd=project,
                          env=attacker_env(), capture_output=True, text=True,
                          timeout=120)
    if done.returncode != 0:
        raise DemoError(f"attacker {' '.join(args)} failed: "
                        f"{(done.stderr or done.stdout).strip()[-400:]}")
    return done.stdout


def arm_clean(python: Path, project: Path) -> None:
    """Reset, then the clean server on v1n - the menu's test 1."""
    _attacker(python, project, "reset")
    _attacker(python, project, "benign", "--release", "v1n")


def serve_args(project: Path) -> list[str]:
    """How the dashboard starts the attacker: with the shared home."""
    return ["-m", "attacker", "--home", str(demo_home(project)), "serve"]


def baseline_status(name: str, python: Path, project: Path) -> tuple[str, Any]:
    """('ok' | 'missing' | 'fixed' | 'other_server', baseline or None)."""
    from driftsentry.store import BaselineStore

    baseline = BaselineStore().load(name)
    if baseline is None:
        return "missing", None
    if baseline.probe_mode != "keyed":
        return "fixed", baseline
    launch = baseline.launch or {}
    if (Path(launch.get("command", "")) != python
            or list(launch.get("args") or []) != serve_args(project)):
        return "other_server", baseline
    return "ok", baseline


def backup_baseline(name: str) -> Path | None:
    """Copy a baseline aside before replacing it. Never deleted.

    Into a folder of its own, NOT next to the baselines. The dashboard treats
    every JSON file in the baselines folder as a server to monitor, so a
    backup saved there showed up as a second server - measured: "monitoring
    2 server(s)" with one attacker running.
    """
    from driftsentry.store import BaselineStore

    store = BaselineStore()
    path = store.path_for(name)
    if not path.exists():
        return None
    folder = store.baseline_dir.parent / "baseline_backups"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = folder / f"{path.stem}.before-demo-{stamp}{path.suffix}"
    shutil.copy2(path, backup)
    return backup


async def enrol(name: str, python: Path, project: Path) -> Any:
    """A keyed baseline of the clean server, saved to the store."""
    from driftsentry import keys as key_store
    from driftsentry.baseline import capture_baseline
    from driftsentry.store import BaselineStore

    baseline = await capture_baseline(
        name, str(python), serve_args(project), cwd=str(project),
        probe_mode="keyed", key=key_store.get_or_create(name))
    BaselineStore().save(baseline)
    return baseline


def calibration_note(backend: str) -> str | None:
    """A warning if the threshold in use is not a calibrated one."""
    from driftsentry.calibration import active_threshold

    _, source = active_threshold(backend)
    if "provisional" in source:
        return (f"the alert threshold is provisional ({source}). Calibrate "
                f"before the demo: driftsentry calibrate --server {DEFAULT_NAME}")
    return None


def open_menu(python: Path, project: Path) -> bool:
    """The attacker's test menu in its own console window."""
    if sys.platform == "win32":
        subprocess.Popen([str(python), "-m", "attacker", "--home",
                          str(demo_home(project)), "menu"], cwd=project,
                         env=attacker_env(),
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True
    return False


def prepare(name: str, attacker: str | Path | None, *, rebaseline: bool,
            say=print) -> tuple[Path, Path]:
    """Everything before the windows open. Returns (project, python)."""
    project, python = find_attacker(attacker)
    say(f"attacker   : {project}")
    say(f"home       : {demo_home(project)}  (shared by the server and the menu)")
    arm_clean(python, project)
    say("scenario   : reset to the clean server (release v1n, test 1)")

    status, existing = baseline_status(name, python, project)
    if status == "ok" and not rebaseline:
        say(f"baseline   : {name!r} is keyed and current - reused")
        backend = existing.embedding_backend
    else:
        reason = {"missing": "none yet",
                  "fixed": "the existing one uses FIXED probes, which a "
                           "probe-aware server can recognise",
                  "other_server": "the existing one launches the attacker "
                                  "differently",
                  "ok": "--rebaseline given"}[status]
        backup = backup_baseline(name)
        if backup:
            say(f"baseline   : old one kept at {backup}")
        say(f"baseline   : enrolling {name!r} with keyed probes ({reason}); "
            f"this takes a minute or two")
        backend = asyncio.run(enrol(name, python, project)).embedding_backend

    note = calibration_note(backend)
    if note:
        say(f"WARNING    : {note}")
    return project, python
