"""Building the environments Gap 3 measures in, and finding the SDK pin.

Gap 3 needs two installations of the same server - the release the baseline
is captured on and the release it is re-probed against - and nothing in the
repository built them. The first run was driven from a script that was never
committed, which is why `mcp-server-time` and `mcp-server-git` have results
and `mcp-server-calculator` and `mcp-server-sqlite` have an error message.

That error message is the reason this module exists. Both failed with

    AttributeError: 'Server' object has no attribute 'list_resources'

which is not a property of those servers. It is what happens when a release
from 2024 or early 2025 is installed and pip resolves its unpinned `mcp`
dependency to whatever is current - an SDK that has since removed the API
the server was written against. The server never starts, so there is nothing
to baseline, so the upgrade cannot be measured. Two of four candidates were
recorded as "unmeasurable" on that basis, and they are not: the environment
was wrong, not the server.

The fix is to install each release beside an SDK it can actually run on. The
version is NOT guessed. `resolve_sdk_pin` asks PyPI which `mcp` versions
exist, walks them newest to oldest, and takes the first one under which the
server starts and answers tools/list. What it finds is recorded in the
result file, because "this release needs mcp<=X" is itself a finding about
the ecosystem the gap is asking about.

The walk is bounded and ordered newest-first on purpose. The newest SDK a
release can run on is the closest thing to how that release would have been
deployed; walking from the oldest would pin something needlessly ancient and
make the two phases differ by more than the upgrade.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

log = logging.getLogger("eval.real_envs")

PYPI = "https://pypi.org/pypi/{package}/json"

# How long a pip install or a server handshake is given. An install that
# takes longer than this is a broken resolver, not a slow network.
INSTALL_TIMEOUT_S = 600
HANDSHAKE_TIMEOUT_S = 60

# The ceiling on the SDK walk. Each step is a full pip install, so an
# unbounded walk over sixty-odd mcp releases is hours per server. If the
# pin is not found within this many steps the server is reported as
# unresolved rather than searched for indefinitely - an honest "not found
# within N attempts" beats an overnight loop.
MAX_SDK_ATTEMPTS = 8


class EnvError(RuntimeError):
    """An environment could not be built, with the reason preserved."""


@dataclass
class Installed:
    """One built environment, and what went into it."""

    server: str
    version: str
    root: Path
    python: Path
    sdk_version: str | None = None       # None -> whatever pip resolved
    sdk_resolved_by: str = "pip"         # "pip" or "walk"
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "version": self.version,
            "root": str(self.root),
            "sdk_version": self.sdk_version,
            "sdk_resolved_by": self.sdk_resolved_by,
            "attempts": self.attempts,
        }


# --------------------------------------------------------------------------- #
# PyPI
# --------------------------------------------------------------------------- #
def release_dates(package: str, *, timeout: float = 30.0) -> dict[str, str]:
    """Version -> first upload time (ISO), for every live release, from PyPI."""
    url = PYPI.format(package=package)
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        payload = json.load(response)
    releases = payload.get("releases") or {}
    return {v: min((f.get("upload_time_iso_8601") or f.get("upload_time") or "")
                   for f in files)
            for v, files in releases.items()
            if files and not all(f.get("yanked") for f in files)}


def released_versions(package: str, *, timeout: float = 30.0,
                      before: str | None = None) -> list[str]:
    """Every version of a package, newest first, from the PyPI JSON API.

    Read rather than remembered. A version list in a source file goes stale
    and a guessed version number is not a measurement.

    ``before`` (an ISO timestamp) keeps only versions published by then.
    """
    dates = release_dates(package, timeout=timeout)
    live = [v for v, when in dates.items() if before is None or when <= before]
    return sorted(live, key=_version_key, reverse=True)


def sdk_candidates(package: str, version: str) -> list[str]:
    """The mcp SDK versions to try for one server release, newest first.

    Anchored at the server release's OWN publication date. The first version
    of the walk simply took the newest SDKs, and measured on 9 Nov it could
    never work: calculator 0.1.2, sqlite 0.6.2 and duckdb 1.0.1 were all
    published against SDKs dozens of releases older than today's, and a walk
    bounded at eight attempts from the newest end never reached one. The SDK
    that existed when a release was published is what it was written against;
    newest-of-those first is the closest to how it was actually deployed.
    SDKs released after it follow, in case the release only ran on a later one.
    """
    published = release_dates(package).get(version)
    every = released_versions("mcp")
    if not published:
        return every
    then = released_versions("mcp", before=published)
    return then + [v for v in every if v not in set(then)]


def _version_key(version: str) -> tuple:
    """Order versions numerically where possible, lexically where not.

    Deliberately simple. The candidates here are either date-based
    (2026.10.28) or plain semver (0.6.2); both sort correctly on their
    numeric parts, and anything stranger falls back to string order rather
    than raising in the middle of a run.
    """
    parts: list[tuple[int, int | str]] = []
    for chunk in version.replace("-", ".").split("."):
        if chunk.isdigit():
            parts.append((0, int(chunk)))
        else:
            parts.append((1, chunk))
    return tuple(parts)


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #
def _run(cmd: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True,
                          timeout=timeout, check=False)


def create_venv(root: Path, *, clean: bool = False) -> Path:
    """A throwaway virtual environment, and the interpreter inside it.

    Built with REAL_ENV_PYTHON when set, else the interpreter running this.
    Measured: three releases could not start on CPython 3.14 because the
    pydantic-core they pin has no 3.14 wheel and the SDK they need imports a
    private pydantic API that 3.14-era pydantic removed. The same release
    on an interpreter of its own era is the release as it was deployed.
    """
    import os

    root = Path(root)
    base = os.environ.get("REAL_ENV_PYTHON") or sys.executable
    if clean and root.exists():
        shutil.rmtree(root, ignore_errors=True)
    if not root.exists():
        done = _run([base, "-m", "venv", str(root)],
                    timeout=INSTALL_TIMEOUT_S)
        if done.returncode != 0:
            raise EnvError(f"venv failed in {root}: {done.stderr.strip()[-400:]}")
    for candidate in (root / "Scripts" / "python.exe", root / "bin" / "python"):
        if candidate.is_file():
            return candidate
    raise EnvError(f"no interpreter in {root}")


def pip_install(python: Path, specs: Sequence[str]) -> None:
    """Install exact pins into one environment, newest spec winning.

    ``--no-input`` because this runs unattended, and a pip that stops to ask
    something would hang the sweep rather than fail it.
    """
    done = _run([str(python), "-m", "pip", "install", "--no-input",
                 "--disable-pip-version-check", *specs],
                timeout=INSTALL_TIMEOUT_S)
    if done.returncode != 0:
        raise EnvError(f"pip install {' '.join(specs)} failed: "
                       f"{done.stderr.strip()[-600:]}")


def installed_version(python: Path, package: str) -> str | None:
    """What pip actually put there, which is not always what was asked for."""
    done = _run([str(python), "-m", "pip", "show", package], timeout=120)
    if done.returncode != 0:
        return None
    for line in done.stdout.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


# --------------------------------------------------------------------------- #
# Does it start?
# --------------------------------------------------------------------------- #
def starts_and_lists(python: Path, entry: Sequence[str],
                     *, cwd: str | None = None,
                     env: dict[str, str] | None = None) -> tuple[bool, str]:
    """Start the server over stdio and ask for its tool list.

    This is the only acceptance test. A package that imports is not a server
    that runs: the failure these environments exist to fix happens when the
    SDK's decorator is looked up at import time of the server's own module,
    which is after pip has reported success.

    Returns (ok, detail). ``detail`` carries the server's own error text when
    it fails, because that text is what identified the SDK mismatch in the
    first place and a boolean would have hidden it.
    """
    probe = (
        "import anyio, json, sys\n"
        "from mcp import ClientSession, StdioServerParameters\n"
        "from mcp.client.stdio import stdio_client\n"
        "async def main():\n"
        "    params = StdioServerParameters(command=sys.argv[1],\n"
        "                                   args=json.loads(sys.argv[2]),\n"
        "                                   cwd=(sys.argv[3] or None),\n"
        "                                   env=json.loads(sys.argv[4]))\n"
        "    async with stdio_client(params) as (r, w):\n"
        "        async with ClientSession(r, w) as session:\n"
        "            await session.initialize()\n"
        "            tools = await session.list_tools()\n"
        "            print(json.dumps([t.name for t in tools.tools]))\n"
        "anyio.run(main)\n"
    )
    try:
        done = _run([str(python), "-c", probe, str(python),
                     json.dumps(list(entry)), cwd or "", json.dumps(env or {})],
                    timeout=HANDSHAKE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return False, f"no handshake within {HANDSHAKE_TIMEOUT_S}s"
    if done.returncode == 0 and done.stdout.strip().startswith("["):
        return True, done.stdout.strip()
    detail = (done.stderr or done.stdout or "").strip()
    return False, detail[-600:] or f"exit {done.returncode}"


def tool_names(detail: str) -> list[str]:
    """The tool list out of a successful starts_and_lists detail."""
    try:
        names = json.loads(detail)
    except (ValueError, TypeError):
        return []
    return [str(n) for n in names] if isinstance(names, list) else []


# --------------------------------------------------------------------------- #
# The SDK walk
# --------------------------------------------------------------------------- #
def resolve_sdk_pin(
    python: Path,
    package: str,
    version: str,
    entry: Sequence[str],
    *,
    cwd: str | None = None,
    candidates: Sequence[str] | None = None,
    max_attempts: int = MAX_SDK_ATTEMPTS,
    env: dict[str, str] | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Find the newest ``mcp`` under which this release starts.

    Tried first with whatever pip resolved on its own, because for a current
    release that is both correct and free. Only when that fails does the walk
    begin, newest SDK first.

    Returns (sdk_version or None, attempts). ``attempts`` records every
    version tried and the server's own error for each, so an unresolved
    server can be reported as "not found in N attempts, here is what each
    said" rather than as a bare failure.
    """
    attempts: list[dict[str, Any]] = []

    resolved = installed_version(python, "mcp")
    ok, detail = starts_and_lists(python, entry, cwd=cwd, env=env)
    attempts.append({"mcp": resolved, "source": "pip", "ok": ok,
                     "detail": detail if not ok else "started"})
    if ok:
        return resolved, attempts

    if candidates is None:
        candidates = sdk_candidates(package, version)
    tried = {resolved} if resolved else set()

    for sdk in candidates:
        if sdk in tried:
            continue
        if len(attempts) > max_attempts:
            log.warning("%s %s: no SDK found in %d attempts",
                        package, version, max_attempts)
            break
        tried.add(sdk)
        try:
            # The server is reinstalled alongside, so a pin that drags in a
            # different dependency set cannot leave a half-built environment.
            pip_install(python, [f"{package}=={version}", f"mcp=={sdk}"])
        except EnvError as exc:
            attempts.append({"mcp": sdk, "source": "walk", "ok": False,
                             "detail": f"install failed: {exc}"[-600:]})
            continue
        ok, detail = starts_and_lists(python, entry, cwd=cwd, env=env)
        attempts.append({"mcp": sdk, "source": "walk", "ok": ok,
                         "detail": detail if not ok else "started"})
        if ok:
            return sdk, attempts

    return None, attempts


def build(
    server: str,
    package: str,
    version: str,
    entry: Sequence[str],
    root: Path,
    *,
    cwd: str | None = None,
    sdk: str | None = None,
    clean: bool = False,
    resolve: bool = True,
    env: dict[str, str] | None = None,
) -> Installed:
    """One release, installed and confirmed to start.

    ``sdk`` pins the SDK outright and skips the walk - for re-running a
    server whose pin a previous run already found. ``resolve=False`` turns
    the walk off entirely, which is how the "measured as unmeasurable"
    result can be reproduced rather than only described.
    """
    python = create_venv(root, clean=clean)
    specs = [f"{package}=={version}"]
    if sdk:
        specs.append(f"mcp=={sdk}")
    pip_install(python, specs)

    out = Installed(server=server, version=version, root=Path(root),
                    python=python,
                    sdk_version=sdk or installed_version(python, "mcp"),
                    sdk_resolved_by="pinned" if sdk else "pip")

    if sdk or not resolve:
        ok, detail = starts_and_lists(python, entry, cwd=cwd, env=env)
        out.attempts = [{"mcp": out.sdk_version,
                         "source": out.sdk_resolved_by, "ok": ok,
                         "detail": detail if not ok else "started"}]
        if not ok:
            raise EnvError(f"{server} {version} did not start under mcp "
                           f"{out.sdk_version}: {detail}")
        return out

    found, attempts = resolve_sdk_pin(python, package, version, entry, cwd=cwd,
                                      env=env)
    out.attempts = attempts
    if found is None:
        raise EnvError(
            f"{server} {version} started under no mcp version tried "
            f"({len(attempts)} attempts). Last error: "
            f"{attempts[-1]['detail'] if attempts else 'none'}")
    out.sdk_version = found
    out.sdk_resolved_by = attempts[0]["ok"] and "pip" or "walk"
    return out
