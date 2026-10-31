"""One place that decides how a server is started, so RQ3 measures traffic.

The problem this module exists to fix
    RQ3 trains a classifier to tell probe calls from genuine agent calls using
    only what the server can see. Before this, the two kinds of call reached
    the attacker through launches that differed in a way nothing about MCP
    required:

        probe cycles   eval/harness.py::_launch passed AttackerControl.env(),
                       a full copy of os.environ. The MCP SDK merges that over
                       its own default set, so the attacker saw ~96 variables.
        agent traffic  arrives through `driftsentry run --forward-env
                       ATTACKER_HOME`, which passes exactly one variable. The
                       SDK default set is 12, so the attacker saw 13.

    Measured on this machine: 12 default, 95 in os.environ, 13 through the
    proxy. A classifier handed env_count would separate the two classes almost
    perfectly and the RQ3 headline would be an artefact of the harness rather
    than a property of probing. The environment family would be reported as the
    strongest signal a real attacker has, and it would not be true.

What parity means here
    Both paths give the attacker the SDK default set plus ATTACKER_HOME, and
    the same working directory. That is also what a real deployment looks
    like: a client launches a server with a filtered environment, not with the
    user's whole shell.

Why the old behaviour is still the default
    Experiments 1 and 2 were run with the full-environment launch, and are the
    control the rest of the work is compared against. Changing how they start
    would quietly invalidate them, so parity is opt-in per episode via
    ``EpisodeConfig.launch_parity`` and off unless asked for.

DRIFTSENTRY_HOME is given to the proxy and never to the attacker. The proxy
needs it to find the baseline that passive monitoring compares against; the
attacker has no business knowing the detector's state directory exists.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

#: Forwarded to the real server by name, never by value, on both paths.
FORWARDED = ("ATTACKER_HOME",)

ROOT = Path(__file__).resolve().parent.parent


def _venv_python(project: Path) -> Path:
    """The interpreter inside a project's own virtual environment."""
    candidates = (project / ".venv" / "Scripts" / "python.exe",
                  project / ".venv" / "bin" / "python")
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        f"no virtual environment found in {project}; expected one of "
        + ", ".join(str(c) for c in candidates)
    )


def detector_python() -> Path:
    """This project's interpreter, for launching the proxy as a subprocess."""
    try:
        return _venv_python(ROOT)
    except FileNotFoundError:
        # Running from an activated environment rather than a .venv directory.
        return Path(sys.executable)


def attacker_cwd(atk_project: str | Path) -> str:
    """The working directory the attacker runs in, on EITHER path.

    A single definition on purpose. ``cwd`` reaches the feature row as
    ``cwd_base`` in the environment family, so if the two paths disagreed here
    the classifier would separate them on the directory name alone.
    """
    return str(Path(atk_project).resolve())


def probe_launch(atk_project: str | Path, atk_home: str | Path) -> dict[str, Any]:
    """Start the attacker directly, the way the daemon does for a probe cycle.

    The environment is ATTACKER_HOME and nothing else. The SDK adds its own
    default set on top, which is what the proxy path also ends up with.
    """
    project = Path(atk_project).resolve()
    return {
        "command": str(_venv_python(project)),
        "args": ["-m", "attacker", "serve"],
        "cwd": attacker_cwd(project),
        "env": {"ATTACKER_HOME": str(atk_home)},
    }


def agent_launch(
    atk_project: str | Path,
    atk_home: str | Path,
    ds_home: str | Path,
    server_id: str = "target",
    *,
    passive: bool = True,
) -> dict[str, Any]:
    """Start the attacker BEHIND the proxy, the way a real client would.

    The returned launch starts ``driftsentry run``; the proxy in turn starts
    the attacker, forwarding ATTACKER_HOME by name and setting the same cwd
    ``probe_launch`` uses. Agent traffic therefore reaches the attacker having
    crossed a real proxy, which is what RQ2's replay and RQ3's genuine half
    both need.
    """
    project = Path(atk_project).resolve()
    attacker_py = str(_venv_python(project))

    args = ["-m", "driftsentry", "run", "--server", str(server_id)]
    if passive:
        args.append("--passive")
    for key in FORWARDED:
        args += ["--forward-env", key]
    # The attacker's cwd, set explicitly so it matches probe_launch rather
    # than inheriting the proxy's own directory.
    args += ["--cwd", attacker_cwd(project)]
    # --exec consumes the remainder, so it has to come last.
    args += ["--exec", attacker_py, "-m", "attacker", "serve"]

    return {
        "command": str(detector_python()),
        "args": args,
        # The proxy runs from this project; only the attacker's cwd is pinned.
        "cwd": str(ROOT),
        "env": {
            "ATTACKER_HOME": str(atk_home),   # forwarded on to the attacker
            "DRIFTSENTRY_HOME": str(ds_home),  # the proxy's own state, not the attacker's
        },
    }


def expected_child_env(atk_home: str | Path) -> dict[str, str]:
    """What the attacker's environment should be on both paths.

    Exposed so a test can assert parity against a stated expectation rather
    than against whatever the code currently happens to produce.
    """
    from mcp.client.stdio import get_default_environment

    return {**get_default_environment(), "ATTACKER_HOME": str(atk_home)}


def describe_parity(atk_home: str | Path) -> dict[str, Any]:
    """Numbers for the write-up: how large the artefact was, and what remains."""
    from mcp.client.stdio import get_default_environment

    default = get_default_environment()
    return {
        "sdk_default_vars": len(default),
        "full_environ_vars": len(os.environ),
        "parity_child_vars": len(default) + 1,
        "forwarded": list(FORWARDED),
    }
