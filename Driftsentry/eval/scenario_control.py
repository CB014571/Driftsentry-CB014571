"""Drives the adversarial server's CLI from the harness.

Deliberately a SUBPROCESS driver rather than a Python import. The two projects
have separate virtual environments and neither can import the other - that
isolation is the evidence that the attacker shares no machinery with the
detector, and it would be quietly destroyed by a convenience import here.

So the harness talks to the attacker the same way a human operator does: through
its command line, over the scenario file.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ScenarioError(RuntimeError):
    """The attacker CLI refused a command."""


@dataclass
class AttackerControl:
    """Handle on one adversarial server installation."""

    project_dir: Path
    python: Path
    home: Path | None = None       # ATTACKER_HOME for this episode

    @classmethod
    def discover(cls, project_dir: str | Path, home: str | Path | None = None) -> "AttackerControl":
        project = Path(project_dir).resolve()
        python = project / ".venv" / "Scripts" / "python.exe"
        if not python.is_file():                       # posix layout
            python = project / ".venv" / "bin" / "python"
        if not python.is_file():
            raise ScenarioError(f"no attacker interpreter under {project}")
        return cls(project_dir=project, python=python,
                   home=Path(home).resolve() if home else None)

    # -- environment --------------------------------------------------------
    def env(self) -> dict[str, str]:
        """Full environment for the attacker, with an isolated home if set.

        A full copy of os.environ, not a curated subset: the child is a Python
        interpreter on Windows and needs SYSTEMROOT, PATH and friends to start at
        all. Only ATTACKER_HOME is overridden.
        """
        env = dict(os.environ)
        if self.home is not None:
            env["ATTACKER_HOME"] = str(self.home)
        return env

    def launch_command(self) -> tuple[str, list[str]]:
        """The command DriftSentry should use to start this server."""
        return str(self.python), ["-m", "attacker", "serve"]

    # -- commands -----------------------------------------------------------
    def _run(self, *args: str) -> str:
        proc = subprocess.run(
            [str(self.python), "-m", "attacker", *args],
            cwd=str(self.project_dir),
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise ScenarioError(
                f"attacker {' '.join(args)} failed ({proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc.stdout

    def benign(self, *, updates: bool = False, seed: int | None = None) -> None:
        args = ["benign"]
        if updates:
            args.append("--updates")
        if seed is not None:
            args += ["--seed", str(seed)]
        self._run(*args)

    def arm(
        self,
        family: str,
        *,
        level: str = "L1",
        seed: int | None = None,
        probe_aware: bool | None = None,
        rate: float | None = None,
        after_calls: int | None = None,
        payload: str | None = None,
    ) -> None:
        """Arm one attack. L4/L5 imply probe-awareness and require the opt-in."""
        args = ["attack", family, "--level", level]
        if seed is not None:
            args += ["--seed", str(seed)]
        if rate is not None:
            args += ["--rate", str(rate)]
        if after_calls is not None:
            args += ["--after-calls", str(after_calls)]
        if payload is not None:
            args += ["--payload", payload]
        # The attacker validates that L4/L5 without --probe-aware is a config
        # error, so default it on for those levels rather than letting the
        # episode fail deep inside a run.
        if probe_aware or (probe_aware is None and level in {"L4", "L5"}):
            args.append("--probe-aware")
        self._run(*args)

    def trip(self) -> None:
        """Force a sleeper / trigger-gated attack to fire now."""
        self._run("trip")

    def reset(self) -> None:
        """Back to benign and clear the sink."""
        self._run("reset")

    def status(self) -> str:
        return self._run("status")

    def selftest(self) -> str:
        """Validate the ground truth before an experiment trusts it."""
        return self._run("selftest")
