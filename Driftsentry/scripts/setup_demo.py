"""One-time setup for the live 'watch' demo.

Baseline captures a fingerprint and calibration sets the alert threshold. Both
are legitimately install-time steps, both take a few minutes, and both are easy
to get subtly wrong by hand - in particular, the threshold has to be calibrated
against a benign server AND a legitimately-updated one, or it sits too low and a
noisy tool false-alarms during the demo.

So this does the whole setup correctly in one command, writing to the default
state directory that `driftsentry watch` reads afterwards. Run it once:

    python scripts/setup_demo.py

Then, in two terminals:
    driftsentry watch --server acme          # the monitor
    attacker                                 # arm attacks; watch catches them
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from driftsentry.baseline import capture_baseline  # noqa: E402
from driftsentry.calibration import save as save_calibration  # noqa: E402
from driftsentry.store import BaselineStore  # noqa: E402
from driftsentry.verify import calibrate_servers  # noqa: E402

SERVER = "acme"


def find_attacker() -> tuple[Path, Path]:
    project = ROOT.parent / "mcp rug pull attack server"
    python = project / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        python = project / ".venv" / "bin" / "python"
    if not (project / "attacker" / "server.py").is_file() or not python.is_file():
        raise SystemExit(
            "Could not find the attacker project (with its .venv) next to this one.\n"
            f"Expected at: {project}"
        )
    return project, python


def attacker(python: Path, project: Path, *args: str) -> None:
    result = subprocess.run([str(python), "-m", "attacker", *args],
                            capture_output=True, text=True, cwd=str(project))
    if result.returncode != 0:
        raise SystemExit(f"attacker {' '.join(args)} failed:\n{result.stderr}")


async def main() -> int:
    project, python = find_attacker()
    # A second scenario: a legitimately UPDATED benign server, kept in this
    # project's state dir. Part of the calibration set so the threshold tolerates
    # real updates instead of alarming on them.
    updated = ROOT / ".driftsentry_data" / "updated_variant.json"
    updated.parent.mkdir(parents=True, exist_ok=True)

    print("Attacker:", project)
    print("[1/4] setting the attacker to benign")
    attacker(python, project, "benign")
    attacker(python, project, "configure", "--mode", "benign", "--updates",
             "--seed", "99", "--scenario", str(updated))

    print("[2/4] capturing the behavioural baseline (this is the slow part) ...")
    baseline = await capture_baseline(
        SERVER, str(python), ["-m", "attacker", "serve"], cwd=str(project),
        n_probes=3, n_samples=8,
    )
    BaselineStore().save(baseline)
    probed = [t.tool for t in baseline.tools if t.probed]
    print(f"      baselined {len(probed)} tools with {baseline.embedding_backend}")

    print("[3/4] calibrating the threshold on benign data (incl. an updated version) ...")
    updated_launch = {"command": str(python),
                      "args": ["-m", "attacker", "serve", "--scenario", str(updated)],
                      "cwd": str(project)}
    calibration, _ = await calibrate_servers(
        [SERVER], repeats=3, samples_per_probe=2, variants={SERVER: [updated_launch]},
    )
    save_calibration(calibration)
    print(f"      threshold: ratio >= {calibration.threshold_ratio:.3f}  "
          f"(false-alarm rate {calibration.empirical_far:.0%})")

    print("[4/4] leaving the attacker benign")
    attacker(python, project, "benign")

    print("\nReady. Now, in two terminals:")
    print("  1)  driftsentry watch --server acme")
    print("  2)  attacker            (then: use content-injection  ->  run)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
