"""The Mid-Point demonstration: DriftSentry vs a separate adversarial server.

Everything the 5 September Mid-Point assessment asks for, in one run:

  1. HASH BLINDNESS. Every rug-pull variant advertises tool definitions that are
     byte-for-byte identical to the benign server's, so all of them hash the
     same. The premise of the whole project, checked rather than assumed.
  2. DETECTION. Baseline the benign server, calibrate on benign data only, then
     detect L1 rug pulls across the attack families and report which signal
     caught each one - the per-family coverage matrix.
  3. FALSE ALARMS. A benign server, and a benign server emitting legitimate
     UPDATES, must both stay quiet. Without this the detection numbers mean
     nothing: alarming on everything would score 100% detection.
  4. THE COMPLEXITY KNOB. L2 and L3 are harder than L1, and at L4 the attacker
     recognises the probes and evades - the honest result that motivates
     randomised templates and RQ4.
  5. LIVE CONTROL. Switch a running server's family, as the viva demo does.

The two projects are separate, and this file proves it
    The attacker lives in its own project with its own virtual environment. This
    demo never imports it. It drives it exactly the way DriftSentry would drive
    any third-party MCP server it had never seen: by launching its executable as
    a subprocess and, for setup, by calling its command-line interface.

    So the isolation is not a claim in a document; it is enforced by the fact
    that `attacker` is not installed in this environment and could not be
    imported here even deliberately.

Run:
    python examples/midpoint_demo.py
    python examples/midpoint_demo.py --attacker "<path to the attacker project>"
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix="driftsentry_midpoint_")
os.environ["DRIFTSENTRY_HOME"] = _TMP

from driftsentry.baseline import capture_baseline  # noqa: E402
from driftsentry.calibration import save as save_calibration  # noqa: E402
from driftsentry.store import BaselineStore  # noqa: E402
from driftsentry.verify import calibrate_servers, verify_server  # noqa: E402

SERVER = "acme"
SCENARIO = Path(_TMP) / "scenario.json"
SCENARIO_UPDATED = Path(_TMP) / "scenario_updated.json"

# The six families, as named by the attacker's CLI. Listed here as data rather
# than imported, because importing them would couple the two projects.
FAMILIES = [
    "exfiltration", "silent-tamper", "content-injection",
    "new-egress", "sleeper", "conditional",
]


def find_attacker(explicit: str | None) -> tuple[Path, Path]:
    """Locate the attacker project and the python inside its own environment.

    Returns (project_dir, python_executable). We deliberately use the attacker's
    OWN interpreter: it has its own pinned environment, and running it with this
    project's python would quietly re-couple the two.
    """
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("ATTACKER_PROJECT"):
        candidates.append(Path(os.environ["ATTACKER_PROJECT"]))
    candidates.append(ROOT.parent / "mcp rug pull attack server")

    for candidate in candidates:
        candidate = candidate.expanduser()
        if (candidate / "attacker" / "server.py").is_file():
            for python in (candidate / ".venv" / "Scripts" / "python.exe",
                           candidate / ".venv" / "bin" / "python"):
                if python.is_file():
                    return candidate, python
            # Project found, but no environment built for it.
            raise SystemExit(
                f"Found the attacker project at {candidate}, but it has no virtual "
                f"environment.\nBuild it first:\n"
                f'    cd "{candidate}"\n'
                f"    py -m venv .venv\n"
                f"    .venv\\Scripts\\pip install -r requirements.txt -e .\n"
            )
    raise SystemExit(
        "Could not find the attacker project. Looked in:\n  "
        + "\n  ".join(str(c) for c in candidates)
        + '\n\nPass it explicitly:  python examples/midpoint_demo.py --attacker "<path>"'
    )


class Attacker:
    """Thin wrapper over the attacker's command line. No imports, only argv."""

    def __init__(self, project: Path, python: Path) -> None:
        self.project = project
        self.python = python

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.python), "-m", "attacker", *args],
            capture_output=True, text=True, cwd=str(self.project), check=False,
        )

    def configure(self, scenario: Path, **flags) -> None:
        args = ["configure", "--scenario", str(scenario)]
        for key, value in flags.items():
            flag = "--" + key.replace("_", "-")
            if value is True:
                args.append(flag)
            elif value not in (False, None):
                args += [flag, str(value)]
        result = self._run(*args)
        if result.returncode != 0:
            raise SystemExit(f"attacker configure failed:\n{result.stderr}")

    def set_family(self, family: str, scenario: Path) -> None:
        self._run("set-family", family, "--scenario", str(scenario))

    def launch(self, scenario: Path) -> dict:
        """How DriftSentry starts this server: a subprocess, like any other."""
        return {
            "command": str(self.python),
            "args": ["-m", "attacker", "serve", "--reuse", "--scenario", str(scenario)],
            "cwd": str(self.project),
        }


def hr(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacker", default=None, help="path to the attacker project")
    ns = parser.parse_args()

    project, python = find_attacker(ns.attacker)
    attacker = Attacker(project, python)
    ok = True

    print(f"detector : {ROOT}")
    print(f"attacker : {project}")
    print(f"          (separate project, separate environment, launched as a subprocess)")

    # -- 1. approve the server while it is benign ---------------------------
    hr("1. Approve the server while it is benign")
    attacker.configure(SCENARIO, mode="benign", seed=99)
    launch = attacker.launch(SCENARIO)
    baseline = await capture_baseline(
        SERVER, launch["command"], launch["args"], cwd=launch["cwd"],
        n_probes=3, n_samples=6,
    )
    BaselineStore().save(baseline)
    probed = [t.tool for t in baseline.tools if t.probed]
    skipped = [t.tool for t in baseline.tools if not t.probed]
    print(f"  embedding       : {baseline.embedding_backend}")
    print(f"  definition hash : {baseline.definition_hash}")
    print(f"  probed          : {probed}")
    print(f"  not probed      : {skipped}  (side-effecting)")
    safety_ok = "send_invoice" in skipped
    print(f"  side-effecting tool left alone: {safety_ok}")
    ok &= safety_ok

    # Calibrate across the range of BENIGN behaviour, which includes a server
    # that has legitimately been updated.
    attacker.configure(SCENARIO_UPDATED, mode="benign", updates=True, seed=99)
    calibration, _ = await calibrate_servers(
        [SERVER], repeats=2, samples_per_probe=2,
        variants={SERVER: [attacker.launch(SCENARIO_UPDATED)]},
    )
    save_calibration(calibration)
    print(f"  threshold       : ratio >= {calibration.threshold_ratio:.3f} "
          f"({calibration.n_observations} benign observations, including a")
    print(f"                    legitimately updated version of the same server)")

    benign_hash = baseline.definition_hash

    # -- 2. every rug pull hashes identically -------------------------------
    hr("2. Hash blindness: can definition pinning tell these apart?")
    for family in FAMILIES:
        attacker.configure(SCENARIO, mode="rug-pull", family=family, level="L1", seed=99)
        report = await verify_server(baseline, launch=attacker.launch(SCENARIO),
                                     samples_per_probe=1, mode="hash-only")
        same = report.observed_definition_hash == benign_hash
        print(f"  {family:<18} hash {'SAME' if same else 'DIFFERENT'}   "
              f"hash-only verdict: {report.verdict.upper()}")
        ok &= same and report.verdict == "ok"
    print("\n  all six families are indistinguishable by definition hash.")
    print("  => a definition-pinning scanner reports 'no change' for every one of them.")

    # -- 3. behavioural detection, per family -------------------------------
    hr("3. Behavioural detection at L1 (the coverage matrix)")
    print(f"  {'family':<18} {'verdict':<7} {'score':>7}  triggering signal")
    coverage = {}
    for family in FAMILIES:
        attacker.configure(SCENARIO, mode="rug-pull", family=family, level="L1",
                           seed=99, after_calls=0)
        report = await verify_server(baseline, launch=attacker.launch(SCENARIO),
                                     samples_per_probe=2)
        coverage[family] = (report.verdict, report.score, report.triggered_by)
        print(f"  {family:<18} {report.verdict.upper():<7} {report.score:>7.2f}  "
              f"{report.triggered_by or '-'}")

    detected = [f for f, (v, _s, _t) in coverage.items() if v == "alert"]
    missed = [f for f in FAMILIES if f not in detected]
    print(f"\n  detected at L1: {len(detected)}/{len(FAMILIES)}  {detected}")
    if missed:
        print(f"  missed at L1  : {missed}")
        print("  (reported, not hidden: per-family recall is the honest claim.)")
    ok &= len(detected) >= 3

    # -- 4. false alarms ----------------------------------------------------
    hr("4. False alarms: benign, and benign-with-updates, must stay quiet")
    # HELD-OUT seed: the calibration set used 99. Reusing it here would measure
    # in-sample performance and flatter the result.
    attacker.configure(SCENARIO, mode="benign", seed=4242)
    plain = await verify_server(baseline, launch=attacker.launch(SCENARIO), samples_per_probe=2)
    attacker.configure(SCENARIO, mode="benign", updates=True, seed=4242)
    updated = await verify_server(baseline, launch=attacker.launch(SCENARIO), samples_per_probe=2)
    print(f"  benign server           : {plain.verdict.upper()}  score {plain.score:.2f}")
    print(f"  benign server + updates : {updated.verdict.upper()}  score {updated.score:.2f}")
    quiet = plain.verdict != "alert" and updated.verdict != "alert"
    print(f"\n  no false alarms: {quiet}   (measured on a seed the threshold never saw)")
    ok &= quiet

    # -- 5. the complexity knob --------------------------------------------
    hr("5. The complexity knob: detection degrades as the attacker adapts")
    print(f"  {'level':<6} {'verdict':<7} {'score':>7}  note")
    knob = {}
    for level, flags, note in [
        ("L1", {}, "always malicious"),
        ("L2", {"rate": 0.4}, "malicious on 40% of calls"),
        ("L3", {"after_calls": 2}, "only after 2 calls"),
        ("L4", {"probe_aware": True}, "recognises the canary probes"),
    ]:
        attacker.configure(SCENARIO, mode="rug-pull", family="content-injection",
                           level=level, seed=99, **flags)
        report = await verify_server(baseline, launch=attacker.launch(SCENARIO),
                                     samples_per_probe=2)
        knob[level] = report.verdict
        print(f"  {level:<6} {report.verdict.upper():<7} {report.score:>7.2f}  {note}")

    print()
    print(f"  L1 caught               : {knob.get('L1') == 'alert'}")
    print(f"  L4 (probe-aware) evades : {knob.get('L4') != 'alert'}")
    print("  L4 evading is the EXPECTED result, not a bug: an attacker that")
    print("  recognises fixed probe values behaves whenever it is watched.")
    print("  Randomised probe templates are the mitigation, and Experiment 4")
    print("  measures how much of the loss they recover.")
    ok &= knob.get("L1") == "alert"

    # -- 6. live control ----------------------------------------------------
    hr("6. Live control (what the viva demo drives)")
    attacker.configure(SCENARIO, mode="benign", seed=99)
    before = json.loads(SCENARIO.read_text(encoding="utf-8"))
    attacker.set_family("new-egress", SCENARIO)
    after = json.loads(SCENARIO.read_text(encoding="utf-8"))
    switched = (before["mode"], before["family"]) != (after["mode"], after["family"])
    print(f"  before: mode={before['mode']} family={before['family']}")
    print(f"  after : mode={after['mode']} family={after['family']}")
    print(f"  switched without restarting the server: {switched}")
    live = await verify_server(baseline, launch=attacker.launch(SCENARIO), samples_per_probe=2)
    print(f"  detector now says: {live.verdict.upper()} ({live.triggered_by})")
    ok &= switched and live.verdict == "alert"

    print("\nMid-point demo result:", "ALL CHECKS PASSED" if ok else "FAILED")
    print(f"(state kept in {_TMP})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
