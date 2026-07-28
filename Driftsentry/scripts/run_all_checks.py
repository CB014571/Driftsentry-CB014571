"""Run every phase's definition-of-done check and report a summary.

One command to answer "does the build actually work?". Each phase ships an
executable check that exercises the real code paths end to end (not mocks), and
this runner executes them in order and reports pass/fail.

    python scripts/run_all_checks.py            # run everything
    python scripts/run_all_checks.py --verbose  # show each check's full output
    python scripts/run_all_checks.py --only 3   # run one phase's check

Exit code is 0 only if every check passes, so this is also usable in CI.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (phase, script, what a pass actually proves)
CHECKS: list[tuple[str, Path, str]] = [
    ("0", ROOT / "scripts" / "check_stack.py",
     "ChromaDB persists/reloads and embeddings run offline"),
    ("0", ROOT / "examples" / "echo_client.py",
     "an MCP client can drive a server over stdio (handshake, list, call)"),
    ("1", ROOT / "examples" / "proxy_demo.py",
     "the proxy is transparent, survives 8 concurrent calls, and logs every exchange"),
    ("2", ROOT / "examples" / "init_demo.py",
     "config rewrite produces a WORKING config, hides secrets, is idempotent, and restores"),
    ("3", ROOT / "examples" / "baseline_demo.py",
     "probe safety, learned variance, and drift caught on an identical definition hash"),
]


def run_check(script: Path, verbose: bool) -> tuple[bool, float, str]:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, cwd=str(ROOT),
    )
    elapsed = time.perf_counter() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    if verbose:
        print(output)
    return proc.returncode == 0, elapsed, output


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all DriftSentry phase checks.")
    parser.add_argument("--verbose", action="store_true", help="print each check's full output")
    parser.add_argument("--only", default=None, metavar="PHASE", help="run only this phase's checks")
    ns = parser.parse_args()

    checks = [c for c in CHECKS if ns.only is None or c[0] == ns.only]
    if not checks:
        print(f"no checks for phase {ns.only!r}", file=sys.stderr)
        return 2

    print("DriftSentry - full verification")
    print("=" * 72)

    results: list[tuple[str, str, bool, float]] = []
    for phase, script, proves in checks:
        label = f"Phase {phase}: {script.name}"
        print(f"\n>>> {label}")
        print(f"    proves: {proves}")
        ok, elapsed, output = run_check(script, ns.verbose)
        results.append((phase, script.name, ok, elapsed))
        print(f"    {'PASS' if ok else 'FAIL'}  ({elapsed:.1f}s)")
        if not ok and not ns.verbose:
            # Show enough of the failure to act on without dumping everything.
            tail = [line for line in output.splitlines() if line.strip()][-15:]
            print("    --- last lines of output ---")
            for line in tail:
                print(f"    {line}")

    print("\n" + "=" * 72)
    print("SUMMARY")
    for phase, name, ok, elapsed in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] Phase {phase}  {name:<22} {elapsed:6.1f}s")

    passed = sum(1 for *_, ok, _ in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
