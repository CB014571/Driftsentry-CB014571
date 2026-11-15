"""Out-of-process sweeper for ContinuousMonitor (H2c).

Run as ``python -m driftsentry._watcher <owner-pid> <pid> [<pid> ...]``. Sweeps
the process trees one after another and writes one JSON line per sweep to
stdout: ``{"t0": .., "t1": .., "hosts": [..], "files": [..]}`` with
``time.monotonic()`` stamps, which on Windows (QueryPerformanceCounter) and
POSIX (CLOCK_MONOTONIC) are shared by every process on the machine.

Why a process and not a thread
    Measured: with the sweep loop on a thread inside the detector, an
    ``anyio.sleep(0.005)`` took a median 0.056 s instead of 0.007 s, because
    psutil's sweep holds the interpreter lock. Every probe paced from genuine
    gaps then arrived ~50 ms late - a timing tell of the detector's own
    making. In a separate process the sweep cannot touch the session's
    event loop at all.

Exits when its stdout closes (the detector went away) or the owner dies.
"""
from __future__ import annotations

import json
import os
import sys
import time


def main(argv: list[str]) -> int:
    import psutil

    from driftsentry.sandbox import SandboxMonitor

    owner, pids = int(argv[0]), [int(p) for p in argv[1:]]
    monitor = SandboxMonitor(pids)
    # Handles the DETECTOR holds are inherited by the server it launched and
    # must not be attributed to it (SandboxMonitor._own_handles explains). In
    # this process psutil.Process() is the watcher, so ask about the owner.
    own: set[str] = set()
    try:
        for handle in psutil.Process(owner).open_files():
            own.add(os.path.normpath(handle.path))
    except Exception:
        pass
    monitor._own = own
    out = sys.stdout
    while True:
        if not psutil.pid_exists(owner):
            return 0
        t0 = time.monotonic()
        hosts, files = monitor._collect()
        t1 = time.monotonic()
        try:
            out.write(json.dumps({"t0": t0, "t1": t1, "hosts": sorted(hosts),
                                  "files": sorted(files)}) + "\n")
            out.flush()
        except (BrokenPipeError, OSError, ValueError):
            return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
