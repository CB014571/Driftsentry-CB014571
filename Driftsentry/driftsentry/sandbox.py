"""Phase 3 — sandbox monitor: what did the server *do* while we probed it?

The embedding and structural signals look at what a tool *said*. This module
watches what it *did*: which remote hosts its process contacted and which files
it opened while a probe was in flight. Those are the highest-value signals in the
Phase 4 scorer, because "this tool now contacts a host it never contacted at
baseline" or "this tool now reads ~/.ssh/id_rsa" is near-proof of a rug pull,
whereas prose changing is weak evidence on its own.

How it works
    For locally launched (stdio) servers we own the child process, so we can walk
    it and its descendants with psutil, snapshot their open files and established
    connections before a probe, poll during, and report what is new afterwards.

Limitations — state these plainly in the write-up
    * **Polling, not tracing.** A connection opened and closed entirely between
      two polls is missed. Shrinking the interval narrows but never closes the
      gap. A kernel-level tracer (eBPF/ETW) or seccomp/AppArmor would close it;
      that is out of scope for this project and is named as such.
    * **Windows `open_files()` is partial.** It can require privileges and does
      not report every handle type, so file evidence is weaker than network
      evidence on this platform.
    * **Local servers only.** A remote HTTP MCP server runs on someone else's
      machine; there is no process to watch, so this signal is simply unavailable
      — which is one more reason the roadmap does stdio first.
    * **Evidence, not enforcement.** This observes; it does not contain. A tool
      that wants to exfiltrate is not stopped here, only noticed.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("driftsentry.sandbox")

try:  # psutil is optional: without it we degrade to "no side-effect evidence".
    import psutil

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    _HAVE_PSUTIL = False

# Runtime artefacts that say nothing about what a TOOL did.
#
# The distinction that matters: file evidence is only meaningful for files the
# tool's own logic touched. Shared libraries, bytecode caches and operating-system
# resources are opened by the interpreter and by Windows itself, and crucially
# WHICH of them a process holds depends on how it was launched - a server started
# from a console has console resource files open, the same server started from a
# background service does not.
#
# That made the set environment-dependent, so a baseline captured one way and a
# check run another way differed by files neither the tool nor the attacker ever
# chose to open, and a perfectly benign server raised new_file_access. Filtering
# them is not about tidiness; an unfiltered monitor measures the launcher rather
# than the tool.
_NOISE_SUFFIXES = (
    ".pyc", ".pyd", ".dll", ".so", ".dylib",
    ".mui", ".cat", ".manifest", ".nls", ".drv", ".sys", ".exe",
)
_NOISE_FRAGMENTS = ("site-packages", "lib-dynload", "__pycache__", ".venv")


def _system_roots() -> tuple[str, ...]:
    """Directories owned by the OS or the interpreter, normalised for comparison."""
    roots = [sys.prefix, sys.base_prefix]
    for var in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(var)
        if value:
            roots.append(value)
    out = []
    for root in roots:
        try:
            out.append(str(Path(root)).lower().replace("\\", "/").rstrip("/"))
        except Exception:  # pragma: no cover
            continue
    return tuple(sorted(set(out)))


_SYSTEM_ROOTS = _system_roots()


def _is_noise(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    if lowered.endswith(_NOISE_SUFFIXES):
        return True
    if any(fragment in lowered for fragment in _NOISE_FRAGMENTS):
        return True
    if any(lowered.startswith(root + "/") for root in _SYSTEM_ROOTS):
        return True
    return False


@dataclass
class Observation:
    """Side effects associated with one probe.

    Two views, and the distinction matters more than it first appears:

    ``hosts`` / ``files``
        Everything the process had open at any point *during* the call,
        including things opened earlier and still held. This is the view the
        drift comparison uses, because the question a detector must answer is
        "does this tool now touch something it did not touch when it was
        approved?" - not "did it open it in this particular millisecond".

    ``new_hosts`` / ``new_files``
        Only what appeared between the start of this call and its end.

    Using the second view for drift comparison was a real bug: an exfiltration
    channel that opens its sink once and keeps the handle - which is what a real
    one does, and what makes it observable at all - looks "new" on the first
    probe and invisible on every probe after it. The attack was live the whole
    time; the monitor was answering the wrong question.
    """

    hosts: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    available: bool = True

    def is_empty(self) -> bool:
        return not self.hosts and not self.files


class SandboxMonitor:
    """Polls a process tree for new network peers and opened files."""

    def __init__(self, pid: int | None | list[int], *, interval: float = 0.02) -> None:
        self.interval = interval
        pids = [pid] if isinstance(pid, int) else list(pid or [])
        self.available = bool(_HAVE_PSUTIL and pids)
        self._procs: list[Any] = []
        if self.available:
            for candidate in pids:
                try:
                    self._procs.append(psutil.Process(candidate))
                except Exception as exc:  # pragma: no cover
                    log.debug("cannot attach to pid %s: %s", candidate, exc)
            self.available = bool(self._procs)

        self._own: set[str] | None = None   # handles inherited from us
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen_hosts: set[str] = set()
        self._seen_files: set[str] = set()
        self._lock = threading.Lock()

    # -- collection ---------------------------------------------------------
    def _processes(self):
        out = []
        for proc in self._procs:
            try:
                out.extend([proc, *proc.children(recursive=True)])
            except Exception:  # pragma: no cover - process died mid-walk
                continue
        return out

    def _own_handles(self) -> set[str]:
        """Files THIS process has open, which a launched child inherits.

        A child process inherits its parent's open handles, so anything
        DriftSentry itself holds - its own log file, a redirected stdout, a
        store it has open - is reported by psutil as being open in the server
        too. Attributing those to the server is simply wrong: the server never
        opened them, and they produce a permanent new_file_access alert on a
        perfectly honest server.

        This was found live, with a benign server alarming every cycle on the
        detector's own log file.
        """
        if self._own is not None:
            return self._own
        own: set[str] = set()
        try:
            for handle in psutil.Process().open_files():
                own.add(os.path.normpath(handle.path))
        except Exception:  # pragma: no cover - best effort
            pass
        self._own = own
        return own

    def _collect(self) -> tuple[set[str], set[str]]:
        hosts: set[str] = set()
        files: set[str] = set()
        inherited = self._own_handles()
        for proc in self._processes():
            try:
                for conn in proc.net_connections(kind="inet"):
                    if conn.raddr:
                        # Compare on the peer ADDRESS, not address:port.
                        #
                        # Ports are ephemeral: a process that talks to the same
                        # endpoint twice uses a different port each time, so
                        # keying on address:port would make every connection look
                        # like a brand-new host and fire the egress rule on every
                        # check forever. Worse, Python's own asyncio self-pipe is
                        # a loopback TCP socketpair on Windows, so a perfectly
                        # innocent server would appear to contact a new host each
                        # run. The identity of the peer is the signal; the source
                        # port is noise.
                        hosts.add(conn.raddr.ip)
            except Exception:  # AccessDenied / NoSuchProcess / platform quirks
                pass
            try:
                for handle in proc.open_files():
                    path = os.path.normpath(handle.path)
                    if not _is_noise(path) and path not in inherited:
                        files.add(path)
            except Exception:
                pass
        return hosts, files

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            hosts, files = self._collect()
            with self._lock:
                self._seen_hosts |= hosts
                self._seen_files |= files
            self._stop.wait(self.interval)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        """Snapshot the current state and begin polling for anything new."""
        if not self.available:
            return
        base_hosts, base_files = self._collect()
        with self._lock:
            # Seed with the baseline so `stop()` reports only what appeared after.
            self._seen_hosts = set(base_hosts)
            self._seen_files = set(base_files)
            self._base_hosts = set(base_hosts)
            self._base_files = set(base_files)
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, name="driftsentry-sandbox", daemon=True)
        self._thread.start()

    def stop(self) -> Observation:
        """Stop polling and report what the process touched during this call."""
        if not self.available:
            return Observation(available=False)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        # One final sweep, to catch activity since the last poll. Without it a
        # call that completes between two polls leaves no trace at all, and the
        # experiment would measure the poll interval rather than the detector.
        hosts, files = self._collect()
        with self._lock:
            self._seen_hosts |= hosts
            self._seen_files |= files
            all_hosts = sorted(self._seen_hosts)
            all_files = sorted(self._seen_files)
            new_hosts = sorted(self._seen_hosts - self._base_hosts)
            new_files = sorted(self._seen_files - self._base_files)
        return Observation(
            hosts=all_hosts, files=all_files,
            new_hosts=new_hosts, new_files=new_files,
            available=True,
        )

    # -- convenience --------------------------------------------------------
    def __enter__(self) -> "SandboxMonitor":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._observation = self.stop()


# --------------------------------------------------------------------------- #
# Continuous monitoring (product v1.1, follow-up H2c)
# --------------------------------------------------------------------------- #
@dataclass
class _Sample:
    t0: float                  # monotonic, when the sweep began
    t1: float                  # monotonic, when it finished
    hosts: frozenset
    files: frozenset


class ContinuousMonitor:
    """Watches a process tree for the whole session, one sweep after another.

    Why it replaced the per-probe window for in-session verification
        SandboxMonitor snapshots the tree before a probe and sweeps it again
        after. On Windows each sweep costs about 0.1-0.2 s (psutil's
        open_files), measured at 0.12 s to start and 0.20 s to stop. H2b found
        probes arriving a median 0.52 s after the previous call against 0.03 s
        for genuine calls, and timing alone recognised them at AUC 0.80: the
        detector's own bookkeeping was the tell. Here the sweeps run all the
        time on their own thread, so a call costs nothing to watch, and a
        window is answered afterwards from timestamped sweeps.

    What a window means
        ``window(start, end)`` unions every sweep that overlapped the call plus
        the first sweep that began after it ended - the same "held during, or
        still held just after" view SandboxMonitor gives. ``new_*`` is what
        was absent from the last sweep that finished before the call began.

    Attribution limit, stated rather than hidden
        Two calls in flight at once share their sweeps, so a side effect is
        attributed to every call it overlapped. In-session verification sends
        one call at a time, so this only arises when a client sends calls
        concurrently with a probe in the live proxy.
    """

    def __init__(self, pid: int | None | list[int], *, interval: float = 0.0,
                 keep_s: float = 900.0, isolate: bool = True) -> None:
        self._pids = [pid] if isinstance(pid, int) else list(pid or [])
        self._inner = SandboxMonitor(pid)
        self.available = self._inner.available
        self.interval = interval
        self.keep_s = keep_s
        # Sweep in a separate process (driftsentry/_watcher.py explains the
        # measured reason). ``isolate=False`` keeps the in-thread loop.
        self.isolate = isolate
        self._proc = None
        self._samples: list[_Sample] = []
        self._lock = threading.Lock()
        self._new_sample = threading.Condition(self._lock)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "ContinuousMonitor":
        if not self.available or self._thread is not None:
            return self
        target = self._loop
        if self.isolate:
            import subprocess

            package_root = str(Path(__file__).resolve().parents[1])
            env = dict(os.environ)
            env["PYTHONPATH"] = package_root + os.pathsep + env.get("PYTHONPATH", "")
            self._proc = subprocess.Popen(
                [sys.executable, "-m", "driftsentry._watcher", str(os.getpid()),
                 *[str(p) for p in self._pids]],
                stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
            target = self._read
        self._thread = threading.Thread(target=target, name="driftsentry-watch",
                                        daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=2.0)
            except Exception:  # pragma: no cover - best effort
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _add(self, sample: _Sample) -> None:
        with self._new_sample:
            self._samples.append(sample)
            cutoff = sample.t1 - self.keep_s
            while self._samples and self._samples[0].t1 < cutoff:
                self._samples.pop(0)
            self._new_sample.notify_all()

    def _read(self) -> None:
        """Collect sweeps from the watcher process. Blocks on I/O, not the GIL."""
        import json

        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            try:
                d = json.loads(line)
                self._add(_Sample(float(d["t0"]), float(d["t1"]),
                                  frozenset(d.get("hosts") or ()),
                                  frozenset(d.get("files") or ())))
            except Exception:  # noqa: BLE001 - one bad line is one lost sweep
                continue
        with self._new_sample:
            self._new_sample.notify_all()

    def _loop(self) -> None:
        import time

        while not self._stop.is_set():
            t0 = time.monotonic()
            hosts, files = self._inner._collect()
            t1 = time.monotonic()
            self._add(_Sample(t0, t1, frozenset(hosts), frozenset(files)))
            if self.interval:
                self._stop.wait(self.interval)

    def window(self, start: float, end: float, *, wait_s: float = 2.0) -> Observation:
        """Side effects for a call that ran from ``start`` to ``end`` (monotonic).

        Blocks (up to ``wait_s``) until a sweep that began after ``end`` exists,
        so call it once the call is over - after a cycle's calls, not between
        them, or the wait itself becomes a timing tell.
        """
        if not self.available:
            return Observation(available=False)
        import time

        deadline = time.monotonic() + wait_s
        with self._new_sample:
            while not any(s.t0 >= end for s in self._samples):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._stop.is_set():
                    break
                if self._thread is not None and not self._thread.is_alive():
                    break
                self._new_sample.wait(remaining)
            samples = list(self._samples)
        during = [s for s in samples if s.t1 >= start and s.t0 <= end]
        after = next((s for s in samples if s.t0 >= end), None)
        if after is not None:
            during.append(after)
        before = [s for s in samples if s.t1 < start]
        base = before[-1] if before else None
        hosts = set().union(*(s.hosts for s in during)) if during else set()
        files = set().union(*(s.files for s in during)) if during else set()
        return Observation(
            hosts=sorted(hosts), files=sorted(files),
            new_hosts=sorted(hosts - (base.hosts if base else set())),
            new_files=sorted(files - (base.files if base else set())),
            available=True,
        )
