"""In-session verification: probes inside the user's own session.

Why this exists
    RQ1 measured how a server tells a probe from a genuine call, and four of
    the five channels had nothing to do with probe VALUES: client identity
    (AUC 1.000), session counters (0.983), timing (0.951) and, through them,
    argument shape (0.763). Every one of those is a property of the separate
    verification session the detector opened - its own process, handshake,
    counters and rhythm. RQ2's countermeasures imitated that session's
    surface (borrowed client name, paced calls, subsampled probes) and the
    best AUC stayed at 0.994: H2 failed.

    The camouflage module already named the root cause: "fixing that properly
    means routing verification through the live session". This module does
    that. A probe is sent through the session the user's own client opened,
    so the client identity, process, environment and session counters it
    carries ARE the user's. They cannot differ because there is nothing
    separate to differ.

What is left, and what is done about it
    position    A probe always arriving first or last would be a tell, so
                genuine calls and probes are interleaved uniformly at random
                under a keyed RNG: before each probe, each remaining genuine
                call is sent first with probability G / (G + P), which makes
                every ordering equally likely.
    timing      Each call waits a gap, as a user's does. Genuine calls keep
                the gap they were recorded with; a probe draws one from the
                gaps observed in genuine traffic (and the first call of a
                session draws a startup delay the same way).
    arguments   Not handled here: the keyed generator shapes probe values
                to genuine lengths and character mix (probe_generator.py,
                ``shapes``).

Side effects are never mis-attributed
    ``prepare_probe`` sends the genuine calls due before a probe, and waits
    out the pacing, BEFORE the sandbox window for that probe opens
    (baseline._call_once calls it first). Only the probe itself is inside
    the window. A residual remains and is measured rather than assumed away:
    a side effect a genuine call left behind, such as a file it still holds
    open, can still be visible while a probe runs. The follow-up experiment
    counts a detection as probe-earned only when the attacker's own log shows
    it fired during a probe call.

Two ways to drive it
    In the evaluation the harness owns a client session (through the proxy)
    and replays recorded genuine sessions into it. In deployment the proxy
    owns the session and injects probes into it (proxy.ProbeInjector). From
    the server's side the two are the same thing: one session, one client,
    one process, calls arriving one at a time.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import anyio

log = logging.getLogger("driftsentry.insession")

#: Longest pause honoured, in seconds. A recorded pause of minutes is a user
#: who walked away, and would stall verification for no benefit.
MAX_WAIT_S = 15.0


@dataclass
class CallRecord:
    """One call as it went out: what, when, and whether it was a probe."""

    kind: str                      # "genuine" | "probe"
    tool: str
    args: dict[str, Any]
    start: float                   # wall clock, for matching the server's log
    end: float = 0.0
    failed: bool = False
    text: str = ""


@dataclass
class InSessionChannel:
    """A live client session shared by genuine calls and probes.

    ``session`` is an initialised MCP ``ClientSession`` (or anything with
    ``list_tools`` and ``call_tool``). ``genuine`` is the queue of the user's
    calls still to send, each ``{"tool", "args", "proc_age_s", "gap_s"}`` as
    eval.replay records them. ``profile`` is a traffic.TrafficProfile: its
    gaps and startup delays pace the probes. ``expected_probes`` is how many
    probe calls this cycle will make; it sets the interleaving odds and does
    not need to be exact.
    """

    session: Any
    genuine: list[dict[str, Any]]
    key: bytes
    server: str
    cycle: int
    profile: Any = None
    expected_probes: int = 1
    max_wait_s: float = MAX_WAIT_S
    records: list[CallRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        from driftsentry.camouflage import _rng

        self._rng = _rng(self.key, "insession", self.server, self.cycle)
        self._queue = list(self.genuine)
        self._probes_left = max(1, int(self.expected_probes))
        self._opened = time.monotonic()
        self._last_end: float | None = None
        self._probe_index = 0

    # -- the ClientSession surface verification uses -----------------------
    async def list_tools(self) -> Any:
        return await self.session.list_tools()

    async def prepare_probe(self, tool: str) -> None:
        """Send the genuine calls due before this probe, then pace the probe."""
        while self._queue:
            g, p = len(self._queue), self._probes_left
            if self._rng.random() >= g / (g + p):
                break
            await self._send_genuine(self._queue.pop(0))
        await self._pace(self._probe_wait())

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """A probe. Called by verification inside its side-effect window."""
        record = CallRecord("probe", name, dict(arguments or {}), start=time.time())
        self.records.append(record)
        try:
            return await self.session.call_tool(name, arguments or {})
        except Exception:
            record.failed = True
            raise
        finally:
            record.end = time.time()
            self._last_end = time.monotonic()
            self._probes_left = max(1, self._probes_left - 1)
            self._probe_index += 1

    async def finish(self) -> list[CallRecord]:
        """Send whatever genuine calls are left, and return every record."""
        while self._queue:
            await self._send_genuine(self._queue.pop(0))
        return self.records

    # -- internals -----------------------------------------------------------
    def _first_call(self) -> bool:
        return self._last_end is None

    def _probe_wait(self) -> float:
        from driftsentry.camouflage import gap_from_profile, startup_from_profile

        if self._first_call():
            return startup_from_profile(self.key, self.server, self.cycle, self.profile)
        return gap_from_profile(self.key, self.server, self.cycle,
                                self._probe_index, self.profile)

    async def _pace(self, wanted: float | None) -> None:
        """Wait so the call lands ``wanted`` seconds after the last one.

        The first call of a session is measured from when the session opened,
        because what a server sees is its own process age, not how long the
        caller chose to sleep.
        """
        if not wanted:
            return
        since = self._opened if self._last_end is None else self._last_end
        remaining = float(wanted) - (time.monotonic() - since)
        if remaining > 0:
            await anyio.sleep(min(remaining, self.max_wait_s))

    async def _send_genuine(self, call: dict[str, Any]) -> None:
        wanted = call.get("proc_age_s") if self._first_call() else call.get("gap_s")
        await self._pace(wanted)
        record = CallRecord("genuine", call["tool"], dict(call.get("args") or {}),
                            start=time.time())
        self.records.append(record)
        try:
            result = await self.session.call_tool(call["tool"], call.get("args") or {})
            record.text = "\n".join(getattr(b, "text", "") or ""
                                    for b in (getattr(result, "content", None) or []))
            record.failed = bool(getattr(result, "isError", False))
        except Exception as exc:  # noqa: BLE001 - a failed user call is still traffic
            record.text, record.failed = f"error: {exc}", True
        finally:
            record.end = time.time()
            self._last_end = time.monotonic()


def expected_probe_calls(baseline: Any, samples_per_probe: int, subsample_bank: bool) -> int:
    """How many probe calls a keyed cycle will make, for the interleaving odds."""
    from driftsentry import camouflage

    total = 0
    for tool in getattr(baseline, "tools", []):
        if not getattr(tool, "probed", False):
            continue
        family = baseline.family_for(tool.tool) if hasattr(baseline, "family_for") else None
        count = getattr(family, "n_instances", 3) if family is not None else 3
        if subsample_bank:
            count = min(camouflage.DEFAULT_DRAW, camouflage.DEFAULT_BANK)
        total += count * samples_per_probe
    return max(1, total)
