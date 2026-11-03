"""What genuine traffic looks like, learned from the proxy's own log.

RQ3 measured three channels that still separate probes from real calls once
the client name is borrowed (T17):

    session   AUC 1.000. A verification cycle makes every probe in one
              process - 18 calls in about 0.2 seconds - while a real agent
              session makes one to six over several seconds. calls_before
              above five occurs only in probe traffic, so the split is exact.
    timing    AUC 0.817. Probe calls arrive back to back; a model pauses to
              think between them.
    argument  AUC 0.786, the reference. Keyed values are no longer drawn from
              an enumerable pool, but they are still shaped unlike the things
              a user asks for.

All three are properties of HOW probing is scheduled rather than of what it
sends, so none of them can be fixed by changing probe values. This module
learns the shape of real traffic so the schedule can be made to match it.

Learned from the proxy log, which is the only record of genuine calls the
detector legitimately has. Three things are taken from it:

    how many calls a session makes;
    how long the gaps between them are;
    how long an argument is, and what it is made of.

Argument SHAPES, never argument values. Replaying a user's actual arguments
would send their data to a server that may be hostile, and would make the
detector's probes a channel for exfiltrating the very traffic it protects.
The keyed generator still produces every value; this only tells it what size
and character mix to aim for.
"""
from __future__ import annotations

import json
import logging
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("driftsentry.traffic")

#: Below this many genuine sessions, a learned profile describes an accident
#: rather than a habit, and imitating it would be its own fingerprint.
MIN_SESSIONS = 5

#: Gaps longer than this are a user walking away, not a model thinking. Kept
#: out of the distribution so probes do not idle for minutes.
MAX_GAP_S = 30.0


@dataclass
class ToolShape:
    """How long a tool's arguments tend to be, and what they contain."""

    n_observed: int = 0
    min_len: int = 0
    max_len: int = 0
    median_len: int = 0
    digit_ratio: float = 0.0
    space_ratio: float = 0.0


@dataclass
class TrafficProfile:
    """The habits of genuine traffic against one server."""

    server: str = ""
    n_sessions: int = 0
    n_calls: int = 0
    calls_per_session: list[int] = field(default_factory=list)
    gaps_s: list[float] = field(default_factory=list)
    tool_shapes: dict[str, ToolShape] = field(default_factory=dict)

    # -- derived -----------------------------------------------------------
    @property
    def usable(self) -> bool:
        """Whether there is enough here to imitate rather than to guess."""
        return self.n_sessions >= MIN_SESSIONS and bool(self.calls_per_session)

    def median_gap(self) -> float:
        return float(statistics.median(self.gaps_s)) if self.gaps_s else 0.0

    def median_session(self) -> int:
        return (int(statistics.median(self.calls_per_session))
                if self.calls_per_session else 0)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["usable"] = self.usable
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrafficProfile":
        shapes = {k: ToolShape(**v) for k, v in (data.get("tool_shapes") or {}).items()}
        return cls(
            server=data.get("server", ""),
            n_sessions=int(data.get("n_sessions", 0)),
            n_calls=int(data.get("n_calls", 0)),
            calls_per_session=list(data.get("calls_per_session") or []),
            gaps_s=list(data.get("gaps_s") or []),
            tool_shapes=shapes,
        )


def _arg_text(args: Any) -> str:
    if isinstance(args, dict):
        return " ".join(str(v) for v in args.values())
    return "" if args is None else str(args)


def learn(log_path: str | Path, server: str = "") -> TrafficProfile:
    """Build a profile from a proxy exchange log.

    Only tools/call requests from the client are counted, grouped by the
    session id the proxy stamps on every record (T1). Probe traffic is not in
    this log: probes bypass the proxy and talk to the server directly, which
    is why the log is a clean record of genuine calls.
    """
    path = Path(log_path)
    if not path.is_file():
        return TrafficProfile(server=server)

    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("dir") != "c2s" or rec.get("method") != "tools/call":
            continue
        if rec.get("kind") != "request":
            continue
        by_session[rec.get("session", "?")].append(rec)

    calls_per_session: list[int] = []
    gaps: list[float] = []
    texts: dict[str, list[str]] = defaultdict(list)

    for calls in by_session.values():
        calls.sort(key=lambda r: r.get("ts", ""))
        calls_per_session.append(len(calls))
        previous = None
        for rec in calls:
            tool = rec.get("tool")
            if tool:
                texts[tool].append(_arg_text(rec.get("args")))
            stamp = _parse_ts(rec.get("ts"))
            if previous is not None and stamp is not None:
                gap = stamp - previous
                # A long gap is a user who walked away, not a model thinking.
                if 0.0 <= gap <= MAX_GAP_S:
                    gaps.append(gap)
            if stamp is not None:
                previous = stamp

    shapes = {}
    for tool, values in texts.items():
        lengths = [len(v) for v in values]
        joined = "".join(values)
        shapes[tool] = ToolShape(
            n_observed=len(values),
            min_len=min(lengths) if lengths else 0,
            max_len=max(lengths) if lengths else 0,
            median_len=int(statistics.median(lengths)) if lengths else 0,
            digit_ratio=(sum(c.isdigit() for c in joined) / len(joined)) if joined else 0.0,
            space_ratio=(joined.count(" ") / len(joined)) if joined else 0.0,
        )

    profile = TrafficProfile(
        server=server,
        n_sessions=len(by_session),
        n_calls=sum(calls_per_session),
        calls_per_session=calls_per_session,
        gaps_s=gaps,
        tool_shapes=shapes,
    )
    if not profile.usable:
        log.info("traffic profile for %r has only %d session(s); not enough to "
                 "imitate (need %d)", server, profile.n_sessions, MIN_SESSIONS)
    return profile


def _parse_ts(value: Any) -> float | None:
    if not value:
        return None
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except Exception:
        return None


def profile_path(server: str) -> Path:
    from driftsentry.paths import data_dir

    path = data_dir() / "traffic"
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{server}.json"


def save(profile: TrafficProfile) -> Path:
    path = profile_path(profile.server)
    path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
    return path


def load(server: str) -> TrafficProfile | None:
    path = profile_path(server)
    if not path.is_file():
        return None
    try:
        return TrafficProfile.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None
