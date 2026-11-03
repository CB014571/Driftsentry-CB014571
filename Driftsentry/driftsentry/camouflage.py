"""Making verification look less like verification.

Randomising probe *values* is necessary and not sufficient. A server can
recognise it is being tested without reading a single argument:

    * checks arrive exactly every 20 seconds
    * always the same number of calls
    * always the same tools, in the same order
    * always in a session that does nothing else

Each is a tell, and none is affected by how unpredictable the values are. This
module removes the cheap ones.

Everything here is keyed and therefore reproducible: an experiment replays
exactly, while a server watching the traffic cannot predict the next interval or
ordering. Camouflage that used ordinary randomness would break reproducibility
for no security benefit, since the server cannot see the seed either way.

What is NOT claimed
    The out-of-band verification session remains structurally distinguishable
    from a user session - it connects, lists tools, calls only probeable ones,
    and disconnects. Fixing that properly means routing verification through the
    live session, which the architecture deliberately avoids so probes never add
    latency to real calls. The residual fingerprint is documented rather than
    hidden, and `session_fingerprint()` below enumerates exactly what a server
    could still key on.
"""
from __future__ import annotations

import hmac
import random
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Sequence

#: Interval jitter as a fraction of the base interval. +/-30% turns a fixed
#: 20-second cadence into a 14-26 second one - enough that a server cannot lock
#: onto a period, while the average rate a user configured is preserved.
DEFAULT_JITTER = 0.30

#: Probe count varies by at most this many either way, and never below one.
DEFAULT_COUNT_VARIANCE = 1


def _rng(key: bytes, *parts: Any) -> random.Random:
    """Keyed RNG for one camouflage decision."""
    message = "|".join(str(p) for p in parts).encode("utf-8")
    digest = hmac.new(key, message, sha256).digest()
    return random.Random(int.from_bytes(digest, "big"))


def next_interval(
    key: bytes,
    server: str,
    cycle: int,
    base_interval: float,
    *,
    jitter: float = DEFAULT_JITTER,
) -> float:
    """A verification interval that cannot be locked onto.

    Uniform within the band rather than Gaussian: a normal distribution
    concentrates around the base interval, which leaves the modal period exactly
    where an observer would look for it.
    """
    if base_interval <= 0 or jitter <= 0:
        return base_interval
    rng = _rng(key, "interval", server, cycle)
    factor = 1.0 + rng.uniform(-jitter, jitter)
    return max(1.0, base_interval * factor)


def permute(key: bytes, server: str, cycle: int, items: Sequence[Any]) -> list[Any]:
    """Keyed permutation of the probe order.

    A fixed A -> B -> C ordering is a fingerprint in its own right, and it also
    lets a stateful attacker count calls to predict which tool comes next.
    """
    ordered = list(items)
    if len(ordered) < 2:
        return ordered
    rng = _rng(key, "order", server, cycle)
    rng.shuffle(ordered)
    return ordered


def probe_count(
    key: bytes,
    server: str,
    tool: str,
    cycle: int,
    base_count: int,
    *,
    variance: int = DEFAULT_COUNT_VARIANCE,
) -> int:
    """Vary how many probes a tool receives this cycle.

    A constant count is a tell, and it also tells a stochastic attacker exactly
    how much hold-back is enough. Never returns zero: a tool that went unprobed
    would silently lose coverage.
    """
    if base_count <= 1 or variance <= 0:
        return max(1, base_count)
    rng = _rng(key, "count", server, tool, cycle)
    return max(1, base_count + rng.randint(-variance, variance))


@dataclass
class SessionFingerprint:
    """What a monitored server can still tell about a verification session.

    Enumerated deliberately. These are the tells camouflage does NOT remove, and
    an honest write-up names them rather than implying the problem is solved.
    """

    separate_session: bool = True
    lists_tools_first: bool = True
    calls_only_probeable_tools: bool = True
    no_interleaved_user_traffic: bool = True
    short_lived_connection: bool = True
    # Set False once T18's session shaping is on: a cycle is then split into
    # several sessions whose lengths are drawn from the observed distribution,
    # instead of one burst of every probe.
    uniform_session_length: bool = True
    back_to_back_calls: bool = True

    def residual_tells(self) -> list[str]:
        tells = []
        if self.separate_session:
            tells.append("verification uses its own stdio session, not the user's")
        if self.lists_tools_first:
            tells.append("every session begins with tools/list")
        if self.calls_only_probeable_tools:
            tells.append("side-effecting tools are never called, so their absence is a signal")
        if self.no_interleaved_user_traffic:
            tells.append("no unrelated calls are interleaved with the probes")
        if self.short_lived_connection:
            tells.append("the connection closes immediately after the last probe")
        if self.uniform_session_length:
            tells.append("every cycle sends the same number of calls in one session, "
                         "which RQ3 measured at AUC 1.000")
        if self.back_to_back_calls:
            tells.append("probe calls arrive with no pause between them, unlike a "
                         "model that stops to think")
        return tells

    def describe(self) -> str:
        return ("verification remains distinguishable by session structure; "
                f"{len(self.residual_tells())} residual tell(s)")

# --------------------------------------------------------------------------- #
# Session shaping (T18)
#
# `session` was the worst channel RQ3 found, at AUC 1.000, and it is not about
# what probes contain. A verification cycle makes every probe inside one
# process - eighteen calls in about 0.2 seconds - while a genuine agent
# session makes one to six over several seconds. calls_before above five
# occurs only in probe traffic, so the split is exact and no amount of value
# randomisation touches it.
#
# The fix is structural: break one cycle into several short sessions, each
# sized from the distribution real sessions actually follow, and space the
# calls inside them with gaps drawn from real gaps.
#
# What this costs is honest to state. More sessions means more process
# launches per cycle, so a cycle takes longer and costs more. T20 measures
# that rather than assuming it is free.
# --------------------------------------------------------------------------- #
def session_plan(
    key: bytes,
    server: str,
    cycle: int,
    total_probes: int,
    profile: Any | None = None,
) -> list[int]:
    """How to split one cycle's probes into separate sessions.

    Returns a list of call counts, one per session, summing to
    ``total_probes``. With no usable profile this returns a single session -
    the current behaviour - rather than inventing a shape. A made-up
    distribution matching neither probes nor users would be a fingerprint of
    its own, which is the same reasoning as hostprofile.implementation().
    """
    if total_probes <= 0:
        return []
    if profile is None or not getattr(profile, "usable", False):
        return [total_probes]

    sizes = [n for n in profile.calls_per_session if n > 0]
    if not sizes:
        return [total_probes]

    rng = _rng(key, "sessions", server, cycle)
    plan: list[int] = []
    remaining = total_probes
    while remaining > 0:
        draw = min(sizes[rng.randrange(len(sizes))], remaining)
        plan.append(draw)
        remaining -= draw
    return plan


def gap_from_profile(
    key: bytes,
    server: str,
    cycle: int,
    index: int,
    profile: Any | None = None,
    *,
    fallback: float = 0.0,
) -> float:
    """A pause before the next probe call, drawn from observed gaps.

    Keyed, so a cycle is replayable, and drawn from the real distribution
    rather than from a parametric guess - a tool whose users pause in a
    bimodal way is not described by any single mean.
    """
    if profile is None or not getattr(profile, "usable", False):
        return fallback
    gaps = [g for g in getattr(profile, "gaps_s", []) if g >= 0]
    if not gaps:
        return fallback
    rng = _rng(key, "gap", server, cycle, index)
    return float(gaps[rng.randrange(len(gaps))])
