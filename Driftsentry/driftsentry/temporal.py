"""Temporal detection: catching drift that never crosses the line in one step.

Every signal so far judges a single verification cycle in isolation. That leaves
a gap an attacker can walk through slowly:

    0.20 -> 0.24 -> 0.29 -> 0.35 -> 0.41 -> ...

No individual observation is remarkable. The trend is. CUSUM is the classical
answer to exactly this problem - it was designed for detecting a small sustained
shift in a process mean, which is precisely what a low-and-slow rug pull is.

    S_n = max(0, S_{n-1} + (score_n - k))        alert when S_n > h

`k` is the slack: how far above the benign mean an observation has to sit before
it counts as evidence at all. `h` is how much accumulated evidence is needed.
Both belong to calibration, not to this file - the defaults below are starting
points chosen from the benign scores observed during development, and are
reported as provisional until a calibration run replaces them.

EWMA is kept alongside as a smoothed trend for display. It is deliberately NOT a
second alerting path: two independent temporal detectors on the same series would
correlate heavily, and the corroboration scorer treats each evidence family as
independent.

The honest failure mode
    CUSUM accumulates. A tool that legitimately settles slightly above its
    baseline - after an update the user accepted - will eventually alert, however
    small the excess. Two things bound that: the accumulator is capped, and it is
    reset whenever the baseline is re-approved, which is exactly the action a
    user takes when they accept an update. Neither is a complete answer, and the
    residual risk belongs in the false-alarm discussion.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.temporal")

#: Slack. Observations at or below this contribute nothing, so ordinary benign
#: noise cannot accumulate. Sits above the benign scores seen in development
#: (0.05-0.10) and well below the alert line.
DEFAULT_K = 0.20

#: Decision interval. With k=0.20, a run at 0.35 accumulates 0.15 per cycle and
#: alerts on the seventh - slow enough that a single elevated reading does not
#: trigger it, fast enough to catch a gradual climb before it arrives.
DEFAULT_H = 1.0

#: EWMA smoothing, for the displayed trend only.
DEFAULT_ALPHA = 0.3

#: Hard cap on the accumulator, so a long-running slightly-elevated tool cannot
#: drift into an alert months later on evidence nobody can reconstruct.
MAX_CUSUM = 4.0

#: Evidence weight when the accumulator crosses h. Below the strong security
#: rules: a trend is real evidence but it is inferential, where a new egress host
#: is direct.
W_TEMPORAL = 1.3


@dataclass
class TemporalState:
    """Accumulated evidence for one tool, across verification cycles."""

    server: str
    tool: str
    baseline_id: str = ""
    cusum_s: float = 0.0
    ewma: float = 0.0
    n: int = 0
    peak_s: float = 0.0
    last_score: float = 0.0
    last_updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TemporalState":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class TemporalSignal:
    """What the temporal detector concluded this cycle."""

    fired: bool
    score: float                      # evidence units
    cusum: float
    ewma: float
    cycles: int
    detail: str
    k: float = DEFAULT_K
    h: float = DEFAULT_H

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TemporalDetector:
    """CUSUM (+ EWMA) per (server, tool), persisted between runs."""

    def __init__(
        self,
        *,
        k: float = DEFAULT_K,
        h: float = DEFAULT_H,
        alpha: float = DEFAULT_ALPHA,
        path: Path | None = None,
    ) -> None:
        self.k = k
        self.h = h
        self.alpha = alpha
        # The daemon's in-memory history is lost on restart, and a detector for
        # slow attacks that forgets everything when the process cycles would
        # never see one. State therefore lives on disk.
        self.path = path or (data_dir() / "temporal.json")
        self._states: dict[str, TemporalState] = {}
        self.load()

    # -- persistence --------------------------------------------------------
    @staticmethod
    def _key(server: str, tool: str) -> str:
        return f"{server}::{tool}"

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - corrupt state must not break scoring
            log.warning("could not read %s (%s); starting temporal state fresh", self.path, exc)
            return
        self._states = {k: TemporalState.from_dict(v) for k, v in data.items()}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({k: v.to_dict() for k, v in self._states.items()}, indent=2),
            encoding="utf-8",
        )

    # -- the detector -------------------------------------------------------
    def state(self, server: str, tool: str) -> TemporalState:
        key = self._key(server, tool)
        if key not in self._states:
            self._states[key] = TemporalState(server=server, tool=tool)
        return self._states[key]

    def update(
        self,
        server: str,
        tool: str,
        score: float,
        *,
        baseline_id: str = "",
        persist: bool = True,
    ) -> TemporalSignal:
        """Fold one cycle's score into the running trend."""
        state = self.state(server, tool)

        # A different baseline is a different normal. Carrying an accumulator
        # across a re-approval would charge the new baseline for evidence
        # gathered against the old one.
        if baseline_id and state.baseline_id and state.baseline_id != baseline_id:
            log.info("temporal: baseline changed for %s/%s; resetting", server, tool)
            state.cusum_s = 0.0
            state.ewma = 0.0
            state.n = 0
            state.peak_s = 0.0
        if baseline_id:
            state.baseline_id = baseline_id

        state.cusum_s = min(MAX_CUSUM, max(0.0, state.cusum_s + (score - self.k)))
        state.ewma = (self.alpha * score + (1 - self.alpha) * state.ewma
                      if state.n else score)
        state.n += 1
        state.peak_s = max(state.peak_s, state.cusum_s)
        state.last_score = score
        state.last_updated = datetime.now(timezone.utc).isoformat()

        fired = state.cusum_s > self.h
        if persist:
            self.save()

        if fired:
            detail = (f"sustained elevation over {state.n} cycles: CUSUM "
                      f"{state.cusum_s:.2f} above the decision interval {self.h:.2f} "
                      f"(slack {self.k:.2f}, current score {score:.2f})")
        else:
            detail = (f"CUSUM {state.cusum_s:.2f} of {self.h:.2f} after "
                      f"{state.n} cycle(s)")

        return TemporalSignal(
            fired=fired,
            # Scaled by how far past the interval it has gone, capped, so a
            # long-running mild trend and a sharp one are distinguishable.
            score=(min(W_TEMPORAL * (state.cusum_s / self.h), W_TEMPORAL * 1.5)
                   if fired else 0.0),
            cusum=round(state.cusum_s, 4),
            ewma=round(state.ewma, 4),
            cycles=state.n,
            detail=detail,
            k=self.k,
            h=self.h,
        )

    def reset(self, server: str, tool: str | None = None) -> int:
        """Forget accumulated evidence. Called on re-baseline and on trust."""
        removed = 0
        for key in list(self._states):
            state = self._states[key]
            if state.server == server and (tool is None or state.tool == tool):
                self._states.pop(key)
                removed += 1
        if removed:
            self.save()
        return removed

    def calibrate(self, benign_scores: list[float], *, target_cycles: int = 50) -> dict[str, float]:
        """Derive k and h from benign observations only.

        k goes just above the benign distribution so ordinary noise contributes
        nothing. h is then set so that a purely benign series of ``target_cycles``
        would not be expected to trigger - the in-control run length, which is
        what converts directly into a false-alarm rate per cycle.
        """
        if not benign_scores:
            raise ValueError("no benign observations supplied; cannot calibrate")
        ordered = sorted(benign_scores)
        index = max(0, min(len(ordered) - 1, int(round(0.95 * len(ordered))) - 1))
        k = round(ordered[index], 4)

        # Worst-case benign accumulation per cycle, extended over the target run.
        residual = max(0.0, (sum(s - k for s in ordered if s > k) / len(ordered)))
        h = round(max(0.5, residual * target_cycles * 1.25), 4)
        self.k, self.h = k, h
        return {"k": k, "h": h, "n_observations": len(ordered),
                "target_cycles": target_cycles}
