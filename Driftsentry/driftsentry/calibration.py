"""Phase 4 - threshold calibration.

The scorer needs exactly one calibrated parameter: the drift ratio at which a
behavioural change stops being normal noise and becomes an alert. This module
derives it, records how it was derived, and persists it.

The methodological rule this module exists to enforce
    "Calibrate the threshold on a held-out set of benign servers only, placed
    above the observed benign drift distribution. No test-set data may touch the
    threshold - this is what makes RQ2/RQ3 defensible."

    A threshold fitted after looking at the attacks it is meant to catch proves
    nothing: the detector was told the answer. So calibration here only ever
    consumes re-probes of servers the user has approved as benign, every run
    records which servers and how many observations produced the number, and the
    saved record is what the write-up cites. Phase 8 supplies the disjoint
    calibration/test split; this module supplies the mechanism and the paper
    trail.

Why the threshold sits ABOVE the benign band, not at it
    A probe's variance band already estimates how far benign samples spread, so
    roughly half of future benign samples of a noisy tool land near ratio 1.0 by
    construction. Alerting at ratio > 1.0 would therefore fire on healthy tools
    constantly. The alert line belongs above the whole observed benign
    distribution, with a margin for the samples we have not seen yet.
"""
from __future__ import annotations

import json
import logging
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.calibration")

# Used when nothing has been calibrated yet. Chosen to sit above the benign
# ratios seen on the development fixtures, and reported everywhere as
# "provisional" so it can never be mistaken for a measured result.
PROVISIONAL_THRESHOLD = 1.5

# Multiplicative headroom above the chosen benign operating point.
DEFAULT_MARGIN = 1.25

# Target false-alarm rate on benign data. The threshold is placed at this
# quantile of the benign ratio distribution, which also makes calibration robust
# to outliers: taking the raw maximum would let one freak observation dictate the
# threshold. That matters here because a perfectly deterministic tool has a
# near-zero variance band, so a single flicker yields a ratio in the hundreds of
# thousands - and a max-based threshold would then silence the detector
# permanently. Allowing the top TARGET_FAR fraction to sit above the line keeps
# one outlier from doing that, and states the operating point explicitly, which
# is what RQ2 has to report anyway.
DEFAULT_TARGET_FAR = 0.01

# The calibrated threshold is a multiplier on each probe's own variance band, and
# a ratio of 1.0 means "exactly at the edge of the benign band this tool measured
# for itself". Alerting below that would contradict the band: those samples are,
# by construction, ones benign behaviour is expected to produce. So the threshold
# never drops under 1.0 no matter what a small calibration set suggests - the two
# layers stay consistent, and a thin calibration run cannot make the detector
# hair-trigger.
MIN_THRESHOLD = 1.0

# Below this many servers or observations the number is too fragile to defend;
# it is still written, but flagged as weak.
MIN_SERVERS = 3
MIN_OBSERVATIONS = 30


@dataclass
class Calibration:
    """A calibrated threshold together with the provenance to defend it."""

    threshold_ratio: float
    method: str
    margin: float
    n_servers: int
    n_observations: int
    servers: list[str]
    max_benign_ratio: float
    p99_benign_ratio: float
    mean_benign_ratio: float
    embedding_backend: str
    created_at: str
    target_far: float = DEFAULT_TARGET_FAR
    empirical_far: float = 0.0
    seed: int | None = None
    weak: bool = False
    notes: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Calibration":
        known = {f for f in cls.__dataclass_fields__}  # tolerate older files
        return cls(**{k: v for k, v in data.items() if k in known})

    def describe(self) -> str:
        base = (f"{self.threshold_ratio:.3f} from {self.n_observations} benign observations "
                f"across {self.n_servers} server(s), FAR {self.empirical_far:.1%} "
                f"[{self.embedding_backend}]")
        return base + (" - WEAK" if self.weak else "")


def calibration_path() -> Path:
    return data_dir() / "calibration.json"


def save(calibration: Calibration) -> Path:
    path = calibration_path()
    path.write_text(json.dumps(calibration.to_dict(), indent=2), encoding="utf-8")
    log.info("calibration saved: %s", path)
    return path


def load() -> Calibration | None:
    path = calibration_path()
    if not path.is_file():
        return None
    try:
        return Calibration.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001 - a corrupt file must not brick scoring
        log.warning("could not read %s (%s); falling back to the provisional threshold", path, exc)
        return None


def active_threshold(backend: str | None = None) -> tuple[float, str]:
    """Return (threshold, source) for scoring right now.

    Refuses to reuse a threshold calibrated under a different embedding backend:
    distances from two different embedding spaces are not comparable, so a
    threshold carried across them would be meaningless.
    """
    calibration = load()
    if calibration is None:
        return PROVISIONAL_THRESHOLD, "provisional (not calibrated)"
    if backend and calibration.embedding_backend != backend:
        log.warning(
            "stored calibration was made with %s but scoring uses %s; "
            "thresholds are not comparable across embedding spaces - using the provisional value",
            calibration.embedding_backend, backend,
        )
        return PROVISIONAL_THRESHOLD, (
            f"provisional (calibration was for {calibration.embedding_backend}, "
            f"current backend is {backend})"
        )
    source = f"calibrated {calibration.created_at[:10]}"
    if calibration.weak:
        source += " (weak)"
    return calibration.threshold_ratio, source


def _quantile(ordered: Sequence[float], q: float) -> float:
    """Nearest-rank quantile of an already-sorted sequence."""
    if not ordered:
        raise ValueError("empty sequence")
    index = int(round(q * len(ordered))) - 1
    return ordered[max(0, min(len(ordered) - 1, index))]


def calibrate_from_ratios(
    ratios: Sequence[float],
    *,
    servers: Sequence[str],
    embedding_backend: str,
    margin: float = DEFAULT_MARGIN,
    target_far: float = DEFAULT_TARGET_FAR,
    seed: int | None = None,
    notes: str = "",
) -> Calibration:
    """Derive a threshold from benign drift ratios.

    ``ratios`` must come exclusively from re-probes of servers believed benign.
    The threshold is the (1 - target_far) quantile of that benign distribution,
    times a margin for the samples we have not seen yet. Choosing an operating
    point this way - rather than "above the worst thing we happened to observe" -
    states the accepted false-alarm rate explicitly and keeps a single freak
    observation from dictating the threshold.
    """
    if not ratios:
        raise ValueError("no benign observations supplied; cannot calibrate")

    ordered = sorted(float(r) for r in ratios)
    max_ratio = ordered[-1]
    mean_ratio = float(statistics.fmean(ordered))
    p99 = _quantile(ordered, 0.99)

    operating_point = _quantile(ordered, 1.0 - target_far)
    threshold = max(operating_point * margin, MIN_THRESHOLD)
    empirical_far = sum(1 for r in ordered if r >= threshold) / len(ordered)

    warnings: list[str] = []
    if operating_point * margin < MIN_THRESHOLD:
        warnings.append(
            f"the calibration data alone suggested {operating_point * margin:.3f}, which is "
            f"below the floor of {MIN_THRESHOLD}; using the floor. This usually means too few "
            "benign observations - collect more before quoting this threshold"
        )
    if empirical_far > target_far:
        warnings.append(
            f"empirical false-alarm rate on the calibration set is {empirical_far:.1%}, "
            f"above the {target_far:.1%} target - more benign data is needed"
        )
    unique_servers = sorted(set(servers))
    if len(unique_servers) < MIN_SERVERS:
        warnings.append(
            f"calibrated on {len(unique_servers)} server(s); at least {MIN_SERVERS} are "
            "needed before this threshold should be quoted as a result"
        )
    if len(ordered) < MIN_OBSERVATIONS:
        warnings.append(
            f"only {len(ordered)} benign observations; at least {MIN_OBSERVATIONS} are "
            "needed for a stable estimate"
        )

    calibration = Calibration(
        threshold_ratio=round(threshold, 4),
        method=f"quantile(benign_ratios, {1.0 - target_far:.4f}) x {margin}",
        margin=margin,
        target_far=target_far,
        empirical_far=round(empirical_far, 4),
        n_servers=len(unique_servers),
        n_observations=len(ordered),
        servers=unique_servers,
        max_benign_ratio=round(max_ratio, 4),
        p99_benign_ratio=round(p99, 4),
        mean_benign_ratio=round(mean_ratio, 4),
        embedding_backend=embedding_backend,
        created_at=datetime.now(timezone.utc).isoformat(),
        seed=seed,
        weak=bool(warnings),
        notes=notes or "benign servers only; no rug-pull or test data was used",
        warnings=warnings,
    )
    return calibration
