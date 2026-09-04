"""One row of experimental evidence, and how to write it down.

Every experiment in Phase 9 reduces to a stream of these. The field list is
deliberately wide: it is far cheaper to record a column now than to re-run
several hours of episodes because one number was not captured.

Two fields carry more weight than the rest:

``attack_fired``
    Comes from the adversarial server's own event log, never from the detector.
    A row where the attack never fired is not a missed detection, and mixing the
    two would silently inflate or deflate every recall figure in the write-up.

``config_hash``
    A digest of the detector configuration that produced the row. The
    methodology promises that thresholds were not tuned after seeing test data;
    this is what makes that promise auditable rather than merely stated.
"""
from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class ExperimentRow:
    """A single verification cycle within a single episode."""

    # -- identity ----------------------------------------------------------
    experiment_id: str
    episode_id: str
    timestamp: str
    schema_version: int = SCHEMA_VERSION

    # -- independent variables --------------------------------------------
    seed: int = 0
    key_id: str = ""
    server_id: str = ""
    tool_id: str = ""
    attack_family: str = "benign"
    attack_level: str = ""
    probe_mode: str = "fixed"
    scoring_mode: str = "max"
    partition: str = "development"          # development | calibration | test

    # -- ground truth (from the attacker, never the detector) --------------
    attack_fired: bool = False
    probe_recognised: bool = False
    probe_skip_count: int = 0
    ground_truth_events: str = ""           # comma-separated event kinds

    # -- detector outcome --------------------------------------------------
    detected: bool = False
    outcome: str = ""                       # detected | missed | never_triggered | benign_ok | false_alarm
    verdict: str = ""
    final_score: float = 0.0
    winning_signal: str = ""
    threshold_ratio: float = 0.0

    # -- component scores --------------------------------------------------
    embedding_score: float = 0.0
    structure_score: float = 0.0
    error_score: float = 0.0
    determinism_score: float = 0.0
    field_drift_score: float = 0.0
    rule_score: float = 0.0                 # content rules
    sideeffect_score: float = 0.0           # network / file / process rules
    consistency_score: float = 0.0          # differential probing
    passive_score: float = 0.0
    temporal_score: float = 0.0
    definition_changed: bool = False

    # -- evidence families (corroboration) ---------------------------------
    family_a: float = 0.0                   # semantic / content
    family_b: float = 0.0                   # structure / error
    family_c: float = 0.0                   # side effects
    family_d: float = 0.0                   # surface integrity
    family_e: float = 0.0                   # adaptive evasion

    # -- timing / cost -----------------------------------------------------
    verification_cycle: int = 0
    calls_to_detection: int = 0
    time_to_detection: float = 0.0
    execution_duration: float = 0.0
    cpu_pct: float = 0.0
    rss_mb: float = 0.0

    # -- provenance --------------------------------------------------------
    detector_version: str = ""
    embedding_backend: str = ""
    config_hash: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


FIELD_NAMES = [f.name for f in fields(ExperimentRow)]


# --------------------------------------------------------------------------- #
# Pulling component scores out of a scored report
# --------------------------------------------------------------------------- #
_CONTENT_RULES = {"rule:credential_shaped_output", "rule:instruction_shaped_output"}
_SIDEEFFECT_RULES = {"rule:new_egress_host", "rule:secret_file_read", "rule:new_file_access"}


def _max_signal(report, *names: str) -> float:
    """Highest score among the named signals, across every probe of every tool."""
    best = 0.0
    for tool in report.tools:
        pools = [tool.signals]
        pools.extend(p.signals for p in tool.probes)
        for signals in pools:
            for signal in signals:
                if signal.name in names and signal.score > best:
                    best = signal.score
    return best


def _max_signal_prefix(report, prefix: str, allowed: set[str]) -> float:
    best = 0.0
    for tool in report.tools:
        pools = [tool.signals]
        pools.extend(p.signals for p in tool.probes)
        for signals in pools:
            for signal in signals:
                if signal.name.startswith(prefix) and signal.name in allowed:
                    best = max(best, signal.score)
    return best


def components(report) -> dict[str, float]:
    """Decompose a DriftReport into the per-signal columns.

    Reported separately rather than only as the winning signal, because the
    ablation experiment needs to know what each signal contributed even on the
    cycles where it did not win.
    """
    return {
        "embedding_score": _max_signal(report, "behavioural_drift"),
        "structure_score": _max_signal(report, "structural_change"),
        "error_score": _max_signal(report, "error_behaviour"),
        "determinism_score": _max_signal(report, "determinism_break"),
        "field_drift_score": _max_signal(report, "field_drift"),
        "rule_score": _max_signal_prefix(report, "rule:", _CONTENT_RULES),
        "sideeffect_score": _max_signal_prefix(report, "rule:", _SIDEEFFECT_RULES),
        "consistency_score": _max_signal(report, "probe_consistency"),
        "passive_score": _max_signal(report, "passive_inconsistency"),
        "temporal_score": _max_signal(report, "temporal_trend"),
    }


def config_hash(config: dict[str, Any]) -> str:
    """Stable digest of the detector configuration behind a row."""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)
    return "cfg:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
class ResultWriter:
    """Appends rows to CSV and JSONL simultaneously.

    Both, on purpose: the CSV is what goes into a spreadsheet or R for the
    write-up, and the JSONL keeps nested detail the CSV flattens away. Rows are
    flushed as they arrive so an interrupted run keeps everything up to the
    interruption instead of losing the batch.
    """

    def __init__(self, out_dir: Path, name: str) -> None:
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = self.dir / f"{name}.csv"
        self.jsonl_path = self.dir / f"{name}.jsonl"
        self._csv_handle = None
        self._writer = None
        self._jsonl_handle = None
        self.count = 0

    def __enter__(self) -> "ResultWriter":
        new_file = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        self._csv_handle = self.csv_path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._csv_handle, fieldnames=FIELD_NAMES)
        if new_file:
            self._writer.writeheader()
        self._jsonl_handle = self.jsonl_path.open("a", encoding="utf-8")
        return self

    def append(self, row: ExperimentRow, extra: dict[str, Any] | None = None) -> None:
        data = row.to_dict()
        self._writer.writerow(data)
        self._csv_handle.flush()
        payload = dict(data)
        if extra:
            payload["detail"] = extra
        self._jsonl_handle.write(json.dumps(payload, default=str) + "\n")
        self._jsonl_handle.flush()
        self.count += 1

    def __exit__(self, *exc: object) -> None:
        for handle in (self._csv_handle, self._jsonl_handle):
            try:
                if handle is not None:
                    handle.close()
            except Exception:  # pragma: no cover - best effort on shutdown
                pass
