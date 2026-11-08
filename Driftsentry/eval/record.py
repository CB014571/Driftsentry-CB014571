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
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


class SchemaMismatch(RuntimeError):
    """An existing results file does not match the current row definition."""


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

    # -- the three detectors, scored on the SAME episode (RQ2 / H2) --------
    #
    # Separate booleans rather than one verdict, because H2 compares detectors
    # that saw identical traffic. Running them as three experiments would make
    # the comparison unpaired, discard the pairing McNemar needs, and let a
    # real difference be missed.
    hash_detected: bool = False      # definition changed: what mcp-scan sees
    passive_detected: bool = False   # a frozen rule over passive findings
    full_detected: bool = False      # the full scorer's verdict
    passive_available: bool = False  # distinguishes "saw nothing" from "did not run"

    # -- timing / cost -----------------------------------------------------
    verification_cycle: int = 0
    calls_to_detection: int = 0
    time_to_detection: float = 0.0
    execution_duration: float = 0.0
    cpu_pct: float = 0.0
    rss_mb: float = 0.0
    proxy_latency_ms: float = 0.0    # mean per replayed call, through the proxy
    cycle_seconds: float = 0.0       # wall clock for one verification cycle
    replayed_calls: int = 0

    # -- provenance --------------------------------------------------------
    detector_version: str = ""
    embedding_backend: str = ""
    config_hash: str = ""
    note: str = ""

    # -- update episodes (T27, RQ3a) --------------------------------------
    #
    # Appended after every existing column, never inserted, so a results file
    # written before these existed is an exact prefix of this header and can
    # still be resumed (see ResultWriter). Empty on every non-update row.
    release: str = ""                # the release verified: v2 for an update
    cover: str = ""                  # C0-C3
    declared_changes: str = ""       # DeclaredDiff.to_dict() as JSON
    residue_verdict: str = ""        # accepted | residue_alert | escalation | held_for_review
    residue_signals: str = ""        # residue signal names, comma-separated
    escalations: str = ""            # tool:escalation, comma-separated
    held_for_review: int = 0

    # The SAME re-probe scored five ways. H3 compares these, so they must
    # come from one measurement: separate runs would make the comparison
    # unpaired and discard what McNemar needs. "alert" is any alert;
    # "attributed" is an alert on the attacked tool naming a signal the
    # attack causes, which is what H3 counts.
    alert_accept_rebaseline: bool = False
    attributed_accept_rebaseline: bool = False
    alert_refuse_all: bool = False
    attributed_refuse_all: bool = False
    alert_definition_diff: bool = False
    attributed_definition_diff: bool = False
    alert_new_host_only: bool = False
    attributed_new_host_only: bool = False
    alert_residue: bool = False
    attributed_residue: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


FIELD_NAMES = [f.name for f in fields(ExperimentRow)]

# Each column's default, so a writer can tell whether a row carries anything
# in a column an older file does not have.
_DEFAULTS: dict[str, Any] = {
    f.name: (f.default if f.default is not MISSING
             else f.default_factory() if f.default_factory is not MISSING  # type: ignore[misc]
             else None)
    for f in fields(ExperimentRow)
}


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
        self._dropped: list[str] = []
        self.count = 0

    def __enter__(self) -> "ResultWriter":
        new_file = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        header = FIELD_NAMES if new_file else self._require_matching_header()
        self._dropped = [f for f in FIELD_NAMES if f not in header]
        self._csv_handle = self.csv_path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._csv_handle, fieldnames=header,
                                      extrasaction="ignore")
        if new_file:
            self._writer.writeheader()
        self._jsonl_handle = self.jsonl_path.open("a", encoding="utf-8")
        return self

    def _require_matching_header(self) -> None:
        """Refuse to append rows the existing header cannot describe.

        Measured failure, not a hypothetical. Seven columns were added to
        ExperimentRow while an exp3 CSV from an earlier run was still on disk.
        Appending wrote 56 fields under a 49-field header, so every value past
        the insertion point shifted one column left: config_hash came out
        holding "121.2", a latency. Nothing raised at the time, and a results
        file that silently misaligns is worse than one that fails - the
        numbers still look like numbers.

        The file is rotated rather than overwritten, because the old rows are
        still evidence of whatever run produced them.

        One mismatch is safe, and is accepted: an older file whose header is
        an exact PREFIX of today's. Columns are only ever appended (T27), so
        such a file lines up with every column it has, and the rows going into
        it leave the newer columns at their defaults - append() refuses any
        row that does not. Without this, adding a column would retire every
        results file still being resumed, and a 66-episode sweep would restart
        from nothing. Returns the header to write under.
        """
        with self.csv_path.open("r", newline="", encoding="utf-8") as handle:
            existing = next(csv.reader(handle), [])
        if existing == FIELD_NAMES:
            return FIELD_NAMES
        if existing and FIELD_NAMES[:len(existing)] == existing:
            return existing

        missing = [f for f in FIELD_NAMES if f not in existing]
        extra_cols = [f for f in existing if f not in FIELD_NAMES]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        retired = self.csv_path.with_name(f"{self.csv_path.stem}.{stamp}.old.csv")
        self.csv_path.rename(retired)
        if self.jsonl_path.exists():
            self.jsonl_path.rename(
                self.jsonl_path.with_name(f"{self.jsonl_path.stem}.{stamp}.old.jsonl"))

        raise SchemaMismatch(
            f"{self.csv_path.name} was written with a different schema "
            f"({len(existing)} columns, now {len(FIELD_NAMES)}). "
            f"Missing: {missing or 'none'}. Unknown: {extra_cols or 'none'}. "
            f"Appending would have shifted every value past the first new "
            f"column. The old file has been moved to {retired.name}; re-run to "
            f"start a clean one."
        )

    def append(self, row: ExperimentRow, extra: dict[str, Any] | None = None) -> None:
        data = row.to_dict()
        carried = [f for f in self._dropped if data.get(f) != _DEFAULTS.get(f)]
        if carried:
            raise SchemaMismatch(
                f"{self.csv_path.name} predates the columns {carried}, and this "
                f"row has values in them. Writing it would lose those values "
                f"silently; write update episodes to a results file of their own.")
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
