"""Join the attacker's observations to the collector's labels.

The attacker wrote one row per call and does not know what kind of traffic it
was serving. The collector wrote time windows and does know. This module is
the only place the two meet, and it is deliberately strict about how.

Why the checks here are assertions and not warnings
    Every downstream number in RQ3 - AUC, which family wins, how much
    detection an L6 attacker costs - rests on these labels being right. A row
    attributed to the wrong window is not noise: it looks exactly like signal,
    it is invisible in the output, and it would survive into the write-up. So
    anything ambiguous fails the build rather than being quietly dropped.

The grouping rule
    ``group`` is one process INSTANCE. Calls inside one server process are not
    independent - they share a client, a working directory, a session counter
    and a process age - so a split that put some calls from a session in train
    and others in test would leak, and every AUC would be inflated.

    A pid alone is not that identity. Windows recycles process ids, and a
    240-session collection spawns short-lived processes fast enough for it to
    happen: in the first full run, 9 of 226 pids were reused by a later
    process, twice with over a thousand seconds between them. Grouping on the
    raw pid merged those into one group and made it look as though a single
    process had served both genuine and probe traffic.

    The identity used instead is (pid, process start), where the start is
    recovered exactly as ``t - proc_age_s`` - features.py derives both from a
    single time.time() call, so the subtraction is lossless rather than
    approximate.

    A process instance must still belong to exactly ONE window, and that check
    is kept: with recycling accounted for, a mixed group now means genuinely
    overlapping sessions, which would be a real defect.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

GENUINE, PROBE = 0, 1


class LabelError(RuntimeError):
    """The labels cannot be trusted, so nothing downstream should run."""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def process_key(row: dict[str, Any]) -> str:
    """Identity of the process instance that served this call.

    A pid is reused; a pid plus the moment that process started is not.
    """
    pid = row.get("pid")
    age = row.get("proc_age_s")
    t = row.get("t")
    if age is None or t is None:
        return f"{pid}:unknown"
    return f"{pid}:{t - age!r}"


def _window_for(t: float, windows: list[dict[str, Any]]) -> list[int]:
    """Indices of every window containing this instant. More than one is a bug."""
    return [i for i, w in enumerate(windows) if w["start"] <= t <= w["end"]]


def build(
    collection_dir: str | Path,
    *,
    out_name: str = "dataset.jsonl",
    drop_before: float | None = None,
    mixed_groups: bool = False,
) -> dict[str, Any]:
    """Produce the labelled dataset, or raise if the labels are unsound.

    ``mixed_groups`` is for in-session traffic (follow-up H2b), where probes
    and genuine calls share one server process by design. Grouping on the
    process still keeps every session whole on one side of each split, so
    the purity check - which exists to catch overlapping *separate*
    sessions - does not apply there and is skipped.
    """
    source = Path(collection_dir)
    features = _read_jsonl(source / "features.jsonl")
    windows = _read_jsonl(source / "windows.jsonl")

    if not features:
        raise LabelError(f"no feature rows in {source}")
    if not windows:
        raise LabelError(f"no windows in {source} - nothing can be labelled")

    # The baseline capture is probe traffic, but it is not part of the
    # alternating collection: it runs once, with a different sample count, so
    # its session features are a shape that occurs exactly once. Rows before
    # the cutoff are outside every window anyway; this is explicit about why.
    if drop_before is None:
        meta = source / "collection.json"
        if meta.is_file():
            drop_before = json.loads(meta.read_text(encoding="utf-8")).get(
                "baseline_cutoff")

    rows: list[dict[str, Any]] = []
    unlabelled = 0
    ambiguous: list[dict[str, Any]] = []
    pre_baseline = 0

    for row in features:
        t = row.get("t")
        if t is None:
            raise LabelError("a feature row has no timestamp; it cannot be labelled")
        if drop_before is not None and t < drop_before:
            pre_baseline += 1
            continue

        hits = _window_for(t, windows)
        if not hits:
            # Between sessions: setup, teardown, or the attacker's own startup.
            unlabelled += 1
            continue
        if len(hits) > 1:
            ambiguous.append({"t": t, "pid": row.get("pid"),
                              "windows": [windows[i] for i in hits]})
            continue

        window = windows[hits[0]]
        rows.append({**row, "label": window["label"],
                     "group": process_key(row), "window": hits[0]})

    if ambiguous:
        raise LabelError(
            f"{len(ambiguous)} row(s) fall inside more than one window, so their "
            f"label is undefined. Sessions must run strictly in sequence; "
            f"overlapping windows mean the collector ran two at once. "
            f"First: {ambiguous[0]}"
        )

    if not mixed_groups:
        _check_pid_purity(rows)

    out_path = source / out_name
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")

    labels = Counter(r["label"] for r in rows)
    groups = {r["group"] for r in rows}
    summary = {
        "rows": len(rows),
        "genuine_rows": labels[GENUINE],
        "probe_rows": labels[PROBE],
        "groups": len(groups),
        "unlabelled_dropped": unlabelled,
        "pre_baseline_dropped": pre_baseline,
        "mixed_groups": mixed_groups,
        "dataset": str(out_path),
    }
    (source / "dataset.json").write_text(json.dumps(summary, indent=2),
                                         encoding="utf-8")
    return summary


def _check_pid_purity(rows: list[dict[str, Any]]) -> None:
    """Every process instance must have served exactly one kind of traffic.

    Sessions run one at a time, so a group seeing both labels means the
    collector overlapped them - GroupKFold would then mix labels within a
    fold. Recycled pids used to trigger this falsely; the group key now
    includes the process start, so a failure here is a real one.
    """
    by_pid: dict[Any, set[int]] = defaultdict(set)
    for row in rows:
        by_pid[row["group"]].add(row["label"])

    impure = {key: sorted(labels) for key, labels in by_pid.items() if len(labels) > 1}
    if impure:
        raise LabelError(
            f"{len(impure)} process instance(s) served BOTH genuine and probe "
            f"traffic: {dict(list(impure.items())[:3])}. Grouping on the process "
            f"is what stops a session leaking across a train/test split, so a "
            f"mixed group makes every AUC untrustworthy. Process-id recycling is "
            f"already accounted for by keying on (pid, start), so this means the "
            f"sessions genuinely overlapped - they must run strictly in sequence."
        )


def describe(dataset_path: str | Path) -> dict[str, Any]:
    """Shape of a built dataset, for the checkpoint report."""
    rows = _read_jsonl(Path(dataset_path))
    labels = Counter(r["label"] for r in rows)
    per_group = Counter(r["group"] for r in rows)
    return {
        "rows": len(rows),
        "genuine": labels[GENUINE],
        "probe": labels[PROBE],
        "groups": len(per_group),
        "min_calls_per_group": min(per_group.values()) if per_group else 0,
        "max_calls_per_group": max(per_group.values()) if per_group else 0,
        "tools": sorted({r.get("tool") for r in rows if r.get("tool")}),
        "clients": sorted({r.get("client_name") for r in rows}),
    }
