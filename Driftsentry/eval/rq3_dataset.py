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
    ``group`` is the attacker's pid, not the row index. Calls inside one server
    process are not independent - they share a client, a working directory, a
    session counter and a process age - so a split that put some calls from a
    session in train and others in test would leak, and every AUC would be
    inflated. GroupKFold on pid is what prevents that.

    This also means a pid must belong to exactly ONE window. A process serving
    both genuine and probe traffic could not be assigned a single label, and
    because sessions run strictly in sequence that should never happen. The
    check exists to prove it did not.
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


def _window_for(t: float, windows: list[dict[str, Any]]) -> list[int]:
    """Indices of every window containing this instant. More than one is a bug."""
    return [i for i, w in enumerate(windows) if w["start"] <= t <= w["end"]]


def build(
    collection_dir: str | Path,
    *,
    out_name: str = "dataset.jsonl",
    drop_before: float | None = None,
) -> dict[str, Any]:
    """Produce the labelled dataset, or raise if the labels are unsound."""
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
        rows.append({**row, "label": window["label"], "group": row["pid"],
                     "window": hits[0]})

    if ambiguous:
        raise LabelError(
            f"{len(ambiguous)} row(s) fall inside more than one window, so their "
            f"label is undefined. Sessions must run strictly in sequence; "
            f"overlapping windows mean the collector ran two at once. "
            f"First: {ambiguous[0]}"
        )

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
        "dataset": str(out_path),
    }
    (source / "dataset.json").write_text(json.dumps(summary, indent=2),
                                         encoding="utf-8")
    return summary


def _check_pid_purity(rows: list[dict[str, Any]]) -> None:
    """Every process must have served exactly one kind of traffic.

    Sessions run one at a time, so a pid seeing both labels means either the
    collector overlapped them or the operating system recycled a pid between
    sessions. Either way the group is not a valid unit to split on, and
    GroupKFold would mix labels within a fold.
    """
    by_pid: dict[Any, set[int]] = defaultdict(set)
    for row in rows:
        by_pid[row["group"]].add(row["label"])

    impure = {pid: sorted(labels) for pid, labels in by_pid.items() if len(labels) > 1}
    if impure:
        raise LabelError(
            f"{len(impure)} process id(s) served BOTH genuine and probe traffic: "
            f"{dict(list(impure.items())[:3])}. Grouping on pid is what stops a "
            f"session leaking across a train/test split, so a mixed group makes "
            f"every AUC untrustworthy. Likely causes: overlapping sessions, or a "
            f"recycled pid between runs."
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
