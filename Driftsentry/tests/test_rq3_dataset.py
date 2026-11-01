"""Can the RQ3 labels be trusted?

Every number in RQ3 rests on these labels. A row joined to the wrong window is
not noise - it is indistinguishable from signal, invisible in the output, and
would survive into the write-up unchallenged. So the builder is written to
fail loudly on anything ambiguous, and these tests are mostly about proving
that it does.

The two failures worth most attention:

    overlapping windows   mean the collector ran an agent session and a probe
                          cycle at the same time. Rows in the overlap have no
                          defined label at all.
    a mixed process       means one server process served both genuine and
                          probe traffic. Grouping on pid is what stops a
                          session leaking across a train/test split, so a
                          mixed group silently inflates every AUC.
"""
from __future__ import annotations

import json

import pytest

from eval.rq3_dataset import GENUINE, PROBE, LabelError, build, describe


def _write(tmp_path, features, windows, collection=None):
    (tmp_path / "features.jsonl").write_text(
        "\n".join(json.dumps(f) for f in features), encoding="utf-8")
    (tmp_path / "windows.jsonl").write_text(
        "\n".join(json.dumps(w) for w in windows), encoding="utf-8")
    if collection is not None:
        (tmp_path / "collection.json").write_text(json.dumps(collection),
                                                  encoding="utf-8")
    return tmp_path


def _row(t, pid, **extra):
    base = {"t": t, "pid": pid, "tool": "lookup_customer",
            "args": {"customer_id": "C-1001"}, "client_name": "claude-ai",
            "client_version": "0.1.0", "env_count": 13, "has_home": True,
            "cwd": "/x", "parent_name": "", "parent_argc": None,
            "calls_before": 0, "distinct_tools_before": 0,
            "proc_age_s": 0.5, "gap_s": None}
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #
def test_rows_are_labelled_from_the_window_that_contains_them(tmp_path):
    summary = build(_write(
        tmp_path,
        features=[_row(10.0, 100), _row(10.5, 100), _row(20.0, 200)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0, "task": "t01"},
                 {"label": PROBE, "start": 19.0, "end": 22.0, "cycle": 1}],
    ))
    assert summary["rows"] == 3
    assert summary["genuine_rows"] == 2
    assert summary["probe_rows"] == 1
    assert summary["groups"] == 2


def test_group_is_the_process_not_the_row(tmp_path):
    """Calls inside one process share a client, a cwd and a session counter."""
    build(_write(
        tmp_path,
        features=[_row(10.0, 100), _row(10.5, 100), _row(11.0, 100)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    rows = [json.loads(l) for l in
            (tmp_path / "dataset.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {r["group"] for r in rows} == {100}
    assert all(r["label"] == GENUINE for r in rows)


def test_rows_between_sessions_are_dropped_not_guessed(tmp_path):
    """Startup and teardown traffic belongs to no session."""
    summary = build(_write(
        tmp_path,
        features=[_row(5.0, 99), _row(10.0, 100), _row(50.0, 101)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    assert summary["rows"] == 1
    assert summary["unlabelled_dropped"] == 2


# --------------------------------------------------------------------------- #
# The failures that must be loud
# --------------------------------------------------------------------------- #
def test_overlapping_windows_fail_the_build(tmp_path):
    """Two sessions at once means rows with no defined label."""
    with pytest.raises(LabelError, match="more than one window"):
        build(_write(
            tmp_path,
            features=[_row(10.0, 100)],
            windows=[{"label": GENUINE, "start": 9.0, "end": 12.0},
                     {"label": PROBE, "start": 9.5, "end": 11.0}],
        ))


def test_a_process_serving_both_labels_fails_the_build(tmp_path):
    """A mixed group would leak a session across a train/test split."""
    with pytest.raises(LabelError, match="BOTH genuine and probe"):
        build(_write(
            tmp_path,
            features=[_row(10.0, 100), _row(20.0, 100)],   # same pid, two windows
            windows=[{"label": GENUINE, "start": 9.0, "end": 12.0},
                     {"label": PROBE, "start": 19.0, "end": 22.0}],
        ))


def test_a_row_without_a_timestamp_fails_rather_than_being_dropped(tmp_path):
    with pytest.raises(LabelError, match="no timestamp"):
        build(_write(
            tmp_path,
            features=[{"pid": 100, "tool": "x"}],
            windows=[{"label": GENUINE, "start": 0.0, "end": 99.0}],
        ))


def test_no_windows_is_an_error_not_an_empty_dataset(tmp_path):
    with pytest.raises(LabelError, match="nothing can be labelled"):
        build(_write(tmp_path, features=[_row(10.0, 100)], windows=[]))


def test_no_feature_rows_is_an_error(tmp_path):
    with pytest.raises(LabelError, match="no feature rows"):
        build(_write(tmp_path, features=[],
                     windows=[{"label": GENUINE, "start": 0.0, "end": 9.0}]))


# --------------------------------------------------------------------------- #
# The baseline capture
# --------------------------------------------------------------------------- #
def test_baseline_traffic_is_excluded_by_the_recorded_cutoff(tmp_path):
    """Baselining probes once, with a different sample count.

    Its session features are a shape that occurs exactly once in the whole
    collection, so including it would hand the classifier a free split.
    """
    summary = build(_write(
        tmp_path,
        features=[_row(1.0, 50), _row(2.0, 50), _row(10.0, 100)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
        collection={"baseline_cutoff": 5.0},
    ))
    assert summary["pre_baseline_dropped"] == 2
    assert summary["rows"] == 1


def test_an_explicit_cutoff_overrides_the_recorded_one(tmp_path):
    summary = build(_write(
        tmp_path,
        features=[_row(1.0, 50), _row(10.0, 100)],
        windows=[{"label": GENUINE, "start": 0.0, "end": 99.0}],
        collection={"baseline_cutoff": 5.0},
    ), drop_before=0.0)
    assert summary["pre_baseline_dropped"] == 0
    assert summary["rows"] == 2


# --------------------------------------------------------------------------- #
# Window boundaries
# --------------------------------------------------------------------------- #
def test_a_row_exactly_on_a_boundary_is_inside_the_window(tmp_path):
    summary = build(_write(
        tmp_path,
        features=[_row(9.0, 100), _row(12.0, 100)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    assert summary["rows"] == 2


def test_windows_are_not_widened_to_catch_stragglers(tmp_path):
    """Widening risks swallowing a neighbour's first call.

    A dropped row costs one observation. A mislabelled row looks like signal.
    """
    summary = build(_write(
        tmp_path,
        features=[_row(12.001, 100)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    assert summary["rows"] == 0
    assert summary["unlabelled_dropped"] == 1


# --------------------------------------------------------------------------- #
# describe()
# --------------------------------------------------------------------------- #
def test_describe_reports_the_shape_for_the_checkpoint(tmp_path):
    build(_write(
        tmp_path,
        features=[_row(10.0, 100, tool="lookup_customer"),
                  _row(10.5, 100, tool="read_document"),
                  _row(20.0, 200, tool="get_weather")],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0},
                 {"label": PROBE, "start": 19.0, "end": 22.0}],
    ))
    shape = describe(tmp_path / "dataset.jsonl")
    assert shape == {
        "rows": 3, "genuine": 2, "probe": 1, "groups": 2,
        "min_calls_per_group": 1, "max_calls_per_group": 2,
        "tools": ["get_weather", "lookup_customer", "read_document"],
        "clients": ["claude-ai"],
    }


# --------------------------------------------------------------------------- #
# Durability
#
# A 120-session collection was interrupted at session 79. The attacker's
# feature rows were on disk, but the labels were held in memory and written
# only at the end, so every one was lost and the run was unusable. Labels
# could not be reconstructed from row counts either: that would make "number
# of calls in the process" the label, and testing whether the session family
# separates would then be circular.
# --------------------------------------------------------------------------- #
def test_windows_are_on_disk_before_the_collection_ends(tmp_path):
    from eval.collect import GENUINE, PROBE, Collector

    collector = Collector(tmp_path / "atk-project", tmp_path / "out",
                          tmp_path / "ws")
    collector.out_dir.mkdir(parents=True, exist_ok=True)
    collector.windows_path.unlink(missing_ok=True)

    collector._window(GENUINE, 10.0, 12.0, task="t01")
    collector._window(PROBE, 13.0, 25.0, cycle=1)

    # No finish(), no clean shutdown - the process "died" here.
    assert collector.windows_path.is_file()
    written = [json.loads(l) for l in
               collector.windows_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(written) == 2
    assert [w["label"] for w in written] == [GENUINE, PROBE]
    assert written[0]["task"] == "t01" and written[1]["cycle"] == 1


def test_a_new_run_does_not_inherit_the_previous_run_s_windows(tmp_path):
    """Stale labels joined to fresh rows would mislabel silently."""
    from eval.collect import GENUINE, Collector

    collector = Collector(tmp_path / "atk-project", tmp_path / "out",
                          tmp_path / "ws")
    collector.out_dir.mkdir(parents=True, exist_ok=True)
    collector._window(GENUINE, 1.0, 2.0, task="old")
    assert collector.windows_path.is_file()

    collector.prepare()          # a fresh run starts here
    assert not collector.windows_path.exists(), \
        "prepare() must clear windows from an earlier run"
