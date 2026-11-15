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


def _row(t, pid, start=None, **extra):
    """One observation. ``start`` is when that process began; rows sharing a
    pid AND a start are one process instance, which is the grouping unit."""
    base = {"t": t, "pid": pid, "tool": "lookup_customer",
            "args": {"customer_id": "C-1001"}, "client_name": "claude-ai",
            "client_version": "0.1.0", "env_count": 13, "has_home": True,
            "cwd": "/x", "parent_name": "", "parent_argc": None,
            "calls_before": 0, "distinct_tools_before": 0,
            "proc_age_s": t - (start if start is not None else t - 0.5),
            "gap_s": None}
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #
def test_rows_are_labelled_from_the_window_that_contains_them(tmp_path):
    summary = build(_write(
        tmp_path,
        features=[_row(10.0, 100, start=9.5), _row(10.5, 100, start=9.5),
                  _row(20.0, 200, start=19.5)],
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
        features=[_row(10.0, 100, start=9.5), _row(10.5, 100, start=9.5),
                  _row(11.0, 100, start=9.5)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    rows = [json.loads(l) for l in
            (tmp_path / "dataset.jsonl").read_text(encoding="utf-8").splitlines()]
    # One group, and it is the process instance rather than the bare pid.
    assert len({r["group"] for r in rows}) == 1
    assert all(str(r["group"]).startswith("100:") for r in rows)
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
    with pytest.raises(LabelError, match="genuinely overlapped"):
        build(_write(
            tmp_path,
            # One process instance (same pid AND start) spanning two windows.
            features=[_row(10.0, 100, start=9.5), _row(20.0, 100, start=9.5)],
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
        features=[_row(10.0, 100, start=9.5, tool="lookup_customer"),
                  _row(10.5, 100, start=9.5, tool="read_document"),
                  _row(20.0, 200, start=19.5, tool="get_weather")],
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


# --------------------------------------------------------------------------- #
# Process identity
#
# Windows recycles process ids. A 240-session collection spawns short-lived
# processes fast enough for it to happen - 9 of 226 pids were reused in the
# first full run, twice with over a thousand seconds between them. Grouping on
# the raw pid merged those into one group and reported a mixed-label process
# that never existed.
# --------------------------------------------------------------------------- #
def test_a_recycled_pid_is_two_processes_not_one(tmp_path):
    """The false failure that stopped a completed 120-session collection."""
    summary = build(_write(
        tmp_path,
        features=[
            # pid 4242 serving genuine traffic, process started at t=9.5
            dict(_row(10.0, 4242), proc_age_s=0.5),
            # the SAME pid, reused 1000s later by a probe cycle
            dict(_row(1010.0, 4242), proc_age_s=0.5),
        ],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0},
                 {"label": PROBE, "start": 1009.0, "end": 1012.0}],
    ))
    assert summary["rows"] == 2
    assert summary["groups"] == 2, "a recycled pid must not merge two processes"


def test_calls_from_one_process_stay_in_one_group(tmp_path):
    """The property the grouping exists for, which must still hold."""
    build(_write(
        tmp_path,
        features=[dict(_row(10.0, 77), proc_age_s=0.1),
                  dict(_row(10.5, 77), proc_age_s=0.6),
                  dict(_row(11.0, 77), proc_age_s=1.1)],
        windows=[{"label": GENUINE, "start": 9.0, "end": 12.0}],
    ))
    rows = [json.loads(l) for l in
            (tmp_path / "dataset.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len({r["group"] for r in rows}) == 1, "one process is one group"


def test_genuinely_overlapping_sessions_still_fail(tmp_path):
    """Recycling is excused; a real overlap must not be."""
    with pytest.raises(LabelError, match="genuinely overlapped"):
        build(_write(
            tmp_path,
            features=[dict(_row(10.0, 55), proc_age_s=0.5),
                      dict(_row(20.0, 55), proc_age_s=10.5)],   # same process
            windows=[{"label": GENUINE, "start": 9.0, "end": 12.0},
                     {"label": PROBE, "start": 19.0, "end": 22.0}],
        ))


def test_process_start_is_recovered_exactly(tmp_path):
    """features.py derives t and proc_age_s from one time.time() call."""
    from eval.rq3_dataset import process_key

    a = process_key({"pid": 1, "t": 1000.25, "proc_age_s": 0.25})
    b = process_key({"pid": 1, "t": 1005.25, "proc_age_s": 5.25})
    assert a == b, "the same process must key identically at any age"
    c = process_key({"pid": 1, "t": 2000.0, "proc_age_s": 0.0})
    assert c != a, "a later process reusing the pid must key differently"


# --------------------------------------------------------------------------- #
# Results-file schema
#
# Seven columns were added to ExperimentRow while an exp3 CSV from an earlier
# run was still on disk. ResultWriter appends and only writes a header when
# the file is new, so 56 fields went under a 49-field header and every value
# past the insertion point shifted one column left. config_hash came out
# holding "121.2" - a latency. Nothing raised.
#
# A results file that silently misaligns is worse than one that fails: the
# numbers still look like numbers, and they would have reached the write-up.
# --------------------------------------------------------------------------- #
def test_appending_under_a_stale_header_is_refused(tmp_path):
    import csv as _csv

    from eval.record import FIELD_NAMES, ExperimentRow, ResultWriter, SchemaMismatch

    # A column missing from the MIDDLE: the case that was measured, where
    # appending shifted every later value one column left. A header that is
    # merely shorter - a prefix - lines up and is accepted; see below.
    stale = tmp_path / "exp.csv"
    with stale.open("w", newline="", encoding="utf-8") as fh:
        _csv.writer(fh).writerow(FIELD_NAMES[:5] + FIELD_NAMES[6:])

    with pytest.raises(SchemaMismatch, match="different schema"):
        with ResultWriter(tmp_path, "exp"):
            pass


def test_the_old_file_is_kept_not_overwritten(tmp_path):
    import csv as _csv

    from eval.record import FIELD_NAMES, ResultWriter, SchemaMismatch

    stale = tmp_path / "exp.csv"
    with stale.open("w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(FIELD_NAMES[:5] + FIELD_NAMES[6:])
        w.writerow(["keep-me"] * (len(FIELD_NAMES) - 1))

    with pytest.raises(SchemaMismatch):
        with ResultWriter(tmp_path, "exp"):
            pass

    retired = list(tmp_path.glob("exp.*.old.csv"))
    assert retired, "the previous run's rows are still evidence; keep them"
    assert "keep-me" in retired[0].read_text(encoding="utf-8")
    assert not stale.exists(), "the mismatched file must not stay in place"


def test_a_matching_header_appends_normally(tmp_path):
    from eval.record import ExperimentRow, ResultWriter, now

    row = ExperimentRow(experiment_id="e", episode_id="ep", timestamp=now())
    with ResultWriter(tmp_path, "exp") as w:
        w.append(row)
    with ResultWriter(tmp_path, "exp") as w:          # same schema, second run
        w.append(row)

    lines = (tmp_path / "exp.csv").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3, "one header and two rows"


def test_a_fresh_file_writes_the_current_header(tmp_path):
    import csv as _csv

    from eval.record import FIELD_NAMES, ResultWriter

    with ResultWriter(tmp_path, "exp"):
        pass
    with (tmp_path / "exp.csv").open(newline="", encoding="utf-8") as fh:
        assert next(_csv.reader(fh)) == FIELD_NAMES


# --------------------------------------------------------------------------- #
# A header that is a prefix of today's (T27)
# --------------------------------------------------------------------------- #
# Columns are only ever appended. A file written before the update-episode
# columns existed is therefore an exact prefix of today's header, lines up with
# every column it has, and must stay resumable - otherwise adding a column
# would retire every half-finished sweep and restart it from nothing.
# The columns a file written before RQ3a lacks: the 17 update columns, and
# the 2 H2b columns appended after them. A file that predates the update
# columns is exactly this many short of today's header.
_UPDATE_AND_LATER_COLUMNS = 17 + 2


def _prefix_file(tmp_path, n_dropped):
    import csv as _csv

    from eval.record import FIELD_NAMES
    path = tmp_path / "exp.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        _csv.writer(fh).writerow(FIELD_NAMES[:-n_dropped])
    return path


def test_a_prefix_header_is_appended_to_under_its_own_columns(tmp_path):
    import csv as _csv

    from eval.record import FIELD_NAMES, ExperimentRow, ResultWriter, now
    path = _prefix_file(tmp_path, _UPDATE_AND_LATER_COLUMNS)
    with ResultWriter(tmp_path, "exp") as w:
        w.append(ExperimentRow(experiment_id="e", episode_id="ep", timestamp=now(),
                               config_hash="cfg:x"))
    rows = list(_csv.reader(path.open(encoding="utf-8")))
    assert rows[0] == FIELD_NAMES[:-_UPDATE_AND_LATER_COLUMNS]
    assert len(rows[1]) == len(rows[0])
    assert rows[1][rows[0].index("config_hash")] == "cfg:x"


def test_a_row_with_values_in_a_column_the_file_lacks_is_refused(tmp_path):
    """Writing it would drop the values silently."""
    from eval.record import ExperimentRow, ResultWriter, SchemaMismatch, now
    _prefix_file(tmp_path, _UPDATE_AND_LATER_COLUMNS)
    with ResultWriter(tmp_path, "exp") as w:
        with pytest.raises(SchemaMismatch, match="predates the columns"):
            w.append(ExperimentRow(experiment_id="e", episode_id="ep",
                                   timestamp=now(), cover="C2"))


def test_a_prefix_file_keeps_its_rows(tmp_path):
    from eval.record import ExperimentRow, ResultWriter, now
    path = _prefix_file(tmp_path, _UPDATE_AND_LATER_COLUMNS)
    with ResultWriter(tmp_path, "exp") as w:
        w.append(ExperimentRow(experiment_id="e", episode_id="ep1", timestamp=now()))
    with ResultWriter(tmp_path, "exp") as w:
        w.append(ExperimentRow(experiment_id="e", episode_id="ep2", timestamp=now()))
    text = path.read_text(encoding="utf-8")
    assert "ep1" in text and "ep2" in text
    assert not list(tmp_path.glob("exp.*.old.csv")), "nothing should be retired"


def test_every_existing_results_file_is_a_prefix_of_todays_header():
    """The property the prefix rule rests on, checked on the real files."""
    import csv as _csv
    from pathlib import Path

    from eval.record import FIELD_NAMES
    results = Path(__file__).resolve().parents[1] / "eval_results"
    # Archives are excluded by name: the August Experiment 1 file predates the
    # columns inserted mid-row that the header guard was written for, so it is
    # NOT a prefix - and it is never resumed, because its detector
    # configuration can no longer be reproduced. Everything else must be.
    files = [p for p in results.rglob("*.csv")
             if ".old." not in p.name and "SUPERSEDED" not in p.name
             and p.stat().st_size]
    checked = 0
    for path in files:
        header = next(_csv.reader(path.open(encoding="utf-8")), [])
        if "episode_id" not in header or "experiment_id" not in header:
            continue                          # not an ExperimentRow file
        assert FIELD_NAMES[:len(header)] == header, path.name
        checked += 1
    assert checked, "expected at least one results file to check"
