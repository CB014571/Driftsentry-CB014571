"""The RQ3 analysis, on data whose answer is known in advance.

Two things are being guarded.

The first is the obvious one: a family that genuinely separates must score
near 1, and one that carries no signal must score near 0.5. Synthetic data
with a planted signal makes that checkable.

The second matters more and is easy to get wrong silently. The exported model
has to be loadable by `attacker.features.p_probe`, which is plain arithmetic
with no scikit-learn. If the export and that function ever disagree - a
different feature order, a missed standardisation - the analysis would report
one AUC and the L6 attacker would behave with a different one. Nothing would
crash, the experiment would simply measure something other than what the
report claims. So the round-trip is asserted against sklearn's own
predict_proba, to eight decimal places.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest

from eval.rq3_distinguish import REFERENCE, analyse, load_families, report

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"

pytestmark = pytest.mark.skipif(
    not ATTACKER.is_dir(), reason=f"attacker project not found at {ATTACKER}")


def _planted(tmp_path, n_groups=24, per_group=6, seed=0):
    """A dataset where exactly one channel carries the label.

    `client_name` is perfectly predictive. Everything else is drawn the same
    way for both classes, so any family other than `client` has nothing to
    find and should land near chance.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for g in range(n_groups):
        label = g % 2
        for i in range(per_group):
            rows.append({
                "t": 1000.0 + g * 10 + i,
                "pid": 7000 + g,
                "group": 7000 + g,
                "label": label,
                "tool": "lookup_customer",
                # The planted signal.
                "client_name": "mcp" if label else "claude-ai",
                "client_version": "0.1.0",
                # Everything below is label-independent.
                "args": {"customer_id": f"C-{rng.integers(1000, 9999)}"},
                "env_count": 13,
                "has_home": True,
                "cwd": "/same/for/both",
                "parent_name": "",
                "parent_argc": None,
                "calls_before": i,
                "distinct_tools_before": 1,
                "proc_age_s": float(i) + rng.normal(0, 0.01),
                "gap_s": None if i == 0 else 0.5 + rng.normal(0, 0.01),
            })
    path = tmp_path / "dataset.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Does it find a planted signal, and only that signal?
# --------------------------------------------------------------------------- #
def test_the_family_carrying_the_signal_is_the_one_that_scores(tmp_path):
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    fam = summary["families"]
    assert fam["client"]["auc"] > 0.95, "the planted channel must be found"
    assert fam["environment"]["auc"] == pytest.approx(0.5, abs=0.2), \
        "a channel identical across classes must score near chance"


def test_a_confidence_interval_is_reported_for_every_family(tmp_path):
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    for name, res in summary["families"].items():
        if "auc" not in res:
            continue
        assert res["low"] <= res["auc"] <= res["high"], name


def test_cross_validation_is_grouped_by_process(tmp_path):
    """Calls in one session must never be split across folds."""
    summary = analyse(_planted(tmp_path, n_groups=24), ATTACKER, n_boot=50)
    assert summary["groups"] == 24
    assert 2 <= summary["cv_splits"] <= 5


def test_few_groups_do_not_crash_the_fold_count(tmp_path):
    """A quick collection can have fewer sessions than the requested folds."""
    summary = analyse(_planted(tmp_path, n_groups=2, per_group=4),
                      ATTACKER, n_boot=20)
    assert summary["cv_splits"] == 2


# --------------------------------------------------------------------------- #
# The comparison against the reference family
# --------------------------------------------------------------------------- #
def test_every_family_is_tested_against_argument_not_against_chance(tmp_path):
    """The attacker already discriminates on arguments; that is the bar."""
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    compared = set(summary["vs_reference"])
    assert REFERENCE not in compared, "the reference is not compared with itself"
    assert "all" not in compared, "the union is not a separate channel"
    assert {"client", "environment", "session", "timing"} <= compared


def test_comparisons_are_holm_corrected(tmp_path):
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    for name, cmp in summary["vs_reference"].items():
        assert "p_holm" in cmp, name
        assert cmp["p_holm"] >= cmp["p"] - 1e-12, "correction must not lower a p-value"


def test_beating_the_reference_requires_a_higher_auc_not_just_a_small_p(tmp_path):
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    for name, cmp in summary["vs_reference"].items():
        if cmp.get("beats_reference"):
            assert cmp["auc1"] > cmp["auc2"], f"{name} flagged but scores lower"


# --------------------------------------------------------------------------- #
# H3
# --------------------------------------------------------------------------- #
def test_h3_reports_the_auc_half_only(tmp_path):
    summary = analyse(_planted(tmp_path), ATTACKER, n_boot=200)
    h3 = summary["h3"]
    assert h3["threshold"] == 0.90
    assert h3["auc_part_passes"] is True        # client is planted at ~1.0
    assert "client" in h3["qualifying_families"]
    assert REFERENCE not in h3["qualifying_families"], \
        "the reference family cannot satisfy a hypothesis about beating it"
    assert "T16" in h3["note"], "the recall half must be named, not implied"


def test_h3_fails_when_no_family_separates(tmp_path):
    """A failed hypothesis is a result and must be reported as one."""
    rng = np.random.default_rng(1)
    rows = []
    for g in range(16):
        for i in range(5):
            rows.append({
                "t": 1000.0 + g, "pid": 100 + g, "group": 100 + g,
                "label": g % 2, "tool": "x",
                "args": {"q": "same"}, "client_name": "claude-ai",
                "client_version": "1", "env_count": 13, "has_home": True,
                "cwd": "/x", "parent_name": "", "parent_argc": None,
                "calls_before": i, "distinct_tools_before": 1,
                "proc_age_s": float(rng.normal(1, 0.01)),
                "gap_s": float(rng.normal(1, 0.01)),
            })
    path = tmp_path / "flat.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    summary = analyse(path, ATTACKER, n_boot=100)
    assert summary["h3"]["auc_part_passes"] is False
    assert summary["h3"]["qualifying_families"] == {}


# --------------------------------------------------------------------------- #
# The export, which the L6 attacker consumes
# --------------------------------------------------------------------------- #
def test_the_exported_model_reproduces_sklearn_exactly(tmp_path):
    """If these disagree, T16 measures something the report does not describe."""
    sys.path.insert(0, str(ATTACKER))
    try:
        from attacker.features import FAMILIES, p_probe
    finally:
        sys.path.remove(str(ATTACKER))

    path = _planted(tmp_path)
    analyse(path, ATTACKER, n_boot=50)

    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    model = json.loads((tmp_path / "recogniser_client.json").read_text(encoding="utf-8"))

    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    X = [FAMILIES["client"](r) for r in rows]
    y = [r["label"] for r in rows]
    pipe = make_pipeline(DictVectorizer(sparse=False), StandardScaler(),
                         LogisticRegression(max_iter=2000))
    pipe.fit(X, y)
    expected = pipe.predict_proba(X)[:, 1]

    for row, want in zip(rows, expected):
        assert p_probe(row, model) == pytest.approx(want, abs=1e-8)


def test_the_export_records_which_dataset_it_was_fitted_to(tmp_path):
    """A recogniser trained on evaluation data would be circular."""
    path = _planted(tmp_path)
    summary = analyse(path, ATTACKER, n_boot=50)
    model = json.loads((tmp_path / "recogniser_client.json").read_text(encoding="utf-8"))
    assert model["trained_on"] == summary["dataset_digest"]
    assert model["trained_on"].startswith("sha256:")


def test_one_recogniser_is_written_per_family(tmp_path):
    analyse(_planted(tmp_path), ATTACKER, n_boot=50)
    for name in load_families(ATTACKER):
        assert (tmp_path / f"recogniser_{name}.json").is_file(), name


def test_the_export_has_everything_p_probe_needs(tmp_path):
    analyse(_planted(tmp_path), ATTACKER, n_boot=50)
    model = json.loads((tmp_path / "recogniser_timing.json").read_text(encoding="utf-8"))
    assert set(model) >= {"family", "feature_names", "mean", "scale",
                          "coef", "intercept", "trained_on"}
    n = len(model["feature_names"])
    assert len(model["mean"]) == len(model["scale"]) == len(model["coef"]) == n


# --------------------------------------------------------------------------- #
# Guards and output
# --------------------------------------------------------------------------- #
def test_a_single_class_dataset_is_refused(tmp_path):
    rows = [{"t": 1.0, "pid": 1, "group": 1, "label": 1, "args": {},
             "client_name": "mcp"} for _ in range(10)]
    path = tmp_path / "one.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="only one class"):
        analyse(path, ATTACKER, n_boot=10)


def test_roc_points_are_saved_for_the_figures(tmp_path):
    analyse(_planted(tmp_path), ATTACKER, n_boot=50)
    roc = json.loads((tmp_path / "rq3_roc.json").read_text(encoding="utf-8"))
    assert "client" in roc
    assert len(roc["client"]["fpr"]) == len(roc["client"]["tpr"])


def test_the_report_names_the_winning_family(tmp_path):
    text = report(analyse(_planted(tmp_path), ATTACKER, n_boot=100))
    assert "client" in text and "H3" in text
    assert "PASS" in text
