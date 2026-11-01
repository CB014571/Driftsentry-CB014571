"""Can a malicious server tell probe calls from genuine agent calls?

This is RQ3, and the answer is a number per feature family: the AUC a
classifier reaches using only what that channel reveals. Families rather than
one pooled model, because "a server can tell" is far less useful than "a
server can tell FROM THE CLIENT NAME" - the first is a worry, the second says
what to fix.

Three decisions that shape every number here

    GroupKFold on the process, never a random split
        Calls inside one server process share a client, a working directory,
        a session counter and a process age. A random split would put some
        calls from a session in train and others in test, and the model would
        recognise the session rather than the kind of traffic. Every AUC would
        be inflated and nothing in the output would say so.

    Each family is compared against `argument`, not against 0.5
        The current L4 attacker already discriminates on arguments; that is
        the state of the art it has to beat. A family at AUC 0.95 is only
        interesting if argument is lower. DeLong tests the difference
        pairwise, on the same rows, and Holm corrects for testing five
        families at once.

    Models are exported in the attacker's own format
        The L6 attacker scores calls with `attacker.features.p_probe`, which
        is plain arithmetic with no scikit-learn. Exporting the coefficients
        here - rather than pickling an estimator - is what lets the attacker
        use the finding without importing the analysis. A test round-trips
        the export against sklearn's own predict_proba.

The features come from the attacker's module, imported directly. One source
of truth: a classifier fitted to features the attacker does not compute would
measure something nobody can exploit.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

#: H3 asks for a non-argument family at or above this.
H3_AUC = 0.90

#: The family every other is measured against: what the attacker already does.
REFERENCE = "argument"


def load_families(attacker_project: str | Path) -> dict[str, Any]:
    """Import FAMILIES from the attacker, so both sides compute the same thing."""
    project = str(Path(attacker_project).resolve())
    added = project not in sys.path
    if added:
        sys.path.insert(0, project)
    try:
        from attacker.features import FAMILIES
        return dict(FAMILIES)
    finally:
        if added:
            sys.path.remove(project)


def load_dataset(path: str | Path) -> tuple[list[dict], np.ndarray, np.ndarray]:
    """Rows, labels and groups from a built dataset."""
    rows = [json.loads(line) for line in
            Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"no rows in {path}")
    y = np.array([r["label"] for r in rows], dtype=int)
    groups = np.array([r["group"] for r in rows])
    if len(np.unique(y)) < 2:
        raise ValueError("the dataset has only one class; nothing to separate")
    return rows, y, groups


def _dataset_digest(path: str | Path) -> str:
    return "sha256:" + hashlib.sha256(
        Path(path).read_bytes()).hexdigest()[:16]


def _pipeline():
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    return make_pipeline(
        DictVectorizer(sparse=False),
        StandardScaler(),
        LogisticRegression(max_iter=2000),
    )


def _export(pipeline, family: str, digest: str) -> dict[str, Any]:
    """Coefficients in the shape attacker.features.p_probe expects."""
    vec, scaler, model = pipeline.steps[0][1], pipeline.steps[1][1], pipeline.steps[2][1]
    return {
        "family": family,
        "feature_names": list(vec.get_feature_names_out()),
        "mean": [float(v) for v in scaler.mean_],
        "scale": [float(v) for v in scaler.scale_],
        "coef": [float(v) for v in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "trained_on": digest,
    }


def analyse(
    dataset_path: str | Path,
    attacker_project: str | Path,
    *,
    out_dir: str | Path | None = None,
    n_splits: int = 5,
    n_boot: int = 2000,
    seed: int = 0,
) -> dict[str, Any]:
    """Cross-validated AUC per family, with intervals and pairwise tests."""
    from sklearn.metrics import roc_curve
    from sklearn.model_selection import GroupKFold, cross_val_predict

    from eval.stats import bootstrap_auc, delong, holm

    dataset_path = Path(dataset_path)
    out = Path(out_dir) if out_dir else dataset_path.parent
    out.mkdir(parents=True, exist_ok=True)

    rows, y, groups = load_dataset(dataset_path)
    families = load_families(attacker_project)
    digest = _dataset_digest(dataset_path)

    n_groups = len(np.unique(groups))
    splits = max(2, min(n_splits, n_groups))

    scores: dict[str, np.ndarray] = {}
    results: dict[str, dict[str, Any]] = {}

    for name, fn in families.items():
        X = [fn(row) for row in rows]
        try:
            proba = cross_val_predict(
                _pipeline(), X, y, groups=groups,
                cv=GroupKFold(splits), method="predict_proba")[:, 1]
        except Exception as exc:
            results[name] = {"error": f"{type(exc).__name__}: {exc}"}
            continue

        scores[name] = proba
        boot = bootstrap_auc(y, proba, groups, n=n_boot, seed=seed)
        fpr, tpr, _ = roc_curve(y, proba)
        results[name] = {
            "auc": boot["auc"],
            "low": boot["low"],
            "high": boot["high"],
            "n_boot": boot["n_boot"],
            "roc": {"fpr": [float(v) for v in fpr], "tpr": [float(v) for v in tpr]},
        }

        # The model the L6 attacker would actually load, fitted on everything.
        pipeline = _pipeline()
        pipeline.fit(X, y)
        (out / f"recogniser_{name}.json").write_text(
            json.dumps(_export(pipeline, name, digest), indent=2), encoding="utf-8")

    # Every family against the reference, on the same rows, then Holm.
    comparisons: dict[str, dict[str, Any]] = {}
    if REFERENCE in scores:
        names = [n for n in scores if n not in (REFERENCE, "all")]
        raw = []
        for name in names:
            test = delong(y, scores[name], scores[REFERENCE])
            comparisons[name] = test
            raw.append(test["p"])
        if raw:
            corrected = holm(raw)
            for name, adj, rej in zip(names, corrected["adjusted"], corrected["reject"]):
                comparisons[name]["p_holm"] = adj
                comparisons[name]["beats_reference"] = bool(
                    rej and comparisons[name]["auc1"] > comparisons[name]["auc2"])

    # H3, AUC half: a family OTHER than argument at or above 0.90.
    qualifying = {
        name: res["auc"] for name, res in results.items()
        if name not in (REFERENCE, "all") and "auc" in res and res["auc"] >= H3_AUC
    }
    verdict = {
        "threshold": H3_AUC,
        "qualifying_families": qualifying,
        "auc_part_passes": bool(qualifying),
        "note": ("H3 also requires the recall half - an L6 attacker cutting "
                 "detection by >= 50 points. That is T16, not this."),
    }

    summary = {
        "dataset": str(dataset_path),
        "dataset_digest": digest,
        "rows": len(rows),
        "genuine": int((y == 0).sum()),
        "probe": int((y == 1).sum()),
        "groups": n_groups,
        "cv_splits": splits,
        "families": {k: {kk: vv for kk, vv in v.items() if kk != "roc"}
                     for k, v in results.items()},
        "vs_reference": comparisons,
        "h3": verdict,
    }
    (out / "rq3_analysis.json").write_text(json.dumps(summary, indent=2),
                                           encoding="utf-8")
    (out / "rq3_roc.json").write_text(json.dumps(
        {k: v["roc"] for k, v in results.items() if "roc" in v}, indent=2),
        encoding="utf-8")
    return summary


def report(summary: dict[str, Any]) -> str:
    """The table that goes in the write-up."""
    lines = [
        "",
        f"  rows {summary['rows']}  ({summary['genuine']} genuine, "
        f"{summary['probe']} probe)  across {summary['groups']} sessions",
        f"  grouped {summary['cv_splits']}-fold cross-validation on the server process",
        "",
        f"  {'family':<14}{'AUC':>7}{'95% CI':>18}{'vs argument':>14}{'':>4}",
        "  " + "-" * 60,
    ]
    for name, res in summary["families"].items():
        if "auc" not in res:
            lines.append(f"  {name:<14}{'error':>7}  {res.get('error', '')[:40]}")
            continue
        ci = f"[{res['low']:.3f}, {res['high']:.3f}]"
        cmp = summary["vs_reference"].get(name)
        if cmp is None:
            verdict = "reference" if name == REFERENCE else ""
        elif cmp.get("beats_reference"):
            verdict = f"p={cmp['p_holm']:.4f} BEATS"
        else:
            verdict = f"p={cmp.get('p_holm', float('nan')):.4f}"
        lines.append(f"  {name:<14}{res['auc']:7.3f}{ci:>18}{verdict:>18}")

    h3 = summary["h3"]
    lines += ["", f"  H3 (AUC half, >= {h3['threshold']}): "
                  f"{'PASS' if h3['auc_part_passes'] else 'FAIL'}"]
    if h3["qualifying_families"]:
        for name, auc in sorted(h3["qualifying_families"].items(),
                                key=lambda kv: -kv[1]):
            lines.append(f"      {name:<14}{auc:.3f}")
    lines.append(f"      {h3['note']}")
    return "\n".join(lines)
