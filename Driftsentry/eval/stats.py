"""The statistics the hypotheses are decided by.

Four of the five functions here exist because the obvious alternative is
wrong in a way that would flatter the results.

``wilson`` rather than a normal-approximation interval
    Detection rates in this project are measured on small samples and sit
    near 0 or 1 - "6 of 6 detected", "0 false alarms in 6". The textbook
    interval gives [1.0, 1.0] for 6/6, claiming certainty from six
    observations, and can run below zero for 0/6. Wilson does neither.

``mcnemar_p`` rather than comparing two independent proportions
    H2 compares detectors scored on THE SAME episodes. Treating those as two
    independent samples throws away the pairing and inflates the p-value, so a
    real difference can be missed. McNemar uses only the episodes where the
    two disagreed, which is the actual evidence.

``holm`` because several families are tested at once
    RQ3 compares five feature families against a reference. At the 0.05 level,
    five independent tests produce a false positive about 23% of the time.
    Holm controls that without the over-correction of Bonferroni.

``bootstrap_auc`` resampling GROUPS, not rows
    Calls within one server process share a client, a working directory and a
    session counter, so they are not independent observations. Resampling rows
    would treat 300 correlated calls as 300 pieces of evidence and produce an
    interval several times too narrow.

``delong`` because two AUCs on the same data are paired too
    Comparing AUCs by checking whether their intervals overlap is a weaker
    test than comparing them directly, and the overlap heuristic is wrong
    often enough to matter. DeLong gives an exact variance for the difference.

Nothing here decides anything on its own. A hypothesis passes or fails on the
rule written in GAPS_PLAN.md section 3, and a failure is a result.
"""
from __future__ import annotations

from typing import Any, Sequence

import math

import numpy as np


# --------------------------------------------------------------------------- #
# Proportions
# --------------------------------------------------------------------------- #
def wilson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float, float]:
    """Point estimate and Wilson score interval for k successes in n trials."""
    if n <= 0:
        return (float("nan"), 0.0, 1.0)
    # The Wilson score formula, computed directly for the same reason as
    # mcnemar_p's exact path: statsmodels is unavailable whenever Windows
    # Application Control blocks its pandas DLL. Pinned equal by a test.
    from statistics import NormalDist

    z = NormalDist().inv_cdf(1.0 - alpha / 2.0)
    phat = k / n
    denom = 1.0 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (phat, max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_p(a: Sequence[bool], b: Sequence[bool], *, exact: bool = True) -> dict[str, Any]:
    """Paired comparison of two detectors scored on the same episodes.

    Returns the discordant counts as well as the p-value, because those are
    what the result actually rests on: b01 and b10 are the only episodes that
    carry information, and a p-value from two or three of them means little
    however small it is.
    """
    first = np.asarray(a, dtype=bool)
    second = np.asarray(b, dtype=bool)
    if first.shape != second.shape:
        raise ValueError(f"paired inputs must match: {first.shape} vs {second.shape}")
    if first.size == 0:
        return {"p": float("nan"), "n": 0, "b01": 0, "b10": 0,
                "a_rate": float("nan"), "b_rate": float("nan")}

    b01 = int(np.sum(~first & second))      # only the second detected
    b10 = int(np.sum(first & ~second))      # only the first detected
    table = [[int(np.sum(first & second)), b10],
             [b01, int(np.sum(~first & ~second))]]

    if exact:
        # Exact McNemar is a two-sided binomial test on the discordant pairs
        # with p = 0.5 - computed directly, the same formula statsmodels
        # uses. Directly because on 9 Nov Windows Application Control blocked
        # a pandas DLL that statsmodels imports, and every paired test in the
        # evaluation failed with it; the H3 verdict should not hinge on a
        # library a security policy can switch off. A test pins the two equal.
        n_disc = b01 + b10
        k = min(b01, b10)
        p = (min(1.0, 2.0 * sum(math.comb(n_disc, i) for i in range(k + 1)) / 2 ** n_disc)
             if n_disc else 1.0)
    else:
        from statsmodels.stats.contingency_tables import mcnemar
        p = float(mcnemar(table, exact=False).pvalue)
    return {
        "p": float(p),
        "n": int(first.size),
        "b01": b01,
        "b10": b10,
        "discordant": b01 + b10,
        "a_rate": float(first.mean()),
        "b_rate": float(second.mean()),
    }


def holm(pvals: Sequence[float], alpha: float = 0.05) -> dict[str, Any]:
    """Holm-corrected p-values and rejections, in the input order."""
    if len(pvals) == 0:
        return {"adjusted": [], "reject": [], "alpha": alpha}
    # Holm's step-down, directly (see wilson). The i-th smallest p-value is
    # scaled by (m - i), then made monotone so an adjusted value never falls
    # below the one before it.
    m = len(pvals)
    order = sorted(range(m), key=lambda i: pvals[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * float(pvals[i])))
        adjusted[i] = running
    return {"adjusted": adjusted,
            "reject": [a <= alpha for a in adjusted],
            "alpha": alpha}


# --------------------------------------------------------------------------- #
# AUC
# --------------------------------------------------------------------------- #
def _auc(y: np.ndarray, s: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    return float(roc_auc_score(y, s))


def bootstrap_auc(
    y: Sequence[int],
    s: Sequence[float],
    groups: Sequence[Any],
    *,
    n: int = 2000,
    seed: int = 0,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """AUC with a percentile interval from resampling whole groups.

    Groups, never rows: calls inside one session are correlated, so row
    resampling would treat them as independent and shrink the interval to a
    fraction of its honest width.
    """
    y = np.asarray(y, dtype=int)
    s = np.asarray(s, dtype=float)
    groups = np.asarray(groups)

    point = _auc(y, s)
    unique = np.unique(groups)
    index_of = {g: np.flatnonzero(groups == g) for g in unique}
    rng = np.random.default_rng(seed)

    draws: list[float] = []
    for _ in range(n):
        picked = rng.choice(unique, size=len(unique), replace=True)
        rows = np.concatenate([index_of[g] for g in picked])
        yy = y[rows]
        # A resample can contain only one class, where AUC is undefined.
        # Skipping is correct; substituting 0.5 would drag the interval inward.
        if yy.min() == yy.max():
            continue
        draws.append(_auc(yy, s[rows]))

    if not draws:
        return {"auc": point, "low": float("nan"), "high": float("nan"),
                "n_boot": 0, "n_groups": len(unique)}

    low, high = np.percentile(draws, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return {"auc": point, "low": float(low), "high": float(high),
            "n_boot": len(draws), "n_groups": len(unique)}


def _midrank(x: np.ndarray) -> np.ndarray:
    """Ranks with ties averaged, as DeLong's estimator requires."""
    order = np.argsort(x)
    sorted_x = x[order]
    n = len(x)
    ranks = np.zeros(n, dtype=float)
    i = 0
    while i < n:
        j = i
        while j < n and sorted_x[j] == sorted_x[i]:
            j += 1
        ranks[i:j] = 0.5 * (i + j - 1) + 1
        i = j
    out = np.empty(n, dtype=float)
    out[order] = ranks
    return out


def delong(y: Sequence[int], s1: Sequence[float], s2: Sequence[float]) -> dict[str, Any]:
    """Compare two AUCs measured on the same labels (Sun & Xu, 2014).

    Paired, because both scores come from the same rows. Checking whether two
    separate confidence intervals overlap is a different and weaker question.
    """
    y = np.asarray(y).astype(bool)
    pos, neg = np.flatnonzero(y), np.flatnonzero(~y)
    m, n = len(pos), len(neg)
    if m == 0 or n == 0:
        raise ValueError("DeLong needs at least one positive and one negative label")

    aucs: list[float] = []
    v10: list[np.ndarray] = []
    v01: list[np.ndarray] = []
    for scores in (np.asarray(s1, dtype=float), np.asarray(s2, dtype=float)):
        tx = _midrank(scores[pos])
        ty = _midrank(scores[neg])
        tz = _midrank(np.concatenate([scores[pos], scores[neg]]))
        aucs.append((tz[:m].sum() - m * (m + 1) / 2) / (m * n))
        v10.append((tz[:m] - tx) / n)
        v01.append(1 - (tz[m:] - ty) / m)

    sx = np.cov(np.vstack(v10))
    sy = np.cov(np.vstack(v01))
    var = ((sx[0, 0] + sx[1, 1] - 2 * sx[0, 1]) / m
           + (sy[0, 0] + sy[1, 1] - 2 * sy[0, 1]) / n)

    if var <= 0:
        # Identical scores, or too few observations to estimate a variance.
        # No evidence of a difference, which is p = 1 rather than an error.
        return {"auc1": float(aucs[0]), "auc2": float(aucs[1]),
                "p": 1.0, "var": float(var)}

    from scipy.stats import norm

    z = abs(aucs[0] - aucs[1]) / np.sqrt(var)
    return {"auc1": float(aucs[0]), "auc2": float(aucs[1]),
            "p": float(2 * norm.sf(z)), "var": float(var), "z": float(z)}
