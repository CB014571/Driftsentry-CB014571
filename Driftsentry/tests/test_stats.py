"""The statistics the hypotheses are decided by, checked against references.

These functions decide whether H1 to H4 pass. A quiet error here would not
crash anything - it would produce a p-value, and the p-value would go into the
report. So each one is checked against an independent implementation
(scikit-learn, statsmodels) or against a case whose answer is known by hand.

The bootstrap test is the one that matters most. Resampling rows instead of
groups is an easy mistake that makes every interval look impressively tight,
and nothing about the output would reveal it.
"""
from __future__ import annotations

import numpy as np
import pytest

from eval.stats import bootstrap_auc, delong, holm, mcnemar_p, wilson


# --------------------------------------------------------------------------- #
# Wilson
# --------------------------------------------------------------------------- #
def test_wilson_matches_statsmodels():
    from statsmodels.stats.proportion import proportion_confint

    for k, n in ((0, 6), (3, 6), (6, 6), (1, 100), (54, 54)):
        point, low, high = wilson(k, n)
        expected = proportion_confint(k, n, alpha=0.05, method="wilson")
        assert point == pytest.approx(k / n)
        assert (low, high) == pytest.approx(expected)


def test_wilson_does_not_claim_certainty_from_six_observations():
    """The reason this is not a normal-approximation interval.

    6/6 would give [1.0, 1.0] under the textbook formula - certainty from six
    episodes - and 0/6 would give [0.0, 0.0] or go negative.
    """
    _, low, high = wilson(6, 6)
    assert low < 1.0, "an upper-bounded estimate must still admit doubt"
    assert high == pytest.approx(1.0)

    _, low, high = wilson(0, 6)
    assert low == pytest.approx(0.0)
    assert high > 0.0


def test_wilson_handles_an_empty_sample():
    point, low, high = wilson(0, 0)
    assert np.isnan(point) and (low, high) == (0.0, 1.0)


# --------------------------------------------------------------------------- #
# McNemar
# --------------------------------------------------------------------------- #
def test_mcnemar_on_a_known_table():
    """b01 = 8, b10 = 1. Exact binomial two-sided p = 2 * P(X <= 1 | 9, 0.5)."""
    a = [True] * 1 + [False] * 8 + [True] * 10 + [False] * 10
    b = [False] * 1 + [True] * 8 + [True] * 10 + [False] * 10
    out = mcnemar_p(a, b)
    assert out["b10"] == 1 and out["b01"] == 8
    expected = 2 * (9 + 1) / 2 ** 9          # 2 * (C(9,0)+C(9,1)) / 2^9
    assert out["p"] == pytest.approx(expected)


def test_mcnemar_reports_the_discordant_counts_not_just_a_p_value():
    """A tiny p from two disagreements is not strong evidence."""
    a, b = [True, False], [False, True]
    out = mcnemar_p(a, b)
    assert out["discordant"] == 2
    assert out["b01"] == 1 and out["b10"] == 1


def test_identical_detectors_give_no_evidence_of_a_difference():
    flags = [True, False, True, True, False]
    assert mcnemar_p(flags, flags)["p"] == pytest.approx(1.0)


def test_mcnemar_rejects_unpaired_inputs():
    with pytest.raises(ValueError, match="must match"):
        mcnemar_p([True, False], [True])


def test_symmetric_disagreement_is_not_evidence_either_way():
    """Ten each way is a lot of disagreement and no reason to prefer either."""
    out = mcnemar_p([True] * 10 + [False] * 10, [False] * 10 + [True] * 10)
    assert out["b01"] == out["b10"] == 10
    assert out["p"] == pytest.approx(1.0)


def test_pairing_finds_a_difference_that_marginals_alone_would_miss():
    """Why H2 is paired rather than two independent proportions.

    A detects every episode; B misses eight, and those eight are a strict
    subset of what A caught. Comparing 100/100 against 92/100 as two
    independent samples is a much weaker test than observing that B failed on
    eight episodes where A succeeded and succeeded on none where A failed.
    """
    a = [True] * 100
    b = [False] * 8 + [True] * 92
    out = mcnemar_p(a, b)
    assert out["b10"] == 8 and out["b01"] == 0, "one-sided discordance"
    # Exact binomial on the 8 discordant pairs: 2 * P(X = 0 | 8, 0.5).
    assert out["p"] == pytest.approx(2 / 2 ** 8)
    assert out["p"] < 0.01

    # The evidence is the 8 discordant pairs, not the 200 observations. A
    # two-proportion test on the same data reports p = 0.0039, which looks
    # stronger but is not: with one arm at 100/100 its variance estimate
    # collapses and the interval is anti-conservative. McNemar conditions on
    # the discordant pairs and is the defensible number here.
    assert out["discordant"] == 8
    assert out["n"] == 100


# --------------------------------------------------------------------------- #
# Holm
# --------------------------------------------------------------------------- #
def test_holm_matches_statsmodels_and_keeps_input_order():
    from statsmodels.stats.multitest import multipletests

    pvals = [0.04, 0.005, 0.5, 0.01]
    out = holm(pvals)
    reject, adjusted, _, _ = multipletests(pvals, alpha=0.05, method="holm")
    assert out["adjusted"] == pytest.approx(list(adjusted))
    assert out["reject"] == list(reject)


def test_holm_is_why_five_families_are_not_tested_naively():
    """Five p-values just under 0.05 are not five findings."""
    out = holm([0.04] * 5)
    assert not any(out["reject"]), "Holm must not pass all five"


def test_holm_on_nothing():
    assert holm([]) == {"adjusted": [], "reject": [], "alpha": 0.05}


# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #
def _grouped(n_groups=40, per_group=8, seed=0):
    """Correlated data: every call in a session shares its label and score."""
    rng = np.random.default_rng(seed)
    y, s, g = [], [], []
    for gi in range(n_groups):
        label = gi % 2
        base = rng.normal(1.2 if label else 0.0)
        for _ in range(per_group):
            y.append(label)
            s.append(base + rng.normal(0, 0.05))   # tight within a session
            g.append(gi)
    return np.array(y), np.array(s), np.array(g)


def test_bootstrap_auc_point_estimate_matches_sklearn():
    from sklearn.metrics import roc_auc_score

    y, s, g = _grouped()
    out = bootstrap_auc(y, s, g, n=200, seed=1)
    assert out["auc"] == pytest.approx(roc_auc_score(y, s))
    assert out["low"] <= out["auc"] <= out["high"]
    assert out["n_groups"] == 40


def test_resampling_groups_gives_a_wider_interval_than_resampling_rows():
    """The whole reason the signature takes `groups`.

    Rows inside a session are correlated. Resampling them independently
    pretends 320 calls are 320 pieces of evidence rather than 40.
    """
    y, s, g = _grouped()
    by_group = bootstrap_auc(y, s, g, n=400, seed=2)
    by_row = bootstrap_auc(y, s, np.arange(len(y)), n=400, seed=2)
    assert (by_group["high"] - by_group["low"]) > (by_row["high"] - by_row["low"]), (
        "group resampling must not produce the narrower interval")


def test_bootstrap_is_reproducible_from_its_seed():
    y, s, g = _grouped()
    assert bootstrap_auc(y, s, g, n=100, seed=7) == bootstrap_auc(y, s, g, n=100, seed=7)


def test_single_class_resamples_are_skipped_not_scored_as_half():
    """Substituting 0.5 for an undefined AUC would drag the interval inward."""
    y = np.array([1, 1, 0, 0])
    s = np.array([0.9, 0.8, 0.2, 0.1])
    g = np.array([0, 0, 1, 1])
    out = bootstrap_auc(y, s, g, n=200, seed=0)
    assert out["n_boot"] < 200, "some resamples must have been single-class"
    assert out["auc"] == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# DeLong
# --------------------------------------------------------------------------- #
def test_delong_aucs_equal_sklearn():
    from sklearn.metrics import roc_auc_score

    rng = np.random.default_rng(3)
    y = rng.integers(0, 2, 200)
    s1 = y * 0.8 + rng.normal(0, 1, 200)
    s2 = y * 0.3 + rng.normal(0, 1, 200)
    out = delong(y, s1, s2)
    assert out["auc1"] == pytest.approx(roc_auc_score(y, s1), abs=1e-9)
    assert out["auc2"] == pytest.approx(roc_auc_score(y, s2), abs=1e-9)


def test_the_same_scores_twice_give_p_of_one():
    rng = np.random.default_rng(4)
    y = rng.integers(0, 2, 120)
    s = y * 0.7 + rng.normal(0, 1, 120)
    out = delong(y, s, s)
    assert out["auc1"] == out["auc2"]
    assert out["p"] == pytest.approx(1.0)


def test_a_clearly_better_classifier_is_detected():
    rng = np.random.default_rng(5)
    y = rng.integers(0, 2, 400)
    strong = y * 2.5 + rng.normal(0, 1, 400)
    weak = rng.normal(0, 1, 400)              # pure noise
    out = delong(y, strong, weak)
    assert out["auc1"] > 0.85 and 0.4 < out["auc2"] < 0.6
    assert out["p"] < 0.05


def test_two_equally_useless_classifiers_are_not_called_different():
    rng = np.random.default_rng(6)
    y = rng.integers(0, 2, 400)
    out = delong(y, rng.normal(0, 1, 400), rng.normal(0, 1, 400))
    assert out["p"] > 0.05


def test_delong_handles_ties_through_midranks():
    """Scores from a coarse model are full of ties; ranks must be averaged."""
    y = [1, 1, 0, 0, 1, 0]
    s1 = [1.0, 1.0, 0.0, 0.0, 1.0, 0.0]        # perfect, entirely tied
    out = delong(y, s1, s1)
    assert out["auc1"] == pytest.approx(1.0)
    assert out["p"] == pytest.approx(1.0)


def test_delong_needs_both_classes():
    with pytest.raises(ValueError, match="positive and one negative"):
        delong([1, 1, 1], [0.1, 0.2, 0.3], [0.3, 0.2, 0.1])


def test_exact_mcnemar_matches_statsmodels_without_needing_it():
    """Computed directly since Application Control blocked statsmodels' pandas
    DLL on 9 Nov. Must give exactly what statsmodels gives."""
    import itertools
    import random

    from statsmodels.stats.contingency_tables import mcnemar

    from eval.stats import mcnemar_p
    rng = random.Random(7)
    for _ in range(200):
        n = rng.randint(1, 40)
        a = [rng.random() < 0.5 for _ in range(n)]
        b = [rng.random() < 0.5 for _ in range(n)]
        mine = mcnemar_p(a, b)
        b01 = sum(1 for x, y in zip(a, b) if not x and y)
        b10 = sum(1 for x, y in zip(a, b) if x and not y)
        both = sum(1 for x, y in zip(a, b) if x and y)
        neither = n - b01 - b10 - both
        ref = mcnemar([[both, b10], [b01, neither]], exact=True).pvalue
        assert abs(mine["p"] - ref) < 1e-12, (b01, b10, mine["p"], ref)


def test_exact_mcnemar_known_value():
    from eval.stats import mcnemar_p
    # five discordant pairs all one way: 2 * 0.5**5 = 0.0625
    assert mcnemar_p([False] * 5 + [True] * 5, [True] * 5 + [True] * 5)["p"] == 0.0625


def test_wilson_matches_statsmodels_without_needing_it():
    from statsmodels.stats.proportion import proportion_confint

    from eval.stats import wilson
    for n in (1, 2, 5, 10, 33, 100):
        for k in range(n + 1):
            for alpha in (0.05, 0.1):
                _, lo, hi = wilson(k, n, alpha)
                rlo, rhi = proportion_confint(k, n, alpha=alpha, method="wilson")
                assert abs(lo - rlo) < 1e-12 and abs(hi - rhi) < 1e-12, (k, n, alpha)


def test_holm_matches_statsmodels_without_needing_it():
    import random

    from statsmodels.stats.multitest import multipletests

    from eval.stats import holm
    rng = random.Random(11)
    for _ in range(300):
        ps = [rng.random() ** rng.choice((1, 3, 6)) for _ in range(rng.randint(1, 8))]
        mine = holm(ps)
        rej, adj, _, _ = multipletests(ps, alpha=0.05, method="holm")
        assert all(abs(a - b) < 1e-12 for a, b in zip(mine["adjusted"], adj))
        assert mine["reject"] == [bool(r) for r in rej]
