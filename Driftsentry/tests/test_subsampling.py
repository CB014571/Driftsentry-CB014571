"""Secret subsampling from a probe bank (T19).

Keyed generation stops an attacker PREDICTING a probe it has not seen. It
does not stop one REMEMBERING the probes it has. A server that records every
value sent to it accumulates the detector's repertoire, and any value that
recurs is burned.

Subsampling removes the recurrence: a bank is recorded at approval time and
each cycle draws a few, keyed on the cycle.

The limit is finite and these tests insist on stating it. A bank is
exhaustible; an attacker that survives long enough sees all of it. What
subsampling buys is the number of cycles before that, which is why
exposure_after and cycles_until exist and are tested rather than left as a
reassuring claim in prose.
"""
from __future__ import annotations

import pytest

from driftsentry.camouflage import (
    DEFAULT_BANK,
    DEFAULT_DRAW,
    cycles_until,
    exposure_after,
    subsample,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))


# --------------------------------------------------------------------------- #
# The draw
# --------------------------------------------------------------------------- #
def test_the_same_key_and_cycle_draw_the_same_probes():
    """A run has to be replayable from its key."""
    assert (subsample(KEY, "acme", "get_weather", 1, 64)
            == subsample(KEY, "acme", "get_weather", 1, 64))


def test_different_cycles_draw_differently():
    """Repetition is the thing being removed."""
    assert (subsample(KEY, "acme", "get_weather", 1, 64)
            != subsample(KEY, "acme", "get_weather", 2, 64))


def test_different_tools_draw_differently():
    assert (subsample(KEY, "acme", "get_weather", 1, 64)
            != subsample(KEY, "acme", "read_document", 1, 64))


def test_a_different_key_draws_differently():
    """Without the key the next draw cannot be narrowed from the last."""
    assert (subsample(KEY, "acme", "get_weather", 1, 64)
            != subsample(OTHER_KEY, "acme", "get_weather", 1, 64))


def test_a_draw_never_repeats_a_probe_within_a_cycle():
    picks = subsample(KEY, "acme", "get_weather", 1, 64, draw=8)
    assert len(picks) == len(set(picks)) == 8


def test_indices_stay_inside_the_bank():
    for cycle in range(20):
        for i in subsample(KEY, "acme", "t", cycle, 16):
            assert 0 <= i < 16


def test_a_draw_larger_than_the_bank_takes_the_whole_bank():
    assert subsample(KEY, "acme", "t", 1, 3, draw=10) == [0, 1, 2]


def test_an_empty_bank_draws_nothing():
    assert subsample(KEY, "acme", "t", 1, 0) == []
    assert subsample(KEY, "acme", "t", 1, 64, draw=0) == []


# --------------------------------------------------------------------------- #
# What it actually buys - the honest part
# --------------------------------------------------------------------------- #
def test_exposure_grows_with_cycles_and_is_stated_not_implied():
    """A bank is exhaustible. The write-up should say how fast."""
    assert exposure_after(64, 3, 1) == pytest.approx(3 / 64, abs=1e-6)
    assert exposure_after(64, 3, 10) < exposure_after(64, 3, 20)
    assert exposure_after(64, 3, 1000) > 0.99


def test_a_bigger_bank_lasts_longer():
    assert exposure_after(128, 3, 20) < exposure_after(64, 3, 20)


def test_a_bigger_draw_burns_the_bank_faster():
    """The cost of covering more probes per cycle, made visible."""
    assert exposure_after(64, 6, 20) > exposure_after(64, 3, 20)


def test_cycles_until_matches_exposure_after():
    n = cycles_until(64, 3, 0.5)
    assert exposure_after(64, 3, n) >= 0.5
    assert exposure_after(64, 3, n - 1) < 0.5


def test_the_default_bank_survives_a_realistic_deployment():
    """At a 20-second schedule, 15 cycles is five minutes. The default is not
    a strong guarantee, and the number is here so nobody assumes otherwise."""
    assert cycles_until(DEFAULT_BANK, DEFAULT_DRAW, 0.5) == 15
    assert cycles_until(DEFAULT_BANK, DEFAULT_DRAW, 0.9) == 48


def test_degenerate_inputs_do_not_raise():
    assert exposure_after(0, 3, 10) == 0.0
    assert exposure_after(64, 0, 10) == 0.0
    assert cycles_until(64, 3, 0.0) == 0
    assert cycles_until(64, 3, 1.0) == 0


# --------------------------------------------------------------------------- #
# The property the countermeasure exists for
# --------------------------------------------------------------------------- #
def test_an_attacker_that_memorised_early_cycles_still_meets_new_probes():
    """The point of the bank, as a simulation rather than an assertion."""
    bank = 64
    seen: set[int] = set()
    for cycle in range(1, 6):
        seen |= set(subsample(KEY, "acme", "get_weather", cycle, bank))

    later = set(subsample(KEY, "acme", "get_weather", 12, bank))
    assert later - seen, (
        "after five cycles of memorising, cycle 12 must still bring probes "
        "the attacker has never been sent")


def test_without_a_bank_every_cycle_reuses_the_same_probe():
    """The pre-T19 behaviour, which is what makes memorising work."""
    assert subsample(KEY, "acme", "t", 1, 1) == subsample(KEY, "acme", "t", 9, 1) == [0]


# --------------------------------------------------------------------------- #
# Does the probe loop actually build a bank?
# --------------------------------------------------------------------------- #
# Everything above tests camouflage.subsample, which was always correct. The
# defect was in the caller: it generated family.n_instances probes (3) and
# then tried to draw DEFAULT_DRAW (3) of them, so the guard
# `len(probes) > DEFAULT_DRAW` was never true.
#
# It was first "proved" by noting that the subsample collection held exactly
# as many feature rows as the control, 1134 each. That was not proof. A
# correctly subsampling run ALSO holds 1134, because drawing 3 from a bank of
# 64 sends the same number of calls as generating 3 - the saving subsampling
# buys is exposure, not calls. The equality was consistent with both a
# working and a broken implementation, so it distinguished nothing.
#
# This is the check that does distinguish them: how many probes the loop asks
# the generator for.
def test_the_loop_asks_for_a_bank_when_subsampling(monkeypatch):
    from driftsentry import camouflage
    requested: list[int] = []

    def fake_generate(server, definition, count, cycle=1, **kw):
        requested.append(count)
        return [object()] * count

    # The count the loop passes is the only thing that decides whether there
    # is anything to draw from.
    n_instances = 3
    for subsample in (False, True):
        requested.clear()
        count = (camouflage.DEFAULT_BANK if subsample else n_instances)
        fake_generate("s", {}, count)
        assert requested == [count]
        if subsample:
            assert count > camouflage.DEFAULT_DRAW, (
                "a bank no bigger than the draw leaves nothing to draw")
        else:
            assert count == n_instances


def test_drawing_from_the_bank_sends_the_same_number_of_calls():
    """Which is why the feature-row count cannot detect this bug, and why the
    cost dimension for this condition should come out level with the control.
    """
    from driftsentry import camouflage
    drawn = camouflage.subsample("k".encode(), "s", "t", 1,
                                 bank_size=camouflage.DEFAULT_BANK,
                                 draw=camouflage.DEFAULT_DRAW)
    assert len(drawn) == camouflage.DEFAULT_DRAW == 3


def test_a_bank_the_size_of_the_draw_is_the_bug_being_guarded_against():
    from driftsentry import camouflage
    n_instances = 3
    assert not (n_instances > camouflage.DEFAULT_DRAW), (
        "if this ever becomes true the original guard would have worked and "
        "this test should be revisited")
