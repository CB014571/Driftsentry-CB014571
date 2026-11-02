"""Probes announcing the identity the real client announced (T17).

RQ3 measured what this costs when it is absent. Probe sessions opened
``ClientSession(read, write)`` with no client_info, so the SDK sent its
default name - "mcp", which appears in no real host - while genuine traffic
announced "claude-ai". A classifier separated the two at AUC 1.000 on that
field alone, and an L6 attacker using it took detection from 100% to 0%.

The countermeasure is the obvious one, and the tests are mostly about the
ways it could go quietly wrong:

    recording the wrong thing  - the proxy must not record another probe's
      SDK default as if it were a host, or the detector learns to imitate
      itself;
    inventing an identity      - with no handshake ever observed, falling
      back to the SDK default is correct. A made-up name matching no real
      host and no other probe is a fingerprint of its own, and worse than
      the default it replaces;
    leaking                    - the handshake carries capabilities and the
      process has an environment. This file is written on every proxied
      session, so neither may reach it.
"""
from __future__ import annotations

import json

import pytest

from driftsentry.hostprofile import (
    SDK_DEFAULT_NAME,
    implementation,
    load,
    profile_path,
    record,
)


# --------------------------------------------------------------------------- #
# Recording
# --------------------------------------------------------------------------- #
def test_a_genuine_handshake_is_recorded():
    record("acme", {"name": "claude-ai", "version": "0.14.2"}, cwd="/srv")
    profile = load("acme")
    assert profile["name"] == "claude-ai"
    assert profile["version"] == "0.14.2"
    assert profile["cwd"] == "/srv"


def test_the_sdk_default_is_never_recorded_as_a_host():
    """Otherwise a probe session teaches the detector to imitate itself."""
    record("acme", {"name": SDK_DEFAULT_NAME, "version": "1.0"})
    assert load("acme") is None


def test_a_handshake_without_a_name_is_ignored():
    record("acme", {"version": "1.0"})
    record("acme", None)
    assert load("acme") is None


def test_a_later_handshake_replaces_an_earlier_one():
    record("acme", {"name": "cursor", "version": "1.0"})
    record("acme", {"name": "claude-ai", "version": "0.14.2"})
    assert load("acme")["name"] == "claude-ai"


def test_profiles_are_kept_per_server():
    record("a", {"name": "claude-ai", "version": "1"})
    record("b", {"name": "cursor", "version": "2"})
    assert load("a")["name"] == "claude-ai"
    assert load("b")["name"] == "cursor"


def test_a_missing_version_does_not_produce_a_null():
    """A probe announcing version null would be as distinctive as "mcp"."""
    record("acme", {"name": "claude-ai"})
    assert load("acme")["version"] == "unknown"


# --------------------------------------------------------------------------- #
# What must not be written
# --------------------------------------------------------------------------- #
def test_only_name_version_and_cwd_are_stored():
    record("acme", {"name": "claude-ai", "version": "1.0",
                    "capabilities": {"roots": {"listChanged": True}},
                    "extra": "should-not-appear"}, cwd="/srv")
    stored = json.loads(profile_path("acme").read_text(encoding="utf-8"))
    assert set(stored) == {"name", "version", "cwd"}


def test_no_environment_value_can_reach_the_profile(monkeypatch):
    """Written on every proxied session, so a leak here would be routine."""
    secret = "sk-live-must-never-be-written-to-disk"
    monkeypatch.setenv("DRIFTSENTRY_TEST_SECRET", secret)
    record("acme", {"name": "claude-ai", "version": "1.0"}, cwd="/srv")
    assert secret not in profile_path("acme").read_text(encoding="utf-8")


def test_a_corrupt_profile_reads_as_absent_rather_than_raising():
    profile_path("acme").write_text("{not json", encoding="utf-8")
    assert load("acme") is None


# --------------------------------------------------------------------------- #
# Using it
# --------------------------------------------------------------------------- #
def test_an_unseen_server_yields_no_identity():
    """The caller must fall back, not invent. See the module docstring."""
    assert implementation("never-seen") is None


def test_a_recorded_server_yields_the_host_identity():
    record("acme", {"name": "claude-ai", "version": "0.14.2"})
    impl = implementation("acme")
    assert impl.name == "claude-ai"
    assert impl.version == "0.14.2"


def test_the_identity_is_never_the_sdk_default_once_a_host_is_known():
    record("acme", {"name": "claude-ai", "version": "0.14.2"})
    assert implementation("acme").name != SDK_DEFAULT_NAME


# --------------------------------------------------------------------------- #
# The option, and the control condition
# --------------------------------------------------------------------------- #
def test_mimic_host_is_off_by_default():
    """Experiments 1, 2 and 3's L1 arm must keep announcing the SDK default,
    or the condition they measure changes underneath them."""
    import inspect

    from driftsentry.baseline import capture_baseline, reprobe
    from driftsentry.verify import verify_server

    for fn in (capture_baseline, reprobe, verify_server):
        assert inspect.signature(fn).parameters["mimic_host"].default is False


def test_with_the_option_off_no_identity_is_sent_even_if_one_is_known():
    from driftsentry.baseline import _probe_client_info

    record("acme", {"name": "claude-ai", "version": "0.14.2"})
    assert _probe_client_info("acme", mimic_host=False) is None


def test_with_the_option_on_but_nothing_recorded_it_falls_back():
    from driftsentry.baseline import _probe_client_info

    assert _probe_client_info("never-seen", mimic_host=True) is None


def test_with_the_option_on_and_a_profile_the_host_identity_is_used():
    from driftsentry.baseline import _probe_client_info

    record("acme", {"name": "claude-ai", "version": "0.14.2"})
    impl = _probe_client_info("acme", mimic_host=True)
    assert impl is not None and impl.name == "claude-ai"
