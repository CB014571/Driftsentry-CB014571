"""The environments Gap 3 measures in, and the tool list it is allowed to probe.

Two of the four Gap 3 candidates were recorded as "unmeasurable" because
their old releases crashed with

    AttributeError: 'Server' object has no attribute 'list_resources'

which says nothing about those servers. It says pip resolved an unpinned
`mcp` dependency to an SDK that had removed the API the release was written
against. The tests here are mostly about not repeating the two mistakes that
produced that record: treating an environment failure as a server property,
and trusting a package summary about which tools are safe to call.

Nothing here installs anything. The acceptance test for an environment is a
real handshake, so the tests stub the handshake and check what the code does
with each answer.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from eval import real_envs
from eval.real_envs import EnvError, _version_key, resolve_sdk_pin, tool_names


# --------------------------------------------------------------------------- #
# Version ordering
# --------------------------------------------------------------------------- #
def test_date_based_versions_sort_newest_first():
    """The official servers use dates, so string order is nearly right and
    numerically wrong in exactly the places that matter."""
    versions = ["2026.8.18", "2026.10.28", "2026.1.9"]
    assert sorted(versions, key=_version_key, reverse=True) == [
        "2026.10.28", "2026.8.18", "2026.1.9"]


def test_semver_sorts_numerically_not_lexically():
    versions = ["0.6.2", "0.10.0", "0.9.0"]
    assert sorted(versions, key=_version_key, reverse=True) == [
        "0.10.0", "0.9.0", "0.6.2"]


def test_a_strange_version_does_not_raise():
    """An unparseable version must not take down a run mid-sweep."""
    assert sorted(["1.0", "1.0rc1", "0.9"], key=_version_key)


# --------------------------------------------------------------------------- #
# The SDK walk
# --------------------------------------------------------------------------- #
def test_pips_own_resolution_is_tried_first_and_costs_nothing(monkeypatch):
    """For a current release pip is right, and a walk would be wasted installs."""
    installs: list[list[str]] = []
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(real_envs, "starts_and_lists",
                        lambda p, e, cwd=None: (True, '["a"]'))
    monkeypatch.setattr(real_envs, "pip_install",
                        lambda p, specs: installs.append(list(specs)))

    sdk, attempts = resolve_sdk_pin(Path("py"), "pkg", "1.0", ["-m", "pkg"])
    assert sdk == "1.28.1"
    assert installs == []
    assert len(attempts) == 1 and attempts[0]["source"] == "pip"


def test_the_walk_takes_the_newest_sdk_that_starts(monkeypatch):
    """Newest-first, because that is closest to how the release was deployed."""
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(real_envs, "pip_install", lambda p, specs: None)

    works_from = "1.2.0"
    seen: list[str] = []

    def fake_start(python, entry, cwd=None):
        if not seen:
            return False, "AttributeError: 'Server' object has no attribute"
        return (seen[-1] == works_from), "started" if seen[-1] == works_from \
            else "AttributeError: 'Server' object has no attribute"

    def fake_install(python, specs):
        seen.append(specs[-1].split("==")[1])

    monkeypatch.setattr(real_envs, "pip_install", fake_install)
    monkeypatch.setattr(real_envs, "starts_and_lists", fake_start)

    sdk, attempts = resolve_sdk_pin(
        Path("py"), "pkg", "0.1.2", ["-m", "pkg"],
        candidates=["1.5.0", "1.4.0", "1.2.0", "1.0.0"])
    assert sdk == "1.2.0"
    # It did not keep walking past the first version that worked.
    assert "1.0.0" not in seen


def test_the_walk_is_bounded(monkeypatch):
    """An unresolved server is reported, not searched for indefinitely."""
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(real_envs, "pip_install", lambda p, specs: None)
    monkeypatch.setattr(real_envs, "starts_and_lists",
                        lambda p, e, cwd=None: (False, "never works"))

    sdk, attempts = resolve_sdk_pin(
        Path("py"), "pkg", "0.1.2", ["-m", "pkg"],
        candidates=[f"1.{n}.0" for n in range(40)], max_attempts=4)
    assert sdk is None
    assert len(attempts) <= 6          # the pip attempt plus the bounded walk


def test_every_attempt_keeps_the_servers_own_error(monkeypatch):
    """The error text is what identified the SDK mismatch; a boolean hides it."""
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(real_envs, "pip_install", lambda p, specs: None)
    monkeypatch.setattr(
        real_envs, "starts_and_lists",
        lambda p, e, cwd=None: (False, "AttributeError: no list_resources"))

    sdk, attempts = resolve_sdk_pin(Path("py"), "pkg", "0.1.2", ["-m", "pkg"],
                                    candidates=["1.1.0"], max_attempts=2)
    assert sdk is None
    assert all("list_resources" in a["detail"] for a in attempts)


def test_an_install_failure_during_the_walk_is_recorded_not_raised(monkeypatch):
    """One unbuildable SDK must not end the search for a working one."""
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(real_envs, "starts_and_lists",
                        lambda p, e, cwd=None: (False, "nope"))

    def fake_install(python, specs):
        if specs[-1].endswith("1.5.0"):
            raise EnvError("no matching distribution")

    monkeypatch.setattr(real_envs, "pip_install", fake_install)
    sdk, attempts = resolve_sdk_pin(Path("py"), "pkg", "0.1.2", ["-m", "pkg"],
                                    candidates=["1.5.0", "1.4.0"])
    assert sdk is None
    assert any("install failed" in a["detail"] for a in attempts)


def test_no_sdk_walk_reproduces_the_unmeasurable_result(monkeypatch, tmp_path):
    """resolve=False must fail the way the first run failed, not quietly fix it.

    The point is that the earlier record can be reproduced. A fix that cannot
    reproduce the thing it fixes is not evidence of anything.
    """
    monkeypatch.setattr(real_envs, "create_venv", lambda root, clean=False:
                        Path("py"))
    monkeypatch.setattr(real_envs, "pip_install", lambda p, specs: None)
    monkeypatch.setattr(real_envs, "installed_version", lambda p, k: "1.28.1")
    monkeypatch.setattr(
        real_envs, "starts_and_lists",
        lambda p, e, cwd=None: (False,
                                "AttributeError: 'Server' object has no "
                                "attribute 'list_resources'"))
    with pytest.raises(EnvError, match="list_resources"):
        real_envs.build("calculator", "mcp-server-calculator", "0.1.2",
                        ["-m", "mcp_server_calculator"], tmp_path / "env",
                        resolve=False)


# --------------------------------------------------------------------------- #
# The handshake is the acceptance test
# --------------------------------------------------------------------------- #
def test_a_package_that_imports_is_not_a_server_that_runs(monkeypatch):
    """pip reporting success says nothing: the failure is at the server's
    own import of the SDK decorator, which is after pip is done."""
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(
            cmd, 1, "", "AttributeError: 'Server' object has no attribute")

    monkeypatch.setattr(real_envs, "_run", fake_run)
    ok, detail = real_envs.starts_and_lists(Path("py"), ["-m", "pkg"])
    assert ok is False
    assert "AttributeError" in detail


def test_a_handshake_that_hangs_is_a_failure_not_a_wait(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, real_envs.HANDSHAKE_TIMEOUT_S)

    monkeypatch.setattr(real_envs, "_run", fake_run)
    ok, detail = real_envs.starts_and_lists(Path("py"), ["-m", "pkg"])
    assert ok is False and "handshake" in detail


def test_the_tool_list_comes_back_parsed(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(
            cmd, 0, json.dumps(["get_current_time", "convert_time"]), "")

    monkeypatch.setattr(real_envs, "_run", fake_run)
    ok, detail = real_envs.starts_and_lists(Path("py"), ["-m", "pkg"])
    assert ok is True
    assert tool_names(detail) == ["get_current_time", "convert_time"]


def test_tool_names_survives_rubbish():
    assert tool_names("not json") == []
    assert tool_names('{"a": 1}') == []


# --------------------------------------------------------------------------- #
# Yanked releases
# --------------------------------------------------------------------------- #
def test_a_yanked_release_is_not_offered(monkeypatch):
    """Pinning a yanked version installs something nobody ships."""
    payload = {"releases": {
        "1.0.0": [{"yanked": False}],
        "1.1.0": [{"yanked": True}],
        "0.9.0": [],
    }}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    monkeypatch.setattr(real_envs.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse())
    monkeypatch.setattr(real_envs.json, "load",
                        lambda fh: json.loads(fh.read().decode()))
    assert real_envs.released_versions("mcp") == ["1.0.0"]
