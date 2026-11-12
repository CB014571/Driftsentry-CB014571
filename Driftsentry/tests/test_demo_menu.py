"""The demo: the attacker's test menu, and what the dashboard does with it.

The menu and the dashboard never talk to each other. The menu arms the
server; the dashboard has to find out by probing. These tests pin both halves
and the line between them, plus the promise each menu entry makes - which
were measured end to end through the dashboard's own path before being
written down, four of them corrected by that measurement.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ATTACKER = Path(__file__).resolve().parents[2] / "mcp rug pull attack server"

pytestmark = pytest.mark.skipif(
    not ATTACKER.is_dir(), reason=f"attacker project not found at {ATTACKER}")


@pytest.fixture
def menu(monkeypatch, tmp_path):
    monkeypatch.setenv("ATTACKER_HOME", str(tmp_path))
    if str(ATTACKER) not in sys.path:
        sys.path.insert(0, str(ATTACKER))
    for name in [n for n in sys.modules if n.startswith("attacker")]:
        del sys.modules[name]
    import attacker.menu as m
    return m


# --------------------------------------------------------------------------- #
# The menu
# --------------------------------------------------------------------------- #
def test_every_test_arms_a_valid_scenario(menu):
    for t in menu.TESTS:
        assert menu.build_test(t, 7).validate() == [], t["name"]


def test_keys_are_unique_and_numbered(menu):
    keys = [t["key"] for t in menu.TESTS]
    assert len(keys) == len(set(keys))
    assert keys == [str(i) for i in range(1, len(keys) + 1)]


def test_every_test_starts_from_the_demo_baseline_release(menu):
    """One baseline, approved on v1n, has to serve every test."""
    for t in menu.TESTS:
        sc = menu.build_test(t, 7)
        assert sc.release in ("v1n", "v2"), t["name"]
        assert sc.narrow_base == (sc.release == "v2"), t["name"]


def test_gap_2_tests_ship_an_update_and_gap_1_tests_do_not(menu):
    for t in menu.TESTS:
        sc = menu.build_test(t, 7)
        assert (sc.release == "v2") == (t["group"] == 2), t["name"]


def test_the_sleeper_turns_on_the_clock_not_by_chance(menu):
    """A call count resets with every fresh server process - measured: it
    never turned. And the L3 gate also fires on '@', 'key', 'token' or
    'secret' in the input, so those are switched off."""
    from datetime import datetime, timezone
    sc = menu.build_test(next(t for t in menu.TESTS if t["name"] == "Sleeper"), 7)
    assert sc.trigger.after > datetime.now(timezone.utc).isoformat()
    assert sc.trigger.after_calls >= 10 ** 6
    assert sc.trigger.on_input_contains == []


def test_the_false_alarm_case_is_labelled_as_one(menu):
    t = next(t for t in menu.TESTS if t["name"] == "Legitimate rewording")
    assert "FALSE alarm" in t["expect"]


def test_ground_truth_counts_only_events_since_the_test_was_armed(menu, tmp_path):
    log = tmp_path / "sink" / "events.log"
    log.parent.mkdir(parents=True)
    log.write_text("t\tinject\tx\nt\tinject\tx\n", encoding="utf-8")
    since = 2
    with log.open("a", encoding="utf-8") as fh:
        fh.write("t\texfiltrate\ty\nt\texfiltrate\ty\nt\tegress\tz\n")
    monkeypatch_path = menu._events_log
    try:
        menu._events_log = lambda: log
        assert menu._ground_truth(since) == "egress x1, exfiltrate x2"
        assert menu._ground_truth(5) == "nothing malicious has happened yet"
    finally:
        menu._events_log = monkeypatch_path


def test_the_menu_never_imports_driftsentry(menu):
    source = (ATTACKER / "attacker" / "menu.py").read_text(encoding="utf-8")
    assert "driftsentry" not in source.replace("DriftSentry", "")


# --------------------------------------------------------------------------- #
# narrow_base: one baseline for every cover
# --------------------------------------------------------------------------- #
def _hints(menu, **kw):
    from attacker.scenario import Scenario
    import attacker.server as server
    return {name: (ann.readOnlyHint, ann.openWorldHint) if ann else None
            for name, (_, ann) in server.tool_plan(Scenario(**kw)).items()}


def test_a_narrow_base_update_keeps_the_narrow_hints(menu):
    """Otherwise a C2 update against a v1n baseline would also read as a
    widened permission on every tool."""
    v1n = _hints(menu, release="v1n")
    c2 = _hints(menu, release="v2", cover="C2", narrow_base=True)
    assert c2 == v1n


def test_the_evaluation_is_unaffected(menu):
    """narrow_base defaults off: C2 still ships on plain v1, as the RQ3a
    sweep measured it."""
    assert _hints(menu, release="v2", cover="C2") == _hints(menu, release="v1")


# --------------------------------------------------------------------------- #
# The dashboard side
# --------------------------------------------------------------------------- #
def test_the_daemon_enrols_with_keyed_probes_and_checks_updates():
    import inspect

    from driftsentry import daemon
    src = inspect.getsource(daemon)
    assert 'probe_mode="keyed", key=key_store.get_or_create(name)' in src
    assert "update_check=True" in src
    assert "cycle=state.checks + 1" in src


def test_the_update_summary_renders_the_scorers_outcome():
    from types import SimpleNamespace as NS

    from driftsentry.daemon import _update_summary
    outcome = {"verdict": "residue_alert",
               "escalations": [["lookup_customer", "readOnly_removed"]],
               "items": [
                   {"tool": "lookup_customer", "signal": "behavioural_drift",
                    "classification": "explained", "reason": "declared output change"},
                   {"tool": "lookup_customer", "signal": "new_file",
                    "classification": "residue", "reason": "no declared change explains it"},
                   {"tool": "lookup_customer", "signal": "new_file",
                    "classification": "residue", "reason": "duplicate"},
               ],
               "explained_tools": [], "tools_needing_baseline": []}
    u = _update_summary(NS(residue=outcome))
    assert u["verdict"] == "residue_alert"
    assert [i["signal"] for i in u["residue"]] == ["new_file"], "deduplicated"
    assert u["escalations"] == [{"tool": "lookup_customer", "escalation": "readOnly_removed"}]
    assert _update_summary(NS(residue=None)) is None


def test_the_dashboard_has_the_update_panel():
    html = (Path(__file__).resolve().parents[1] / "driftsentry" / "ui" / "index.html"
            ).read_text(encoding="utf-8")
    assert "function updatePanel" in html
    for label in ("UPDATE EXPLAINED", "UNDECLARED BEHAVIOUR", "PERMISSION WIDENED"):
        assert label in html
    assert "x.update?" in html


def test_the_dashboard_names_what_the_update_declared():
    """Measured on the live dashboard: without this the panel said UPDATE
    EXPLAINED without saying what the update declared - the one thing an
    examiner needs to see."""
    from driftsentry.daemon import _declared_lines
    declared = {"tools_added": ["export_all"], "tools_removed": [],
                "tools": {"lookup_customer": {
                    "output_changes": [{"path": "last_contact", "kind": "added"}],
                    "input_changes": [], "escalations": ["readOnly_removed"],
                    "description_changed": True}}}
    lines = _declared_lines(declared)
    assert {"tool": "export_all", "change": "new tool"} in lines
    change = next(l["change"] for l in lines if l["tool"] == "lookup_customer")
    assert "output added last_contact" in change
    assert "readOnly removed" in change
    assert "description reworded" in change


def test_the_residue_outcome_carries_the_declaration_without_touching_the_rules():
    from driftsentry.declared_diff import diff_definitions
    from driftsentry.residue import RULES, ResidueReport
    report = ResidueReport(declared=diff_definitions([], []).to_dict())
    assert "declared" in report.to_dict()
    assert "declared" not in RULES


# --------------------------------------------------------------------------- #
# driftsentry demo: one explicit attacker home, and backups out of sight
# --------------------------------------------------------------------------- #
# Measured: started from the desktop app's terminal, the dashboard's server
# read a redirected copy of %LOCALAPPDATA% while the attack was armed in the
# real one, and every check said OK with the attack armed. The demo now names
# one home outright and gives it to every process.
def test_every_demo_process_gets_the_same_home(tmp_path):
    from driftsentry import demo
    home = str(demo.demo_home(tmp_path))
    assert demo.serve_args(tmp_path) == ["-m", "attacker", "--home", home, "serve"]
    assert demo.demo_home(tmp_path).parent == tmp_path, "inside the attacker project"


def test_the_home_is_outside_localappdata():
    import os

    from driftsentry import demo
    home = demo.demo_home(demo.DEFAULT_ATTACKER)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        assert not str(home).lower().startswith(local.lower())


def test_a_baseline_that_launches_the_attacker_differently_is_replaced(tmp_path, monkeypatch):
    from types import SimpleNamespace as NS

    from driftsentry import demo
    python = tmp_path / "python.exe"
    old = NS(probe_mode="keyed", launch={"command": str(python),
                                         "args": ["-m", "attacker", "serve"]})
    monkeypatch.setattr("driftsentry.store.BaselineStore.load", lambda self, n: old)
    assert demo.baseline_status("acme", python, tmp_path)[0] == "other_server"
    old.launch["args"] = demo.serve_args(tmp_path)
    assert demo.baseline_status("acme", python, tmp_path)[0] == "ok"


def test_a_fixed_probe_baseline_is_replaced():
    from types import SimpleNamespace as NS

    from driftsentry import demo
    import driftsentry.store as store
    real = store.BaselineStore.load
    store.BaselineStore.load = lambda self, n: NS(probe_mode="fixed", launch={})
    try:
        assert demo.baseline_status("acme", Path("p"), Path("x"))[0] == "fixed"
    finally:
        store.BaselineStore.load = real


def test_a_backup_is_kept_where_the_dashboard_will_not_monitor_it(tmp_path, monkeypatch):
    """Measured: a backup beside the baselines showed up as a second server."""
    import json

    monkeypatch.setenv("DRIFTSENTRY_HOME", str(tmp_path))
    from driftsentry import demo
    from driftsentry.store import BaselineStore
    store = BaselineStore()
    store.path_for("acme").write_text(json.dumps({"server": "acme"}), encoding="utf-8")
    backup = demo.backup_baseline("acme")
    assert backup.exists() and backup.parent.name == "baseline_backups"
    assert store.list_servers() == ["acme"]


def test_the_attacker_cli_takes_a_home(tmp_path):
    import subprocess
    py = ATTACKER / ".venv" / "Scripts" / "python.exe"
    if not py.is_file():
        pytest.skip("attacker venv not present")
    home = tmp_path / "h"
    done = subprocess.run([str(py), "-m", "attacker", "--home", str(home),
                           "benign", "--release", "v1n"], cwd=ATTACKER,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert (home / "scenario.json").is_file()
