"""H3c - residue rules v1.2 on upgrades they were not designed on.

H3 FAILED and stays failed. H3b FAILED on its real-upgrade half and stays
failed: under frozen v1.1, 1 of 3 held-out upgrades left a residue (sqlite,
whose upgrade renamed all six tools), although its synthetic half passed
(45/45 attacks, all baselines beaten, 0/6 benign updates alarmed).

Rules v1.2 = v1.1 plus two rules, both about what a tool list can declare:
    renaming   a tool removed and a tool added whose names and input fields
               are equal once case and punctuation are ignored, one-to-one,
               is probed under its new name against the old name's record.
    removal    a probe of a tool the new release no longer lists is explained
               by the removal; side effects and content flags during it are
               not.
Designed on sqlite (now design data, with time, git, motherduck, alchemy,
calculator and duckdb), so it is judged on servers it has never seen:

    HELD-OUT REAL UPGRADES. excel-mcp-server, office-word-mcp-server,
    mcp-server-tree-sitter - approved for this test on 15 Nov 2026. Release
    pairs chosen by a fixed rule before any run (eval/real_servers.json,
    _decisions.h3c_scope.release_rule).

    THE SYNTHETIC SWEEP, RE-RUN under v1.2, so the new rules are shown not to
    cost detection of attacks hidden in updates.

Same bar as H3 and H3b, unchanged.

Stated weaknesses, in advance
    Three servers: the real half passes only if none leaves a residue.
    These servers work on files, and generated arguments rarely name a file
    that exists, so many probe answers are errors. Each server's error rate
    at baseline is reported beside its result; a server whose probes all
    erred is a weak test and is labelled as such, not dropped.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval_results" / "followup" / "h3c"
PREREG = OUT / "preregistration.json"
RULES_FILE = OUT / "rules_v1_2_frozen.json"

HELD_OUT = ("excel-server", "office-word-server", "tree-sitter")
HELD_OUT_PACKAGES = ("excel-mcp-server", "office-word-mcp-server", "mcp-server-tree-sitter")
DESIGN = ("time", "git", "motherduck", "alchemy", "calculator", "sqlite", "duckdb")
DETECT_AT_LEAST_PCT = 80.0
REAL_UPGRADES_AT_MOST_PCT = 15.0


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preregister(interpreter: str) -> dict[str, Any]:
    from driftsentry.residue import freeze_rules

    if PREREG.exists():
        raise FileExistsError(f"{PREREG} exists; a pre-registration is written once")
    OUT.mkdir(parents=True, exist_ok=True)
    freeze_rules(RULES_FILE, "1.2")
    servers = json.loads((ROOT / "eval" / "real_servers.json").read_text(encoding="utf-8"))
    pairs = {s["name"]: {"old": s["old"], "new": s["new"],
                         "old_date": s.get("old_date"), "new_date": s.get("new_date")}
             for s in servers["servers"] if s["name"] in HELD_OUT_PACKAGES}
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    doc = {
        "id": "H3c",
        "written": datetime.now().isoformat(timespec="seconds"),
        "code_commit": commit,
        "status": ("post-hoc follow-up, designed after H3 and H3b failed; both stay FAIL. "
                   "Tests product v1.1's update check, rules v1.2."),
        "rules": {"version": "1.2", "file": RULES_FILE.name, "sha256": _sha(RULES_FILE)},
        "designed_on": list(DESIGN),
        "held_out": list(HELD_OUT_PACKAGES),
        "release_pairs": pairs,
        "release_rule": servers["_decisions"]["h3c_scope"]["release_rule"],
        "held_out_interpreter": interpreter,
        "hypothesis": (
            "Under residue rules v1.2, (a) at most "
            f"{REAL_UPGRADES_AT_MOST_PCT}% of the held-out real benign upgrades leave a "
            "residue; (b) residue detection of attacks hidden in updates, re-run on the "
            f"RQ3a matrix, is at least {DETECT_AT_LEAST_PCT}% pooled over C0-C2 and beats "
            "accept_rebaseline, definition_diff and new_host_only (exact McNemar, Holm "
            "p < 0.05); (c) synthetic benign updates raise no more false alarms than "
            "under v1.0."),
        "thresholds": {"detect_at_least_pct": DETECT_AT_LEAST_PCT,
                       "real_upgrades_at_most_pct": REAL_UPGRADES_AT_MOST_PCT,
                       "holm_alpha": 0.05},
        "procedure": {
            "held_out": ("python -m eval real --servers excel-server,office-word-server,"
                         "tree-sitter --rules 1.2 --interpreter <3.12> --as-of-release "
                         "--runs 3; a server leaves a residue if any of its 3 upgrade "
                         "runs has residue_verdict residue_alert"),
            "synthetic": "python -m eval rq3u --rules 1.2 (same families, covers, seeds "
                         "and cycles as v1.0 and v1.1); analysed with eval.rq3u_analyse",
            "design_check": "the seven design servers re-run under v1.2 are reported as "
                            "design evidence only, never as part of the verdict",
            "unmeasurable": "a held-out server that cannot start, or for which no tool "
                            "is confirmed read-only, is reported as unmeasurable and not "
                            "counted either way",
            "weak_test": "each held-out server's baseline error rate is reported; one "
                         "at 100% is labelled a weak test, not removed",
        },
    }
    PREREG.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    PREREG.with_suffix(".sha256").write_text(_sha(PREREG) + "\n", encoding="utf-8")
    return doc


def verify_preregistration() -> dict[str, Any]:
    from driftsentry.residue import verify_rules

    doc = json.loads(PREREG.read_text(encoding="utf-8"))
    if _sha(PREREG) != PREREG.with_suffix(".sha256").read_text(encoding="utf-8").strip():
        raise RuntimeError("H3c preregistration.json no longer matches its sha256")
    if _sha(RULES_FILE) != doc["rules"]["sha256"]:
        raise RuntimeError("rules_v1_2_frozen.json changed after pre-registration")
    verify_rules(RULES_FILE, "1.2")
    return doc


def held_out_result() -> dict[str, Any]:
    """Per held-out server: measured or not, residue or not, and how strong a test."""
    out: dict[str, Any] = {}
    for short in HELD_OUT:
        path = OUT / "held_out" / f"rq1_{short}.jsonl"
        meta_path = OUT / "held_out" / f"rq1_{short}_meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
        rows = ([json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
                 if l.strip()] if path.is_file() else [])
        new = [r for r in rows if r.get("phase") == "new" and not r.get("error")]
        same = [r for r in rows if r.get("phase") == "old" and not r.get("error")]
        if not new:
            out[short] = {"measured": False, "reason": meta.get("error") or "not run"}
            continue
        rate = meta.get("baseline_error_rate")
        out[short] = {
            "measured": True,
            "upgrade_runs": len(new),
            "residue_runs": sum(r.get("residue_verdict") == "residue_alert" for r in new),
            "left_residue": any(r.get("residue_verdict") == "residue_alert" for r in new),
            "same_release_alerts": sum(bool(r.get("alerted")) for r in same),
            "same_release_runs": len(same),
            "baseline_error_rate": rate,
            "weak_test": rate is not None and rate >= 1.0,
            "renamed": (meta.get("declared") or {}).get("tools_renamed") or {},
        }
    return out
