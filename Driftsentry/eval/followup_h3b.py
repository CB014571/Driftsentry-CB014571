"""H3b - the follow-up to H3: residue rules v1.1 on upgrades they were not designed on.

H3 FAILED on its false-alarm half and stays failed: under the frozen v1.0
rules, 2 of 4 real benign upgrades (time, git) left a residue. Inspecting the
raw responses (driftsentry/residue.py, RULES_V1_1) showed both were MCP SDK
envelope changes, not tool behaviour. Rules v1.1 removes those two artefacts.

Because v1.1 was designed on time and git, it cannot be judged on them.
H3b is judged on:

    HELD-OUT REAL UPGRADES. mcp-server-calculator, mcp-server-sqlite and
    mcp-server-duckdb - approved servers that v1.0 could not run (their old
    releases do not start on CPython 3.14), built here on CPython 3.12. None
    of them informed v1.1.

    THE SYNTHETIC SWEEP, RE-RUN. RQ3a's 78 episodes again, scored with v1.1,
    so the rules change is shown not to cost detection - paired with v1.0.

Same bar as H3: residue detects >= 80% pooled C0-C2 and beats all three
baselines (Holm p < 0.05), and at most 15% of real upgrades leave a
residue. With three held-out servers, 15% means none of them may. That is
a small sample and the pre-registration says so.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval_results" / "followup" / "h3b"
PREREG = OUT / "preregistration.json"
RULES_FILE = OUT / "rules_v1_1_frozen.json"

HELD_OUT = ("calculator", "sqlite", "duckdb")
DESIGN = ("time", "git", "motherduck", "alchemy")
DETECT_AT_LEAST_PCT = 80.0
REAL_UPGRADES_AT_MOST_PCT = 15.0


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preregister(interpreter: str) -> dict[str, Any]:
    """Freeze rules v1.1 and the hypothesis. Written once."""
    from driftsentry.residue import freeze_rules

    if PREREG.exists():
        raise FileExistsError(f"{PREREG} exists; a pre-registration is written once")
    OUT.mkdir(parents=True, exist_ok=True)
    freeze_rules(RULES_FILE, "1.1")
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    doc = {
        "id": "H3b",
        "written": datetime.now().isoformat(timespec="seconds"),
        "code_commit": commit,
        "status": "post-hoc follow-up to H3, designed after H3 failed; H3 stays FAIL",
        "rules": {"version": "1.1", "file": RULES_FILE.name, "sha256": _sha(RULES_FILE)},
        "designed_on": list(DESIGN),
        "held_out": list(HELD_OUT),
        "held_out_interpreter": interpreter,
        "hypothesis": (
            "Under residue rules v1.1, (a) at most "
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
            "held_out": "python -m eval real --servers calculator,sqlite,duckdb --rules 1.1 "
                        "--interpreter <3.12> --runs 3; a server leaves a residue if any of "
                        "its 3 upgrade runs has residue_verdict residue_alert",
            "synthetic": "python -m eval rq3u --rules 1.1 (same families, covers, seeds and "
                         "cycles as the v1.0 sweep); analysed with eval.rq3u_analyse",
            "small_sample": "three held-out servers: the real-upgrade half passes only if "
                            "none leaves a residue; the Wilson interval is reported",
            "unmeasurable": "a held-out server whose old release still cannot start is "
                            "reported as unmeasurable and not counted either way",
        },
    }
    PREREG.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    PREREG.with_suffix(".sha256").write_text(_sha(PREREG) + "\n", encoding="utf-8")
    return doc


def verify_preregistration() -> dict[str, Any]:
    from driftsentry.residue import verify_rules

    doc = json.loads(PREREG.read_text(encoding="utf-8"))
    if _sha(PREREG) != PREREG.with_suffix(".sha256").read_text(encoding="utf-8").strip():
        raise RuntimeError("H3b preregistration.json no longer matches its sha256")
    if _sha(RULES_FILE) != doc["rules"]["sha256"]:
        raise RuntimeError("rules_v1_1_frozen.json changed after pre-registration")
    verify_rules(RULES_FILE, "1.1")
    return doc


def held_out_result() -> dict[str, Any]:
    """Per held-out server: measured or not, and whether it left a residue."""
    out: dict[str, Any] = {}
    for short in HELD_OUT:
        path = OUT / "held_out" / f"rq1_{short}.jsonl"
        meta = OUT / "held_out" / f"rq1_{short}_meta.json"
        rows = ([json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
                if path.is_file() else [])
        new = [r for r in rows if r.get("phase") == "new" and not r.get("error")]
        same = [r for r in rows if r.get("phase") == "old" and not r.get("error")]
        if not new:
            err = (json.loads(meta.read_text(encoding="utf-8")).get("error")
                   if meta.is_file() else "not run")
            out[short] = {"measured": False, "reason": err}
            continue
        out[short] = {
            "measured": True,
            "upgrade_runs": len(new),
            "residue_runs": sum(r.get("residue_verdict") == "residue_alert" for r in new),
            "left_residue": any(r.get("residue_verdict") == "residue_alert" for r in new),
            "same_release_alerts": sum(bool(r.get("alerted")) for r in same),
            "same_release_runs": len(same),
        }
    return out
