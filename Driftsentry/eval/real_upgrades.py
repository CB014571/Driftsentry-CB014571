"""Does a behavioural detector alarm on a genuine version upgrade? (Gap 3)

The gap, as the report states it: existing benchmarks label attack cases
built from registration-time metadata, or compare benign servers against
injected copies. No study reports the false-alarm rate of a
response-and-sandbox detector across real version upgrades.

The measurement is deliberately the same shape as a rug pull, because that
is the point. Baseline the OLD release, upgrade, re-probe against the NEW
one. Nothing malicious happened. Every alert is a false alarm.

Two things are recorded that the attack matrix cannot show

    definition_changed  whether hash pinning would have fired at all. This
                        is the other half of Gap 1: the report cites a
                        census saying real servers change their advertised
                        fields often, but that is someone else's number.
                        This measures it on the servers actually tested.

    per-tool ratios     kept so T8's per-tool thresholds can be fitted on a
                        server's OWN pre-upgrade runs, which is what H1
                        proposes. A tool's threshold must never come from
                        runs after the upgrade being judged.

Only tools confirmed read-only by introspection are probed. A guess from a
package summary is not good enough when the cost of being wrong is a write
against someone's real server.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("eval.real_upgrades")


@dataclass
class UpgradeResult:
    """One server, one upgrade, one phase."""

    server: str
    phase: str                      # "old" (noise) or "new" (the upgrade)
    run: int
    score: float = 0.0
    verdict: str = ""
    triggered_by: str | None = None
    definition_changed: bool = False
    definition_hash: str = ""
    alerted: bool = False
    per_tool: dict[str, float] = field(default_factory=dict)
    error: str | None = None
    # T29, RQ3b. Filled only for a run scored with update_check.
    update_check: bool = False
    residue_verdict: str = ""        # accepted | residue_alert | escalation | held_for_review
    residue_signals: list[str] = field(default_factory=list)
    escalations: list[str] = field(default_factory=list)
    held_for_review: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def venv_python(root: Path) -> Path:
    for candidate in (root / "Scripts" / "python.exe", root / "bin" / "python"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no interpreter in {root}")


def launch_for(python: Path, entry: list[str], cwd: str | None = None) -> dict[str, Any]:
    """A launch dict for a real server.

    The environment is empty: the MCP SDK adds its own default set, which is
    what a real client gives a server. Passing anything more would be the
    launch-parity mistake from T4 in a new place.
    """
    return {"command": str(python), "args": list(entry), "cwd": cwd, "env": {}}


async def probe_phase(
    server_id: str,
    baseline: Any,
    launch: dict[str, Any],
    *,
    phase: str,
    run: int,
    samples_per_probe: int = 2,
    threshold_ratio: float | None = None,
    cycle: int = 1,
    key: bytes | None = None,
    update_check: bool = False,
    per_tool: dict[str, float] | None = None,
) -> UpgradeResult:
    """Score one release against a baseline captured on the old one.

    ``update_check`` (T29) scores the release as an update: declared
    definition changes explain the behaviour they cover, and only the residue
    can alert. That is RQ3b's measurement. Off, it is the plain detector,
    which is what the same-release noise phase must stay.
    """
    from driftsentry.verify import verify_server

    out = UpgradeResult(server=server_id, phase=phase, run=run)
    try:
        report = await verify_server(
            baseline, launch=launch, samples_per_probe=samples_per_probe,
            monitor_sandbox=True, threshold_ratio=threshold_ratio,
            cycle=cycle, key=key, update_check=update_check,
            per_tool=per_tool)
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
        return out

    out.score = round(report.score, 4)
    out.verdict = report.verdict
    out.triggered_by = report.triggered_by
    out.alerted = report.verdict == "alert"
    out.definition_changed = bool(getattr(report, "definition_changed", False))
    out.definition_hash = getattr(report, "observed_definition_hash", "") or ""
    out.per_tool = {t.tool: round(t.score, 4) for t in report.tools}
    if update_check:
        _fill_residue(out, report)
    return out


def _fill_residue(out: UpgradeResult, report: Any) -> None:
    """The residue outcome of one update-checked run.

    With nothing declared the residue checker never runs and the base
    detector decides - row 1 of the rules - so its alerts are the residue.
    Recording "accepted" there would contradict the alert beside it.
    """
    from driftsentry.residue import SIGNAL_NAMES
    from driftsentry.scorer import ALERT_AT

    out.update_check = True
    outcome = getattr(report, "residue", None)
    if outcome is None:
        signals = {SIGNAL_NAMES.get(s.name, s.name)
                   for t in report.tools for p in t.probes for s in p.signals
                   if s.score >= ALERT_AT}
        out.residue_verdict = "residue_alert" if report.verdict == "alert" else "accepted"
        out.residue_signals = sorted(signals)
        return
    items = outcome.get("items", [])
    out.residue_verdict = outcome.get("verdict", "")
    out.residue_signals = sorted({i["signal"] for i in items
                                  if i["classification"] == "residue"})
    out.escalations = [f"{t}:{e}" for t, e in outcome.get("escalations", [])]
    out.held_for_review = sum(1 for i in items if i["classification"] == "held_for_review")


def summarise(results: list[UpgradeResult]) -> str:
    """False alarms on upgrades, beside what hash pinning would have seen."""
    from eval.stats import wilson

    old = [r for r in results if r.phase == "old" and not r.error]
    new = [r for r in results if r.phase == "new" and not r.error]
    lines = ["", "=" * 72,
             "  REAL BENIGN UPGRADES - false alarms (Gap 3 / RQ1)",
             "=" * 72]

    for label, rows in (("same release (noise)", old), ("after upgrade", new)):
        if not rows:
            lines.append(f"  {label:<24} no runs")
            continue
        hits = sum(1 for r in rows if r.alerted)
        rate, low, high = wilson(hits, len(rows))
        lines.append(f"  {label:<24}{rate:6.1%} [{low:.2f}, {high:.2f}]  "
                     f"{hits}/{len(rows)} runs alerted")

    changed = sum(1 for r in new if r.definition_changed)
    lines += ["",
              f"  hash pinning would have fired on {changed}/{len(new)} upgrades",
              "    (Gap 1's second half: whether pinning is noisy on real"
              " upgrades, measured here", "     rather than cited)"]

    if new:
        by_signal: dict[str, int] = {}
        for r in new:
            if r.alerted and r.triggered_by:
                by_signal[r.triggered_by] = by_signal.get(r.triggered_by, 0) + 1
        if by_signal:
            lines += ["", "  what fired on an upgrade:"]
            for sig, n in sorted(by_signal.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {sig:<28}{n}")
    return "\n".join(lines)


def save(results: list[UpgradeResult], out_dir: str | Path, name: str = "rq1") -> Path:
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    target = path / f"{name}.jsonl"
    with target.open("w", encoding="utf-8") as handle:
        for r in results:
            handle.write(json.dumps(r.to_dict(), default=str) + "\n")
    return target
