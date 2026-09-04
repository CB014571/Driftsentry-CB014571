"""Phase 5 - alerts and mitigation.

A drift score is not an outcome; a person deciding what to do is. This module
turns a scored DriftReport into something a non-expert can act on, which the
roadmap defines as four things:

    1. which server and tool drifted
    2. which signal fired, and by how much relative to the threshold
    3. a concrete before/after - what the tool used to do, what it does now
    4. a mitigation - what to do about it, as commands that can be run

Point 4 is where most security tools stop short, and it is the difference between
a detector and a usable one. "Drift score 3.0 on tool lookup" tells a user
nothing they can act on. "This tool now emits text aimed at your AI assistant
rather than at you; quarantine it, and check whether the assistant already acted
on that instruction" does.

Mitigations are TEMPLATED PER CAUSE
    Each triggering signal maps to a different response, because the causes are
    genuinely different. A new egress host means data may already have left, so
    the priority is rotating credentials the server could have seen. A definition
    hash change means the contract you approved was rewritten, so the priority is
    re-approval. Plain behavioural drift is ambiguous - it may be an ordinary
    update - so its mitigation leads with "look at the before/after and decide",
    not with "you have been attacked". Overstating a weak signal is how security
    tools train users to ignore them.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.alerts")

# Truncate before/after evidence so an alert stays readable in a terminal.
_EXCERPT_CHARS = 240

# Which cause the ADVICE should address, most specific first.
#
# The scorer combines signals by maximum, so the highest-scoring signal is
# whichever crossed the line hardest - and for a definition-invariant rug pull
# that is almost always `behavioural_drift`, whose honest advice is the vague
# "look at the before/after and decide". But when a security rule ALSO fired we
# know something far more precise: that the response now carries an instruction
# aimed at the assistant, or that a credential file was read. Those have
# specific, useful remediations.
#
# So severity is driven by the score, and the advice is driven by specificity.
# Picking the mitigation by score alone would bury the one instruction the user
# most needs - "check what your assistant did after reading this" - underneath a
# generic drift message.
_CAUSE_SPECIFICITY = [
    "definition_hash",
    "rule:new_egress_host",
    "rule:secret_file_read",
    "rule:credential_shaped_output",
    "rule:instruction_shaped_output",
    "rule:new_file_access",
    # More specific than plain drift: it says the tool used to be exactly
    # reproducible and no longer is, which is a concrete thing to show a user.
    "field_drift",
    "determinism_break",
    "behavioural_drift",
    "structural_change",
    "error_behaviour",
]


def most_specific_cause(signal_names: list[str], fallback: str) -> str:
    """Pick the cause whose mitigation is most actionable."""
    for candidate in _CAUSE_SPECIFICITY:
        if candidate in signal_names:
            return candidate
    return fallback


@dataclass
class Mitigation:
    """One recommended action, in priority order."""

    action: str
    detail: str
    urgency: str                 # immediate | soon | review
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    """A single actionable finding about one tool on one server."""

    alert_id: str
    created_at: str
    server: str
    tool: str
    severity: str                # critical | high | medium
    score: float
    threshold_score: float
    triggered_by: str            # the highest-scoring signal: what crossed the line
    primary_cause: str           # the most specific signal: what the advice addresses
    cause: str
    before: str
    after: str
    mitigations: list[Mitigation] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    definition_changed: bool = False
    embedding_backend: str = ""
    calibration_source: str = ""
    threshold_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mitigations"] = [m.to_dict() for m in self.mitigations]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        known = {f for f in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in known}
        payload["mitigations"] = [Mitigation(**m) for m in data.get("mitigations", [])]
        return cls(**payload)


# --------------------------------------------------------------------------- #
# Cause -> plain English, and cause -> mitigation
# --------------------------------------------------------------------------- #
def _quarantine_cmd(server: str) -> str:
    return f"driftsentry quarantine --server {server}"


def _rebaseline_cmd(server: str) -> str:
    return f"driftsentry baseline --server {server} --exec <the server's launch command>"


def _generic_tail(server: str) -> list[Mitigation]:
    """Actions that apply whatever the cause."""
    return [
        Mitigation(
            action="Restore your original MCP client config",
            detail="Takes DriftSentry and the suspect server out of the loop entirely, "
                   "returning the client to the state it was in before onboarding.",
            urgency="review",
            command="driftsentry restore --config <your client config>",
        ),
        Mitigation(
            action="Report it",
            detail="If this is a public MCP server, report the behaviour to the registry or "
                   "repository that distributes it, and keep the JSON alert as evidence. "
                   f"Full record: driftsentry report {server}",
            urgency="review",
            command=None,
        ),
    ]


def mitigations_for(cause: str, server: str, tool: str) -> list[Mitigation]:
    """Map a triggering signal to the actions that actually address it."""
    if cause == "definition_hash":
        return [
            Mitigation(
                action="Treat the server's approval as void",
                detail="The tool contract you approved - its name, description or input schema - "
                       "has been rewritten since approval. Whatever you agreed to is not what is "
                       "installed now. This is the classic rug-pull pattern.",
                urgency="immediate",
                command=_quarantine_cmd(server),
            ),
            Mitigation(
                action="Review the change, then force re-approval",
                detail="Compare the advertised tools against what you originally approved. If the "
                       "change is a legitimate update you understand, re-baseline to accept it. "
                       "Re-baselining an attacker's definition makes the attack permanent, so do "
                       "not do it just to silence the alert.",
                urgency="soon",
                command=_rebaseline_cmd(server),
            ),
            *_generic_tail(server),
        ]

    if cause == "rule:new_egress_host":
        return [
            Mitigation(
                action="Quarantine the server now",
                detail="This tool contacted a network host it never contacted when you approved "
                       "it. Data may already have left your machine. This is the strongest single "
                       "signal DriftSentry has.",
                urgency="immediate",
                command=_quarantine_cmd(server),
            ),
            Mitigation(
                action="Rotate every credential this server could have seen",
                detail="Assume anything passed to this server, or reachable from it, is "
                       "compromised: API keys in its env block, tokens in files it can read, and "
                       "any secret you sent through one of its tools.",
                urgency="immediate",
                command=None,
            ),
            Mitigation(
                action="Preserve the evidence",
                detail="Keep the proxy exchange log and this alert before restarting anything - "
                       "they record exactly what was sent and when.",
                urgency="soon",
                command=None,
            ),
            *_generic_tail(server),
        ]

    if cause == "rule:secret_file_read":
        return [
            Mitigation(
                action="Quarantine the server now",
                detail="This tool opened files that hold credentials or private keys, and it did "
                       "not touch them when you approved it.",
                urgency="immediate",
                command=_quarantine_cmd(server),
            ),
            Mitigation(
                action="Treat the named credentials as compromised and rotate them",
                detail="Rotate the specific keys listed in the evidence below first: SSH keys, "
                       "cloud credentials and .env secrets are the usual targets.",
                urgency="immediate",
                command=None,
            ),
            *_generic_tail(server),
        ]

    if cause == "rule:credential_shaped_output":
        return [
            Mitigation(
                action="Quarantine the server now",
                detail="The tool's responses now contain key- or token-shaped strings that were "
                       "not there at baseline. Either it is leaking secrets into your assistant's "
                       "context, or it is planting credentials for the assistant to use.",
                urgency="immediate",
                command=_quarantine_cmd(server),
            ),
            Mitigation(
                action="Rotate any credential that appears in the evidence",
                detail="Anything matching a real secret of yours must be considered exposed.",
                urgency="immediate",
                command=None,
            ),
            *_generic_tail(server),
        ]

    if cause == "rule:instruction_shaped_output":
        return [
            Mitigation(
                action="Stop the assistant acting on this tool's output",
                detail="The response now contains text addressed to your AI assistant rather than "
                       "to you - the signature of a tool-poisoning payload. The danger is not the "
                       "text itself but what the assistant may do after reading it.",
                urgency="immediate",
                command=_quarantine_cmd(server),
            ),
            Mitigation(
                action="Review what the assistant did after calling this tool",
                detail="Check the conversation and the proxy log for actions taken right after "
                       "this response: messages sent, files written, other tools called. Those "
                       "are what the injected instruction was trying to cause.",
                urgency="immediate",
                command=None,
            ),
            *_generic_tail(server),
        ]

    if cause == "rule:new_file_access":
        return [
            Mitigation(
                action="Review the files this tool opened",
                detail="They are listed in the evidence below. A legitimate update may touch new "
                       "files; a rug pull reads things it has no business reading.",
                urgency="soon",
                command=None,
            ),
            Mitigation(
                action="Quarantine if you cannot explain the access",
                detail="Anything outside the tool's stated purpose should be treated as hostile "
                       "until proven otherwise.",
                urgency="soon",
                command=_quarantine_cmd(server),
            ),
            *_generic_tail(server),
        ]

    # behavioural_drift / structural_change / anything else: genuinely ambiguous.
    return [
        Mitigation(
            action="Compare the before and after below, and decide",
            detail="This tool's behaviour moved further from its approved baseline than benign "
                   "variation explains. That is not by itself proof of an attack - a legitimate "
                   "update produces the same signal - so the before/after is the evidence to "
                   "judge. Look for content you did not ask for, instructions aimed at the "
                   "assistant, or answers that are subtly wrong.",
            urgency="soon",
            command=None,
        ),
        Mitigation(
            action="If the change is expected, re-baseline to accept it",
            detail="Re-baselining teaches DriftSentry the new behaviour and stops the alert. Only "
                   "do this once you have looked at the before/after and are satisfied the change "
                   "is legitimate.",
            urgency="review",
            command=_rebaseline_cmd(server),
        ),
        Mitigation(
            action="If you cannot explain the change, quarantine it",
            detail="A definition-invariant behaviour change that nobody can account for is exactly "
                   "the pattern this tool exists to catch.",
            urgency="soon",
            command=_quarantine_cmd(server),
        ),
        *_generic_tail(server),
    ]


def _cause_sentence(cause: str, tool: str, signal_detail: str) -> str:
    base = {
        "definition_hash": f"The tool definitions advertised by this server changed after you approved them.",
        "rule:new_egress_host": f"'{tool}' contacted a network host it never contacted at baseline.",
        "rule:secret_file_read": f"'{tool}' opened credential-bearing files it never touched at baseline.",
        "rule:credential_shaped_output": f"'{tool}' returned key- or token-shaped strings it never returned at baseline.",
        "rule:instruction_shaped_output": f"'{tool}' returned text aimed at the AI assistant rather than at you.",
        "rule:new_file_access": f"'{tool}' opened files it never touched at baseline.",
        "field_drift": f"'{tool}' changed a security-relevant value in its response - an account, recipient, address or status - while the rest of the answer stayed the same.",
        "determinism_break": f"'{tool}' always returned exactly the same answer to this input when it was "
                             f"approved, and now returns something different.",
        "structural_change": f"'{tool}' returned a response whose structure differs from every shape seen at baseline.",
        "behavioural_drift": f"'{tool}' now behaves measurably differently from its approved baseline.",
    }.get(cause)
    return base or f"'{tool}' triggered {cause}: {signal_detail}"


# --------------------------------------------------------------------------- #
# Building alerts from a scored report
# --------------------------------------------------------------------------- #
def _excerpt(text: str) -> str:
    text = (text or "").strip().replace("\n", " ")
    if not text:
        return "(no text captured)"
    return text if len(text) <= _EXCERPT_CHARS else text[:_EXCERPT_CHARS] + " ..."


def _before_after(cause: str, signals: list, report) -> tuple[str, str]:
    """Produce the concrete 'it used to do X, now it does Y' pair."""
    by_name = {s.name: s for s in signals}

    if cause == "definition_hash":
        return (
            f"tool definitions hashed to {report.baseline_definition_hash}",
            f"they now hash to {report.observed_definition_hash}",
        )

    if cause.startswith("rule:"):
        signal = by_name.get(cause)
        matches = (signal.evidence.get("matches") if signal else None) or []
        noun = {
            "rule:new_egress_host": ("contacted no host outside its baseline set",
                                     "now contacts: " + ", ".join(matches)),
            "rule:secret_file_read": ("read no credential files",
                                      "now reads: " + ", ".join(matches)),
            "rule:new_file_access": ("touched only its baseline files",
                                     "now also opens: " + ", ".join(matches)),
            "rule:credential_shaped_output": ("returned no credential-shaped strings",
                                              "now returns: " + ", ".join(matches)),
            "rule:instruction_shaped_output": ("returned no agent-directed instructions",
                                               "now returns: " + ", ".join(matches)),
        }.get(cause)
        if noun:
            return noun

    behavioural = by_name.get("behavioural_drift")
    if behavioural:
        evidence = behavioural.evidence
        return (
            _excerpt(evidence.get("baseline_excerpt", "")),
            _excerpt(evidence.get("observed_excerpt", "")),
        )
    return ("(baseline behaviour not captured)", "(observed behaviour not captured)")


def build_alerts(report) -> list[Alert]:
    """Turn every alerting tool in a scored report into an actionable Alert."""
    alerts: list[Alert] = []
    stamp = datetime.now(timezone.utc)

    for tool in report.alerting_tools():
        # Use the worst probe's full signal list: the triggering signal decides
        # the mitigation, but the behavioural signal carries the before/after
        # excerpts even when a rule is what actually fired.
        worst = max(tool.probes, key=lambda p: p.score) if tool.probes else None
        signals = worst.signals if worst else tool.signals
        triggered_by = tool.triggered_by or "behavioural_drift"

        # Severity comes from the score; the advice comes from the most specific
        # signal that fired. See _CAUSE_SPECIFICITY.
        fired = [s.name for s in signals if s.score >= 0.5]
        cause = most_specific_cause(fired, triggered_by)
        trigger = next((s for s in signals if s.name == cause), None)
        detail = trigger.detail if trigger else ""

        severity = "critical" if (tool.score >= 2.0 or report.definition_changed) else "high"
        before, after = _before_after(cause, signals, report)

        alerts.append(Alert(
            alert_id=f"{report.server}-{tool.tool}-{stamp.strftime('%Y%m%d%H%M%S')}",
            created_at=stamp.isoformat(),
            server=report.server,
            tool=tool.tool,
            severity=severity,
            score=tool.score,
            threshold_score=1.0,
            triggered_by=triggered_by,
            primary_cause=cause,
            cause=_cause_sentence(cause, tool.tool, detail),
            before=before,
            after=after,
            mitigations=mitigations_for(cause, report.server, tool.tool),
            signals=[s.to_dict() for s in signals if s.score >= 0.5],
            definition_changed=report.definition_changed,
            embedding_backend=report.embedding_backend,
            calibration_source=report.calibration_source,
            threshold_ratio=report.threshold_ratio,
        ))
    return alerts


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
class AlertStore:
    """Append-only JSONL of alerts, one file per server."""

    def __init__(self, root: Path | None = None) -> None:
        self.dir = (root or data_dir()) / "alerts"
        self.dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, server: str) -> Path:
        return self.dir / f"{server}.jsonl"

    def append(self, alert: Alert) -> Path:
        path = self.path_for(alert.server)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict()) + "\n")
        return path

    def history(self, server: str, limit: int | None = None) -> list[Alert]:
        path = self.path_for(server)
        if not path.is_file():
            return []
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        alerts = [Alert.from_dict(r) for r in rows]
        return alerts[-limit:] if limit else alerts

    def servers(self) -> list[str]:
        return sorted(p.stem for p in self.dir.glob("*.jsonl"))


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
_URGENCY_ORDER = {"immediate": 0, "soon": 1, "review": 2}
_SEVERITY_COLOUR = {"critical": "bold red", "high": "red", "medium": "yellow"}


def render_text(alert: Alert) -> str:
    """Plain-text rendering. ASCII only, so it survives any console codepage."""
    lines: list[str] = []
    bar = "=" * 74
    lines.append(bar)
    lines.append(f"  DRIFT ALERT [{alert.severity.upper()}]  {alert.server} / {alert.tool}")
    lines.append(bar)
    lines.append("")
    lines.append("WHAT HAPPENED")
    lines.append(f"  {alert.cause}")
    over = alert.score / alert.threshold_score if alert.threshold_score else 0.0
    lines.append(f"  Signal      : {alert.triggered_by}")
    lines.append(f"  Drift score : {alert.score:.2f}  (alert at {alert.threshold_score:.2f} "
                 f"- {over:.1f}x over the line)")
    others = [s["name"] for s in alert.signals if s["name"] != alert.triggered_by]
    if others:
        lines.append(f"  Also fired  : {', '.join(others)}")
    lines.append("")
    lines.append("BEFORE  (when you approved it)")
    lines.append(f"  {alert.before}")
    lines.append("AFTER   (what it does now)")
    lines.append(f"  {alert.after}")
    lines.append("")
    lines.append("WHAT TO DO")
    for i, m in enumerate(sorted(alert.mitigations, key=lambda x: _URGENCY_ORDER.get(x.urgency, 9)), 1):
        lines.append(f"  {i}. [{m.urgency.upper()}] {m.action}")
        lines.append(f"     {m.detail}")
        if m.command:
            lines.append(f"     $ {m.command}")
    lines.append("")
    lines.append(f"  detected {alert.created_at[:19]}Z | embedding {alert.embedding_backend} "
                 f"| threshold {alert.calibration_source}")
    lines.append(bar)
    return "\n".join(lines)


def render(alert: Alert, use_rich: bool = True) -> None:
    """Print an alert, preferring rich for colour but never requiring it."""
    if not use_rich:
        print(render_text(alert))
        return
    try:
        from rich import box
        from rich.console import Console, Group
        from rich.panel import Panel
        from rich.text import Text
    except Exception:  # pragma: no cover - rich is a dependency, but never hard-fail
        print(render_text(alert))
        return

    console = Console()
    colour = _SEVERITY_COLOUR.get(alert.severity, "yellow")
    over = alert.score / alert.threshold_score if alert.threshold_score else 0.0

    body: list[Any] = []
    body.append(Text(alert.cause, style="bold"))
    body.append(Text(f"\nsignal      : {alert.triggered_by}"))
    body.append(Text(f"drift score : {alert.score:.2f}  (alert at {alert.threshold_score:.2f}, "
                     f"{over:.1f}x over)"))
    others = [s["name"] for s in alert.signals if s["name"] != alert.triggered_by]
    if others:
        body.append(Text(f"also fired  : {', '.join(others)}"))
    body.append(Text("\nBEFORE  (at approval)", style="bold green"))
    body.append(Text(f"  {alert.before}"))
    body.append(Text("AFTER   (now)", style=f"bold {colour}"))
    body.append(Text(f"  {alert.after}"))
    body.append(Text("\nWHAT TO DO", style="bold"))
    for i, m in enumerate(sorted(alert.mitigations, key=lambda x: _URGENCY_ORDER.get(x.urgency, 9)), 1):
        style = "bold red" if m.urgency == "immediate" else ("yellow" if m.urgency == "soon" else "dim")
        body.append(Text(f"  {i}. [{m.urgency}] {m.action}", style=style))
        body.append(Text(f"     {m.detail}", style="dim"))
        if m.command:
            body.append(Text(f"     $ {m.command}", style="cyan"))
    body.append(Text(f"\ndetected {alert.created_at[:19]}Z | embedding {alert.embedding_backend} "
                     f"| threshold {alert.calibration_source}", style="dim"))

    console.print(Panel(
        Group(*body),
        title=f"DRIFT ALERT [{alert.severity.upper()}]  {alert.server} / {alert.tool}",
        border_style=colour,
        box=box.ASCII,          # ASCII box: renders correctly on any console codepage
    ))
