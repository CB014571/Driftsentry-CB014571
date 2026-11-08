"""Phase 4 - the drift scorer.

Turns "this response looks different" into a single, calibrated, reproducible
number per tool per check, with the triggering signal attributable.

The three signals (roadmap Phase 4)
    definition hash change   classic / sleeper rug pull that edits the name,
                             description or schema        -> HARD TRIGGER
    embedding distance       response content shifting while the definition is
                             unchanged                    -> scaled by per-tool variance
    security rules           new egress host, secret-file read, credential- or
                             instruction-shaped output    -> HIGH, strong evidence of harm

A fourth, weaker signal - a change in the response's *structure* - is carried
alongside the embedding, because a hidden field appearing is visible structurally
even when the prose barely moves.

Design decision 1: one common scale, where 1.0 is the alert line
    Each signal is expressed in "evidence units" normalised so that 1.0 means
    "exactly at the alert threshold". The behavioural signal gets there by
    dividing its variance-scaled ratio by the calibrated threshold; the discrete
    signals get there by fixed weights chosen to reflect how conclusive they are.
    A single number is therefore interpretable on sight (2.4 means "2.4x the
    alert line"), comparable across tools with wildly different noise levels, and
    governed by exactly one calibrated parameter.

Design decision 2: combine by MAX, not by sum
    The score is the strongest single piece of evidence, not the accumulation of
    all of it. Summing is tempting but wrong here: the embedding distance and the
    structural signal are strongly correlated (they read the same response), so a
    sum lets ordinary benign noise on a chatty tool add up to an alert. That
    inflates the false-alarm rate, which is the one metric this project cannot
    afford to be sloppy about (gap G3 / RQ2). Max also keeps attribution
    unambiguous - the alert names precisely the signal that caused it.

    The honest cost: an attacker who keeps every individual signal just under the
    line is not caught by corroboration. That is a real limit, it is exactly the
    L4/L5 mimicry case the roadmap already concedes, and Phase 9's per-level
    recall curve is where it gets measured rather than hidden.

Design decision 3: no language model anywhere in this path
    Every number here is produced by arithmetic over stored vectors and by
    regular expressions. Given the same baseline and the same responses, the
    score is bit-for-bit identical on every run. That determinism is the property
    the project is positioned on against MCPShield, and it is why an LLM may only
    ever appear as a secondary *explainer* in an alert, never as the decision.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from driftsentry import rules as security_rules

# --------------------------------------------------------------------------- #
# Weights, in evidence units (1.0 == the alert line)
# --------------------------------------------------------------------------- #
# A changed definition is not evidence of a rug pull, it IS one class of rug pull
# (the classic / sleeper form) and needs no calibration to interpret. It is
# weighted well clear of the line so it can never be argued down by a tight
# threshold.
W_DEFINITION_HASH = 3.0

# Near-proof behaviours. The roadmap: "Weight a new egress host or secret-file
# read far above plain text change: the former is near-proof of a rug pull, the
# latter is a weak signal on its own."
W_RULE_HIGH = 2.0

# Suspicious, but with plausible benign explanations (a legitimate update may
# touch a new file). Above the line, but only just: it should alert, and it
# should be the kind of alert a user can dismiss after looking.
W_RULE_MEDIUM = 1.1

# Structure changed but the words did not move much. Deliberately BELOW 1.0: on
# its own this produces a "watch", not an alert, because benign updates add
# optional fields all the time. It becomes decisive only when the embedding
# signal is also elevated - and then the embedding signal is what alerts.
W_STRUCTURAL = 0.85

# The tool started erroring when it never used to (or vice versa). Informational:
# it is recorded on the probe and appears in the structured report, but on its
# own it never raises a tool's verdict.
W_ERROR_RATE = 0.4

# A probe that never varied by a single character at baseline has returned
# something different.
#
# Why this needs its own signal rather than relying on the embedding distance:
# a deterministic probe's variance band is MIN_BAND, a numerical floor rather
# than a measurement. Dividing by it and then by a calibrated threshold of ~10
# means such a tool is allowed a large semantic shift before anything fires -
# which is exactly the room a low-drift mimicry attacker works in. Measured on
# the acme baseline, lookup_customer and read_document both required a cosine
# distance of 0.108 to alert despite having zero observed variance.
#
# Placed just above the line, not far above it. "This changed at all" is strong
# evidence for a deterministic tool, but a legitimate update produces exactly the
# same signal, so it should alert and be dismissible rather than alarm loudly.
W_DETERMINISM = 1.15

# A security-relevant FIELD changed value.
#
# The signal a whole-response embedding is worst at. Changing one digit of an
# account number leaves the sentence meaning the same thing, so the vector
# barely moves - measured at 0.1367 cosine distance on a real response, against
# a field-drift score of 1.0 for the same edit.
#
# The incoming score is already weighted by what KIND of field moved: identity
# (account, recipient, URL, host) at 1.0, prose at 0.3. Multiplying by this
# weight means a redirected recipient alerts clearly while a reworded summary
# lands around 0.5 and never does. Fields the baseline learned to be volatile -
# timestamps, request ids - are masked before comparison and cannot contribute.
W_FIELD_DRIFT = 1.6

# Ceiling on the behavioural signal.
#
# Past a few multiples of the threshold the signal has said everything it can:
# "this response is definitely not what was baselined". Letting the number keep
# climbing adds no information and produces scores in the tens of thousands for
# tools whose baseline behaviour was perfectly deterministic, which are unusable
# in a report or on a plot. Saturating keeps the scale interpretable while
# preserving the ordering that matters (below / at / far above the line).
W_BEHAVIOURAL_MAX = 3.0

# Verdict bands on the common scale.
#
# Calibration places the threshold a margin (default 1.25x) above the benign
# operating point, so ordinary benign behaviour scores up to about 1/1.25 = 0.80.
# WATCH therefore begins just above that: it means "past where benign traffic
# normally sits, but not yet at the alert line". Setting it lower would put every
# naturally noisy tool permanently in WATCH, which is alarm fatigue by design.
WATCH_AT = 0.85
ALERT_AT = 1.0

# T25. An update that widened a declared permission - read-only removed,
# open-world or destructive added. Between WATCH_AT and ALERT_AT on purpose:
# the widening is shown to the user every time, but on its own it is a
# declared, visible change, not evidence of an attack. Scores combine by max,
# so on a tool that also carries residue the residue is what alerts - that is
# the only sense in which an escalation is "combined".
W_ESCALATION = 0.9

# T25. A new outbound host on a tool that declares openWorldHint true. Held
# for the user to look at, counted separately, and never an alert: zero, so
# it is logged on the probe and can never decide a verdict.
W_HELD = 0.0


@dataclass
class Signal:
    """One piece of evidence, already normalised to evidence units."""

    name: str
    score: float
    severity: str          # info | low | medium | high | critical
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeScore:
    """Score for a single probe of a single tool."""

    probe_id: str
    score: float
    ratio: float
    distance: float
    band: float
    signals: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "signals": [s.to_dict() for s in self.signals]}


@dataclass
class ToolScore:
    """Aggregated verdict for one tool: its worst probe decides."""

    tool: str
    score: float
    verdict: str                       # ok | watch | alert
    triggered_by: str | None
    probes: list[ProbeScore] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "score": self.score,
            "verdict": self.verdict,
            "triggered_by": self.triggered_by,
            "probes": [p.to_dict() for p in self.probes],
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass
class DriftReport:
    """The scored result of one re-verification of one server."""

    server: str
    scored_at: str
    mode: str                          # full | hash-only
    threshold_ratio: float
    calibration_source: str
    embedding_backend: str
    definition_changed: bool
    baseline_definition_hash: str
    observed_definition_hash: str
    tools: list[ToolScore] = field(default_factory=list)
    # T25. The residue checker's outcome in mode="residue" with a non-empty
    # declared diff, as ResidueReport.to_dict(). None otherwise.
    residue: dict[str, Any] | None = None

    @property
    def score(self) -> float:
        return max((t.score for t in self.tools), default=0.0)

    @property
    def verdict(self) -> str:
        if any(t.verdict == "alert" for t in self.tools):
            return "alert"
        if any(t.verdict == "watch" for t in self.tools):
            return "watch"
        return "ok"

    @property
    def triggered_by(self) -> str | None:
        worst = max(self.tools, key=lambda t: t.score, default=None)
        return worst.triggered_by if worst else None

    def alerting_tools(self) -> list[ToolScore]:
        return [t for t in self.tools if t.verdict == "alert"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "scored_at": self.scored_at,
            "mode": self.mode,
            "threshold_ratio": self.threshold_ratio,
            "calibration_source": self.calibration_source,
            "embedding_backend": self.embedding_backend,
            "definition_changed": self.definition_changed,
            "baseline_definition_hash": self.baseline_definition_hash,
            "observed_definition_hash": self.observed_definition_hash,
            "score": self.score,
            "verdict": self.verdict,
            "triggered_by": self.triggered_by,
            "tools": [t.to_dict() for t in self.tools],
            "residue": self.residue,
        }


def _verdict_for(score: float) -> str:
    if score >= ALERT_AT:
        return "alert"
    if score >= WATCH_AT:
        return "watch"
    return "ok"


def _severity_for(score: float) -> str:
    if score >= 2.0:
        return "critical"
    if score >= ALERT_AT:
        return "high"
    if score >= WATCH_AT:
        return "medium"
    return "low"


def check_signals(
    check,                                   # driftsentry.baseline.ProbeCheck
    *,
    threshold_ratio: float,
    per_tool: dict[str, float] | None = None,
    hash_signal: Signal | None = None,
) -> list[Signal]:
    """Every signal one probe check raises, in evidence units.

    Factored out of score_report unchanged, so the residue checker (T24) can
    score a probe - and the same probe with its declared fields removed - by
    exactly the arithmetic the detector uses, rather than by a copy of it that
    could drift. score_report calls this for every check, so the golden tests
    pin both.
    """
    signals: list[Signal] = []

    # -- signal 2: behavioural drift, scaled by this tool's own variance
    # Dividing by the calibrated threshold puts a noisy tool and a
    # deterministic one on the same scale: both alert at 1.0.
    # A tool with its own calibrated threshold is judged by that one.
    # The global number is set by the noisiest tool in the calibration
    # set, so a deterministic tool is otherwise held to a bar raised
    # for a weather feed. Default None keeps the old behaviour exactly,
    # which is what the golden tests and Experiments 1-2 rely on.
    tool_threshold = threshold_ratio
    if per_tool:
        tool_threshold = per_tool.get(check.tool, threshold_ratio)
    raw_behavioural = check.ratio / tool_threshold if tool_threshold > 0 else 0.0
    # Scale by how comparable this family's responses actually are.
    #
    # For the exact-probe path this is 1.0 and nothing changes. For a
    # keyed family whose answers genuinely differ between inputs, the
    # embedding distance partly measures the input rather than the tool,
    # and asserting otherwise would manufacture false alarms. Where the
    # signal is weak the detector leans on the invariant evidence -
    # structure, rules, side effects - which does not depend on the input.
    comparability = getattr(check, "comparability", 1.0)
    behavioural = min(raw_behavioural * comparability, W_BEHAVIOURAL_MAX)
    signals.append(Signal(
        name="behavioural_drift",
        score=behavioural,
        severity=_severity_for(behavioural),
        detail=(
            f"response drift {check.distance:.4f} against a benign band of "
            f"{check.band:.4f} (ratio {check.ratio:.2f}, alert at {tool_threshold:.2f})"
        ),
        evidence={
            "distance": check.distance,
            "band": check.band,
            "ratio": check.ratio,
            "threshold_ratio": tool_threshold,
            "uncapped_score": raw_behavioural,
            "baseline_excerpt": check.baseline_excerpt,
            "observed_excerpt": check.observed_excerpt,
        },
    ))

    # -- structural change (weak on its own, by design)
    if not check.shape_known:
        signals.append(Signal(
            name="structural_change",
            score=W_STRUCTURAL,
            severity=_severity_for(W_STRUCTURAL),
            detail="the response's structure differs from every shape seen at baseline",
            evidence={"observed_shape": check.observed_shape_hash},
        ))

    # -- a security-relevant field changed value
    field_drift = getattr(check, "field_drift", 0.0)
    if field_drift > 0.0:
        score = min(field_drift * W_FIELD_DRIFT, W_BEHAVIOURAL_MAX)
        signals.append(Signal(
            name="field_drift",
            score=score,
            severity=_severity_for(score),
            detail=("a security-relevant field changed value: "
                    + "; ".join(getattr(check, "field_changes", []) or ["(unspecified)"])),
            evidence={"field_drift": field_drift,
                      "changes": getattr(check, "field_changes", [])},
        ))

    # -- exact-equality break on a provably deterministic probe
    if getattr(check, "determinism_break", False):
        signals.append(Signal(
            name="determinism_break",
            score=W_DETERMINISM,
            severity=_severity_for(W_DETERMINISM),
            detail=(
                "this probe returned byte-identical text on every sample at "
                "baseline, and now returns something different"
            ),
            evidence={
                "baseline_excerpt": check.baseline_excerpt,
                "observed_excerpt": check.observed_excerpt,
                "distance": check.distance,
                "band": check.band,
            },
        ))

    # -- error-rate change
    if check.became_error:
        signals.append(Signal(
            name="error_behaviour",
            score=W_ERROR_RATE,
            severity="low",
            detail="the tool now errors on a probe that succeeded at baseline",
            evidence={"excerpt": check.observed_excerpt[:200]},
        ))

    # -- signal 3: security rules (differential)
    for hit in security_rules.evaluate(
        new_hosts=check.new_hosts,
        new_files=check.new_files,
        new_content_flags=check.new_content_flags,
    ):
        weight = W_RULE_HIGH if hit.severity == "high" else W_RULE_MEDIUM
        signals.append(Signal(
            name=f"rule:{hit.rule}",
            score=weight,
            severity=_severity_for(weight),
            detail=f"{security_rules.describe_rule(hit.rule)} ({hit.detail})",
            evidence={"matches": hit.evidence},
        ))

    # -- signal 1: definition hash applies to every probe on this server
    if hash_signal:
        signals.append(hash_signal)

    return signals


def score_report(
    report,                                  # driftsentry.baseline.ReprobeReport
    *,
    threshold_ratio: float,
    calibration_source: str = "provisional",
    mode: str = "full",
    per_tool: dict[str, float] | None = None,
    declared_diff=None,                      # driftsentry.declared_diff.DeclaredDiff
) -> DriftReport:
    """Score a re-probe measurement into a verdict.

    ``mode="residue"`` (T25) scores an update. With a non-empty
    ``declared_diff`` the re-probe is first passed through the residue
    checker, and what is scored is its residue view: declared output fields
    masked out, explained changes neutralised, escalated and held side
    effects removed. The definition-hash signal does not apply - the changed
    definition is the declaration under test, not evidence against it.
    Widened hints add ``declaration_escalation``; held hosts add
    ``held_for_review`` at zero. With an empty or absent diff there is nothing
    to explain, and the result is identical to ``mode="full"``.

    ``mode="hash-only"`` reproduces the competing method (mcp-scan / Snyk-style
    definition pinning) by discarding every behavioural signal. It is kept here,
    inside the same code path and fed by the same traffic, so Phase 9 can measure
    exactly what the behavioural layer adds rather than comparing against a
    re-implementation that might differ in some incidental way.
    """
    residue_outcome = None
    extra: dict[tuple[str, str], list[Signal]] = {}
    escalated: dict[str, list[str]] = {}
    if mode == "residue" and declared_diff is not None and not declared_diff.empty:
        from driftsentry.residue import check_update

        residue_outcome = check_update(report, declared_diff,
                                       threshold_ratio=threshold_ratio,
                                       per_tool=per_tool)
        for tool, name in residue_outcome.escalations:
            escalated.setdefault(tool, []).append(name)
        for item in residue_outcome.items:
            if item.classification == "held_for_review":
                extra.setdefault((item.tool, item.probe_id), []).append(Signal(
                    name="held_for_review", score=W_HELD, severity="info",
                    detail=item.reason, evidence={"signal": item.signal}))
            elif item.classification == "escalation":
                extra.setdefault((item.tool, item.probe_id), []).append(Signal(
                    name="declaration_escalation", score=W_ESCALATION,
                    severity=_severity_for(W_ESCALATION),
                    detail=f"a widened declaration was exercised: {item.reason}",
                    evidence={"signal": item.signal}))
        scored_report = residue_outcome.residue_view
    else:
        scored_report = report

    hash_signal = None
    if report.definition_changed and residue_outcome is None:
        hash_signal = Signal(
            name="definition_hash",
            score=W_DEFINITION_HASH,
            severity="critical",
            detail="The tool definitions advertised by this server changed since approval.",
            evidence={
                "baseline": report.baseline_definition_hash,
                "observed": report.observed_definition_hash,
            },
        )

    tools: list[ToolScore] = []

    if mode == "hash-only":
        # The control condition sees only the definition hash. Every behavioural
        # observation is deliberately thrown away.
        score = W_DEFINITION_HASH if hash_signal else 0.0
        tools.append(ToolScore(
            tool="<server definition>",
            score=score,
            verdict=_verdict_for(score),
            triggered_by="definition_hash" if hash_signal else None,
            signals=[hash_signal] if hash_signal else [],
        ))
        return DriftReport(
            server=report.server,
            scored_at=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            threshold_ratio=threshold_ratio,
            calibration_source=calibration_source,
            embedding_backend=report.embedding_backend,
            definition_changed=report.definition_changed,
            baseline_definition_hash=report.baseline_definition_hash,
            observed_definition_hash=report.observed_definition_hash,
            tools=tools,
        )

    by_tool: dict[str, list] = {}
    for check in scored_report.checks:
        by_tool.setdefault(check.tool, []).append(check)

    for tool_name, checks in by_tool.items():
        probe_scores: list[ProbeScore] = []

        for check in checks:
            signals = check_signals(check, threshold_ratio=threshold_ratio,
                                    per_tool=per_tool, hash_signal=hash_signal)
            signals += extra.get((check.tool, check.probe_id), [])
            for name in escalated.get(check.tool, []):
                signals.append(Signal(
                    name="declaration_escalation", score=W_ESCALATION,
                    severity=_severity_for(W_ESCALATION),
                    detail=f"the update widened a declared permission: {name}",
                    evidence={"escalation": name}))

            best = max(signals, key=lambda s: s.score)
            probe_scores.append(ProbeScore(
                probe_id=check.probe_id,
                score=best.score,
                ratio=check.ratio,
                distance=check.distance,
                band=check.band,
                signals=signals,
            ))

        # The worst probe decides the tool. A rug pull that only fires on some
        # inputs (an L2 stochastic or L3 trigger-gated attacker) must not be
        # averaged away by the probes that still behave normally.
        worst = max(probe_scores, key=lambda p: p.score)
        worst_signal = max(worst.signals, key=lambda s: s.score)
        tools.append(ToolScore(
            tool=tool_name,
            score=worst.score,
            verdict=_verdict_for(worst.score),
            triggered_by=worst_signal.name if worst.score >= WATCH_AT else None,
            probes=probe_scores,
            signals=[s for s in worst.signals if s.score >= WATCH_AT],
        ))

    # An escalation on a tool with nothing probed is still shown to the user.
    probed_tools = {t.tool for t in tools}
    for tool_name, names in sorted(escalated.items()):
        if tool_name in probed_tools:
            continue
        sigs = [Signal(name="declaration_escalation", score=W_ESCALATION,
                       severity=_severity_for(W_ESCALATION),
                       detail=f"the update widened a declared permission: {n}",
                       evidence={"escalation": n}) for n in names]
        tools.append(ToolScore(tool=tool_name, score=W_ESCALATION,
                               verdict=_verdict_for(W_ESCALATION),
                               triggered_by="declaration_escalation", signals=sigs))

    # A definition change with no probeable tools still has to raise an alert.
    if hash_signal and not tools:
        tools.append(ToolScore(
            tool="<server definition>",
            score=W_DEFINITION_HASH,
            verdict="alert",
            triggered_by="definition_hash",
            signals=[hash_signal],
        ))

    return DriftReport(
        server=report.server,
        scored_at=datetime.now(timezone.utc).isoformat(),
        mode=mode,
        threshold_ratio=threshold_ratio,
        calibration_source=calibration_source,
        embedding_backend=report.embedding_backend,
        definition_changed=report.definition_changed,
        baseline_definition_hash=report.baseline_definition_hash,
        observed_definition_hash=report.observed_definition_hash,
        tools=sorted(tools, key=lambda t: t.score, reverse=True),
        residue=residue_outcome.to_dict() if residue_outcome else None,
    )
