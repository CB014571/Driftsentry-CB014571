"""Phase 4 - the verification and calibration workflows.

Thin orchestration on top of the pieces that already exist: re-probe a server
(measurement), score the result (verdict), or sweep a set of benign servers to
derive the threshold. Kept out of the CLI module so the daemon and the eval
harness can call exactly the same code paths later.
"""
from __future__ import annotations

import logging
from typing import Any, Sequence

from driftsentry.baseline import reprobe
from driftsentry.calibration import Calibration, active_threshold, calibrate_from_ratios
from driftsentry.fingerprint import ServerBaseline
from driftsentry.scorer import DriftReport, score_report
from driftsentry.store import BaselineStore

log = logging.getLogger("driftsentry.verify")


def _launch_of(
    baseline: ServerBaseline, override: dict[str, Any] | None = None
) -> tuple[str, list[str], str | None, dict[str, str] | None]:
    """Resolve how to start a server, preferring an explicit override.

    ``env`` is honoured from an explicit override only, and is never read from
    the stored baseline. Two reasons. An environment block can carry API keys, so
    persisting one into a baseline JSON that the write-up encourages people to
    read would be careless. And the MCP SDK filters the inherited environment
    down to a safe default set when none is given, so a caller that needs a
    custom variable to reach the server - the evaluation harness isolating
    ATTACKER_HOME per episode, for instance - has to pass it explicitly rather
    than hope it survives inheritance.
    """
    launch = override or baseline.launch
    if not launch or not launch.get("command"):
        raise ValueError(
            f"no launch command recorded for {baseline.server!r}; "
            "pass --exec, or re-capture the baseline so it is stored"
        )
    env = (override or {}).get("env")
    return launch["command"], list(launch.get("args") or []), launch.get("cwd"), env


async def verify_server(
    baseline: ServerBaseline,
    *,
    launch: dict[str, Any] | None = None,
    samples_per_probe: int = 2,
    monitor_sandbox: bool = True,
    mode: str = "full",
    threshold_ratio: float | None = None,
    cycle: int = 1,
    key: bytes | None = None,
    mimic_host: bool = False,
    mimic_traffic: bool = False,
    subsample_bank: bool = False,
    update_check: bool = False,
    per_tool: dict[str, float] | None = None,
    session: Any = None,
    server_pids: list[int] | None = None,
    shapes: dict[str, Any] | None = None,
    rules_version: str = "1.0",
    watch: Any = None,
    guard: Any = None,
) -> DriftReport:
    """Re-probe a server and score the result.

    ``watch`` and ``guard`` (H2c, in-session only): a continuous process
    watch shared with the real-call guard, and the guard itself. Real-call
    findings gathered since the last cycle are folded into this report, so a
    server that behaves for probes and attacks the user still alerts.

    ``update_check`` (T25): when the tool definitions the re-probe observed
    differ from the baseline's, compute the declared diff and score in
    residue mode, so declared changes explain the behaviour they cover and
    only the rest can alert. Definitions are compared in full, not by hash -
    the hash covers name, description and inputSchema only, so an added
    output field or a widened annotation would not register as a change at
    all. Off by default: every existing experiment scores exactly as before.

    Nothing is re-baselined here. The residue outcome names the tools whose
    changes were fully explained (``residue["explained_tools"]``); deciding
    to adopt them is left to the caller.

    The countermeasure flags are forwarded, not consumed here. An earlier
    revision accepted them and dropped them, which would have made every T20
    condition identical to the control - the same class of defect as the
    launch-parity one, caught before it produced a number.
    """
    # In-session verification (``session``) needs no launch: the server is
    # already running inside the user's session.
    command, args, cwd, env = (("", [], None, None) if session is not None
                               else _launch_of(baseline, launch))
    measurement = await reprobe(
        baseline, command, args, cwd=cwd, env=env,
        samples_per_probe=samples_per_probe,
        monitor_sandbox=monitor_sandbox,
        cycle=cycle, key=key,
        mimic_host=mimic_host,
        mimic_traffic=mimic_traffic,
        subsample_bank=subsample_bank,
        session=session,
        server_pids=server_pids,
        shapes=shapes,
        watch=watch,
        # Rules v1.1 needs the framework view; v1.0 (the default) does not,
        # so nothing extra is measured for any existing experiment.
        framework_view=(update_check and rules_version == "1.1"),
    )
    if threshold_ratio is None:
        threshold_ratio, source = active_threshold(measurement.embedding_backend)
    else:
        source = "explicit (--threshold)"
    declared_diff = None
    if update_check:
        from driftsentry.declared_diff import diff_definitions

        candidate = diff_definitions(baseline.tool_definitions,
                                     measurement.observed_definitions)
        if not candidate.empty:
            declared_diff, mode = candidate, "residue"
    report = score_report(
        measurement,
        threshold_ratio=threshold_ratio,
        calibration_source=source,
        mode=mode,
        per_tool=per_tool,
        declared_diff=declared_diff,
        rules_version=rules_version,
    )
    if guard is not None:
        from driftsentry.guard import apply_guard

        apply_guard(report, guard.take())
    return report


async def calibrate_servers(
    servers: Sequence[str],
    *,
    repeats: int = 3,
    samples_per_probe: int = 2,
    margin: float | None = None,
    target_far: float | None = None,
    monitor_sandbox: bool = False,
    store: BaselineStore | None = None,
    variants: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[Calibration, dict[str, list[float]]]:
    """Derive a detection threshold by re-probing known-benign servers.

    Every server named here must be one the user has approved as benign. The
    ratios collected are the *only* input to the threshold - no rug-pull or test
    data is ever seen - which is the property that keeps RQ2 and RQ3 defensible.

    ``variants`` supplies additional BENIGN configurations of the same server -
    most importantly, versions that have legitimately been UPDATED.

    Why that matters more than it sounds
        Calibrating only against a server that never changes measures the wrong
        population. Real deployments update: responses get reworded, a field is
        added, a message is reformatted. A threshold fitted to a frozen server is
        far too tight, so the first honest update trips it, and the tool's
        false-alarm rate - the number that decides whether anyone keeps it
        switched on - is measured against a world that does not exist.

        This is gap G3 stated as an engineering requirement: benign updates must
        be part of the benign distribution, not treated as attacks by default.
        Including them widens the threshold and will genuinely cost recall on the
        subtlest families. That trade-off is the finding, and Phase 9 reports it
        as a curve rather than hiding it behind one headline number.

    Sandbox monitoring is off by default during calibration: we are measuring how
    much benign responses drift, and the per-probe monitor start/stop adds time
    without contributing to that number.
    """
    from driftsentry.calibration import DEFAULT_MARGIN, DEFAULT_TARGET_FAR

    store = store or BaselineStore()
    per_server: dict[str, list[float]] = {}
    backends: set[str] = set()
    seeds: set[int] = set()

    for name in servers:
        baseline = store.load(name)
        if baseline is None:
            log.warning("no baseline for %r; skipping", name)
            continue
        backends.add(baseline.embedding_backend)
        seeds.add(baseline.seed)

        # The baseline's own launch, plus any additional benign configurations
        # (typically legitimately-updated versions of the same server).
        launches = [baseline.launch or {}, *(variants or {}).get(name, [])]

        ratios: list[float] = []
        for launch in launches:
            command, args, cwd, env = _launch_of(baseline, launch or None)
            for run in range(repeats):
                measurement = await reprobe(
                    baseline, command, args, cwd=cwd, env=env,
                    samples_per_probe=samples_per_probe,
                    monitor_sandbox=monitor_sandbox,
                )
                if measurement.definition_changed:
                    # A server whose definition moved is not a clean benign sample.
                    log.warning(
                        "%s: definition hash changed during calibration run %d - "
                        "excluding this run; a calibration server must be stable",
                        name, run + 1,
                    )
                    continue
                ratios.extend(c.ratio for c in measurement.checks)
        per_server[name] = ratios
        log.info("%s: %d benign observations over %d configuration(s)", name, len(ratios), len(launches))

    if len(backends) > 1:
        raise ValueError(
            "calibration servers were baselined with different embedding backends "
            f"({sorted(backends)}); distances are not comparable across embedding spaces"
        )

    all_ratios = [r for values in per_server.values() for r in values]
    calibration = calibrate_from_ratios(
        all_ratios,
        servers=list(per_server),
        embedding_backend=next(iter(backends), "unknown"),
        margin=margin if margin is not None else DEFAULT_MARGIN,
        target_far=target_far if target_far is not None else DEFAULT_TARGET_FAR,
        seed=next(iter(seeds), None) if len(seeds) == 1 else None,
    )
    return calibration, per_server
