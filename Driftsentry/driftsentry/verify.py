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
) -> DriftReport:
    """Re-probe a server and score the result."""
    command, args, cwd, env = _launch_of(baseline, launch)
    measurement = await reprobe(
        baseline, command, args, cwd=cwd, env=env,
        samples_per_probe=samples_per_probe,
        monitor_sandbox=monitor_sandbox,
        cycle=cycle, key=key,
    )
    if threshold_ratio is None:
        threshold_ratio, source = active_threshold(measurement.embedding_backend)
    else:
        source = "explicit (--threshold)"
    return score_report(
        measurement,
        threshold_ratio=threshold_ratio,
        calibration_source=source,
        mode=mode,
    )


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
