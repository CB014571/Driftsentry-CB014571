"""One controlled episode, start to finish.

An *episode* is: a fresh baseline of a benign server, one scenario armed, a fixed
number of verification cycles, and a verdict compared against the attacker's own
record of what it actually did.

Isolation is the property that makes episodes comparable. Each one gets its own
DRIFTSENTRY_HOME and its own ATTACKER_HOME, so no baseline, calibration, alert
log or event log leaks between runs, and the developer's real state directory -
which holds the acme baseline the write-up cites - is never touched.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from eval import ground_truth
from eval.record import ExperimentRow, components, config_hash, now
from eval.scenario_control import AttackerControl

try:
    import psutil
    _PROC = psutil.Process()
except Exception:  # pragma: no cover
    _PROC = None


DETECTOR_VERSION = "0.1.0"


@dataclass
class EpisodeConfig:
    """Everything that defines one run. Recorded verbatim into every row."""

    experiment_id: str
    mode: str = "rug-pull"                  # rug-pull | benign
    family: str = "content-injection"
    level: str = "L1"
    seed: int = 1
    updates: bool = False                   # benign mode: emit legitimate changes
    probe_mode: str = "fixed"
    scoring_mode: str = "max"
    partition: str = "development"

    cycles: int = 5
    n_probes: int = 3
    n_samples: int = 6
    samples_per_probe: int = 2
    threshold_ratio: float | None = None    # None -> whatever calibration says
    stop_on_alert: bool = True
    monitor_sandbox: bool = True
    trip_after: int | None = None           # force a sleeper at this cycle

    server_id: str = "target"

    def label(self) -> str:
        if self.mode == "benign":
            return "benign-update" if self.updates else "benign"
        return f"{self.family}/{self.level}"

    def as_config(self) -> dict[str, Any]:
        """The subset that identifies the DETECTOR configuration, for hashing."""
        return {
            "detector_version": DETECTOR_VERSION,
            "probe_mode": self.probe_mode,
            "scoring_mode": self.scoring_mode,
            "n_probes": self.n_probes,
            "n_samples": self.n_samples,
            "samples_per_probe": self.samples_per_probe,
            "threshold_ratio": self.threshold_ratio,
            "monitor_sandbox": self.monitor_sandbox,
        }


@dataclass
class EpisodeResult:
    config: EpisodeConfig
    rows: list[ExperimentRow] = field(default_factory=list)
    outcome: str = ""
    truth: Any = None
    error: str | None = None

    @property
    def detected(self) -> bool:
        return any(r.detected for r in self.rows)


class Episode:
    """Runs one episode against an isolated pair of home directories."""

    def __init__(
        self,
        config: EpisodeConfig,
        attacker_project: str | Path,
        workspace: str | Path,
        *,
        keep_state: bool = False,
    ) -> None:
        self.cfg = config
        self.workspace = Path(workspace)
        self.keep_state = keep_state
        self.episode_id = f"{config.experiment_id}-{config.label().replace('/', '-')}-s{config.seed}"
        self.ds_home = self.workspace / self.episode_id / "driftsentry"
        self.atk_home = self.workspace / self.episode_id / "attacker"
        self.attacker = AttackerControl.discover(attacker_project, home=self.atk_home)

    # -- lifecycle ----------------------------------------------------------
    def _prepare(self) -> None:
        for path in (self.ds_home, self.atk_home):
            shutil.rmtree(path, ignore_errors=True)
            path.mkdir(parents=True, exist_ok=True)
        # data_dir() reads this at call time, so setting it here is enough.
        os.environ["DRIFTSENTRY_HOME"] = str(self.ds_home)
        os.environ["ATTACKER_HOME"] = str(self.atk_home)

    def _cleanup(self) -> None:
        try:
            self.attacker.reset()
        except Exception:
            pass
        if not self.keep_state:
            shutil.rmtree(self.workspace / self.episode_id, ignore_errors=True)

    def _launch(self) -> dict[str, Any]:
        command, args = self.attacker.launch_command()
        return {
            "command": command,
            "args": args,
            "cwd": str(self.attacker.project_dir),
            # Explicit, because the MCP SDK filters inherited environment down to
            # a default set and would drop ATTACKER_HOME - which would send every
            # episode's events to one shared log and destroy the ground truth.
            "env": self.attacker.env(),
        }

    # -- the run ------------------------------------------------------------
    async def run(self) -> EpisodeResult:
        from driftsentry import keys as key_store
        from driftsentry.baseline import capture_baseline
        from driftsentry.store import BaselineStore
        from driftsentry.verify import verify_server

        result = EpisodeResult(config=self.cfg)
        cfg = self.cfg
        cfg_hash = config_hash(cfg.as_config())

        self._prepare()
        try:
            # 1. benign server, clean slate
            self.attacker.benign(seed=cfg.seed)
            ground_truth.clear(attacker_home=self.atk_home)

            # 2. baseline it while it is honest (Trust On First Use)
            launch = self._launch()
            # A key derived from the episode seed, so a keyed run is exactly
            # replayable while the server still cannot predict anything.
            probe_key = (key_store.derive_experiment_key(cfg.seed, cfg.experiment_id)
                         if cfg.probe_mode == "keyed" else None)
            baseline = await capture_baseline(
                cfg.server_id, launch["command"], launch["args"],
                cwd=launch["cwd"], env=launch["env"],
                n_probes=cfg.n_probes, n_samples=cfg.n_samples, seed=cfg.seed,
                probe_mode=cfg.probe_mode, key=probe_key,
            )
            store = BaselineStore()
            store.save(baseline)

            # Baselining fires probes, so clear again: only what happens AFTER
            # the server is armed counts as evidence the attack executed.
            ground_truth.clear(attacker_home=self.atk_home)

            # 3. arm
            if cfg.mode == "benign":
                self.attacker.benign(updates=cfg.updates, seed=cfg.seed)
            else:
                self.attacker.arm(cfg.family, level=cfg.level, seed=cfg.seed)

            # 4. verification cycles
            started = time.perf_counter()
            calls_per_cycle = sum(
                len(t.probes) * cfg.samples_per_probe for t in baseline.tools if t.probed
            )
            for cycle in range(1, cfg.cycles + 1):
                if cfg.trip_after is not None and cycle == cfg.trip_after:
                    self.attacker.trip()

                if _PROC is not None:
                    _PROC.cpu_percent(None)          # prime the interval
                t0 = time.perf_counter()
                report = await verify_server(
                    baseline,
                    launch=launch,
                    samples_per_probe=cfg.samples_per_probe,
                    monitor_sandbox=cfg.monitor_sandbox,
                    threshold_ratio=cfg.threshold_ratio,
                    # Every cycle asks something the server has not seen before.
                    cycle=cycle,
                    key=probe_key,
                )
                duration = time.perf_counter() - t0

                detected = report.verdict == "alert"
                row = ExperimentRow(
                    experiment_id=cfg.experiment_id,
                    episode_id=self.episode_id,
                    timestamp=now(),
                    seed=cfg.seed,
                    server_id=cfg.server_id,
                    tool_id=(report.tools[0].tool if report.tools else ""),
                    attack_family=(cfg.family if cfg.mode == "rug-pull" else cfg.label()),
                    attack_level=(cfg.level if cfg.mode == "rug-pull" else ""),
                    probe_mode=cfg.probe_mode,
                    scoring_mode=cfg.scoring_mode,
                    partition=cfg.partition,
                    detected=detected,
                    verdict=report.verdict,
                    final_score=round(report.score, 4),
                    winning_signal=report.triggered_by or "",
                    threshold_ratio=report.threshold_ratio,
                    definition_changed=report.definition_changed,
                    verification_cycle=cycle,
                    calls_to_detection=(calls_per_cycle * cycle if detected else 0),
                    time_to_detection=(round(time.perf_counter() - started, 3) if detected else 0.0),
                    execution_duration=round(duration, 3),
                    cpu_pct=(_PROC.cpu_percent(None) if _PROC is not None else 0.0),
                    rss_mb=(round(_PROC.memory_info().rss / 1e6, 1) if _PROC is not None else 0.0),
                    key_id=(key_store.key_id(probe_key) if probe_key else ""),
                    detector_version=DETECTOR_VERSION,
                    embedding_backend=report.embedding_backend,
                    config_hash=cfg_hash,
                )
                for name, value in components(report).items():
                    setattr(row, name, round(value, 4))
                result.rows.append(row)

                if detected and cfg.stop_on_alert:
                    break

            # 5. ground truth, read from the attacker
            truth = ground_truth.read(cfg.family, attacker_home=self.atk_home)
            result.truth = truth
            result.outcome = ground_truth.classify(
                mode=cfg.mode, fired=truth.fired, detected=result.detected
            )
            for row in result.rows:
                row.attack_fired = truth.fired
                row.probe_recognised = truth.probe_recognised
                row.probe_skip_count = truth.probe_skips
                row.ground_truth_events = ",".join(sorted(set(truth.kinds)))
                row.outcome = result.outcome

        except Exception as exc:  # noqa: BLE001 - one bad episode must not stop a sweep
            result.error = f"{type(exc).__name__}: {exc}"
            result.outcome = "error"
        finally:
            self._cleanup()
        return result


def run_episode(
    config: EpisodeConfig,
    attacker_project: str | Path,
    workspace: str | Path,
    **kwargs,
) -> EpisodeResult:
    """Synchronous wrapper - one fresh event loop per episode."""
    episode = Episode(config, attacker_project, workspace, **kwargs)
    return asyncio.run(episode.run())
