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
import logging
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


log = logging.getLogger("eval.harness")

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

    # Start the attacker with the same filtered environment the proxy gives it,
    # instead of a full copy of os.environ. Off by default: Experiments 1 and 2
    # were run the old way and are the control. See eval/launch.py for why the
    # difference would otherwise fake the RQ3 result.
    launch_parity: bool = False

    # Replay recorded genuine agent traffic after each verification cycle.
    # Needed by any level that decides per call whether it is being tested:
    # with probes only, an L6 attacker never fires, every episode classifies
    # as never_triggered, and recall is undefined exactly where the question
    # is. Also what gives passive monitoring anything to observe.
    replay_sessions: int = 0

    # Path to an exported recogniser, copied into the attacker's home so an
    # L6 episode can load it. The model must come from the T5 collection,
    # never from evaluation episodes, or the attacker is trained on the runs
    # it is then scored against.
    recogniser: str | None = None

    # Replay sessions that never touch these tools. Supports the case where
    # an attack targets a tool the agent does not use: probing reaches it,
    # passive monitoring cannot, and that difference is the measurement.
    avoid_tools: tuple[str, ...] = ()

    # The T20 countermeasures, each off by default so Experiments 1 to 3
    # remain the control. One condition turns on exactly one more than the
    # last, which is the only way a change in the result is attributable.
    mimic_host: bool = False
    mimic_traffic: bool = False
    subsample_bank: bool = False

    # The frozen rule that turns passive findings into a verdict. None uses
    # the default; the experiment supplies one calibrated on benign episodes
    # only, so the comparison is not fitted to its own result.
    passive_rule: dict | None = None

    # Wall-clock ceiling for one episode. No ceiling is how a sweep dies:
    # a subprocess that never returns blocks Episode.run() forever, and the
    # harness has no way to notice. One hung episode stalled a run for 83
    # minutes before clearing, and the 24-episode sweep before it simply
    # stopped after an hour with no error. An episode that exceeds this is
    # recorded as an error and the sweep moves on, which costs one episode
    # instead of a night.
    #
    # Eight minutes: the observed median is 1.4, and the slowest healthy
    # episode seen is about 3.
    timeout_s: float = 480.0

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
            "mimic_host": self.mimic_host,
            "mimic_traffic": self.mimic_traffic,
            "subsample_bank": self.subsample_bank,
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

        if self.cfg.recogniser:
            source = Path(self.cfg.recogniser)
            if not source.is_file():
                raise FileNotFoundError(
                    f"recogniser {source} not found; an L6 episode without one "
                    f"fires unconditionally and would not measure evasion")
            shutil.copy2(source, self.atk_home / "recogniser.json")

    def _cleanup(self) -> None:
        try:
            self.attacker.reset()
        except Exception:
            pass
        if not self.keep_state:
            shutil.rmtree(self.workspace / self.episode_id, ignore_errors=True)

    def _launch(self) -> dict[str, Any]:
        if self.cfg.launch_parity:
            # Identical to what the proxy hands the attacker, so probe calls
            # and agent calls are indistinguishable by environment alone.
            from eval.launch import probe_launch
            return probe_launch(self.attacker.project_dir, self.atk_home)

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

    async def _replay(self, launch: dict[str, Any], cycle: int) -> list[dict]:
        """Send recorded genuine sessions through the proxy, if asked."""
        if not self.cfg.replay_sessions:
            return []
        from eval.agent import load_host_profile
        from eval.launch import agent_launch
        from eval.replay import choose_sessions, load_sessions, replay_session

        sessions = load_sessions()
        if not sessions:
            log.warning("replay requested but no genuine corpus was found; "
                        "run `eval collect` first")
            return []

        client_info, _ = load_host_profile()
        picked = choose_sessions(sessions, self.cfg.replay_sessions,
                                 seed=self.cfg.seed * 1000 + cycle,
                                 avoid_tools=set(self.cfg.avoid_tools or ()))
        # Through the proxy, so the traffic looks like a real client's and
        # passive monitoring sees it.
        proxied = agent_launch(self.attacker.project_dir, self.atk_home,
                               self.ds_home, self.cfg.server_id, passive=True)
        out: list[dict] = []
        for calls in picked:
            try:
                out.extend(await replay_session(calls, proxied,
                                                client_info=client_info))
            except Exception as exc:
                log.warning("replay session failed: %s", exc)
        return out

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
                mimic_host=cfg.mimic_host,
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
                    mimic_host=cfg.mimic_host,
                    mimic_traffic=cfg.mimic_traffic,
                    subsample_bank=cfg.subsample_bank,
                )
                duration = time.perf_counter() - t0

                # Genuine traffic AFTER the probes, so the attacker has had
                # its chance to recognise them and hold back first. An L6
                # attacker that skipped every probe fires here instead, which
                # is what makes the episode a missed detection rather than
                # one where nothing happened.
                replayed = await self._replay(launch, cycle)

                # Three detectors over ONE episode. Separate runs would make
                # the comparison unpaired and throw away what McNemar needs.
                from eval.detectors import (
                    full_detected, hash_detected, passive_detected)
                from eval.replay import passive_findings

                passive = passive_findings(self.ds_home, cfg.server_id)
                detected = full_detected(report)
                saw_hash = hash_detected(report)
                saw_passive = passive_detected(passive, self.cfg.passive_rule)

                latencies = [r["latency_s"] for r in replayed if "latency_s" in r]
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
                    hash_detected=saw_hash,
                    passive_detected=saw_passive,
                    full_detected=detected,
                    passive_available=bool(passive.get("available")),
                    cycle_seconds=round(duration, 4),
                    replayed_calls=len(replayed),
                    proxy_latency_ms=round(
                        1000 * sum(latencies) / len(latencies), 3) if latencies else 0.0,
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
    """Synchronous wrapper - one fresh event loop per episode.

    The episode is bounded. Without a ceiling a single subprocess that never
    returns blocks the whole sweep, which is not hypothetical: one episode
    stalled a run for 83 minutes before clearing, and an earlier 24-episode
    sweep stopped after an hour with no error at all. A timed-out episode is
    recorded as an error and the sweep continues.
    """
    episode = Episode(config, attacker_project, workspace, **kwargs)

    async def _bounded() -> EpisodeResult:
        try:
            return await asyncio.wait_for(episode.run(), timeout=config.timeout_s)
        except asyncio.TimeoutError:
            log.warning("episode %s exceeded %.0fs and was abandoned",
                        episode.episode_id, config.timeout_s)
            result = EpisodeResult(config=config)
            result.outcome = "error"
            result.error = (f"TimeoutError: episode exceeded {config.timeout_s:.0f}s. "
                            f"The sweep continued; this episode contributes no rows.")
            try:
                episode._cleanup()
            except Exception:
                pass
            return result

    return asyncio.run(_bounded())
