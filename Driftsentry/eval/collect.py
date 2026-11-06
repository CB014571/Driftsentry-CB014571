"""Collect the RQ3 dataset: genuine agent traffic beside probe traffic.

The whole question is whether a malicious server can tell one from the other,
so the collection's only real job is to produce both kinds of traffic without
introducing a difference that is not about probing.

Four rules the design follows
    1. ONE AT A TIME, NEVER OVERLAPPING. An agent session and a probe cycle are
       run strictly in sequence. If they overlapped, the attacker would write
       interleaved rows into one file and the time windows could not separate
       them - every row in the overlap would be unlabelable.
    2. LABELS COME FROM HERE, NOT FROM THE ATTACKER. The collector brackets
       each session with a start and end timestamp and writes those windows to
       its own file. The attacker records only what it observed; it is never
       told which kind of traffic it is serving. Any other arrangement would
       leak the answer into the data.
    3. BOTH SIDES USE THE SAME LAUNCH. Probe cycles use probe_launch and agent
       sessions use agent_launch, which were built in T4 specifically so the
       attacker's environment and working directory are identical either way.
    4. THE SERVER STAYS BENIGN THROUGHOUT. Nothing is armed. This collection
       answers "can probes be recognised", which is a question about traffic,
       not about attacks. Arming the server would change what it returns and
       contaminate the argument family.

The real host's client identity is required before a collection can start,
and the AGENT path announces it. The probe path announces whatever the
detector announces, which by default is the SDK's own name - and that is why
RQ3 measured the client family at AUC 1.000. It is a true property of the
unmodified detector, not an artefact: nothing in it tries to look like a
host. Closing that channel is the `mimic_host` countermeasure, which T20
switches on as its second condition. See eval/host_profile.json.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from eval.agent import SYSTEM_PROMPTS, load_host_profile, load_tasks, run_task
from eval.launch import agent_launch, probe_launch

GENUINE, PROBE = 0, 1


class Collector:
    """Runs alternating agent sessions and probe cycles against one server."""

    def __init__(
        self,
        attacker_project: str | Path,
        out_dir: str | Path,
        workspace: str | Path,
        *,
        server_id: str = "rq3",
        seed: int = 20260720,
        n_probes: int = 3,
        n_samples: int = 6,
        samples_per_probe: int = 2,
        monitor_sandbox: bool = True,
        mimic_host: bool = False,
        mimic_traffic: bool = False,
        subsample_bank: bool = False,
    ) -> None:
        self.attacker_project = Path(attacker_project).resolve()
        self.out_dir = Path(out_dir)
        self.workspace = Path(workspace)
        self.server_id = server_id
        self.seed = seed
        self.n_probes = n_probes
        self.n_samples = n_samples
        self.samples_per_probe = samples_per_probe
        # Must match what the experiment runs with, and the experiment's
        # default is True. Collecting with it off made probe calls faster
        # than the detector actually makes them, so a recogniser fitted to
        # proc_age_s learned a timing profile that does not occur in
        # deployment - and then failed against the real thing. Third
        # artefact of this shape, after launch parity (T4) and replay pacing
        # (T10): the collection has to match the deployment in every respect
        # a feature can observe.
        self.monitor_sandbox = monitor_sandbox
        # T20. A recogniser is only a fair test of a countermeasure if it was
        # fitted to traffic produced WITH that countermeasure on. Fitting on
        # unprotected probing and testing against protected probing measures
        # how stale a model goes, not whether the countermeasure works.
        self.mimic_host = mimic_host
        self.mimic_traffic = mimic_traffic
        self.subsample_bank = subsample_bank

        self.ds_home = self.workspace / "driftsentry"
        self.atk_home = self.workspace / "attacker"
        self.windows: list[dict[str, Any]] = []
        # Appended to as each session closes, not written in finish().
        # Learned the hard way: a run that held its labels in memory and was
        # interrupted at session 79 of 120 lost every one of them. The
        # attacker's feature rows survive on disk regardless, but rows without
        # windows cannot be labelled, so the whole run was unusable.
        self.windows_path = self.out_dir / "windows.jsonl"

    # -- setup --------------------------------------------------------------
    def prepare(self) -> None:
        """A clean slate, so no earlier run's rows end up in this dataset."""
        shutil.rmtree(self.workspace, ignore_errors=True)
        for path in (self.ds_home, self.atk_home, self.out_dir):
            path.mkdir(parents=True, exist_ok=True)
        # A fresh windows file, so a previous run's labels can never be joined
        # to this run's rows.
        self.windows_path.unlink(missing_ok=True)
        os.environ["DRIFTSENTRY_HOME"] = str(self.ds_home)
        os.environ["ATTACKER_HOME"] = str(self.atk_home)

    @property
    def features_log(self) -> Path:
        return self.atk_home / "sink" / "features.jsonl"

    # -- windows ------------------------------------------------------------
    def _window(self, label: int, start: float, end: float, **detail: Any) -> None:
        """Record one labelled time window. A small margin is NOT added.

        Widening a window to be safe would risk swallowing a neighbouring
        session's first call, which is worse than losing a row: a mislabelled
        row is indistinguishable from a real signal.
        """
        window = {"label": label, "start": start, "end": end, **detail}
        self.windows.append(window)
        try:
            with self.windows_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(window) + "\n")
                handle.flush()
        except Exception as exc:  # pragma: no cover - never lose a session
            print(f"warning: could not append window: {exc}")

    # -- the two kinds of traffic -------------------------------------------
    async def agent_session(self, task: dict, model: str, style: str,
                            client_info: dict[str, str]) -> dict[str, Any]:
        launch = agent_launch(self.attacker_project, self.atk_home,
                              self.ds_home, self.server_id, passive=False)
        start = time.time()
        record = await run_task(task, model, launch,
                                client_info=client_info, system_prompt=style)
        end = time.time()
        self._window(GENUINE, start, end, task=task["id"], model=model,
                     style=style, n_calls=record["n_calls"],
                     error=record.get("error"))
        return record

    async def probe_cycle(self, baseline: Any, cycle: int, key: bytes) -> Any:
        from driftsentry.verify import verify_server

        launch = probe_launch(self.attacker_project, self.atk_home)
        start = time.time()
        report = await verify_server(baseline, launch=launch,
                                     samples_per_probe=self.samples_per_probe,
                                     monitor_sandbox=self.monitor_sandbox,
                                     cycle=cycle, key=key,
                                     mimic_host=self.mimic_host,
                                     mimic_traffic=self.mimic_traffic,
                                     subsample_bank=self.subsample_bank)
        end = time.time()
        self._window(PROBE, start, end, cycle=cycle)
        return report

    # -- the run ------------------------------------------------------------
    async def run(self, sessions: int, models: list[str],
                  *, progress: bool = True) -> dict[str, Any]:
        from driftsentry import keys as key_store
        from driftsentry.baseline import capture_baseline

        self.prepare()
        client_info, recorded = load_host_profile()
        if not recorded:
            raise RuntimeError(
                "no host profile recorded. Probe sessions would announce the "
                "SDK's default client name, which appears in no real host, and "
                "the client feature family would separate the classes on that "
                "alone. Record eval/host_profile.json first."
            )

        key = key_store.derive_experiment_key(self.seed, "rq3-collect")
        launch = probe_launch(self.attacker_project, self.atk_home)

        if progress:
            print(f"baseline   : keyed, {self.n_probes} probes x {self.n_samples} samples")
        baseline = await capture_baseline(
            self.server_id, launch["command"], launch["args"],
            cwd=launch["cwd"], env=launch["env"],
            n_probes=self.n_probes, n_samples=self.n_samples, seed=self.seed,
            probe_mode="keyed", key=key, monitor_sandbox=self.monitor_sandbox,
            mimic_host=self.mimic_host)

        # Baselining is itself probe traffic, but it is NOT labelled. It runs
        # once, with a different sample count from every later cycle, so its
        # session features are unlike anything the real collection produces.
        # Including it would hand the classifier a shape that occurs once.
        baseline_cutoff = time.time()

        tasks = load_tasks()
        styles = list(SYSTEM_PROMPTS)
        combos = itertools.cycle(itertools.product(models, styles))
        errors: list[str] = []

        for i in range(sessions):
            task = tasks[i % len(tasks)]
            model, style = next(combos)

            record = await self.agent_session(task, model, style, client_info)
            if record.get("error"):
                errors.append(f"{task['id']}/{model}: {record['error']}")

            report = await self.probe_cycle(baseline, cycle=i + 1, key=key)

            if progress:
                print(f"  [{i + 1:>3}/{sessions}] {task['id']} {model:<16} "
                      f"{style:<8} agent_calls={record['n_calls']:<2} "
                      f"probe_score={getattr(report, 'score', 0.0):.3f}"
                      + (f"  ERROR {record['error']}" if record.get("error") else ""))

        return self.finish(baseline_cutoff, errors)

    def finish(self, baseline_cutoff: float, errors: list[str]) -> dict[str, Any]:
        """Copy the attacker's rows out of the sink and summarise.

        windows.jsonl is NOT written here: every session appended its own line
        as it closed. Rewriting it from memory would undo that, and a run
        interrupted before reaching this point would lose its labels again.
        """
        copied = 0
        if self.features_log.is_file():
            shutil.copy2(self.features_log, self.out_dir / "features.jsonl")
            copied = sum(1 for line in
                         (self.out_dir / "features.jsonl").read_text(
                             encoding="utf-8").splitlines() if line.strip())

        summary = {
            "windows": len(self.windows),
            "genuine_windows": sum(1 for w in self.windows if w["label"] == GENUINE),
            "probe_windows": sum(1 for w in self.windows if w["label"] == PROBE),
            "feature_rows": copied,
            "baseline_cutoff": baseline_cutoff,
            "errors": errors,
            "out_dir": str(self.out_dir),
        }
        (self.out_dir / "collection.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        return summary


def collect(attacker_project, out_dir, workspace, sessions, models, **kwargs):
    """Synchronous entry point for the CLI."""
    collector = Collector(attacker_project, out_dir, workspace, **kwargs)
    return asyncio.run(collector.run(sessions, models))
