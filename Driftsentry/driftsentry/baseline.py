"""Phase 3 — baseline capture and re-probing.

This is the orchestration layer: connect to a server, ask what tools it has,
decide which are safe to probe, fire seeded canaries at them several times each,
fingerprint every response, learn the natural variance, and store the result.

Where probes are sent — a design decision worth defending
    Probe traffic goes to the server over its **own out-of-band session**, not
    through the client's live proxy connection. Three reasons:

      1. The risk register requires probing "out-of-band on a schedule, not on
         every live call" so the proxy never adds latency to a real tool call.
      2. It keeps attribution clean: the proxy's audit log stays a record of what
         the *user's client* actually did, not a mixture of real and synthetic
         calls.
      3. It gives the sandbox monitor a process tree it owns, so file and network
         evidence is attributable to our probe rather than to concurrent traffic.

    The proxy is still what sits in the live path (Phase 1) and still supplies the
    passive signals; this is the active half of the same detector.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from driftsentry.embeddings import EmbeddingBackend, cosine_distance, get_backend
from driftsentry.fingerprint import (
    ProbeSample,
    ServerBaseline,
    ToolBaseline,
    normalize_result,
    summarize_probe,
)
from driftsentry.hashing import tools_definition_hash
from driftsentry.probes import Probe, ProbeGenerator, SafetyPolicy, classify_tool_safety
from driftsentry.families import summarize_family
from driftsentry.fielddrift import FieldProfile, compare as compare_fields
from driftsentry.redact import echo_ratio, redact
from driftsentry.rules import content_flags
from driftsentry.sandbox import Observation, SandboxMonitor

log = logging.getLogger("driftsentry.baseline")

DEFAULT_SEED = 20260720
DEFAULT_N_PROBES = 3
DEFAULT_N_SAMPLES = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_child_pids(before: set[int]) -> list[int]:
    """Identify the server subprocess(es) the SDK just launched.

    ``stdio_client`` owns the process and does not expose its pid, so we diff our
    own children before and after it starts.

    Every new child is returned, not the lowest-numbered one. Picking a single
    pid was quietly unreliable: back-to-back verifications can leave a previous
    server still shutting down, and pids are not ordered by launch time, so the
    guess sometimes attached the monitor to the wrong process and the run
    silently recorded no side effects at all. Watching them all costs nothing and
    cannot pick wrong.
    """
    try:
        import psutil

        children = {p.pid for p in psutil.Process().children(recursive=True)}
        return sorted(children - before)
    except Exception:  # pragma: no cover - psutil optional/unavailable
        return []


async def _call_once(
    session: ClientSession,
    tool_name: str,
    args: dict[str, Any],
    monitor: SandboxMonitor | None,
) -> tuple[dict[str, Any], float, Observation]:
    """Call a tool once, timing it and watching for side effects."""
    if monitor is not None:
        monitor.start()
    started = time.perf_counter()
    try:
        result = await session.call_tool(tool_name, args)
        payload = result.model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001 - a rejected probe is still a behaviour
        payload = {
            "content": [{"type": "text", "text": f"ERROR: {type(exc).__name__}: {exc}"}],
            "isError": True,
        }
    latency_ms = (time.perf_counter() - started) * 1000.0
    observation = monitor.stop() if monitor is not None else Observation(available=False)
    return payload, latency_ms, observation


async def capture_baseline(
    server: str,
    command: str,
    args: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    n_probes: int = DEFAULT_N_PROBES,
    n_samples: int = DEFAULT_N_SAMPLES,
    seed: int = DEFAULT_SEED,
    backend: EmbeddingBackend | None = None,
    backend_name: str = "auto",
    safety_policy: SafetyPolicy = "default",
    monitor_sandbox: bool = True,
    probe_mode: str = "fixed",
    key: bytes | None = None,
) -> ServerBaseline:
    """Capture a full behavioural baseline for one stdio MCP server.

    ``probe_mode="keyed"`` draws probe values from a secret key instead of the
    fixed pool, and records a per-template *family* baseline alongside the
    per-probe ones, so later verification can use values this server has never
    seen. ``"fixed"`` is unchanged and remains the control condition.
    """
    embedder = backend or get_backend(backend_name)
    params = StdioServerParameters(command=command, args=args, cwd=cwd, env=env)

    keyed = probe_mode == "keyed"
    if keyed:
        from driftsentry import keys as key_store
        from driftsentry.probe_generator import (
            GENERATOR_VERSION,
            KeyedProbeGenerator,
            UnsupportedSchema,
        )

        probe_key = key or key_store.get_or_create(server)
        generator = KeyedProbeGenerator(probe_key, cycle=0)
        key_identifier = key_store.key_id(probe_key)
    else:
        generator = ProbeGenerator(seed=seed)
        probe_key = None
        key_identifier = ""
        GENERATOR_VERSION = ""            # noqa: N806 - only used in keyed mode
        UnsupportedSchema = ()            # noqa: N806 - never raised in fixed mode

    import psutil  # local import; only needed to spot the child process

    try:
        before = {p.pid for p in psutil.Process().children(recursive=True)}
    except Exception:  # pragma: no cover
        before = set()

    tool_baselines: list[ToolBaseline] = []
    families: list[Any] = []

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            pids = _find_child_pids(before)
            monitor = SandboxMonitor(pids) if (monitor_sandbox and pids) else None
            if monitor_sandbox and monitor is None:
                log.warning("sandbox monitoring unavailable (no pid); side-effect signals disabled")

            listed = await session.list_tools()
            definitions = [t.model_dump(mode="json") for t in listed.tools]
            definition_hash = tools_definition_hash(definitions)
            log.info("server %r advertises %d tools (%s)", server, len(definitions), definition_hash[:19])

            for definition in definitions:
                name = definition["name"]
                safety, reason = classify_tool_safety(definition, policy=safety_policy)

                if safety == "side-effecting":
                    # Baseline-by-observation: never actively probed. The proxy's
                    # log of real calls is the only evidence we collect for it.
                    log.info("tool %r: NOT probed (%s)", name, reason)
                    tool_baselines.append(
                        ToolBaseline(tool=name, safety=safety, safety_reason=reason, probed=False)
                    )
                    continue

                try:
                    probes: list[Probe] = generator.generate(server, definition, count=n_probes)
                except UnsupportedSchema as exc:
                    # Refuse rather than improvise. A probe built from a
                    # misunderstood schema gets rejected by the server, and that
                    # rejection is then learned as the tool's normal behaviour -
                    # a baseline that is quietly worthless.
                    log.warning("tool %r: NOT probed (%s)", name, exc)
                    tool_baselines.append(ToolBaseline(
                        tool=name, safety=safety,
                        safety_reason=f"schema not supported by the keyed generator: {exc}",
                        probed=False,
                    ))
                    continue

                probe_baselines = []
                samples_by_instance: list[list[ProbeSample]] = []
                echo_ratios: list[float] = []
                for probe in probes:
                    payloads: list[dict[str, Any]] = []
                    latencies: list[float] = []
                    observations: list[Observation] = []
                    for _ in range(n_samples):
                        payload, latency, observation = await _call_once(session, name, probe.args, monitor)
                        payloads.append(payload)
                        latencies.append(latency)
                        observations.append(observation)

                    normalized = [normalize_result(p) for p in payloads]
                    # In keyed mode the probe's own arguments are stripped out of
                    # the response before embedding. Many tools echo their input,
                    # so without this the vector would be dominated by which
                    # value we happened to send - the detector would be measuring
                    # its own probe generator instead of the tool.
                    if keyed:
                        texts = [redact(n.text, probe.args) for n in normalized]
                        echo_ratios.extend(echo_ratio(n.text, probe.args) for n in normalized)
                    else:
                        texts = [n.text for n in normalized]
                    # One batched embedding call per probe keeps remote backends fast.
                    vectors = embedder.embed(texts)

                    samples = [
                        ProbeSample(
                            embedding=vec,
                            normalized=norm,
                            latency_ms=lat,
                            hosts=obs.hosts,
                            files=obs.files,
                            # Recorded so the security rules stay differential:
                            # whatever this tool normally emits can never alarm.
                            content_flags=content_flags(norm.text),
                            raw=payload_i,
                        )
                        for vec, norm, lat, obs, payload_i in
                        zip(vectors, normalized, latencies, observations, payloads)
                    ]
                    samples_by_instance.append(samples)
                    probe_baselines.append(
                        summarize_probe(probe.probe_id, probe.template_id, probe.args, samples)
                    )

                if keyed:
                    family = summarize_family(
                        family_id=probes[0].template_id,
                        tool=name,
                        field_grammars=dict(probes[0].choices),
                        instances=probe_baselines,
                        samples_by_instance=samples_by_instance,
                        echo_ratio=(sum(echo_ratios) / len(echo_ratios)) if echo_ratios else 0.0,
                        generator_version=GENERATOR_VERSION,
                        key_id=key_identifier,
                        cycle=0,
                    )
                    families.append(family)
                    log.info("tool %r: family %s", name, family.describe())

                band_span = ", ".join(f"{p.band:.4f}" for p in probe_baselines)
                log.info("tool %r: %d probes x %d samples, bands [%s]", name, len(probes), n_samples, band_span)
                tool_baselines.append(
                    ToolBaseline(
                        tool=name,
                        safety=safety,
                        safety_reason=reason,
                        probed=True,
                        probes=probe_baselines,
                    )
                )

    return ServerBaseline(
        server=server,
        definition_hash=definition_hash,
        tools=tool_baselines,
        tool_definitions=definitions,
        embedding_backend=embedder.name,
        embedding_dim=embedder.dim,
        seed=seed,
        n_probes=n_probes,
        n_samples=n_samples,
        captured_at=_now(),
        launch={"command": command, "args": list(args), "cwd": cwd},
        schema_version=2 if keyed else 1,
        probe_mode=probe_mode,
        key_id=key_identifier,
        generator_version=GENERATOR_VERSION if keyed else "",
        families=families,
    )


# --------------------------------------------------------------------------- #
# Re-probing (the Phase 3 definition of done; Phase 4 turns this into a score)
# --------------------------------------------------------------------------- #
@dataclass
class ProbeCheck:
    """Result of replaying one stored probe against a live server.

    Purely a *measurement*: it records what was observed relative to the stored
    baseline and passes no judgement. Turning these numbers into a score, a
    verdict and an attributable cause is the scorer's job, kept separate so the
    measurement can be re-scored under a different threshold without re-running
    any probes.
    """

    tool: str
    probe_id: str
    distance: float
    band: float
    ratio: float
    within_band: bool
    shape_known: bool
    new_hosts: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    # Content-rule flags present now but absent at baseline (differential).
    new_content_flags: list[str] = field(default_factory=list)
    observed_shape_hash: str = ""
    observed_excerpt: str = ""
    baseline_excerpt: str = ""
    became_error: bool = False
    # A probe whose baseline never varied by a character has now returned
    # something different. For such a probe this is a far stronger statement
    # than any distance, because its benign variance was genuinely zero.
    determinism_break: bool = False
    # How much the embedding signal can be trusted for this probe's family, 0-1.
    # 1.0 for the exact-probe path, where like is compared with like. Lower for a
    # keyed family whose answers genuinely differ between inputs, and the scorer
    # scales the behavioural signal by it rather than pretending otherwise.
    comparability: float = 1.0
    # Worst weighted per-field change, 0-1. Catches the security-critical
    # edit an embedding is blind to: one digit of an account number.
    field_drift: float = 0.0
    field_changes: list[str] = field(default_factory=list)


@dataclass
class ReprobeReport:
    server: str
    baseline_definition_hash: str
    observed_definition_hash: str
    checks: list[ProbeCheck]
    embedding_backend: str

    @property
    def definition_changed(self) -> bool:
        return self.baseline_definition_hash != self.observed_definition_hash

    @property
    def all_within_band(self) -> bool:
        return all(c.within_band for c in self.checks)

    @property
    def max_ratio(self) -> float:
        return max((c.ratio for c in self.checks), default=0.0)


async def _reprobe_keyed(
    session: ClientSession,
    baseline: ServerBaseline,
    embedder: EmbeddingBackend,
    monitor: SandboxMonitor | None,
    *,
    samples_per_probe: int,
    cycle: int,
    key: bytes | None,
) -> list[ProbeCheck]:
    """Verify with freshly generated values, against family baselines."""
    from driftsentry import keys as key_store
    from driftsentry.families import compare_to_family
    from driftsentry.probe_generator import KeyedProbeGenerator, UnsupportedSchema

    probe_key = key or key_store.get(baseline.server)
    if probe_key is None:
        raise ValueError(
            f"baseline for {baseline.server!r} was captured with keyed probes, but "
            "its key is no longer in the key store; re-baseline the server"
        )

    generator = KeyedProbeGenerator(probe_key, cycle=cycle)
    definitions = {d["name"]: d for d in baseline.tool_definitions}
    checks: list[ProbeCheck] = []

    for tool in baseline.tools:
        if not tool.probed:
            continue
        family = baseline.family_for(tool.tool)
        definition = definitions.get(tool.tool)
        if family is None or definition is None:
            log.warning("no family baseline for %r; skipping", tool.tool)
            continue

        try:
            probes = generator.generate(
                baseline.server, definition, count=family.n_instances, cycle=cycle
            )
        except UnsupportedSchema as exc:  # pragma: no cover - caught at capture time
            log.warning("tool %r: cannot generate probes (%s)", tool.tool, exc)
            continue

        for probe in probes:
            payloads, observations = [], []
            for _ in range(samples_per_probe):
                payload, _latency, observation = await _call_once(
                    session, tool.tool, probe.args, monitor
                )
                payloads.append(payload)
                observations.append(observation)

            normalized = [normalize_result(p) for p in payloads]
            # Same redaction as at capture time, or the comparison is meaningless.
            vectors = embedder.embed([redact(n.text, probe.args) for n in normalized])

            samples = [
                ProbeSample(
                    embedding=vec, normalized=norm, latency_ms=0.0,
                    hosts=obs.hosts, files=obs.files,
                    content_flags=content_flags(norm.text),
                )
                for vec, norm, obs in zip(vectors, normalized, observations)
            ]
            measured = compare_to_family(family, samples)
            checks.append(ProbeCheck(
                tool=tool.tool,
                probe_id=probe.probe_id,
                distance=measured["distance"],
                band=measured["band"],
                ratio=measured["ratio"],
                within_band=measured["within_band"],
                shape_known=measured["shape_known"],
                new_hosts=measured["new_hosts"],
                new_files=measured["new_files"],
                new_content_flags=measured["new_content_flags"],
                observed_shape_hash=measured["observed_shape_hash"],
                observed_excerpt=measured["observed_excerpt"],
                baseline_excerpt=measured["baseline_excerpt"],
                became_error=measured["became_error"],
                determinism_break=measured["determinism_break"],
                comparability=measured["comparability"],
            ))
    return checks


async def reprobe(
    baseline: ServerBaseline,
    command: str,
    args: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    samples_per_probe: int = 1,
    backend: EmbeddingBackend | None = None,
    monitor_sandbox: bool = True,
    cycle: int = 1,
    key: bytes | None = None,
) -> ReprobeReport:
    """Replay a stored baseline's probes against a live server and measure drift.

    Deliberately a *measurement*, not a verdict: it reports each probe's distance
    relative to its benign band. Combining that with the hash and security-rule
    signals into a single calibrated score with a threshold is Phase 4's job.

    For a baseline captured with ``probe_mode="keyed"`` the stored arguments are
    NOT replayed. Fresh values are generated for this ``cycle`` and compared
    against the template family's behavioural distribution instead. Replaying
    stored values would defeat the entire mechanism: the server saw them while it
    was being baselined, so it can recognise them however unpredictable they were
    when first chosen.
    """
    spec, dim = baseline.embedding_spec()
    embedder = backend or get_backend(spec, dim=dim)
    if embedder.dim != baseline.embedding_dim:
        raise ValueError(
            f"embedding mismatch: baseline used {baseline.embedding_backend} "
            f"(dim {baseline.embedding_dim}), current backend is {embedder.name} (dim {embedder.dim})"
        )

    params = StdioServerParameters(command=command, args=args, cwd=cwd, env=env)

    import psutil

    try:
        before = {p.pid for p in psutil.Process().children(recursive=True)}
    except Exception:  # pragma: no cover
        before = set()

    checks: list[ProbeCheck] = []

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            pids = _find_child_pids(before)
            monitor = SandboxMonitor(pids) if (monitor_sandbox and pids) else None

            listed = await session.list_tools()
            observed_definitions = [t.model_dump(mode="json") for t in listed.tools]
            observed_hash = tools_definition_hash(observed_definitions)

            if baseline.probe_mode == "keyed":
                checks.extend(await _reprobe_keyed(
                    session, baseline, embedder, monitor,
                    samples_per_probe=samples_per_probe, cycle=cycle, key=key,
                ))
                return ReprobeReport(
                    server=baseline.server,
                    baseline_definition_hash=baseline.definition_hash,
                    observed_definition_hash=observed_hash,
                    checks=checks,
                    embedding_backend=embedder.name,
                )

            for tool in baseline.tools:
                if not tool.probed:
                    continue
                for probe in tool.probes:
                    payloads, observations = [], []
                    for _ in range(samples_per_probe):
                        payload, _latency, observation = await _call_once(
                            session, tool.tool, probe.args, monitor
                        )
                        payloads.append(payload)
                        observations.append(observation)

                    normalized = [normalize_result(p) for p in payloads]
                    vectors = embedder.embed([n.text for n in normalized])

                    # Worst sample decides: a rug pull that fires intermittently
                    # (an L2 stochastic attacker) must not be averaged away.
                    distance = max(cosine_distance(v, probe.centroid) for v in vectors)
                    known_shapes = set(probe.shape_hashes)
                    shape_known = all(n.shape_hash in known_shapes for n in normalized)

                    # Exact-equality check, only for probes that earned it by
                    # being perfectly stable at baseline. Cheap, and it closes
                    # the gap where a deterministic tool could be altered by less
                    # than the calibrated threshold allows.
                    known_texts = set(probe.text_hashes)
                    determinism_break = (
                        probe.is_deterministic()
                        and any(n.text_hash not in known_texts for n in normalized)
                    )

                    seen_hosts = {h for o in observations for h in o.hosts}
                    seen_files = {f for o in observations for f in o.files}

                    # Differential content rules: only patterns that are new
                    # relative to approval time count as evidence.
                    seen_flags: set[str] = set()
                    for norm in normalized:
                        seen_flags.update(content_flags(norm.text))
                    new_flags = sorted(seen_flags - set(probe.content_flags))

                    # Report the sample that drifted furthest, so the alert shows
                    # the worst observed behaviour rather than an average one.
                    worst_i = max(
                        range(len(vectors)),
                        key=lambda i: cosine_distance(vectors[i], probe.centroid),
                    )
                    worst_norm = normalized[worst_i]

                    profiles = {k: FieldProfile.from_dict(v)
                                for k, v in (probe.field_profiles or {}).items()}
                    field_drift, field_changes = (
                        max((compare_fields(profiles, pay) for pay in payloads),
                            key=lambda r: r[0])
                        if profiles else (0.0, [])
                    )

                    checks.append(
                        ProbeCheck(
                            tool=tool.tool,
                            probe_id=probe.probe_id,
                            distance=distance,
                            band=probe.band,
                            ratio=distance / probe.band if probe.band else float("inf"),
                            within_band=distance <= probe.band,
                            shape_known=shape_known,
                            new_hosts=sorted(seen_hosts - set(probe.hosts)),
                            new_files=sorted(seen_files - set(probe.files)),
                            new_content_flags=new_flags,
                            observed_shape_hash=worst_norm.shape_hash,
                            observed_excerpt=worst_norm.text[:300],
                            baseline_excerpt=probe.excerpt,
                            became_error=any(n.is_error for n in normalized) and probe.error_rate == 0.0,
                            determinism_break=determinism_break,
                            field_drift=field_drift,
                            field_changes=[c.describe() for c in field_changes[:5]],
                        )
                    )

    return ReprobeReport(
        server=baseline.server,
        baseline_definition_hash=baseline.definition_hash,
        observed_definition_hash=observed_hash,
        checks=checks,
        embedding_backend=embedder.name,
    )
