"""Phase 3 — response normalisation, fingerprints, and variance modelling.

A *behavioural fingerprint* is what DriftSentry stores instead of (well, as well
as) a definition hash. For one probe fired at one tool it captures:

    * a normalised text rendering of the response  -> embedding vector
    * a structural signature of the response JSON  -> structural diffing
    * size / error characteristics                 -> cheap sanity signals
    * hosts contacted and files touched            -> the security-rule signals

Why not just embed the raw response
    Many MCP tools answer with structured JSON, not prose, and embedding raw JSON
    is noisy: key names and punctuation dominate the vector, so a meaningful
    change in a value can be swamped while a harmless key reordering looks like
    drift. The roadmap calls this out as a hard problem. The answer here is to
    split the response into two *independent* signals — normalised text for the
    embedding, and a separate shape signature for structure — so a payload that
    changes shape (a hidden field appearing) is caught structurally even when the
    embedding barely moves, and vice versa.

Why variance modelling is not optional
    A weather or search tool legitimately returns different text on every call.
    If we treat "response differs from baseline" as drift, such a tool alarms
    forever and the user turns DriftSentry off. So each probe is sampled several
    times at approval time and we learn a *benign variance band* per probe. Phase
    4 scores drift relative to that band rather than in absolute terms.
"""
from __future__ import annotations

import hashlib
import statistics
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator

import numpy as np

from driftsentry.embeddings import cosine_distance

# Floor on a probe's variance band: the embedding noise floor.
#
# A perfectly deterministic tool has a zero-width band, and Phase 4 divides by
# the band, so some floor is required. The value is not arbitrary: below roughly
# this cosine distance two responses are effectively the same text, and the
# difference is numerical noise in the embedding rather than a behavioural
# change. Flooring here says "we do not claim precision we do not have".
#
# A floor of 1e-6 would technically work but is actively harmful: it implies the
# band is meaningful to six decimal places, so a deterministic tool that moves at
# all yields a drift ratio in the hundreds of thousands. That number is
# meaningless to a user, unusable on a plot, and it distorts calibration.
MIN_BAND = 0.01

# How many standard deviations above the mean count as "still benign".
BAND_SIGMA = 3.0


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def _shape_paths(obj: Any, prefix: str = "") -> Iterator[str]:
    """Yield ``path:type`` strings describing a JSON value's structure.

    Values are deliberately discarded — only keys, nesting and types survive.
    List items are merged into a single ``[]`` path so that returning three
    results instead of two is not a structural change, but an item gaining a new
    field is.
    """
    if isinstance(obj, dict):
        for key in sorted(obj):
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _shape_paths(obj[key], child)
    elif isinstance(obj, list):
        if not obj:
            yield f"{prefix}[]:empty"
            return
        merged: set[str] = set()
        for item in obj:
            merged.update(_shape_paths(item, f"{prefix}[]"))
        yield from sorted(merged)
    else:
        yield f"{prefix}:{type(obj).__name__}"


def _text_leaves(obj: Any) -> Iterator[str]:
    """Yield string leaves of a JSON value, in canonical key order."""
    if isinstance(obj, dict):
        for key in sorted(obj):
            yield from _text_leaves(obj[key])
    elif isinstance(obj, list):
        for item in obj:
            yield from _text_leaves(item)
    elif isinstance(obj, str):
        yield obj


@dataclass
class NormalizedResponse:
    """A tool response reduced to comparable features."""

    text: str
    shape: str
    shape_hash: str
    n_chars: int
    n_blocks: int
    is_error: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_result(result: dict[str, Any]) -> NormalizedResponse:
    """Reduce an MCP ``CallToolResult`` (as a dict) to comparable features."""
    content = result.get("content") or []
    blocks = content if isinstance(content, list) else []

    # Prefer the human-facing text blocks. Fall back to structured content only
    # when there is no text, so responses that carry the same value in both
    # `content` and `structuredContent` are not counted twice.
    texts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
    if any(t.strip() for t in texts):
        text = "\n".join(texts)
    else:
        text = "\n".join(_text_leaves(result.get("structuredContent") or {}))

    # Non-text blocks (images, embedded resources) contribute their type only —
    # binary payloads are not embedded, but their presence is structural.
    for block in blocks:
        if isinstance(block, dict) and block.get("type") != "text":
            text += f"\n[{block.get('type')}]"

    # The shape covers the whole result, including structuredContent, so a hidden
    # field appearing anywhere is visible even if the prose is unchanged.
    shape = "|".join(sorted(set(_shape_paths(result))))
    shape_hash = "sha256:" + hashlib.sha256(shape.encode("utf-8")).hexdigest()[:32]

    return NormalizedResponse(
        text=text,
        shape=shape,
        shape_hash=shape_hash,
        n_chars=len(text),
        n_blocks=len(blocks),
        is_error=bool(result.get("isError")),
    )


# --------------------------------------------------------------------------- #
# Samples and baselines
# --------------------------------------------------------------------------- #
@dataclass
class ProbeSample:
    """One execution of one probe."""

    embedding: list[float]
    normalized: NormalizedResponse
    latency_ms: float
    hosts: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    content_flags: list[str] = field(default_factory=list)


@dataclass
class ProbeBaseline:
    """Aggregated behaviour of one probe across several benign samples."""

    probe_id: str
    template_id: str
    args: dict[str, Any]
    centroid: list[float]
    n_samples: int
    dist_mean: float
    dist_std: float
    dist_max: float
    band: float
    shape_hashes: list[str]
    chars_mean: float
    chars_std: float
    error_rate: float
    latency_ms_mean: float
    hosts: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    # What this tool NORMALLY does. The security rules are differential, so a
    # pattern recorded here can never fire an alert later - only patterns that
    # are new relative to approval time count as evidence.
    content_flags: list[str] = field(default_factory=list)
    # A short, representative sample of the baseline response, kept so an alert
    # can show a concrete "it used to say X, now it says Y". Stored locally only.
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProbeBaseline":
        # Tolerate baselines written by an earlier version that lacked newer fields.
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ToolBaseline:
    """Baseline for one tool: its probes, or why it was not probed."""

    tool: str
    safety: str
    safety_reason: str
    probed: bool
    probes: list[ProbeBaseline] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "safety": self.safety,
            "safety_reason": self.safety_reason,
            "probed": self.probed,
            "probes": [p.to_dict() for p in self.probes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolBaseline":
        return cls(
            tool=data["tool"],
            safety=data["safety"],
            safety_reason=data["safety_reason"],
            probed=data["probed"],
            probes=[ProbeBaseline.from_dict(p) for p in data.get("probes", [])],
        )


@dataclass
class ServerBaseline:
    """Everything captured for one server at approval time."""

    server: str
    definition_hash: str
    tools: list[ToolBaseline]
    tool_definitions: list[dict[str, Any]]
    embedding_backend: str
    embedding_dim: int
    seed: int
    n_probes: int
    n_samples: int
    captured_at: str
    # How to relaunch this server, so a re-probe, a calibration run or a
    # scheduled scan can reach it without the caller having to remember the
    # command. Holds {"command": str, "args": [str], "cwd": str | None}.
    launch: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tools"] = [t.to_dict() for t in self.tools]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerBaseline":
        return cls(
            server=data["server"],
            definition_hash=data["definition_hash"],
            tools=[ToolBaseline.from_dict(t) for t in data["tools"]],
            tool_definitions=data.get("tool_definitions", []),
            embedding_backend=data["embedding_backend"],
            embedding_dim=data["embedding_dim"],
            seed=data["seed"],
            n_probes=data["n_probes"],
            n_samples=data["n_samples"],
            captured_at=data["captured_at"],
            launch=data.get("launch", {}),
        )

    def tool(self, name: str) -> ToolBaseline | None:
        return next((t for t in self.tools if t.tool == name), None)

    def embedding_spec(self) -> tuple[str, int]:
        """Recover the backend spec needed to rebuild the same embedding space.

        Stored names are descriptive ("hashing-256", "onnx:all-MiniLM-L6-v2");
        this maps them back to what ``get_backend()`` accepts, so re-probing
        always scores in the space the baseline was captured in.
        """
        name = self.embedding_backend
        if name.startswith("hashing"):
            return "hashing", self.embedding_dim
        if name.startswith("ollama"):
            return name, self.embedding_dim
        if name.startswith("onnx"):
            return "onnx", self.embedding_dim
        return "auto", self.embedding_dim


# --------------------------------------------------------------------------- #
# Variance maths
# --------------------------------------------------------------------------- #
def centroid_of(embeddings: list[list[float]]) -> list[float]:
    """Mean vector of the samples, L2-normalised."""
    matrix = np.asarray(embeddings, dtype=np.float64)
    mean = matrix.mean(axis=0)
    norm = float(np.linalg.norm(mean))
    if norm:
        mean = mean / norm
    return mean.tolist()


def leave_one_out_distances(embeddings: list[list[float]]) -> list[float]:
    """Out-of-sample distance estimates via leave-one-out cross-validation.

    Why this is not simply "distance from each sample to the centroid":
        That centroid is fitted to the very samples being measured, so the
        distances it produces are an *in-sample* fit and systematically smaller
        than the distance a genuinely new call will show. Building the band from
        them makes it too tight, and the first honest re-probe of a naturally
        noisy tool (weather, search) then breaches it — a false alarm on benign
        behaviour, which is the fastest way to make the detector unusable.

        Leaving each sample out and re-centroiding the rest measures exactly what
        we actually care about: how far a sample the model has *not* seen tends to
        fall. That is the quantity the band must cover.

    With fewer than three samples there is nothing to hold out, so we fall back to
    the in-sample estimate and accept that the band will be optimistic.
    """
    n = len(embeddings)
    if n < 3:
        centroid = centroid_of(embeddings)
        return [cosine_distance(e, centroid) for e in embeddings]

    distances: list[float] = []
    for i in range(n):
        others = embeddings[:i] + embeddings[i + 1:]
        distances.append(cosine_distance(embeddings[i], centroid_of(others)))
    return distances


def summarize_probe(
    probe_id: str,
    template_id: str,
    args: dict[str, Any],
    samples: list[ProbeSample],
) -> ProbeBaseline:
    """Turn repeated benign samples of one probe into its variance band.

    The stored centroid uses all samples (the best available estimate of the
    tool's central behaviour), but the *band* is built from leave-one-out
    distances so it reflects out-of-sample behaviour. The band is the wider of
    "the worst held-out sample" and "mean + 3σ", covering both a noisy-but-tight
    tool and one with rare outliers.
    """
    embeddings = [s.embedding for s in samples]
    centroid = centroid_of(embeddings)
    distances = leave_one_out_distances(embeddings)

    dist_mean = float(statistics.fmean(distances))
    dist_std = float(statistics.pstdev(distances)) if len(distances) > 1 else 0.0
    dist_max = float(max(distances))
    band = max(dist_max, dist_mean + BAND_SIGMA * dist_std, MIN_BAND)

    chars = [s.normalized.n_chars for s in samples]
    hosts = sorted({h for s in samples for h in s.hosts})
    files = sorted({f for s in samples for f in s.files})
    content_flags = sorted({f for s in samples for f in s.content_flags})
    excerpt = samples[0].normalized.text[:300]

    return ProbeBaseline(
        probe_id=probe_id,
        template_id=template_id,
        args=args,
        centroid=centroid,
        n_samples=len(samples),
        dist_mean=dist_mean,
        dist_std=dist_std,
        dist_max=dist_max,
        band=band,
        shape_hashes=sorted({s.normalized.shape_hash for s in samples}),
        chars_mean=float(statistics.fmean(chars)),
        chars_std=float(statistics.pstdev(chars)) if len(chars) > 1 else 0.0,
        error_rate=sum(1 for s in samples if s.normalized.is_error) / len(samples),
        latency_ms_mean=float(statistics.fmean([s.latency_ms for s in samples])),
        hosts=hosts,
        files=files,
        content_flags=content_flags,
        excerpt=excerpt,
    )
