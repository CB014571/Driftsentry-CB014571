"""Phase 3 — pluggable embedding backends.

The drift scorer compares a tool's live response against its baseline partly by
embedding distance. Which model produces that embedding is a genuine threat to
validity (Phase 10: "results may vary by embedding model"), so the backend is
swappable and every baseline records the backend name and dimension it was built
with. A baseline captured with one backend is never comparable to a probe scored
with another, and the store enforces that.

Three backends, in preference order for ``auto``:

  ollama   Local Ollama daemon (the roadmap's primary choice), e.g.
           `nomic-embed-text`. Real semantics, offline, no Python ML deps.
  onnx     all-MiniLM-L6-v2 through ChromaDB's ONNX embedding function. Real
           semantics, no torch, but downloads the model once on first use.
  hashing  Deterministic feature hashing. No dependencies, no download, fully
           offline and reproducible.

On `hashing` — be precise about what it is
    It is the classic "hashing trick": tokens are hashed into a fixed number of
    buckets and the vector is L2-normalised. It captures *lexical* change, not
    *semantic* change: it will notice a response whose wording changed, but it
    cannot tell that "sunny" and "clear skies" mean the same thing. That makes it
    an honest default for tests and CI (deterministic, zero setup), and the wrong
    choice for the headline thesis numbers, which should use a semantic backend.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Protocol, runtime_checkable

import numpy as np

log = logging.getLogger("driftsentry.embeddings")

_TOKEN_RE = re.compile(r"[a-z0-9]+")


@runtime_checkable
class EmbeddingBackend(Protocol):
    """Anything that turns text into fixed-length vectors."""

    name: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def cosine_distance(a: list[float] | np.ndarray, b: list[float] | np.ndarray) -> float:
    """Cosine distance in [0, 2]; 0 means identical direction.

    Used everywhere drift is measured, so it lives here next to the vectors.
    """
    va, vb = np.asarray(a, dtype=np.float64), np.asarray(b, dtype=np.float64)
    na, nb = np.linalg.norm(va), np.linalg.norm(vb)
    if na == 0.0 or nb == 0.0:
        # An empty response has no direction; treat identical-empty as no drift.
        return 0.0 if na == nb else 1.0
    # Clamp: floating-point error can push cosine slightly outside [-1, 1],
    # which would surface as a distracting "-0.0000" distance.
    cosine = float(np.clip((va @ vb) / (na * nb), -1.0, 1.0))
    return max(0.0, 1.0 - cosine)


class HashingEmbedding:
    """Deterministic feature-hashing embedding. Always available, offline."""

    def __init__(self, dim: int = 256) -> None:
        self.name = f"hashing-{dim}"
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = np.zeros(self.dim, dtype=np.float32)
            tokens = _TOKEN_RE.findall(text.lower())
            # Unigrams plus bigrams: bigrams give a little word-order sensitivity,
            # so reordering a response is not invisible to the signal.
            grams = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
            for gram in grams:
                digest = hashlib.sha256(gram.encode("utf-8")).digest()
                bucket = int.from_bytes(digest[:4], "big") % self.dim
                # Signed hashing reduces collision bias.
                sign = 1.0 if digest[4] & 1 else -1.0
                vec[bucket] += sign
            norm = float(np.linalg.norm(vec))
            if norm:
                vec /= norm
            out.append(vec.tolist())
        return out


class OllamaEmbedding:
    """Embeddings from a local Ollama daemon over localhost HTTP."""

    def __init__(self, model: str = "nomic-embed-text", host: str = "http://localhost:11434") -> None:
        import httpx

        self._httpx = httpx
        self.model = model
        self.host = host.rstrip("/")
        self.name = f"ollama:{model}"
        probe = self.embed(["dimension probe"])
        self.dim = len(probe[0])

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            resp = self._httpx.post(
                f"{self.host}/api/embeddings",
                json={"model": self.model, "prompt": text},
                timeout=60.0,
            )
            resp.raise_for_status()
            out.append(resp.json()["embedding"])
        return out


def onnx_model_cached() -> bool:
    """True if the all-MiniLM ONNX model is already on disk.

    ``auto`` consults this so it never triggers a ~79 MB download behind the
    user's back: DriftSentry advertises a no-network-egress stack, and silently
    fetching a model would break that promise. Asking for ``--embedding onnx``
    explicitly is consent to download it.
    """
    from pathlib import Path

    root = Path.home() / ".cache" / "chroma" / "onnx_models" / "all-MiniLM-L6-v2" / "onnx"
    return (root / "model.onnx").is_file()


class OnnxEmbedding:
    """all-MiniLM-L6-v2 via ChromaDB's ONNX embedding function (no torch).

    Downloads the model once on first construction, then runs entirely offline.
    """

    def __init__(self) -> None:
        from chromadb.utils import embedding_functions

        self._fn = embedding_functions.ONNXMiniLM_L6_V2()
        self.name = "onnx:all-MiniLM-L6-v2"
        self.dim = len(self._fn(["dimension probe"])[0])

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in self._fn(texts)]


def get_backend(name: str = "auto", *, dim: int = 256) -> EmbeddingBackend:
    """Construct an embedding backend by name.

    ``auto`` prefers real semantics when the machine can provide them, and falls
    back to hashing so nothing ever hard-fails for want of a model.
    """
    name = (name or "auto").lower()

    if name in {"hash", "hashing"}:
        return HashingEmbedding(dim=dim)
    if name.startswith("ollama"):
        model = name.split(":", 1)[1] if ":" in name else "nomic-embed-text"
        return OllamaEmbedding(model=model)
    if name == "onnx":
        return OnnxEmbedding()

    if name != "auto":
        raise ValueError(f"unknown embedding backend: {name!r}")

    # Only consider backends that are ready to use *now*. Nothing here may
    # download a model; see onnx_model_cached().
    candidates: list[tuple[str, Any]] = [("ollama", OllamaEmbedding)]
    if onnx_model_cached():
        candidates.append(("onnx", OnnxEmbedding))

    reasons: list[str] = []
    for attempt, factory in candidates:
        try:
            backend = factory()
            log.info("embedding backend: %s", backend.name)
            return backend
        except Exception as exc:  # noqa: BLE001 - availability probe; any failure means "not usable"
            reasons.append(f"{attempt}: {type(exc).__name__}: {exc}")
            log.info("embedding backend %s unavailable (%s)", attempt, exc)

    if not onnx_model_cached():
        reasons.append("onnx: model not downloaded (run with --embedding onnx once to fetch it)")

    backend = HashingEmbedding(dim=dim)
    # Loud on purpose. Falling back to lexical hashing quietly would let someone
    # capture a whole evaluation's baselines with the weak backend and never
    # notice, which would invalidate the results.
    log.warning(
        "no semantic embedding backend available - falling back to %s, which measures "
        "LEXICAL change only. Fine for tests; use Ollama or --embedding onnx for "
        "reported results. Tried: %s",
        backend.name,
        "; ".join(reasons),
    )
    return backend
