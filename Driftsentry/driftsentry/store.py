"""Phase 3 — persistence for behavioural baselines.

Two stores, deliberately, because they answer different questions:

  * **JSON on disk** (`.driftsentry_data/baselines/<server>.json`) is the source
    of truth. It holds the whole baseline — probe arguments, seeds, variance
    bands, observed hosts and files — in a form a human can read and a marker can
    audit. Reproducibility is a graded contribution, so the record that lets
    someone re-run your probes must not be locked inside a binary index.

  * **ChromaDB** (`.driftsentry_data/chroma/`) indexes the centroid vectors. It
    is what makes "which stored behaviour does this response most resemble?" a
    cheap query, and it is the fingerprint store the proposal commits to.

Collections are named per embedding backend and dimension
    A baseline captured with one embedding model cannot be compared with a probe
    scored under another — the vectors live in different spaces and the distance
    would be meaningless. Encoding backend and dimension in the collection name
    keeps them physically separate, so mixing them is impossible rather than
    merely discouraged. This also lets Phase 10 repeat the key experiment with a
    second embedding model without wiping the first one's baselines.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any

from driftsentry.fingerprint import ServerBaseline
from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.store")


def _slug(text: str) -> str:
    """Make a string safe for a ChromaDB collection name."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-")
    return slug or "unnamed"


class BaselineStore:
    """Saves and loads behavioural baselines."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or data_dir()
        self.baseline_dir = self.root / "baselines"
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self._client: Any = None

    # -- chroma -------------------------------------------------------------
    def _chroma(self) -> Any:
        if self._client is None:
            import chromadb

            self._client = chromadb.PersistentClient(path=str(self.root / "chroma"))
        return self._client

    def _collection(self, backend: str, dim: int) -> Any:
        name = f"baselines-{_slug(backend)}-{dim}"
        # embedding_function=None: we always supply vectors ourselves, so the
        # store never reaches for a model and stays fully offline.
        return self._chroma().get_or_create_collection(name, embedding_function=None)

    # -- paths --------------------------------------------------------------
    def path_for(self, server: str) -> Path:
        return self.baseline_dir / f"{server}.json"

    def list_servers(self) -> list[str]:
        return sorted(p.stem for p in self.baseline_dir.glob("*.json"))

    def has(self, server: str) -> bool:
        return self.path_for(server).is_file()

    # -- save / load --------------------------------------------------------
    def save(self, baseline: ServerBaseline) -> Path:
        """Persist a baseline to JSON and index its centroids in ChromaDB."""
        path = self.path_for(baseline.server)
        path.write_text(json.dumps(baseline.to_dict(), indent=2), encoding="utf-8")

        ids: list[str] = []
        embeddings: list[list[float]] = []
        metadatas: list[dict[str, Any]] = []
        for tool in baseline.tools:
            for probe in tool.probes:
                ids.append(f"{baseline.server}::{tool.tool}::{probe.probe_id}")
                embeddings.append(probe.centroid)
                metadatas.append(
                    {
                        "server": baseline.server,
                        "tool": tool.tool,
                        "probe_id": probe.probe_id,
                        "template_id": probe.template_id,
                        "band": float(probe.band),
                        "dist_mean": float(probe.dist_mean),
                        "dist_std": float(probe.dist_std),
                        "dist_max": float(probe.dist_max),
                        "n_samples": int(probe.n_samples),
                        "chars_mean": float(probe.chars_mean),
                        "shape_hashes": ",".join(probe.shape_hashes),
                        "hosts": ",".join(probe.hosts),
                        "definition_hash": baseline.definition_hash,
                        "embedding_backend": baseline.embedding_backend,
                        "captured_at": baseline.captured_at,
                    }
                )

        if ids:
            col = self._collection(baseline.embedding_backend, baseline.embedding_dim)
            # Re-baselining replaces the old vectors rather than accumulating them.
            try:
                col.delete(where={"server": baseline.server})
            except Exception as exc:  # pragma: no cover - empty collection
                log.debug("nothing to delete for %s: %s", baseline.server, exc)
            col.add(ids=ids, embeddings=embeddings, metadatas=metadatas)

        log.info("baseline saved: %s (%d probe vectors)", path, len(ids))
        return path

    def load(self, server: str) -> ServerBaseline | None:
        path = self.path_for(server)
        if not path.is_file():
            return None
        return ServerBaseline.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def delete(self, server: str) -> bool:
        """Remove a server's baseline from both stores."""
        removed = False
        path = self.path_for(server)
        if path.is_file():
            baseline = self.load(server)
            path.unlink()
            removed = True
            if baseline:
                try:
                    col = self._collection(baseline.embedding_backend, baseline.embedding_dim)
                    col.delete(where={"server": server})
                except Exception as exc:  # pragma: no cover
                    log.debug("chroma delete failed for %s: %s", server, exc)
        return removed

    # -- queries ------------------------------------------------------------
    def nearest(
        self,
        embedding: list[float],
        backend: str,
        dim: int,
        n_results: int = 3,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Nearest stored probe centroids to a vector, closest first."""
        col = self._collection(backend, dim)
        result = col.query(query_embeddings=[embedding], n_results=n_results, where=where)
        out: list[dict[str, Any]] = []
        for i, doc_id in enumerate(result["ids"][0]):
            out.append(
                {
                    "id": doc_id,
                    "distance": result["distances"][0][i],
                    "metadata": result["metadatas"][0][i],
                }
            )
        return out

    def reset(self) -> None:
        """Wipe all baselines. Used by tests and the eval harness."""
        shutil.rmtree(self.baseline_dir, ignore_errors=True)
        shutil.rmtree(self.root / "chroma", ignore_errors=True)
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self._client = None
