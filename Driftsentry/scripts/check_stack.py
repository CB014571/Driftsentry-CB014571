"""Phase 0 — offline-stack self-check.

Proves the privacy-preserving storage + embedding stack works with no network
egress, which is half of the Phase 0 definition of done. Concretely it checks:

  1. ChromaDB can create a persistent collection, add vectors, close, reopen it
     from disk, and query the vectors back — all offline.
  2. A dependency-free embedding backend turns text into a stable vector locally.
     (This hashing backend is DriftSentry's always-available fallback; the real
     semantic backends — Ollama or ONNX/all-MiniLM — arrive in Phase 3.)

It also *reports* (without failing) whether the optional semantic backends are
reachable, so you know what the machine can do.

Run:
    python scripts/check_stack.py
Exit code 0 = the offline stack is healthy; non-zero = a required check failed.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np


def hashing_embedding(text: str, dim: int = 64) -> list[float]:
    """Deterministic, dependency-free text embedding.

    Not semantically meaningful — same words map to the same buckets — but it is
    stable, offline, and needs no model download, which makes it the reliable
    fallback and the backend our tests run against. Each whitespace token is
    hashed into one of `dim` buckets; the vector is L2-normalised so cosine
    distance behaves sensibly.
    """
    vec = np.zeros(dim, dtype=np.float32)
    for token in text.lower().split():
        bucket = int(hashlib.sha256(token.encode()).hexdigest(), 16) % dim
        vec[bucket] += 1.0
    norm = float(np.linalg.norm(vec))
    if norm:
        vec /= norm
    return vec.tolist()


def check_embeddings() -> bool:
    print("[1/3] embedding backend (hashing, offline)")
    a = hashing_embedding("the quick brown fox")
    b = hashing_embedding("the quick brown fox")
    c = hashing_embedding("completely different text here")
    if a != b:
        print("      FAIL: embedding is not deterministic")
        return False
    # Same text -> distance 0; different text -> distance > 0.
    d_same = float(np.linalg.norm(np.array(a) - np.array(b)))
    d_diff = float(np.linalg.norm(np.array(a) - np.array(c)))
    print(f"      dim={len(a)}  d(same)={d_same:.3f}  d(diff)={d_diff:.3f}")
    if not (d_same == 0.0 and d_diff > 0.0):
        print("      FAIL: embedding does not separate different text")
        return False
    print("      OK")
    return True


def check_chromadb() -> bool:
    print("[2/3] ChromaDB persist + reload (offline)")
    import chromadb  # imported here so the embedding check runs even if chroma is absent

    store = Path(tempfile.mkdtemp(prefix="driftsentry_stack_"))
    try:
        docs = ["a known safe path", "a fixed search query", "an unrelated string"]
        ids = [f"probe-{i}" for i in range(len(docs))]
        embs = [hashing_embedding(d) for d in docs]

        # Write. embedding_function=None: we supply vectors ourselves, so no
        # model is ever downloaded and the store stays fully offline.
        client = chromadb.PersistentClient(path=str(store))
        col = client.create_collection("phase0_check", embedding_function=None)
        col.add(ids=ids, embeddings=embs, documents=docs)

        # Reopen from disk in a fresh client to prove persistence.
        client2 = chromadb.PersistentClient(path=str(store))
        col2 = client2.get_collection("phase0_check")
        if col2.count() != len(docs):
            print(f"      FAIL: expected {len(docs)} rows, got {col2.count()}")
            return False

        # Nearest neighbour of the first doc's vector should be the first doc.
        res = col2.query(query_embeddings=[embs[0]], n_results=1)
        nearest = res["ids"][0][0]
        print(f"      persisted {col2.count()} vectors; nearest to probe-0 = {nearest}")
        if nearest != "probe-0":
            print("      FAIL: query did not return the expected nearest vector")
            return False
        print("      OK")
        return True
    finally:
        shutil.rmtree(store, ignore_errors=True)


def report_semantic_backends() -> None:
    """Best-effort availability report — never fails the check."""
    print("[3/3] optional semantic embedding backends (informational)")

    # Ollama (roadmap's primary backend) — a local HTTP daemon.
    try:
        import httpx

        r = httpx.get("http://localhost:11434/api/tags", timeout=1.0)
        models = [m.get("name") for m in r.json().get("models", [])]
        print(f"      Ollama: reachable; models = {models or '(none pulled)'}")
    except Exception:
        print("      Ollama: not reachable (install from https://ollama.com, then "
              "`ollama pull nomic-embed-text`) - optional")

    # ONNX default (all-MiniLM-L6-v2) via chromadb — no torch needed, but the
    # model downloads once on first use.
    try:
        import onnxruntime  # noqa: F401

        print("      ONNX runtime: present (all-MiniLM available; downloads once)")
    except Exception:
        print("      ONNX runtime: absent")


def main() -> int:
    print("DriftSentry Phase 0 stack check\n" + "-" * 34)
    ok = True
    ok &= check_embeddings()
    ok &= check_chromadb()
    report_semantic_backends()
    print("-" * 34)
    if ok:
        print("RESULT: offline stack healthy (ChromaDB + embeddings work, no network).")
        return 0
    print("RESULT: FAILED — see messages above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
