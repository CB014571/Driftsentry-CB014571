"""Filesystem layout for DriftSentry's local runtime state.

Everything DriftSentry persists — proxy logs now, plus baselines, alerts and the
event database in later phases — lives under a single data directory so the whole
footprint is easy to find, back up, or wipe. The location defaults to
``.driftsentry_data/`` in the current working directory and can be overridden with
the ``DRIFTSENTRY_HOME`` environment variable (useful for tests and the eval
harness, which need isolated state).
"""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the root data directory, creating it if necessary."""
    root = os.environ.get("DRIFTSENTRY_HOME")
    path = Path(root) if root else Path.cwd() / ".driftsentry_data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    """Directory for per-server proxy exchange logs (JSONL)."""
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path
