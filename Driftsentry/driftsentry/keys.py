"""Per-server probe keys.

The detector's defence against a probe-aware server is that the server cannot
predict what it will be asked next. That only holds if the thing driving probe
generation is secret, so each monitored server gets its own random key, created
when it is enrolled and kept locally.

What the key does and does not buy
    It stops the server PREDICTING future probe values. It does not stop the
    server RECOGNISING a value it has already been sent - nothing can, since the
    value has to be transmitted to be useful. That is why keyed generation is
    paired with per-cycle rotation: a value used once and never repeated cannot
    be matched against a lookup table built from earlier traffic.

Threat model, stated plainly
    The key protects against the monitored server, which sees probe *outputs*
    over stdio. It does not protect against an attacker who can already read the
    user's filesystem - such an attacker has the baselines, the alerts and the
    detector's source anyway, and probe unpredictability is not the relevant
    control at that point. The key file is therefore stored with restrictive
    permissions where the platform supports it, and no further.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import stat
from pathlib import Path

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.keys")

KEY_BYTES = 32                      # 256-bit, matching HMAC-SHA256's block security
_FILE_NAME = "keys.json"


def key_path() -> Path:
    return data_dir() / _FILE_NAME


def _restrict(path: Path) -> None:
    """Make the key file owner-only where the platform allows it."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as exc:  # pragma: no cover - best effort, Windows ACLs differ
        log.debug("could not restrict permissions on %s: %s", path, exc)


def _read() -> dict[str, str]:
    path = key_path()
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a corrupt key file must not brick probing
        log.warning("could not read %s (%s); treating as empty", path, exc)
        return {}


def _write(data: dict[str, str]) -> None:
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _restrict(path)


def key_id(key: bytes) -> str:
    """A short public identifier for a key.

    Recorded in baselines and experiment rows so a run can be tied to the key
    that produced it, without the key itself ever appearing in an artefact that
    gets read, copied into a dissertation appendix, or committed.
    """
    return "k:" + hashlib.sha256(key).hexdigest()[:12]


def get_or_create(server: str) -> bytes:
    """Return this server's probe key, creating one on first use."""
    keys = _read()
    stored = keys.get(server)
    if stored:
        return bytes.fromhex(stored)

    key = secrets.token_bytes(KEY_BYTES)
    keys[server] = key.hex()
    _write(keys)
    log.info("created probe key for %r (%s)", server, key_id(key))
    return key


def get(server: str) -> bytes | None:
    stored = _read().get(server)
    return bytes.fromhex(stored) if stored else None


def set_key(server: str, key: bytes) -> None:
    """Install a specific key.

    Used by the evaluation harness so an experiment is replayable: the key is an
    input to the run, recorded alongside the seed, rather than something freshly
    random on every execution.
    """
    keys = _read()
    keys[server] = key.hex()
    _write(keys)


def derive_experiment_key(seed: int, label: str = "") -> bytes:
    """A deterministic key for reproducible experiments.

    Never used for real monitoring - a key derived from a published seed is
    public by construction. It exists so an experiment can be re-run exactly,
    which is a different requirement from being unpredictable to an adversary.
    """
    material = f"driftsentry-experiment|{seed}|{label}".encode("utf-8")
    return hashlib.sha256(material).digest()


def forget(server: str) -> bool:
    keys = _read()
    if server in keys:
        keys.pop(server)
        _write(keys)
        return True
    return False
