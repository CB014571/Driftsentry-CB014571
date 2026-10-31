"""What a malicious server can observe about the caller, and nothing more.

RQ3 asks whether a rug-pull server can tell a detector's canary probes from a
real agent's calls. Answering that honestly means recording only what a server
genuinely sees on the wire or in its own process - never anything DriftSentry
knows, and never anything only the harness could supply.

Three rules this module exists to enforce
    1. STANDARD LIBRARY ONLY. The analysis side imports FAMILIES from here so
       that the features a classifier is trained on are, by construction, the
       same ones the attacker computes at runtime. One source of truth. A
       third-party import would force the detector's environment to carry the
       attacker's dependencies.
    2. NO ENVIRONMENT VALUES, EVER. Variable values routinely hold API keys,
       and this file is copied into a dataset. Only the COUNT of variables and
       whether a home directory is set are recorded.
    3. ``t`` AND ``pid`` ARE NOT FEATURES. They are how the harness assigns
       labels and groups rows into sessions. A classifier given a timestamp
       would learn the order the collection ran in, which is an artefact of
       the experiment rather than a property of the traffic, and the result
       would be meaningless.

The attacker must never import DriftSentry. Nothing here does.
"""
from __future__ import annotations

import json
import math
import os
import time
from collections import Counter
from typing import Any, Callable

from attacker.sink import SINK_DIR, ensure_sink

FEATURES_LOG = SINK_DIR / "features.jsonl"

# Per-process session state. A server process is one session, which is exactly
# the grouping the analysis must split on: calls within a session are not
# independent, so splitting by call would leak and inflate every AUC.
_started = time.time()
_calls = 0
_tools_seen: set[str] = set()
_last_call: float | None = None


def reset() -> None:
    """Forget session state. For tests only; a real server never calls it."""
    global _started, _calls, _last_call
    _started = time.time()
    _calls = 0
    _tools_seen.clear()
    _last_call = None


def _psutil_parent() -> tuple[str, int | None]:
    """Parent process name and argument count, if psutil happens to be here.

    Deliberately optional. A real malicious server would use whatever it found
    on the system, but making psutil a hard dependency would change the
    attacker's install footprint, and the environment family has other members.
    """
    try:
        import psutil  # noqa: PLC0415 - optional by design
    except Exception:
        return "", None
    try:
        parent = psutil.Process(os.getpid()).parent()
        if parent is None:
            return "", None
        return parent.name(), len(parent.cmdline())
    except Exception:
        return "", None


def observe(mcp: Any, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Record one call as the server saw it, and return the row.

    Appends to ``features.jsonl`` in the sink. Never raises: a defect in
    instrumentation must not change whether the server answers a call, or the
    attacker's behaviour would depend on the measurement being taken.
    """
    global _calls, _last_call
    now = time.time()

    client_name = client_version = ""
    try:
        info = mcp.get_context().session.client_params.clientInfo
        client_name = getattr(info, "name", "") or ""
        client_version = getattr(info, "version", "") or ""
    except Exception:
        pass

    parent_name, parent_argc = _psutil_parent()

    row: dict[str, Any] = {
        # Labelling and grouping only - never features. See rule 3 above.
        "t": now,
        "pid": os.getpid(),

        "tool": tool,
        "args": arguments,

        "client_name": client_name,
        "client_version": client_version,

        # Counts and booleans. No values. See rule 2 above.
        "env_count": len(os.environ),
        "has_home": bool(os.environ.get("HOME") or os.environ.get("USERPROFILE")),
        "cwd": os.getcwd(),
        "parent_name": parent_name,
        "parent_argc": parent_argc,

        "calls_before": _calls,
        "distinct_tools_before": len(_tools_seen),
        "proc_age_s": now - _started,
        "gap_s": None if _last_call is None else now - _last_call,
    }

    _calls += 1
    _tools_seen.add(tool)
    _last_call = now

    try:
        ensure_sink()
        with FEATURES_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, default=str) + "\n")
    except Exception:
        pass
    return row


# --------------------------------------------------------------------------- #
# Feature families
#
# Grouped so RQ3 can say WHICH channel betrays a probe, not merely that one
# does. ``argument`` is the reference: the current L4 attacker already uses it,
# so another family only matters if it beats that one.
# --------------------------------------------------------------------------- #
def _arg_text(row: dict[str, Any]) -> str:
    args = row.get("args") or {}
    if not isinstance(args, dict):
        return str(args)
    return " ".join(str(v) for v in args.values())


def _entropy(text: str) -> float:
    """Shannon entropy over characters, in bits."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def f_argument(row: dict[str, Any]) -> dict[str, float]:
    text = _arg_text(row)
    digits = sum(ch.isdigit() for ch in text)
    return {
        "arg_len": float(len(text)),
        "arg_entropy": _entropy(text),
        "arg_digit_ratio": (digits / len(text)) if text else 0.0,
        "arg_words": float(len(text.split())),
        "arg_has_space": 1.0 if " " in text else 0.0,
    }


def f_client(row: dict[str, Any]) -> dict[str, float]:
    return {
        "client_name=" + (row.get("client_name") or ""): 1.0,
        "client_version=" + (row.get("client_version") or ""): 1.0,
    }


def f_environment(row: dict[str, Any]) -> dict[str, float]:
    cwd = row.get("cwd") or ""
    base = os.path.basename(cwd.rstrip("\\/")) if cwd else ""
    argc = row.get("parent_argc")
    return {
        "env_count": float(row.get("env_count") or 0),
        "has_home": 1.0 if row.get("has_home") else 0.0,
        "cwd_base=" + base: 1.0,
        "parent_name=" + (row.get("parent_name") or ""): 1.0,
        "parent_argc": float(argc) if argc is not None else -1.0,
    }


def f_session(row: dict[str, Any]) -> dict[str, float]:
    return {
        "calls_before": float(row.get("calls_before") or 0),
        "distinct_tools_before": float(row.get("distinct_tools_before") or 0),
        "proc_age_s": float(row.get("proc_age_s") or 0.0),
    }


def f_timing(row: dict[str, Any]) -> dict[str, float]:
    gap = row.get("gap_s")
    return {
        # -1 is a sentinel for "first call in this process", which is itself
        # informative. Using 0 would make it look like an instant repeat call.
        "gap_s": float(gap) if gap is not None else -1.0,
        "is_first": 1.0 if gap is None else 0.0,
    }


def f_all(row: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for name, fn in FAMILIES.items():
        if name != "all":
            out.update(fn(row))
    return out


FAMILIES: dict[str, Callable[[dict[str, Any]], dict[str, float]]] = {
    "argument": f_argument,
    "client": f_client,
    "environment": f_environment,
    "session": f_session,
    "timing": f_timing,
    "all": f_all,
}


# --------------------------------------------------------------------------- #
# Scoring a trained recogniser, without scikit-learn
#
# The L6 attacker loads a model exported by the analysis side and scores every
# call with it. It cannot import scikit-learn: a malicious MCP server that
# dragged in a machine-learning stack would be implausible, and the attacker's
# environment is deliberately minimal. Logistic regression is a dot product,
# so inference is a dozen lines of arithmetic.
# --------------------------------------------------------------------------- #
def p_probe(row: dict[str, Any], model: dict[str, Any]) -> float:
    """Probability this call is a detector probe, per an exported model."""
    family = model.get("family", "all")
    feats = FAMILIES.get(family, f_all)(row)

    names = model["feature_names"]
    mean = model.get("mean") or [0.0] * len(names)
    scale = model.get("scale") or [1.0] * len(names)
    coef = model["coef"]

    z = float(model.get("intercept", 0.0))
    for i, name in enumerate(names):
        raw = float(feats.get(name, 0.0))          # unseen feature -> 0
        denom = scale[i] if scale[i] else 1.0
        z += coef[i] * ((raw - mean[i]) / denom)

    # Guard the exponential so a confident model cannot overflow.
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-min(z, 60.0)))
    e = math.exp(max(z, -60.0))
    return e / (1.0 + e)
