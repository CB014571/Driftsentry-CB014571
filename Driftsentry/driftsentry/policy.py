"""Phase 5 - per-server trust state and the opt-in enforcement switch.

Detection is the graded contribution of this project; blocking is a bonus. That
distinction is why enforcement lives behind a per-server opt-in and is off by
default: if DriftSentry silently blocked calls during an evaluation run, every
detection number would be confounded by the fact that the attack never got to
happen. So the policy file separates two things that are easy to conflate:

    status    what DriftSentry believes about the server
              trusted    -> baselined and behaving
              watching   -> drift seen, below the alert line
              quarantined-> alerted on, or the user quarantined it by hand
    enforce   whether the proxy is allowed to ACT on that belief by refusing
              tool calls in the live data path

A quarantined server with ``enforce=false`` is still fully usable by the client;
DriftSentry has recorded its opinion and will keep saying so, but it does not
interfere. Only when the user opts in does the proxy start refusing calls.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from driftsentry.paths import data_dir

log = logging.getLogger("driftsentry.policy")

Status = Literal["trusted", "watching", "quarantined"]


@dataclass
class ServerPolicy:
    """What DriftSentry believes about one server, and what it may do about it."""

    server: str
    status: Status = "trusted"
    enforce: bool = False
    reason: str = ""
    updated_at: str = ""
    # Tools individually implicated by an alert. Enforcement blocks these first;
    # a whole-server quarantine blocks everything.
    flagged_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerPolicy":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def blocks(self, tool: str | None = None) -> bool:
        """True if a call should be refused under the current policy."""
        if not self.enforce or self.status != "quarantined":
            return False
        if not self.flagged_tools:
            return True                       # whole server quarantined
        return tool is None or tool in self.flagged_tools


class PolicyStore:
    """A small JSON file mapping server name -> policy."""

    def __init__(self, root: Path | None = None) -> None:
        self.path = (root or data_dir()) / "policy.json"

    def _read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - a corrupt policy must not break the proxy
            log.warning("could not read %s (%s); treating every server as unrestricted", self.path, exc)
            return {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get(self, server: str) -> ServerPolicy:
        entry = self._read().get(server)
        return ServerPolicy.from_dict(entry) if entry else ServerPolicy(server=server)

    def all(self) -> list[ServerPolicy]:
        return [ServerPolicy.from_dict(v) for v in self._read().values()]

    def set(self, policy: ServerPolicy) -> ServerPolicy:
        policy.updated_at = datetime.now(timezone.utc).isoformat()
        data = self._read()
        data[policy.server] = policy.to_dict()
        self._write(data)
        log.info("policy: %s -> %s (enforce=%s)", policy.server, policy.status, policy.enforce)
        return policy

    def update(
        self,
        server: str,
        *,
        status: Status | None = None,
        enforce: bool | None = None,
        reason: str | None = None,
        flagged_tools: list[str] | None = None,
    ) -> ServerPolicy:
        policy = self.get(server)
        if status is not None:
            policy.status = status
        if enforce is not None:
            policy.enforce = enforce
        if reason is not None:
            policy.reason = reason
        if flagged_tools is not None:
            policy.flagged_tools = sorted(set(flagged_tools))
        return self.set(policy)
