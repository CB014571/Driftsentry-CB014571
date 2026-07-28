"""Phase 4 - deterministic security rules.

The embedding signal notices that a response *changed*; these rules notice that a
response, or the behaviour that produced it, is *dangerous*. The roadmap weights
them highest because "this tool now contacts a host it never contacted" or "this
tool now reads ~/.ssh/id_rsa" is near-proof of a rug pull, whereas prose drifting
is weak evidence on its own.

Two families of rule:

  side-effect rules   read the sandbox monitor's observations: hosts contacted,
                      files opened while a probe was in flight.
  content rules       read the response text: credential-shaped strings, or
                      instruction-shaped text aimed at the agent rather than the
                      user (the content-injection / tool-poisoning family).

Every rule is DIFFERENTIAL
    A rule fires only when its pattern is present now and was absent at baseline.
    This matters more than it sounds. A password-manager tool legitimately emits
    credential-shaped output, and a documentation tool legitimately explains how
    to "ignore previous instructions"; scoring those absolutely would alarm on
    every check forever, and a detector that cries wolf gets switched off. What is
    suspicious is a tool that never did this before starting to do it now.

Everything here is plain pattern matching: deterministic, inspectable, and fast.
No language model sits in this path - that is the reproducibility property the
project is positioned on, and an LLM may only ever appear as a secondary
explainer in an alert, never as the decision.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Content patterns
# --------------------------------------------------------------------------- #
# Credential-shaped output. Deliberately anchored on well-known token *formats*
# rather than on the word "key", so ordinary prose about API keys does not match.
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}={0,2}")),
    ("assigned-secret", re.compile(
        r"\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9._/+-]{12,}", re.IGNORECASE)),
]

# Instruction-shaped text: content addressed to the *agent* rather than the user.
# This is the signature of the content-injection / tool-poisoning family, where a
# tool response smuggles directives into the model's context.
_INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override-instruction", re.compile(
        r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?|messages?)", re.IGNORECASE)),
    ("fake-system-turn", re.compile(
        r"(?:^|\n)\s*(?:\[|<|#{1,3}\s*)?(?:system|assistant)\s*(?:note|message|prompt)?\s*[:\]>]",
        re.IGNORECASE)),
    ("concealment", re.compile(
        r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|show|reveal|display)\s+"
        r"(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator)", re.IGNORECASE)),
    ("credential-exfil-directive", re.compile(
        r"\b(?:forward|send|transmit|upload|post|exfiltrate|leak|share)\b[^.\n]{0,60}?"
        r"\b(?:credential|api[_-]?key|token|password|secret|cookie|session)", re.IGNORECASE)),
    ("agent-directive", re.compile(
        r"\byou\s+(?:must|should|need\s+to|are\s+required\s+to)\b[^.\n]{0,60}?"
        r"\b(?:before\s+continuing|first|immediately|without)", re.IGNORECASE)),
    ("tool-use-directive", re.compile(
        r"\b(?:call|invoke|use|run)\s+the\s+\w+\s+tool\b", re.IGNORECASE)),
]

# --------------------------------------------------------------------------- #
# Sensitive filesystem locations
# --------------------------------------------------------------------------- #
_SECRET_PATH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssh-private-key", re.compile(r"[/\\]\.ssh[/\\]|id_rsa|id_ed25519|id_ecdsa|id_dsa", re.IGNORECASE)),
    ("pem-or-key-file", re.compile(r"\.(?:pem|pfx|p12|keystore|jks)$", re.IGNORECASE)),
    ("dotenv", re.compile(r"(?:^|[/\\])\.env(?:\.|$)", re.IGNORECASE)),
    ("cloud-credentials", re.compile(r"[/\\]\.(?:aws|gcloud|azure|kube)[/\\]", re.IGNORECASE)),
    ("package-manager-auth", re.compile(r"(?:^|[/\\])\.(?:npmrc|pypirc|netrc|docker[/\\]config\.json)$", re.IGNORECASE)),
    ("git-credentials", re.compile(r"\.git-credentials|[/\\]\.git[/\\]config$", re.IGNORECASE)),
    ("browser-secrets", re.compile(r"Login Data|Cookies|key4\.db|logins\.json", re.IGNORECASE)),
    ("generic-secret-file", re.compile(r"(?:credential|secret|token|password)s?[^/\\]*\.(?:json|ya?ml|txt|ini|conf)$", re.IGNORECASE)),
    ("shell-history", re.compile(r"(?:^|[/\\])\.(?:bash_history|zsh_history)$", re.IGNORECASE)),
]


# --------------------------------------------------------------------------- #
# Flag extraction
# --------------------------------------------------------------------------- #
def content_flags(text: str) -> list[str]:
    """Return the content-rule flags present in a response.

    Flags are namespaced strings (``credential:jwt``, ``instruction:concealment``)
    so a baseline can record what is *normal* for a tool and the scorer can diff
    against it.
    """
    flags: list[str] = []
    if not text:
        return flags
    for name, pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(text):
            flags.append(f"credential:{name}")
    for name, pattern in _INSTRUCTION_PATTERNS:
        if pattern.search(text):
            flags.append(f"instruction:{name}")
    return sorted(set(flags))


def secret_paths(paths: Iterable[str]) -> list[str]:
    """Subset of ``paths`` that look like credential or secret material."""
    hits: list[str] = []
    for path in paths:
        for _name, pattern in _SECRET_PATH_PATTERNS:
            if pattern.search(path):
                hits.append(path)
                break
    return sorted(set(hits))


# --------------------------------------------------------------------------- #
# Rule evaluation
# --------------------------------------------------------------------------- #
@dataclass
class RuleHit:
    """One fired security rule."""

    rule: str
    severity: str          # "high" (near-proof) or "medium" (suspicious)
    detail: str
    evidence: list[str] = field(default_factory=list)


# Which content flags count as high severity when they are NEW.
_HIGH_CONTENT_PREFIXES = ("credential:",)


def evaluate(
    *,
    new_hosts: Iterable[str],
    new_files: Iterable[str],
    new_content_flags: Iterable[str],
) -> list[RuleHit]:
    """Turn *newly observed* behaviour into fired rules.

    Every input is already a difference against the baseline: the caller passes
    only hosts/files/flags that were absent when the tool was approved. That is
    what makes these rules differential rather than absolute.
    """
    hits: list[RuleHit] = []

    hosts = sorted(set(new_hosts))
    if hosts:
        # The roadmap's strongest single signal: contact with a host that was not
        # seen at baseline. Near-proof when it fires, and the primary pathway for
        # the exfiltration and new-egress attack families.
        hits.append(RuleHit(
            rule="new_egress_host",
            severity="high",
            detail=f"contacted {len(hosts)} host(s) never seen at baseline",
            evidence=hosts[:5],
        ))

    files = sorted(set(new_files))
    secrets = secret_paths(files)
    if secrets:
        hits.append(RuleHit(
            rule="secret_file_read",
            severity="high",
            detail=f"opened {len(secrets)} credential-bearing file(s) not touched at baseline",
            evidence=secrets[:5],
        ))
    ordinary_new = [f for f in files if f not in set(secrets)]
    if ordinary_new:
        hits.append(RuleHit(
            rule="new_file_access",
            severity="medium",
            detail=f"opened {len(ordinary_new)} file(s) not touched at baseline",
            evidence=ordinary_new[:5],
        ))

    flags = sorted(set(new_content_flags))
    high = [f for f in flags if f.startswith(_HIGH_CONTENT_PREFIXES)]
    medium = [f for f in flags if not f.startswith(_HIGH_CONTENT_PREFIXES)]
    if high:
        hits.append(RuleHit(
            rule="credential_shaped_output",
            severity="high",
            detail="response now contains credential-shaped material it never returned at baseline",
            evidence=high,
        ))
    if medium:
        hits.append(RuleHit(
            rule="instruction_shaped_output",
            severity="medium",
            detail="response now contains instruction-shaped text aimed at the agent",
            evidence=medium,
        ))
    return hits


def describe_rule(rule: str) -> str:
    """One-line explanation of what a rule means, for alerts and reports."""
    return {
        "new_egress_host": "The tool contacted a network host it never contacted when it was approved.",
        "secret_file_read": "The tool opened a file that holds credentials or private keys.",
        "new_file_access": "The tool opened files it did not touch when it was approved.",
        "credential_shaped_output": "The tool's response now contains token- or key-shaped strings.",
        "instruction_shaped_output": "The tool's response now contains text directed at the AI agent "
                                     "rather than at the user, which is how tool-poisoning payloads behave.",
    }.get(rule, rule)
