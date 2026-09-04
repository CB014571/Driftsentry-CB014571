"""Probe-family baselines: learning a tool's behaviour, not one answer.

The exact-argument baseline asks "does this input still produce that output?".
That question is only askable while the input stays fixed - and a fixed input is
one an attacker can learn to recognise, which is how the L4 evasion works.

Dynamic probes change the question to "does this tool still behave the way it did
when approved?", and the unit of comparison becomes the *template family* rather
than one concrete value. A family is defined by which grammar fills which schema
field ("path=filename"), which is a property of the schema and therefore stable
for the life of the tool, even though every value drawn from it is new.

Why this is affordable
    Naively, comparing an unseen input against a distribution over different
    inputs gives a much wider benign band and a much less sensitive detector.
    Argument redaction removes most of that cost: for a tool that echoes its
    input, two responses to different values become textually identical once the
    input is taken out, and the family band collapses back towards zero.

    How well that works is not assumed. `comparability` measures it per family,
    at baseline, and the scorer trusts the embedding signal in proportion.

What survives when comparability is poor
    Some tools genuinely return unrelated content for unrelated inputs, and no
    amount of redaction changes that. For those the embedding signal is weak by
    construction and the family baseline leans on what stays invariant regardless
    of input: response structure, error behaviour, which hosts were contacted,
    which files were opened, and whether dangerous content appeared. Those are
    the signals that catch exfiltration and injection anyway.
"""
from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from typing import Any

from driftsentry.embeddings import cosine_distance
from driftsentry.fingerprint import (
    BAND_SIGMA,
    MIN_BAND,
    ProbeBaseline,
    ProbeSample,
    centroid_of,
    leave_one_out_distances,
)

#: Below this, the embedding signal for a family is treated as unusable and the
#: scorer falls back on the invariant signals. Not a tuned constant - it marks
#: the point where the average pair of benign responses is further apart than a
#: typical attack moves one, so the signal carries no information.
MIN_USEFUL_COMPARABILITY = 0.35


@dataclass
class TemplateFamilyBaseline:
    """How one tool behaves across many values drawn from one template family."""

    family_id: str
    tool: str
    field_grammars: dict[str, str]
    n_instances: int
    n_samples: int

    # Behaviour across inputs, measured on REDACTED text.
    centroid: list[float]
    band: float
    dist_mean: float
    dist_std: float
    dist_max: float
    comparability: float

    # Invariants: what stays true whatever the input.
    text_hashes: list[str] = field(default_factory=list)
    shape_hashes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    content_flags: list[str] = field(default_factory=list)
    error_rate: float = 0.0

    chars_mean: float = 0.0
    chars_std: float = 0.0
    echo_ratio: float = 0.0
    excerpt: str = ""

    # Per-instance detail, kept so a marker can audit what was actually sent.
    instances: list[ProbeBaseline] = field(default_factory=list)

    generator_version: str = ""
    key_id: str = ""
    cycle: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["instances"] = [i.to_dict() for i in self.instances]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TemplateFamilyBaseline":
        known = {f for f in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in known}
        payload["instances"] = [
            ProbeBaseline.from_dict(i) for i in data.get("instances", [])
        ]
        return cls(**payload)

    def is_deterministic(self) -> bool:
        """True if every value in this family produced the same redacted answer.

        The strongest possible case for a family baseline: the tool's answer does
        not depend on its input at all once the echo is removed, so a fresh probe
        is directly comparable to the baseline and any difference is real. With
        redaction this is common - a lookup tool that returns "not found" for
        anything unrecognised behaves exactly this way.
        """
        return (
            self.n_instances >= 3
            and self.dist_max == 0.0
            and len(self.text_hashes) == 1
        )

    def usable_embedding(self) -> bool:
        return self.comparability >= MIN_USEFUL_COMPARABILITY

    def describe(self) -> str:
        kind = "deterministic" if self.is_deterministic() else f"comparability {self.comparability:.2f}"
        return (f"{self.tool}[{self.family_id}] {self.n_instances} instances, "
                f"band {self.band:.4f}, {kind}")


def summarize_family(
    family_id: str,
    tool: str,
    field_grammars: dict[str, str],
    instances: list[ProbeBaseline],
    samples_by_instance: list[list[ProbeSample]],
    *,
    echo_ratio: float = 0.0,
    generator_version: str = "",
    key_id: str = "",
    cycle: int = 0,
) -> TemplateFamilyBaseline:
    """Aggregate several baselined instances into one family baseline.

    The band is built from leave-one-out distances between *instance centroids*,
    not between samples of one instance. That is the quantity that matters here:
    how far a value the model has never seen tends to fall from the family's
    centre. Building it from within-instance noise would produce a band that is
    far too tight for cross-input comparison and would alarm on the first honest
    probe.
    """
    instance_centroids = [i.centroid for i in instances]
    centroid = centroid_of(instance_centroids)

    if len(instance_centroids) >= 2:
        distances = leave_one_out_distances(instance_centroids)
    else:
        distances = [0.0]

    dist_mean = float(statistics.fmean(distances))
    dist_std = float(statistics.pstdev(distances)) if len(distances) > 1 else 0.0
    dist_max = float(max(distances))
    band = max(dist_max, dist_mean + BAND_SIGMA * dist_std, MIN_BAND)

    # Comparability: how alike the family's answers are across different inputs.
    # 1.0 means the input does not affect the answer at all (after redaction);
    # 0.0 means two benign answers are as far apart as anything could be, so the
    # embedding signal says nothing for this tool.
    comparability = max(0.0, min(1.0, 1.0 - dist_mean))

    all_samples = [s for group in samples_by_instance for s in group]
    chars = [s.normalized.n_chars for s in all_samples]

    return TemplateFamilyBaseline(
        family_id=family_id,
        tool=tool,
        field_grammars=dict(field_grammars),
        n_instances=len(instances),
        n_samples=len(all_samples),
        centroid=centroid,
        band=band,
        dist_mean=dist_mean,
        dist_std=dist_std,
        dist_max=dist_max,
        comparability=comparability,
        text_hashes=sorted({s.normalized.text_hash for s in all_samples}),
        shape_hashes=sorted({s.normalized.shape_hash for s in all_samples}),
        hosts=sorted({h for s in all_samples for h in s.hosts}),
        files=sorted({f for s in all_samples for f in s.files}),
        content_flags=sorted({f for s in all_samples for f in s.content_flags}),
        error_rate=(sum(1 for s in all_samples if s.normalized.is_error) / len(all_samples)
                    if all_samples else 0.0),
        chars_mean=float(statistics.fmean(chars)) if chars else 0.0,
        chars_std=float(statistics.pstdev(chars)) if len(chars) > 1 else 0.0,
        echo_ratio=echo_ratio,
        excerpt=(all_samples[0].normalized.text[:300] if all_samples else ""),
        instances=instances,
        generator_version=generator_version,
        key_id=key_id,
        cycle=cycle,
    )


def compare_to_family(
    family: TemplateFamilyBaseline,
    samples: list[ProbeSample],
) -> dict[str, Any]:
    """Measure a freshly generated probe against its family baseline.

    A measurement, not a verdict - the same separation the exact-probe path
    keeps. The scorer decides what any of it means.
    """
    if not samples:
        return {}

    # Worst sample decides, so an intermittently firing attack is not averaged
    # away by the calls on which it stayed quiet.
    distance = max(cosine_distance(s.embedding, family.centroid) for s in samples)
    worst = max(samples, key=lambda s: cosine_distance(s.embedding, family.centroid))

    known_texts = set(family.text_hashes)
    known_shapes = set(family.shape_hashes)
    seen_hosts = {h for s in samples for h in s.hosts}
    seen_files = {f for s in samples for f in s.files}
    seen_flags = {f for s in samples for f in s.content_flags}

    return {
        "distance": distance,
        "band": family.band,
        "ratio": distance / family.band if family.band else float("inf"),
        "within_band": distance <= family.band,
        "shape_known": all(s.normalized.shape_hash in known_shapes for s in samples),
        "determinism_break": (
            family.is_deterministic()
            and any(s.normalized.text_hash not in known_texts for s in samples)
        ),
        "comparability": family.comparability,
        "new_hosts": sorted(seen_hosts - set(family.hosts)),
        "new_files": sorted(seen_files - set(family.files)),
        "new_content_flags": sorted(seen_flags - set(family.content_flags)),
        "observed_shape_hash": worst.normalized.shape_hash,
        "observed_excerpt": worst.normalized.text[:300],
        "baseline_excerpt": family.excerpt,
        "became_error": (any(s.normalized.is_error for s in samples)
                         and family.error_rate == 0.0),
    }
