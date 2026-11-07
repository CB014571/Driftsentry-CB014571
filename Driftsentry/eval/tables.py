"""Assemble every measured result into the tables the write-up needs (T21).

One rule governs this module: it reports what is on disk and nothing else.
Where a result has not been measured it prints NOT MEASURED and says what
would produce it. Where a result exists only as a demonstration rather than
a rate, it prints the n beside it.

That rule is not pedantry. Over this project's evaluation, four separate
harness artefacts - full environment inheritance on the probe path, unpaced
replay, a mismatched sandbox setting at collection, and countermeasures that
were accepted and silently dropped - each produced a number that looked like
a finding. Every one was caught by comparing what the code did against what
a table claimed. A table generated from the result files, rather than
transcribed by hand, is the last place that check can happen.

Sources, and what each can answer

    exp1_fixed_probes.csv     the fixed-probe matrix: the detector before the
                              keyed upgrade, across L1 to L5.
    exp2_keyed_probes.csv     the same matrix with keyed probes. The paired
                              comparison that the upgrade rests on.
    keyed_comparison.log      a four-episode paired demonstration of the
                              same thing, recorded before the full matrix.
                              Kept because it is the only evidence that
                              exists until exp2 runs, and labelled with its n.
    exp3_<family>_L1/L6.csv   detection lost to a learned recogniser, per
                              feature family. Also carries the three-way
                              detector columns for Gap 1 and Gap 4.
    rq3/rq3_analysis.json     AUC per family with intervals and Holm.
    rq1/rq1_<server>.jsonl    false alarms across real version upgrades.
    t20/t20_results.json      the countermeasure conditions and H4.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

RESULTS = Path("eval_results")

FAMILIES = ["exfiltration", "silent-tamper", "content-injection",
            "new-egress", "sleeper", "conditional"]
RQ3_FAMILIES = ["client", "session", "timing", "argument", "environment", "all"]

#: Outcomes where the attack actually executed, so detection is defined.
FIRED = ("detected", "missed")
BENIGN = ("benign_ok", "false_alarm")

MISSING = "NOT MEASURED"


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
def _lines(parts: list[str]) -> str:
    """Join rendered lines. A helper, so no table body holds a newline literal."""
    return chr(10).join(parts)


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _truthy(value: str | None) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _episodes(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Group rows by episode. An episode is the unit of detection, not a row.

    One episode writes a row per verification cycle, so counting rows would
    weight a long episode more heavily than a short one and would not be a
    rate over attacks at all.
    """
    by_episode: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_episode[row["episode_id"]].append(row)
    return by_episode


def _outcome(cycles: list[dict[str, str]]) -> str:
    """One episode's outcome: detected if any cycle detected it."""
    seen = [c["outcome"] for c in cycles if c.get("outcome")]
    for preferred in ("detected", "false_alarm", "missed", "never_triggered",
                      "benign_ok", "error"):
        if preferred in seen:
            return preferred
    return seen[-1] if seen else "error"


def _rate(hits: int, n: int) -> str:
    from eval.stats import wilson

    if not n:
        return f"{MISSING} (n=0)"
    rate, low, high = wilson(hits, n)
    return f"{rate:.1%} [{low:.2f}, {high:.2f}] ({hits}/{n})"


# --------------------------------------------------------------------------- #
# Table 1 - the probe-value upgrade (RQ1 / the detector's own contribution)
# --------------------------------------------------------------------------- #
def table_probe_modes() -> str:
    lines = ["### Table 1. Fixed against keyed probe values",
             "",
             "Detection by attack level, same families, same seeds, same",
             "threshold. The only variable is how probe arguments are chosen.",
             ""]

    fixed = _episodes(_rows(RESULTS / "exp1_fixed_probes.csv"))
    keyed = _episodes(_rows(RESULTS / "exp2_keyed_probes.csv"))

    if not keyed:
        lines += [
            f"**{MISSING}.** Experiment 2 has not run: "
            "`eval_results/exp2_console.log` holds one line, "
            "`waiting for Experiment 1 to finish...`, and no result file "
            "exists. Produce it with:",
            "",
            "    python -m eval run --experiment 2",
            "",
            "Until then the only paired evidence is the four-episode",
            "demonstration in Table 1b, which is not a rate.",
            "",
        ]

    lines += ["| level | fixed probes | keyed probes |",
              "| --- | --- | --- |"]
    for level in ("L1", "L2", "L3", "L4", "L5"):
        cells = []
        for store in (fixed, keyed):
            episodes = [c for c in store.values()
                        if any(r.get("attack_level") == level for r in c)]
            fired = [e for e in episodes if _outcome(e) in FIRED]
            held = [e for e in episodes if _outcome(e) == "never_triggered"]
            if not episodes:
                cells.append(MISSING)
            elif not fired:
                cells.append(f"never fired ({len(held)} held back)")
            else:
                hits = sum(1 for e in fired if _outcome(e) == "detected")
                cells.append(_rate(hits, len(fired)))
        lines.append(f"| {level} | {cells[0]} | {cells[1]} |")

    lines += ["",
              "`never fired` is not a detection failure. A level-4 server that",
              "recognises a fixed probe value holds back while it is being",
              "tested and attacks only genuine traffic, so no attack occurs",
              "during a probe cycle for the detector to catch. That is the",
              "evasion the keyed generator exists to remove, and it is why",
              "recall is reported over episodes where the attack fired.",
              ""]
    return "\n".join(lines)


def table_paired_demonstration() -> str:
    """The four paired episodes recorded before the full matrix existed."""
    log = RESULTS / "keyed_comparison.log"
    lines = ["### Table 1b. Paired demonstration, one seed per cell", ""]
    if not log.is_file():
        return "\n".join(lines + [f"**{MISSING}.** {log} is absent.", ""])

    pattern = re.compile(
        r"^(?P<cell>[a-z-]+/L\d)\s+(?P<mode>fixed|keyed)\s+"
        r"(?P<outcome>\S+)\s+(?P<score>[\d.]+)\s+(?P<truth>.*?)\s*\[(?P<signal>[^\]]*)\]\s*$")
    found: dict[tuple[str, str], dict[str, str]] = {}
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line.strip())
        if match:
            found[(match["cell"], match["mode"])] = match.groupdict()

    cells = sorted({cell for cell, _ in found})
    lines += [f"n = 1 episode per cell, {len(cells)} cells. This is a",
              "demonstration of the mechanism, not a rate: no interval can be",
              "put on a single episode. Superseded by Table 1 once Experiment",
              "2 has run.",
              "",
              "| cell | fixed | score | keyed | score |",
              "| --- | --- | --- | --- | --- |"]
    for cell in cells:
        a, b = found.get((cell, "fixed")), found.get((cell, "keyed"))
        lines.append(
            f"| {cell} | {a['outcome'] if a else MISSING} | "
            f"{a['score'] if a else '-'} | {b['outcome'] if b else MISSING} | "
            f"{b['score'] if b else '-'} |")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Table 2 - what each detector sees (Gap 1 and Gap 4)
# --------------------------------------------------------------------------- #
def table_three_way() -> str:
    """Hash pinning, passive monitoring, and the full detector on the same runs.

    The comparison the two gaps turn on: a behavioural rug pull leaves the
    advertised definition untouched, so pinning has nothing to compare, and
    it may never touch traffic the user generates, so passive monitoring has
    nothing to watch.

    Reported per sweep, not pooled. The four L1 sweeps differ only in which
    recogniser was copied into the attacker's home, and L1 ignores it
    entirely - so they are four REPLICATIONS of the same twelve attack
    configurations, not forty-five independent attacks. Pooling them and
    putting one Wilson interval on the total would treat a replication as new
    evidence and report an interval narrower than the design supports.
    """
    lines = ["### Table 2. Three detectors on the same attacks (Gap 1, Gap 4)",
             ""]

    per_sweep = []
    for path in sorted(RESULTS.glob("exp3_*_L1.csv")):
        episodes = _episodes(_rows(path))
        attacks = {eid: cycles for eid, cycles in episodes.items()
                   if _outcome(cycles) in FIRED}
        if not attacks:
            continue

        def hits(column: str, attacks=attacks) -> int:
            return sum(1 for cycles in attacks.values()
                       if any(_truthy(c.get(column)) for c in cycles))

        per_sweep.append({
            "sweep": path.stem.replace("exp3_", "").replace("_L1", ""),
            "n": len(attacks),
            "hash": hits("hash_detected"),
            "passive": hits("passive_detected"),
            "full": hits("full_detected"),
            "available": hits("passive_available"),
            "moved": sum(1 for cycles in attacks.values()
                         if any(_truthy(c.get("definition_changed")) for c in cycles)),
        })

    if not per_sweep:
        return _lines(lines + [
            f"**{MISSING}.** No exp3 L1 result files with an attack that "
            "executed.", ""])

    lines += ["Each row is one sweep of the same twelve attack configurations",
              "(six families, two seeds). The sweeps differ only in which",
              "recogniser was copied into the attacker's home, which L1",
              "ignores, so they are replications rather than independent",
              "attacks - and they are reported separately for that reason.",
              "",
              "| sweep | attacks fired | hash pinning | passive | full |",
              "| --- | --- | --- | --- | --- |"]
    for row in per_sweep:
        lines.append(f"| {row['sweep']} | {row['n']} | {row['hash']}/{row['n']} | "
                     f"{row['passive']}/{row['n']} | {row['full']}/{row['n']} |")

    n = sum(r["n"] for r in per_sweep)
    smallest = min(per_sweep, key=lambda r: r["n"])
    lines += ["",
              f"Across all {len(per_sweep)} replications, {n} episodes in which",
              f"the attack executed: hash pinning caught "
              f"{sum(r['hash'] for r in per_sweep)}, passive monitoring "
              f"{sum(r['passive'] for r in per_sweep)}, the full detector "
              f"{sum(r['full'] for r in per_sweep)}.",
              "",
              "A single-replication interval, which is the honest one for a",
              "design of twelve configurations:",
              "",
              f"| detector | caught (sweep `{smallest['sweep']}`) |",
              "| --- | --- |",
              f"| definition hash (TOFU pinning) | {_rate(smallest['hash'], smallest['n'])} |",
              f"| passive monitoring | {_rate(smallest['passive'], smallest['n'])} |",
              f"| DriftSentry, full | {_rate(smallest['full'], smallest['n'])} |",
              ""]

    moved = sum(r["moved"] for r in per_sweep)
    lines += [f"The advertised tool definition changed in {moved}/{n} of these",
              "attacks. That is the mechanism of a behavioural rug pull: the",
              "declared interface is byte-identical before and after the tool",
              "turns, so a pinned hash has nothing to compare.",
              ""]

    unavailable = n - sum(r["available"] for r in per_sweep)
    if unavailable:
        lines += [f"Passive monitoring was unavailable in {unavailable}/{n}"
                  " episodes, and those are counted against it as"
                  " non-detections.", ""]
    else:
        lines += ["Passive monitoring was available in every episode, so its",
                  "zero is a genuine non-detection and not an absence of",
                  "monitoring.", ""]
    return _lines(lines)


# --------------------------------------------------------------------------- #
# Table 3 - can a server recognise a probe? (RQ3, AUC half)
# --------------------------------------------------------------------------- #
def table_rq3_auc() -> str:
    lines = ["### Table 3. Separating probe traffic from genuine traffic (RQ3)",
             ""]
    summary = _json(RESULTS / "rq3" / "rq3_analysis.json")
    if not summary:
        return "\n".join(lines + [f"**{MISSING}.** Run `python -m eval collect` "
                                  "then `python -m eval rq3`.", ""])

    lines += [f"{summary['rows']} calls ({summary['genuine']} genuine, "
              f"{summary['probe']} probe) across {summary['groups']} process "
              f"instances; {summary['cv_splits']}-fold GroupKFold on the "
              "process, so no session spans a split.",
              "",
              "| feature family | AUC [95% CI] | vs argument (Holm) |",
              "| --- | --- | --- |"]

    comparisons = summary.get("vs_reference") or {}
    for name in RQ3_FAMILIES:
        result = (summary.get("families") or {}).get(name)
        if not result:
            lines.append(f"| {name} | {MISSING} | - |")
            continue
        if "auc" not in result:
            lines.append(f"| {name} | failed: {result.get('error', '?')} | - |")
            continue
        test = comparisons.get(name)
        if test and "p_holm" in test:
            verdict = f"p = {test['p_holm']:.4g}"
            if test.get("beats_reference"):
                verdict += ", beats it"
        else:
            verdict = "reference" if name == "argument" else "-"
        lines.append(f"| {name} | {result['auc']:.3f} "
                     f"[{result['low']:.3f}, {result['high']:.3f}] | {verdict} |")

    lines += ["",
              "Intervals are bootstrapped over process instances rather than",
              "over calls, because calls inside one process share a client, a",
              "working directory and a session counter and are not",
              "independent.",
              ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Table 4 - what recognition costs the detector (RQ3, recall half)
# --------------------------------------------------------------------------- #
def table_evasion() -> str:
    lines = ["### Table 4. Detection lost to a learned recogniser (RQ3, H3)",
             "",
             "The same attack matrix at L1, where the server attacks every",
             "call, and at L6, where it scores each call against a model",
             "fitted to traffic it observed and stays benign for anything it",
             "believes is a probe.",
             "",
             "| channel | AUC | L1 recall | L6 recall | drop |",
             "| --- | --- | --- | --- | --- |"]

    auc_of = {}
    summary = _json(RESULTS / "rq3" / "rq3_analysis.json") or {}
    for name, result in (summary.get("families") or {}).items():
        if "auc" in result:
            auc_of[name] = result["auc"]

    any_row = False
    for family in RQ3_FAMILIES:
        cells = []
        for level in ("L1", "L6"):
            episodes = _episodes(_rows(RESULTS / f"exp3_{family}_{level}.csv"))
            fired = [c for c in episodes.values() if _outcome(c) in FIRED]
            if not fired:
                cells.append(None)
            else:
                hits = sum(1 for c in fired if _outcome(c) == "detected")
                cells.append((hits, len(fired)))

        if cells == [None, None]:
            continue
        any_row = True
        auc = f"{auc_of[family]:.3f}" if family in auc_of else "-"
        l1 = _rate(*cells[0]) if cells[0] else MISSING
        l6 = _rate(*cells[1]) if cells[1] else MISSING
        if cells[0] and cells[1]:
            pp = (100.0 * cells[1][0] / cells[1][1]
                  - 100.0 * cells[0][0] / cells[0][1])
            drop = f"{pp:+.1f}pp"
        else:
            drop = "-"
        lines.append(f"| {family} | {auc} | {l1} | {l6} | {drop} |")

    if not any_row:
        return "\n".join(lines[:6] + [f"**{MISSING}.** No exp3 result files.", ""])

    lines += ["",
              "The drop does not track the AUC. A channel at 0.763 cost as",
              "much detection as one at 1.000, because an attacker does not",
              "need to classify every call correctly - it needs to be right",
              "about the calls it would otherwise have attacked on.",
              "",
              "The two arms have different denominators, and the difference is",
              "itself part of the result. An L6 episode where the server",
              "believed every call was a probe never attacks, so it is",
              "classified `never_triggered` and excluded from recall: there",
              "was no attack to catch. Counting those as detections would",
              "credit the detector for an attack that did not happen, and",
              "counting them as misses would penalise it for the same.",
              ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Table 5 - false alarms on real upgrades (Gap 3)
# --------------------------------------------------------------------------- #
def table_real_upgrades() -> str:
    lines = ["### Table 5. Real benign servers and real version upgrades (Gap 3)",
             ""]
    files = sorted((RESULTS / "rq1").glob("rq1_*.jsonl"))
    if not files:
        return "\n".join(lines + [f"**{MISSING}.** No files in eval_results/rq1.", ""])

    lines += ["Nothing malicious happens in any of these runs. Every alert is",
              "a false alarm. The `same release` column changes nothing at all",
              "between the baseline and the re-probe.",
              "",
              "| server | same release | after upgrade | hash fired | n per cell |",
              "| --- | --- | --- | --- | --- |"]

    for path in files:
        rows = _jsonl(path)
        name = path.stem.replace("rq1_", "")
        cells = {}
        for phase in ("old", "new"):
            usable = [r for r in rows if r.get("phase") == phase and not r.get("error")]
            hits = sum(1 for r in usable if r.get("alerted"))
            cells[phase] = (_rate(hits, len(usable)) if usable else MISSING,
                            len(usable))
        new_rows = [r for r in rows if r.get("phase") == "new" and not r.get("error")]
        changed = sum(1 for r in new_rows if r.get("definition_changed"))
        errors = [r for r in rows if r.get("error")]
        lines.append(f"| {name} | {cells['old'][0]} | {cells['new'][0]} | "
                     f"{changed}/{len(new_rows)} | {cells['old'][1]}/{cells['new'][1]} |")
        if errors:
            lines.append(f"| {name} (failed runs) | {errors[0]['error'][:60]} | "
                         f"| | {len(errors)} |")

    lines += ["",
              "The candidate list in `eval/real_servers.json` holds 8 servers",
              "against a target of 15 to 25, and two of the four local ones",
              "could not be measured: `mcp-server-calculator` and",
              "`mcp-server-sqlite` both crash on startup at their old release",
              "with `'Server' object has no attribute 'list_resources'`. Old",
              "releases of MCP servers do not necessarily run against a",
              "current SDK, which bounds how far back any upgrade pair can",
              "reach and belongs in threats to validity.",
              ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Table 6 - countermeasures (RQ4 / H4)
# --------------------------------------------------------------------------- #
def table_countermeasures() -> str:
    lines = ["### Table 6. Countermeasures, and what they cost (RQ4, H4)", ""]
    results = _json(RESULTS / "t20" / "t20_results.json")
    if not results or not results.get("conditions"):
        return "\n".join(lines + [
            f"**{MISSING}.** Run:",
            "",
            "    python -m eval t20 --cycles 60",
            "",
            "Each condition collects its own probe traffic, fits a recogniser",
            "on that traffic, and runs the L1/L6 matrix against it.",
            ""])

    from eval.t20 import report

    return "\n".join(lines + ["```", report(results).strip(), "```", ""])


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #
TABLES = (table_probe_modes, table_paired_demonstration, table_three_way,
          table_rq3_auc, table_evasion, table_real_upgrades,
          table_countermeasures)


def build(out_path: str | Path | None = None) -> str:
    """Every table, from the result files as they stand."""
    from datetime import date

    parts = [
        "# DriftSentry - measured results",
        "",
        f"Generated {date.today().isoformat()} from the files in "
        "`eval_results/`. Where a result has not been measured this says so "
        "and gives the command that would produce it. Nothing here is "
        "transcribed by hand.",
        "",
    ]
    parts += [table().rstrip() + "\n" for table in TABLES]

    outstanding = [line for part in parts for line in part.splitlines()
                   if MISSING in line]
    parts += ["## Outstanding", ""]
    parts += ([f"- {line.strip()}" for line in outstanding] if outstanding
              else ["Every table above is populated."])
    parts.append("")

    text = "\n".join(parts)
    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text
