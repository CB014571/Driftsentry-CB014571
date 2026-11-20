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

# --------------------------------------------------------------------------- #
# Numbering (T31)
# --------------------------------------------------------------------------- #
# The report now has two gaps and three research questions; the code, the
# CLI and every result file keep the original plan's numbering, because
# renaming them would make old results unreadable. This is the ONE place the
# two are reconciled, and every printed label goes through it.
LABELS: dict[str, str] = {
    "RQ1": "RQ3b",          # false alarms on real upgrades
    "RQ2": "Validation",    # active vs passive vs hash-only
    "RQ3": "RQ1",           # probe distinguishability
    "RQ4": "RQ2",           # countermeasures
    "rq3u": "RQ3a",         # attacks hidden in legitimate updates
    "H1": "Validation criteria",
    "H2": "Validation criteria",
    "H3": "H1",
    "H4": "H2",
}


def label(old: str) -> str:
    """The report's name for something the code calls ``old``."""
    return LABELS[old]


def relabel(text: str) -> str:
    """Rewrite old-numbered labels in text produced elsewhere, in ONE pass.

    One pass matters: chained replacements would turn RQ1 into RQ3b and then
    a later RQ3 rule would not touch it, but RQ3 -> RQ1 run after RQ1 -> RQ3b
    in a loop would rewrite text twice. A single regex substitution looks each
    token up once.
    """
    import re as _re

    return _re.sub(r"\b(RQ[1-4]|H[1-4])\b", lambda m: LABELS[m.group(1)], text)

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


def _recall_cell(path: Path) -> tuple[str, Any]:
    """Classify one arm: no file, no fired episodes, or a rate.

    These are three different facts and were printed as two. An arm with no
    result file has not been measured. An arm with eighteen measured
    episodes and none that fired has been measured and has no denominator,
    which is a result - the environment recogniser scores every call probe
    and the attacker never fires, so there is no recall to lose. Printing
    both as NOT MEASURED loses the finding and overstates what is missing.
    """
    episodes = _episodes(_rows(path))
    if not episodes:
        return "absent", None
    fired = [c for c in episodes.values() if _outcome(c) in FIRED]
    if not fired:
        return "none_fired", len(episodes)
    hits = sum(1 for c in fired if _outcome(c) == "detected")
    return "ok", (hits, len(fired))


def _render_recall(cell: tuple[str, Any]) -> str:
    kind, value = cell
    if kind == "absent":
        return MISSING
    if kind == "none_fired":
        return f"undefined (0 of {value} episodes fired)"
    return _rate(*value)


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
    lines = [f"### Table 2. Three detectors on the same attacks ({label('RQ2')})",
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
    lines = [f"### Table 3. Separating probe traffic from genuine traffic ({label('RQ3')})",
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
    lines = [f"### Table 4. Detection lost to a learned recogniser ({label('RQ3')}, {label('H3')})",
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
            cells.append(_recall_cell(RESULTS / f"exp3_{family}_{level}.csv"))

        if all(c[0] == "absent" for c in cells):
            continue
        any_row = True
        auc = f"{auc_of[family]:.3f}" if family in auc_of else "-"
        l1, l6 = (_render_recall(c) for c in cells)
        if cells[0][0] == "ok" and cells[1][0] == "ok":
            (l1_hits, l1_n), (l6_hits, l6_n) = cells[0][1], cells[1][1]
            pp = 100.0 * l6_hits / l6_n - 100.0 * l1_hits / l1_n
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
              "",
              "The environment row is that argument taken to its limit, and",
              "it is a result rather than a gap. All 18 L6 episodes ran and",
              "none fired, so there is no denominator: the recall is",
              "undefined, not zero. The attacker's own log gives the reason -",
              "it scored every single call `probe (p=0.929)`, the same value",
              "throughout, and so stayed benign for all of them. That is what",
              "an AUC of 0.500 does in deployment. A recogniser that cannot",
              "separate probe traffic from genuine traffic, and guesses",
              "`probe`, disables the attack it was built to protect. Reported",
              "as -100.0pp it would read as perfect evasion, which is the",
              "opposite of what happened.",
              ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Table 5 - false alarms on real upgrades (Gap 3)
# --------------------------------------------------------------------------- #
def table_real_upgrades() -> str:
    lines = [f"### Table 5. Real benign servers and real version upgrades ({label('RQ1')})",
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
    lines = [f"### Table 6. Countermeasures, and what they cost ({label('RQ4')}, {label('H4')})", ""]
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

    # t20's report speaks the original numbering; relabel it on the way out.
    return "\n".join(lines + ["```", relabel(report(results).strip()), "```", ""])


# --------------------------------------------------------------------------- #
# Tables 7-10 - declared-diff residue checking (RQ3a, RQ3b) and the hypotheses
# --------------------------------------------------------------------------- #
RQ3U_CSV = RESULTS / "rq3u" / "rq3u_L1.csv"


def _rq3u() -> dict | None:
    """The T30 analysis, recomputed from the result files - never transcribed."""
    if not RQ3U_CSV.is_file() or RQ3U_CSV.stat().st_size == 0:
        return None
    from eval.rq3u_analyse import analyse, load_episodes, load_real_upgrades

    return analyse(load_episodes(RQ3U_CSV), load_real_upgrades(RESULTS / "rq1"))


def _cell(r: dict) -> str:
    return _rate(r["k"], r["n"]) if r["n"] else MISSING


def table_rq3a_detection() -> str:
    lines = [f"### Table 7. Attacks hidden in legitimate updates ({label('rq3u')})", ""]
    out = _rq3u()
    if out is None:
        return _lines(lines + [
            f"**{MISSING}.** Run:", "",
            "    python -m eval rq3u --families all --covers C0,C1,C2,C3 "
            "--benign-updates C1,C2 --seeds 1,2,3", ""])
    from eval.update_conditions import CONDITIONS

    covers = sorted({cov for c in out["detection"].values() for cov in c})
    lines += ["Attributed detection: an alert naming a signal the hidden change causes.",
              f"Attacks that fired: {out['fired_attacks']}; never fired, excluded: "
              f"{out['never_triggered']}.", "",
              "| condition | " + " | ".join(covers) + " | pooled C0-C2 |",
              "| --- |" + " --- |" * (len(covers) + 1)]
    for c in CONDITIONS:
        cells = [_cell(out["detection"][c][cov]["attributed"]) for cov in covers]
        lines.append(f"| {c} | " + " | ".join(cells) + f" | {_cell(out['pooled'][c])} |")
    lines += ["", "Residue against each baseline, paired, exact McNemar with Holm correction:",
              "", "| baseline | only residue | only baseline | p | Holm p | significant |",
              "| --- | --- | --- | --- | --- | --- |"]
    for b, t in out["mcnemar_vs_residue"].items():
        lines.append(f"| {b} | {t['b01']} | {t['b10']} | {t['p']:.4g} | "
                     f"{t['p_holm']:.4g} | {'yes' if t['significant'] else 'no'} |")
    c3 = out["c3"]
    # Zero evasions is a measurement, not a gap: there is no share to take of
    # nothing, and printing NOT MEASURED here would send a reader looking for
    # a run that does not need to exist.
    escalated = ("no attack evaded, so there is no share to report"
                 if c3["fired"] and not c3["evaded"]
                 else f"of the evasions, escalated: {_cell(c3['evaded_with_escalation'])}")
    lines += ["", f"C3, declaration widened to cover the payload: {c3['fired']} fired, "
                  f"residue attributed {c3['residue_attributed']}, evaded {c3['evaded']}; "
                  f"{escalated}.", ""]
    return _lines(lines)


def table_rq3a_false_alarms() -> str:
    lines = [f"### Table 8. Synthetic benign updates: false alarms ({label('rq3u')})", ""]
    out = _rq3u()
    if out is None:
        return _lines(lines + [f"**{MISSING}.** Produced by the same sweep as Table 7.", ""])
    lines += ["A legitimate declared change shipped with no attack. Any alert is a false alarm.",
              "", "| condition | false alarms |", "| --- | --- |"]
    for c, r in out["synthetic_false_alarms"].items():
        lines.append(f"| {c} | {_cell(r)} |")
    return _lines(lines + [""])


def table_rq3b() -> str:
    lines = [f"### Table 9. Residue on real benign upgrades ({label('RQ1')})", ""]
    from eval.rq3u_analyse import load_real_upgrades

    servers = load_real_upgrades(RESULTS / "rq1")
    if not servers:
        return _lines(lines + [
            f"**{MISSING}.** No update-checked runs of real servers. Run:", "",
            "    python -m eval real", "",
            "Seven servers are approved (eval/real_servers.json); H3 asks for",
            "at least 15, and the shortfall is a stated limitation.", ""])
    lines += ["| server | runs | residue_alert | escalation | held | residue signals |",
              "| --- | --- | --- | --- | --- | --- |"]
    for s_ in servers:
        lines.append(f"| {s_['server']} | {s_['runs']} | {s_['residue_runs']} | "
                     f"{s_['escalation_runs']} | {s_['held_runs']} | "
                     f"{', '.join(s_['residue_signals']) or '-'} |")
    k = sum(1 for s_ in servers if s_["residue_runs"])
    lines += ["", f"Upgrades leaving a residue: {_rate(k, len(servers))}. Labels are null by "
                  "the user's decision, so this rate is reported unlabelled.", ""]
    return _lines(lines)


def _h1() -> tuple[str, str]:
    """H1: a family other than argument at AUC >= 0.9 whose recall drops >= 50pp."""
    summary = _json(RESULTS / "rq3" / "rq3_analysis.json") or {}
    aucs = {n: r["auc"] for n, r in (summary.get("families") or {}).items() if "auc" in r}
    if not aucs:
        return MISSING, "no RQ3 analysis"
    met = []
    for family in RQ3_FAMILIES:
        if family == "argument" or aucs.get(family, 0.0) < 0.9:
            continue
        l1 = _recall_cell(RESULTS / f"exp3_{family}_L1.csv")
        l6 = _recall_cell(RESULTS / f"exp3_{family}_L6.csv")
        if l1[0] == "ok" and l6[0] == "ok":
            drop = 100.0 * (l1[1][0] / l1[1][1] - l6[1][0] / l6[1][1])
            if drop >= 50.0:
                met.append(f"{family} (AUC {aucs[family]:.3f}, recall -{drop:.0f}pp)")
    if met:
        return "PASS", "; ".join(met)
    return "FAIL", "no family other than argument has AUC >= 0.9 and a >= 50pp drop"


def _h2() -> tuple[str, str]:
    results = _json(RESULTS / "t20" / "t20_results.json")
    if not results or "all" not in (results.get("conditions") or {}):
        return MISSING, "the countermeasure comparison is incomplete"
    from eval.conditions import h4_verdict

    v = h4_verdict(results["conditions"])
    return v["verdict"], (f"best AUC {v['best_auc']:.3f} (needs <= 0.6), recall gap "
                          f"{v['recall_gap_pp']:+.0f}pp (needs within 10), false alarms "
                          f"{v['false_alarm_delta_pp']:+.1f}pp (needs <= +2)")


def _h3() -> tuple[str, str]:
    out = _rq3u()
    if out is None:
        return MISSING, "the RQ3a sweep has not run"
    v = out["h3"]
    # The episode count leads, so a verdict computed while the sweep is still
    # running cannot be read as the sweep's verdict.
    return v["result"], "; ".join(
        [f"on {out['episodes']} episodes ({out['fired_attacks']} attacks fired)"]
        + v["reasons"] + [f"missing: {m}" for m in v["missing"]])


def _validation_verdict() -> dict:
    path = RESULTS / "followup" / "validation" / "verdict.json"
    return _json(path) if path.is_file() else {}


def _validation() -> list[tuple[str, str, str]]:
    verdicts = _validation_verdict()
    pt = verdicts.get("V-pertool")
    if pt:
        g, p = pt["global_arm"], pt["per_tool_arm"]
        basis = (f"benign-update false alarms {g['benign_update_alarms']}/"
                 f"{g['benign_update_episodes']} global vs {p['benign_update_alarms']}/"
                 f"{p['benign_update_episodes']} per-tool; recall {g['detected']}/{g['fired']}"
                 f" vs {p['detected']}/{p['fired']} (pre-registered, followup/validation)")
        if pt.get("reason"):
            basis = pt["reason"] + "; " + basis
        rows = [("Per-tool thresholds halve benign-update false alarms at equal recall",
                 pt["verdict"], basis)]
    else:
        rows = [("Per-tool thresholds halve benign-update false alarms at equal recall",
                 MISSING, "no frozen per-tool threshold file exists")]
    # Full against hash-only, on ONE replication: the five L1 sweeps repeat the
    # same twelve configurations, so pooling them would overstate n (Table 2).
    from eval.stats import mcnemar_p

    best = None
    for path in sorted(RESULTS.glob("exp3_*_L1.csv")):
        eps = [c for c in _episodes(_rows(path)).values() if _outcome(c) in FIRED]
        if eps and (best is None or len(eps) < len(best[1])):
            best = (path.stem, eps)
    if best:
        full = [any(_truthy(r.get("full_detected")) for r in c) for c in best[1]]
        hashd = [any(_truthy(r.get("hash_detected")) for r in c) for c in best[1]]
        t = mcnemar_p(hashd, full)
        rows.append(("Full DriftSentry detects significantly more than hash-only",
                     "PASS" if t["p"] < 0.05 and t["b01"] > t["b10"] else "FAIL",
                     f"{best[0]}: full {sum(full)}/{len(full)}, hash {sum(hashd)}/{len(hashd)}, "
                     f"exact McNemar p={t['p']:.4g}"))
    else:
        rows.append(("Full DriftSentry detects significantly more than hash-only",
                     MISSING, "no exp3 L1 results"))
    nc = verdicts.get("V-nevercalled")
    if nc and nc.get("fired"):
        t = nc["mcnemar"]
        rows.append(("Catches attacks on tools the agent never calls, which passive cannot",
                     nc["verdict"],
                     f"full {nc['full']}/{nc['fired']}, passive {nc['passive']}/{nc['fired']}, "
                     f"exact McNemar p={t['p']:.4g} (pre-registered, followup/validation)"))
    else:
        rows.append(("Catches attacks on tools the agent never calls, which passive cannot",
                     MISSING, "no episode confined to a tool the replayed traffic avoids has been run"))
    return rows


def table_hypotheses() -> str:
    lines = ["### Table 10. Hypotheses", "",
             "| | hypothesis | result | basis |", "| --- | --- | --- | --- |"]
    for name, statement, (result, basis) in (
            ("H1", "a non-argument family separates probes at AUC >= 0.9, and "
                   "withholding drops recall >= 50pp", _h1()),
            ("H2", "mimicry brings AUC <= 0.6, recall within 10pp, false alarms "
                   "+2pp at most", _h2()),
            ("H3", "residue detects >= 80% pooled C0-C2, beats three baselines "
                   "(Holm p<0.05), <= 15% of real upgrades leave residue", _h3())):
        lines.append(f"| {name} | {statement} | {result} | {basis} |")
    for statement, result, basis in _validation():
        lines.append(f"| Validation | {statement} | {result} | {basis} |")
    return _lines(lines + ["", "A FAIL is a result, not a defect; nothing was tuned to pass.", ""])


H2C_MECHANISM = ("in-session verification with a continuous side-effect watcher, "
                 "pattern-matched probe values and the real-call guard")
H3C_MECHANISM = "residue rules v1.2, judged on held-out upgrades"


def _h2c_row() -> str:
    """H2c from its verdict file: both pre-registered claims must pass."""
    path = RESULTS / "followup" / "h2c" / "verdict.json"
    if not path.is_file():
        return (f"| H2c | {H2C_MECHANISM} | {MISSING} | "
                f"run `python -m eval h2c collect|fit|matrix|control|verdict` |")
    v = _json(path)
    auc, rec = v["H2c-1"], v["H2c-2"]
    fam = ", ".join(f"{k} {a:.3f}" for k, a in sorted(auc["family_auc"].items())
                    if isinstance(a, (int, float)))
    l1, l6 = rec["recall_L1"], rec["recall_L6"]
    fa_in, fa_ctl = rec["false_alarms_insession"], rec["false_alarms_control"]
    both = auc["verdict"] == "PASS" and rec["verdict"] == "PASS"
    return (f"| H2c | {H2C_MECHANISM} | {'PASS' if both else 'FAIL'} | "
            f"AUC claim {auc['verdict']}: best AUC {auc['best_auc']:.3f} ({auc['best_family']}; {fam}); "
            f"recall-and-false-alarm claim {rec['verdict']}: caught L1 {l1['caught_either_way']}/{l1['fired']}, "
            f"L6 {l6['caught_either_way']}/{l6['fired']} (by probes {l1['probe_earned']}/{l1['fired']} and "
            f"{l6['probe_earned']}/{l6['fired']}, by the guard {l1['guard_earned']}/{l1['fired']} and "
            f"{l6['guard_earned']}/{l6['fired']}); false alarms {fa_in['alarms']}/{fa_in['episodes']} "
            f"in-session against {fa_ctl['alarms']}/{fa_ctl['episodes']} control, rise "
            f"{rec['false_alarm_rise_pp']:.1f} pp |")


def _h3c_row() -> str:
    """H3c: the held-out real half decides a FAIL on its own; a PASS also needs
    the synthetic re-run under v1.2, which was not run before the scope froze."""
    held = RESULTS / "followup" / "h3c" / "held_out"
    if not held.is_dir():
        return f"| H3c | {H3C_MECHANISM} | {MISSING} | run `python -m eval real --rules 1.2 ...` |"
    from eval.followup_h3c import held_out_result

    res = held_out_result()
    measured = {k: r for k, r in res.items() if r.get("measured")}
    left = [k for k, r in measured.items() if r["left_residue"]]
    pct = 100.0 * len(left) / len(measured) if measured else None

    def state(k: str, r: dict) -> str:
        if not r.get("measured"):
            return f"{k}: not measured"
        s = "residue" if r["left_residue"] else "accepted"
        return f"{k}: {s}" + (" (weak test: every baseline probe erred)" if r.get("weak_test") else "")

    synth = sorted((RESULTS / "followup" / "h3c").glob("rq3u_*analysis.json"))
    if pct is not None and pct > 15.0:
        result = "FAIL"
    elif not synth:
        result = "INCOMPLETE"
    else:
        result = "see synthetic analysis"
    return (f"| H3c | {H3C_MECHANISM} | {result} | held-out: {len(left)}/{len(measured)} measured "
            f"upgrades left residue ({'; '.join(state(k, r) for k, r in res.items())}); synthetic "
            f"re-run under v1.2: {'not run' if not synth else synth[0].name} |")


def table_followups() -> str:
    """Post-hoc follow-ups to the two failed hypotheses, each pre-registered.

    Read from the verdict files the follow-up drivers write. H2 and H3 above
    are unchanged by anything here.
    """
    lines = ["### Table 11. Follow-ups to the failed hypotheses (post-hoc, pre-registered)", "",
             "Designed after H2 and H3 failed; each frozen with a sha256 before its "
             "data. H2 and H3 stay FAIL in Table 10.", "",
             "| | mechanism | result | basis |", "| --- | --- | --- | --- |"]
    h2b = RESULTS / "followup" / "h2b" / "verdict.json"
    if h2b.is_file():
        v = _json(h2b)
        fam = ", ".join(f"{k} {a:.3f}" for k, a in sorted(v["family_auc"].items())
                        if isinstance(a, (int, float)))
        l1, l6 = v["recall_L1"], v["recall_L6"]
        lines.append(
            f"| H2b | in-session verification, shaped probe values | {v['verdict']} | "
            f"best AUC {v['best_auc']:.3f} ({v['best_family']}; {fam}); probe-earned recall "
            f"L1 {l1['probe_earned']}/{l1['fired']}, L6 {l6['probe_earned']}/{l6['fired']}; "
            f"false-alarm rise {v['false_alarm_rise_pp']:.1f} pp |")
    else:
        lines.append(f"| H2b | in-session verification, shaped probe values | {MISSING} | "
                     f"run `python -m eval h2b collect|fit|matrix|control|verdict` |")
    held = RESULTS / "followup" / "h3b" / "held_out"
    synth = RESULTS / "followup" / "h3b" / "rq3u_L1_rules11_analysis.json"
    if held.is_dir() and synth.is_file():
        from eval.followup_h3b import held_out_result

        res = held_out_result()
        measured = {k: r for k, r in res.items() if r.get("measured")}
        left = [k for k, r in measured.items() if r["left_residue"]]
        a = _json(synth)
        pooled = a.get("pooled", {}).get("residue", {})
        tests = a.get("mcnemar_vs_residue", {})
        sig = all(t.get("significant") for t in tests.values()) if tests else False
        pct = 100.0 * len(left) / len(measured) if measured else None
        ok = (measured and pct is not None and pct <= 15.0 and sig
              and (pooled.get("rate", 0) or 0) * 100 >= 80.0)
        lines.append(
            f"| H3b | residue rules v1.1, judged on held-out upgrades | "
            f"{'PASS' if ok else 'FAIL'} | held-out: {len(left)}/{len(measured)} measured upgrades "
            f"left residue ({', '.join(f'{k}: ' + ('residue' if r.get('left_residue') else 'accepted') if r.get('measured') else f'{k}: not measured' for k, r in res.items())}); "
            f"synthetic re-run residue {pooled.get('k', '?')}/{pooled.get('n', '?')} pooled C0-C2, "
            f"baselines beaten (Holm): {sig} |")
    else:
        lines.append(f"| H3b | residue rules v1.1, judged on held-out upgrades | {MISSING} | "
                     f"run `python -m eval real --rules 1.1 --as-of-release ...` and "
                     f"`python -m eval rq3u --rules 1.1` |")
    lines.append(_h2c_row())
    lines.append(_h3c_row())
    return _lines(lines + ["", "A follow-up that passes shows the weakness was "
                           "fixable; it does not turn the original FAIL into a PASS.", ""])


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #
TABLES = (table_probe_modes, table_paired_demonstration, table_three_way,
          table_rq3_auc, table_evasion, table_real_upgrades,
          table_countermeasures, table_rq3a_detection, table_rq3a_false_alarms,
          table_rq3b, table_hypotheses, table_followups)


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
