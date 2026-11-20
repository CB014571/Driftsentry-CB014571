"""Result charts for the report, parsed from eval_results/tables.md (itself
generated from the result files). No number is typed in by hand."""
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TABLES = Path(r"F:\fyp project\Driftsentry\eval_results\tables.md").read_text(encoding="utf-8")
OUT = Path(r"C:\Users\LEGION\AppData\Local\Temp\claude\2ce5231e1b6bed9d\c47f2b0e-8060-47ac-bc36-891685033815\scratchpad\figs")


def section(title):
    i = TABLES.index(title)
    j = TABLES.find("\n### ", i + 1)
    return TABLES[i:j if j > 0 else None]


def rows(text):
    out = []
    for line in text.splitlines():
        if line.startswith("|") and not line.startswith("| ---"):
            out.append([c.strip() for c in line.strip("|").split("|")])
    return out[1:]


RATE = re.compile(r"([\d.]+)% \[([\d.]+), ([\d.]+)\] \((\d+)/(\d+)\)")


def rate(cell):
    m = RATE.search(cell)
    p, lo, hi, k, n = m.groups()
    return float(p), float(lo) * 100, float(hi) * 100, int(k), int(n)


plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
INK, GRID = "#1f2937", "#e5e7eb"
C_RES, C_BASE, C_BAD = "#047857", "#94a3b8", "#b91c1c"

# ---------------------------------------------------------------- RQ3a
det = {r[0]: rate(r[5]) for r in rows(section("### Table 7.")) if len(r) == 6 and "%" in r[5]
       and r[0] in ("accept_rebaseline", "refuse_all", "definition_diff", "new_host_only", "residue")}
fa = {r[0]: rate(r[1]) for r in rows(section("### Table 8."))}
order = ["residue", "refuse_all", "accept_rebaseline", "new_host_only", "definition_diff"]
label = {"residue": "Residue\n(DriftSentry)", "refuse_all": "Refuse all\nupdates",
         "accept_rebaseline": "Accept and\nre-baseline", "new_host_only": "New-host\ncheck only",
         "definition_diff": "Definition\ndiff only"}

fig, axes = plt.subplots(1, 2, figsize=(9.2, 3.1), dpi=200)
for ax, data, title, good_high in ((axes[0], det, "Hidden attacks detected (pooled C0–C2)", True),
                                   (axes[1], fa, "False alarms on benign updates", False)):
    xs = range(len(order))
    vals = [data[c][0] for c in order]
    err = [[data[c][0] - data[c][1] for c in order], [data[c][2] - data[c][0] for c in order]]
    colors = [C_RES if c == "residue" else C_BASE for c in order]
    ax.bar(xs, vals, color=colors, width=0.62, zorder=2)
    ax.errorbar(xs, vals, yerr=err, fmt="none", ecolor=INK, elinewidth=0.9, capsize=3, zorder=3)
    for x, c in zip(xs, order):
        _, _, _, k, n = data[c]
        ax.text(x, data[c][0] + (data[c][2] - data[c][0]) + 3, f"{k}/{n}", ha="center", fontsize=8, color=INK)
    ax.set_xticks(list(xs), [label[c] for c in order], fontsize=7.6)
    ax.set_ylim(0, 118)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("%")
    ax.set_title(title, fontsize=9.5, color=INK, loc="left")
    ax.grid(axis="y", color=GRID, zorder=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
fig.tight_layout()
fig.savefig(OUT / "chart_rq3a.png", facecolor="white")
plt.close(fig)

# ---------------------------------------------------------------- RQ1
ev = rows(section("### Table 4."))
fig, ax = plt.subplots(figsize=(9.2, 2.9), dpi=200)
names, l1, l6, aucs, notes = [], [], [], [], []
for r in ev:
    names.append(r[0]); aucs.append(r[1])
    l1.append(rate(r[2])[0])
    m = RATE.search(r[3])
    l6.append(rate(r[3])[0] if m else None)
xs = range(len(names))
w = 0.36
ax.bar([x - w / 2 for x in xs], l1, w, color=C_BASE, label="L1: attacks every call", zorder=2)
ax.bar([x + w / 2 for x in xs], [v or 0 for v in l6], w, color=C_BAD,
       label="L6: learned recogniser holds back on probes", zorder=2)
for x, v, a in zip(xs, l6, aucs):
    ax.text(x + w / 2, (v or 0) + 3, "0%" if v == 0 else ("never fired" if v is None else f"{v:.0f}%"),
            ha="center", fontsize=7.5, color=C_BAD)
ax.set_xticks(list(xs), [f"{n}\nAUC {a}" for n, a in zip(names, aucs)], fontsize=8)
ax.set_ylim(0, 118); ax.set_yticks([0, 50, 100]); ax.set_ylabel("recall %")
ax.set_title("Detection lost when the server can tell probes from genuine calls (RQ1)", fontsize=9.5,
             color=INK, loc="left")
ax.legend(fontsize=7.6, frameon=False, loc="upper right", ncol=2, bbox_to_anchor=(1, 1.02))
ax.grid(axis="y", color=GRID, zorder=0)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
fig.tight_layout()
fig.savefig(OUT / "chart_rq1.png", facecolor="white")
print("charts:", det["residue"], fa["residue"], names, l6)
