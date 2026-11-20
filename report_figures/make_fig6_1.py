import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

fams = ["Client", "Session", "Timing", "Argument", "Environment", "All combined"]
data = {  # measured AUC: RQ1 (eval_results/tables.md Table 3), h2b/fit.json, h2c/fit.json
    "Separate session (H1)": [1.000, 0.983, 0.951, 0.763, 0.500, 1.000],
    "Iteration 2: in session": [0.499, 0.532, 0.802, 0.737, 0.499, 0.887],
    "Iteration 3: v1.1":      [0.499, 0.541, 0.746, 0.658, 0.499, 0.782],
}
colours = ["#2a78d6", "#eb6834", "#1baf7a"]
markers = ["o", "s", "D"]          # shape as secondary encoding (print, colour vision)
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 10})
fig, ax = plt.subplots(figsize=(6.27, 3.1), dpi=220)
offs = [-0.18, 0.0, 0.18]
for k in range(len(fams)):        # connector: the change across iterations
    ys = [vals[k] for vals in data.values()]
    ax.plot([k + o for o in offs], ys, color="#c9c7bf", linewidth=1.2, zorder=1)
for (label, vals), c, mk, o in zip(data.items(), colours, markers, offs):
    ax.scatter([k + o for k in range(len(fams))], vals, s=46, color=c, marker=mk,
               edgecolors="white", linewidths=1.5, zorder=3, label=label)
ax.axhline(0.6, color="#52514e", linewidth=1, linestyle=(0, (4, 3)), zorder=0)
ax.axhline(0.5, color="#9a9890", linewidth=0.8, zorder=0)
ax.annotate("ceiling 0.6", xy=(1.0, 0.6), xycoords=("axes fraction", "data"), xytext=(4, 0),
            textcoords="offset points", va="center", fontsize=8.5, color="#52514e")
ax.annotate("chance 0.5", xy=(1.0, 0.5), xycoords=("axes fraction", "data"), xytext=(4, 0),
            textcoords="offset points", va="center", fontsize=8.5, color="#77756f")
ax.set_xlim(-0.5, len(fams) - 0.5)
ax.set_ylim(0.44, 1.03)
ax.set_xticks(range(len(fams)), fams)
ax.set_ylabel("AUC (probe vs genuine call)")
ax.yaxis.grid(True, color="#ecebe6", linewidth=0.6)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
for s in ("left", "bottom"):
    ax.spines[s].set_color("#9a9890")
ax.tick_params(colors="#52514e", length=0)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.15), ncol=3, frameon=False, fontsize=9,
          handletextpad=0.3, columnspacing=1.6)
fig.tight_layout()
fig.savefig("fig6_1_auc.png", facecolor="white")
print("saved")
