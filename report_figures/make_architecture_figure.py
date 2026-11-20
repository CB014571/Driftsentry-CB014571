"""DriftSentry architecture figure, drawn only from components in the code."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = r"C:\Users\LEGION\AppData\Local\Temp\claude\2ce5231e1b6bed9d\c47f2b0e-8060-47ac-bc36-891685033815\scratchpad\figs\fig_arch.png"

fig, ax = plt.subplots(figsize=(11, 6.6), dpi=200)
ax.set_xlim(0, 110)
ax.set_ylim(0, 67.5)
ax.axis("off")

INK = "#1f2937"
BLUE, BLUE_BG = "#1d4ed8", "#eff6ff"
GREEN, GREEN_BG = "#047857", "#ecfdf5"
GREY, GREY_BG = "#4b5563", "#f3f4f6"
RED, RED_BG = "#b91c1c", "#fef2f2"


def box(x, y, w, h, title, body="", edge=BLUE, fill=BLUE_BG, size=8.2, bold=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2",
                                linewidth=1.3, edgecolor=edge, facecolor=fill))
    if body:
        ax.text(x + w / 2, y + h - 2.1, title, ha="center", va="top", fontsize=size,
                fontweight="bold" if bold else "normal", color=INK)
        ax.text(x + w / 2, y + h - 5.0, body, ha="center", va="top", fontsize=size - 1.4,
                color=INK, linespacing=1.35)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=size,
                fontweight="bold" if bold else "normal", color=INK)


def group(x, y, w, h, label, edge):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.8",
                                linewidth=1.1, edgecolor=edge, facecolor="none", linestyle=(0, (4, 3))))
    ax.text(x + 1.2, y + h - 1.4, label, ha="left", va="top", fontsize=8.6,
            fontweight="bold", color=edge)


def arrow(x1, y1, x2, y2, text="", color=INK, both=False, tx=0, ty=0.9):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="<|-|>" if both else "-|>", color=color, lw=1.2,
                                shrinkA=2, shrinkB=2, mutation_scale=10))
    if text:
        ax.text((x1 + x2) / 2 + tx, (y1 + y2) / 2 + ty, text, ha="center", va="bottom",
                fontsize=6.6, color=color, style="italic")


# ---------------- data plane ----------------
group(1, 50.6, 108, 16.2, "DATA PLANE  (MCP over stdio)", GREY)
box(3, 52, 20, 11, "MCP client", "e.g. Claude Desktop;\nconfig wrapped by\ndriftsentry init", GREY, GREY_BG)
box(29, 52, 26, 11, "DriftSentry proxy", "driftsentry run: relay,\naudit log; blocks calls if\nquarantined (opt-in)")
box(61, 52, 22, 11, "MCP server", "any stdio server, or\nthe attack server", RED, RED_BG)
box(89, 52, 18, 11, "Attack project", "separate venv;\n12-test menu\nwrites scenario", RED, RED_BG, size=7.8)
arrow(23.6, 57, 28.4, 57, both=True)
arrow(55.6, 57, 60.4, 57, both=True)
arrow(88.4, 57, 83.6, 57, color=RED)
ax.text(26, 58.2, "calls", fontsize=6.4, color=INK, style="italic", ha="center")
ax.text(58, 58.2, "calls", fontsize=6.4, color=INK, style="italic", ha="center")
ax.text(86, 58.2, "arms", fontsize=6.4, color=RED, style="italic", ha="center")

# ---------------- daemon ----------------
group(1, 14, 74, 35, "MONITORING DAEMON  (scheduled, out of band)", BLUE)
box(3, 34, 16, 10, "Scheduler", "re-checks every\nN seconds")
box(23, 34, 22, 10, "Keyed probes", "HMAC-SHA256(key,\ncycle, tool, field):\nnew values each cycle")
box(49, 34, 24, 10, "Re-probe + sandbox", "launches the server;\npsutil: files opened,\nhosts contacted")
arrow(19.6, 39, 22.4, 39)
arrow(45.6, 39, 48.4, 39)
arrow(66, 44.6, 66, 51.9, "probes", color=BLUE, tx=3.2, ty=-1.2)
box(49, 16, 24, 15, "Drift scorer", "definition hash;\nembedding distance vs\nvariance band (MiniLM);\nfield drift, determinism;\nsecurity rules; MAX")
arrow(61, 33.4, 61, 31.6)
box(23, 16, 22, 15, "Update checker", "Gap 2: diff old vs new\ndefinitions; explain\nwhat is DECLARED;\nalert on the residue;\nfrozen rules v1.0", GREEN, GREEN_BG)
arrow(48.4, 23.5, 45.6, 23.5)
box(3, 16, 16, 15, "Alerts + policy", "cause, before/after,\nmitigations;\nquarantine\n(read by proxy)")
arrow(22.4, 23.5, 19.6, 23.5)

# ---------------- stores ----------------
box(3, 1.5, 72, 8.5, "Local store  (.driftsentry_data)",
    "baselines + ChromaDB vectors  ·  benign-only threshold  ·  probe keys  ·  alerts", GREY, GREY_BG)
arrow(38, 13.4, 38, 10.6, both=True)

# ---------------- control plane ----------------
group(79, 1, 30, 48, "CONTROL PLANE", BLUE)
box(81, 34, 26, 10, "Localhost API", "FastAPI + uvicorn,\n127.0.0.1 only")
box(81, 18, 26, 12.5, "Dashboard", "pywebview window:\nstatus, drift graph,\nupdate panel,\ntrust / quarantine")
box(81, 3, 26, 11, "CLI", "baseline, verify,\nwatch, demo,\ncalibrate, init")
arrow(94, 33.4, 94, 31.1, both=True)
arrow(75.6, 39, 80.4, 39, both=True)

plt.savefig(OUT, bbox_inches="tight", facecolor="white")
print(OUT)
