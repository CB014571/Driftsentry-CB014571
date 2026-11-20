"""DriftSentry 1.1.0 architecture: the protect path and the update path.

Drawn only from components in the code: proxy.py (relay, ProbeInjector),
guard.py, _watcher.py / sandbox.py, insession.py, scorer.py, baseline.py,
keys.py, declared_diff.py, residue.py, alerts.py, policy.py, api.py, ui/.
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = sys.argv[1]
fig, ax = plt.subplots(figsize=(11, 6.6), dpi=200)
ax.set_xlim(0, 110)
ax.set_ylim(0, 66)
ax.axis("off")

INK = "#1f2937"
BLUE, BLUE_BG = "#1d4ed8", "#eff6ff"
GREEN, GREEN_BG = "#047857", "#ecfdf5"
GREY, GREY_BG = "#4b5563", "#f3f4f6"
RED, RED_BG = "#b91c1c", "#fef2f2"
AMBER, AMBER_BG = "#92400e", "#fffbeb"


def box(x, y, w, h, title, body="", edge=BLUE, fill=BLUE_BG, size=8.0):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2",
                                linewidth=1.3, edgecolor=edge, facecolor=fill))
    ax.text(x + w / 2, y + h - 1.8, title, ha="center", va="top", fontsize=size,
            fontweight="bold", color=INK)
    if body:
        ax.text(x + w / 2, y + h - 4.6, body, ha="center", va="top", fontsize=size - 1.5,
                color=INK, linespacing=1.35)


def group(x, y, w, h, label, edge):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.8",
                                linewidth=1.1, edgecolor=edge, facecolor="none", linestyle=(0, (4, 3))))
    ax.text(x + 1.2, y + h - 1.2, label, ha="left", va="top", fontsize=8.4,
            fontweight="bold", color=edge)


def arrow(x1, y1, x2, y2, text="", color=INK, both=False, tx=0.0, ty=0.6, dashed=False):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="<|-|>" if both else "-|>", color=color, lw=1.2,
                                shrinkA=2, shrinkB=2, mutation_scale=10,
                                linestyle=(0, (3, 2)) if dashed else "-"))
    if text:
        ax.text((x1 + x2) / 2 + tx, (y1 + y2) / 2 + ty, text, ha="center", va="bottom",
                fontsize=6.4, color=color, style="italic")


# ------------------------------------------------------------ protect (Gap 1)
group(1, 27.5, 108, 37.5, "PROTECT   driftsentry run --in-session   (Gap 1: verification the server cannot "
      "single out)", BLUE)
box(3, 44, 17, 13, "MCP client", "e.g. Claude Desktop;\nits config is rewritten\nby driftsentry init",
    GREY, GREY_BG)
ax.add_patch(FancyBboxPatch((24.5, 40.5), 57, 20.5, boxstyle="round,pad=0.3,rounding_size=1.4",
                            linewidth=1.6, edgecolor=BLUE, facecolor="white"))
ax.text(53, 60.2, "DriftSentry proxy  (proxy.py)", ha="center", va="top", fontsize=8.4,
        fontweight="bold", color=BLUE)
box(26.5, 42, 16, 14, "Relay + log", "every message passed\non unchanged and\nlogged; --enforce\nrefuses calls to a\nquarantined server",
    size=7.6)
box(44.5, 42, 17.5, 14, "Probe injector", "keyed probes sent in\nthe user's own session,\nat the user's pace;\nprobe answers never\nreach the client",
    size=7.6)
box(64, 42, 15.5, 14, "Real-call guard", "every real call:\nnew host, new file\nfolder, secret file,\ninstruction-shaped\noutput  (guard.py)",
    AMBER, AMBER_BG, size=7.6)
box(88, 44, 19, 13, "MCP server", "any stdio server\n(or the separate\nattack server)", RED, RED_BG)
arrow(20.6, 50.5, 23.9, 50.5, both=True)
arrow(82.1, 50.5, 87.4, 50.5, both=True)
ax.text(22.3, 51.4, "calls", fontsize=6.2, color=INK, style="italic", ha="center")
ax.text(84.8, 51.4, "calls", fontsize=6.2, color=INK, style="italic", ha="center")

box(84, 29.5, 23, 9.5, "Side-effect watcher", "its own process (_watcher.py):\nfiles opened, hosts contacted",
    size=7.6)
arrow(95.5, 39.6, 95.5, 43.4, "watches", color=BLUE, tx=3.2, ty=-0.9)
arrow(83.4, 36.5, 79.5, 40.0, "timed sweeps", color=BLUE, tx=-3.6, ty=-4.4)
box(27, 29.5, 31, 8.5, "In-session check", "probe answers scored against the\nbaseline by the drift scorer (MAX)",
    size=7.6)
arrow(53, 41.4, 47, 38.6, "probe answers", color=BLUE, tx=10.5, ty=-1.6)

# ------------------------------------------------------- approve / update / respond
group(1, 1, 108, 22, "", GREY)
ax.text(107.8, 21.8, "APPROVE, CHECK UPDATES, RESPOND", ha="right", va="top", fontsize=8.4, fontweight="bold", color=GREY)
box(3, 3, 22, 15.5, "Approve", "driftsentry baseline:\nkeyed probes from a secret\nper-server key; answers,\nvariance bands, files and\nhosts seen; saved locally",
    size=7.8)
box(29, 3, 30, 15.5, "On update  (Gap 2)", "driftsentry verify --update-check\n1. diff old and new definitions\n2. mask what the update declares\n3. re-score: whatever still alerts\n    is the residue -> ALERT\nrules v1.1, fixed in code",
    GREEN, GREEN_BG, size=7.8)
box(63, 3, 22, 15.5, "Alerts + policy", "which tool, which signal,\nbefore and after,\nwhat to do;\nserver QUARANTINED",
    size=7.8)
box(89, 3, 18, 15.5, "Dashboard + CLI", "report, trust,\nquarantine;\nlocal API on\n127.0.0.1 only", GREY, GREY_BG,
    size=7.8)
arrow(25.6, 10.5, 28.4, 10.5)
arrow(59.6, 10.5, 62.4, 10.5)
arrow(85.6, 10.5, 88.4, 10.5, both=True)
arrow(14, 19.1, 30, 28.9, "baseline", tx=-4.0, ty=0.0)
arrow(56, 28.9, 68, 19.1, "verdict", tx=4.2, ty=0.0)
arrow(72, 41.4, 72, 19.1, "finding", color=AMBER, tx=-3.4, ty=2.0)

fig.savefig(OUT, bbox_inches="tight", facecolor="white")
print("wrote", OUT)
