# Screenshot guide — DriftSentry_Proposal_CB014571.docx

Six screenshots to capture: **Figures 7–12**. Figures 1–6 are diagrams and are
already in the document.

Total time: about **35 minutes**, in two sittings.

---

## Before you start — one-time setup (5 min)

### 1. Make terminal text readable when printed

A screenshot of an 8-point console is unreadable once Word scales it to page
width. Fix this first or you will retake everything.

Open **Windows Terminal** or PowerShell → right-click title bar → **Properties**
→ **Font** → set size to **20**. Then drag the window to roughly **half your
screen width**, so lines do not wrap awkwardly.

### 2. Reset to a clean state

```powershell
cd "F:\fyp project\mcp rug pull attack server"
```
```powershell
.\.venv\Scripts\attacker.exe reset
```
```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\driftsentry.exe trust --server acme
```

The `trust` step matters: after any previous alert the server is marked
quarantined, and DriftSentry only raises a **new** alert on the transition into
alert. Without resetting, Figures 8 and 9 will not appear.

---

## SITTING ONE — Figures 7, 8, 9 (dashboard, ~20 min)

All three come from **one continuous dashboard session**. Do not close the window
between them.

### Start the dashboard

```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\driftsentry.exe ui
```

A native window opens at 1280×860. Leave it running for this whole sitting.

### Figure 7 — Dashboard overview, normal state

> *Caption: Dashboard overview page showing a monitored server in its normal state.*

1. Wait for **3 scheduled checks** to complete — about **60 seconds**. Watch the
   Overview page until `acme` shows a score and a green **OK** status.
2. Stay on the **Overview** page.
3. Capture the **whole dashboard window**.

**What must be visible:** the server card for `acme`, status OK, a drift score
around 0.05–0.10, the sidebar, and the check counter above zero. A score of 0.00
with zero checks means you photographed it before it had done anything.

---

### Figure 8 — Drift graph across attack and recovery

> *Caption: Drift score across an ordinary period, an attack and a recovery,
> against the alert threshold.*

This one needs a live attack. Follow the timing exactly.

1. **Leave the dashboard running.** Open a **second** PowerShell window.

2. Let 3 more benign checks pass (60 s), so the graph has a flat baseline.

3. Arm the attack:
```powershell
cd "F:\fyp project\mcp rug pull attack server"
```
```powershell
.\.venv\Scripts\attacker.exe attack content-injection
```

4. Wait for **3 checks** (about 60 s). In the dashboard the score jumps to roughly
   **2.0** and the status turns red.

5. Disarm:
```powershell
.\.venv\Scripts\attacker.exe benign
```

6. Wait for **2 more checks** (about 40 s) — the score falls back under 0.1.

7. In the dashboard click **Drift graph** in the sidebar. Set the range selector
   to show all points.

8. Capture the **graph panel** — not the whole window. Crop to the chart plus its
   axis labels and legend.

**What must be visible:** the flat low section, the spike above the dashed red
**ALERT THRESHOLD (1.00)** line, the return to low, both axis labels
("Drift score", "Time of scheduled check"), and the OK/Watch/Alert legend.

This is the single most important figure in your proposal. It shows detection
**and** recovery in one image. If the spike is missing, the attack was not armed
long enough — reset and repeat from step 2.

---

### Figure 9 — Opened alert with before/after

> *Caption: An opened alert showing the response before and after, with the
> recommended actions.*

1. Still in the dashboard, click **Alerts** in the sidebar.
2. Click the alert generated in Figure 8 to expand it.
3. Capture the **expanded alert panel**.

**What must be visible:** the severity badge, the drift score, the **BEFORE**
text (the ordinary response) and the **AFTER** text (the response with the
injected `[system note: ignore previous instructions…]` payload), and at least
two numbered **WHAT TO DO** actions.

The before/after pair is the point of this figure — if it is cut off, the
screenshot proves nothing. Scroll within the panel if you must and take two
images, but one is better.

You can now close the dashboard.

---

## SITTING TWO — Figures 10, 11, 12 (terminal, ~15 min)

### Figure 10 — Full detector vs hash-only control

> *Caption: The same attack scored by the full detector and by the hash only
> comparison.*

**The most important evidence in the whole proposal.** Same server, same traffic,
same code path — only the signals differ.

1. Arm the attack again:
```powershell
cd "F:\fyp project\mcp rug pull attack server"
```
```powershell
.\.venv\Scripts\attacker.exe attack content-injection
```

2. In the DriftSentry terminal, run the control condition first:
```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\driftsentry.exe verify --server acme --hash-only
```

3. Then the full detector, **without clearing the screen**:
```powershell
.\.venv\Scripts\driftsentry.exe verify --server acme
```

4. Capture **both outputs in one image**, scrolled so the two commands and their
   two verdicts are visible together.

**What must be visible:** the `--hash-only` command reporting no change, and the
plain `verify` command reporting an alert with a score around 2.0. Seeing the two
commands adjacent is what makes the comparison self-evident.

5. Disarm and clear the quarantine afterwards:
```powershell
cd "F:\fyp project\mcp rug pull attack server"
```
```powershell
.\.venv\Scripts\attacker.exe benign
```

---

### Figure 11 — Self-test and unit test suite

> *Caption: Ground-truth self-test and unit test suite, confirming the validity of
> the experimental basis.*

Two commands, one image.

```powershell
cd "F:\fyp project\mcp rug pull attack server"
```
```powershell
.\.venv\Scripts\python.exe -m attacker selftest
```

Then, without clearing:

```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\python.exe -m pytest tests\ -q
```

Capture both. **What must be visible:** the line
`SELF TEST PASSED - the ground truth is sound` (18 checks), and pytest's
`177 passed`.

If the self-test output is too long to fit with pytest, scroll so that the
**"all six families hash identically to benign"** line and the final PASSED line
are both visible — that check is the one that proves your threat model.

---

### Figure 12 — Evaluation harness classifying episodes

> *Caption: The evaluation harness classifying episodes against ground truth taken
> from the attacker's event log.*

**Note:** your full Experiment 1 run stopped at 38 of 66 episodes on 22 August and
is no longer running. Do **not** restart the full sweep for a screenshot — it
takes over two hours.

Use the quick sweep instead. It runs six episodes in about **six minutes** and
prints the complete summary table, which is a far better screenshot than a partial
run.

```powershell
cd "F:\fyp project\Driftsentry"
```
```powershell
.\.venv\Scripts\python.exe -m eval run --experiment 1 --quick --threshold 10.8086
```

Capture the **final summary block**, not the scrolling progress.

**What must be visible:** the `OVERALL` box with attack recall, false-alarm rate
and trigger exposure; the `RECALL BY LEVEL` table; and — most importantly — the
line reporting that the **probe was recognised by the attacker** in some episodes,
because that is what distinguishes `never_triggered` from a missed detection.

---

## How to actually take the screenshots

### Best method — Snipping Tool

Press **Win + Shift + S**. The screen dims and a crosshair appears. Drag a
rectangle over the region you want. It goes to the clipboard.

Then in Word: click where the figure belongs and press **Ctrl + V**.

### Whole window only

**Alt + PrtScn** copies just the active window — cleaner than a full-screen grab
because it excludes your taskbar and desktop.

### If you want files rather than clipboard

**Win + PrtScn** saves a full-screen PNG to `Pictures\Screenshots\`. Crop
afterwards in Photos or Paint.

### For the dashboard specifically

Click the dashboard window first so it has focus, then **Alt + PrtScn**. This
captures the pywebview window without the rest of your desktop.

---

## Quality checklist — apply to every image

| Check | Why |
|---|---|
| **PNG, never JPG** | JPEG compression smears text into fuzz. Snipping Tool gives PNG by default |
| **No personal paths visible** | `F:\fyp project\...` is fine; anything with your full name or other coursework is not |
| **No other windows in frame** | Crop tight, or use Alt+PrtScn |
| **Text readable at print size** | Print one page and look at it. If you cannot read it on paper, increase the console font and retake |
| **Caption below, not inside** | Word's caption feature, so the List of Figures auto-updates |
| **Consistent width** | Set every figure to the same width in Word (right-click → Size). Mixed widths look careless |

### In Word, after pasting

1. Right-click the image → **Insert Caption** → position **Below selected item**.
2. Type the caption text exactly as it appears in your List of Figures.
3. When all six are in, right-click the List of Figures → **Update Field** →
   **Update entire table**, so the page numbers correct themselves.

---

## Order of work

| Sitting | Figures | Time | Needs |
|---|---|---|---|
| One | 7, 8, 9 | ~20 min | Dashboard running, attacker armed mid-way |
| Two | 10, 11, 12 | ~15 min | Terminal only |

Do sitting one in a single unbroken session — Figure 8 depends on a graph history
that only exists while the dashboard keeps running.

## Two things that will waste your time if you skip them

**Run `driftsentry trust --server acme` before each attack demonstration.** Alerts
fire only on the transition into the alert state. After a previous alert the
server stays quarantined, and the graph will show a flat high line with no visible
spike.

**Do not clear the terminal between the paired commands** in Figures 10 and 11.
The value of both figures is that two results sit next to each other in one frame.
