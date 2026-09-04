# How to draw Figure 3.3 — the architecture diagram

Step by step, two routes. **Method A** takes about five minutes and needs no
drawing skill. **Method B** takes about forty-five and gives full control over
layout.

Do Method A first regardless. Even if you end up drawing it by hand, having a
rendered version tells you whether the layout works before you invest the time.

---

# PART 1 — What the diagram must say

Before any tool: be clear what you are drawing, or you will draw a pretty picture
that is wrong.

## The one structural fact

**There are two separate paths to the same MCP server.**

| Path | What it does | Key property |
|---|---|---|
| **Live** | The proxy sits between client and server, forwarding and logging every message | **Passive** — it never probes |
| **Detection** | The daemon opens its *own* connection on a schedule and does all the probing | **Out of band** — never touches the live path |

Why it is built this way, and what you say when asked: probe traffic stays off
the live path so real tool calls get **no added latency**; the audit log stays a
record of what the *user's client* actually did; and the probe engine owns its
own process tree, so file and network evidence is attributable to the probe
rather than to concurrent user traffic.

**If your diagram shows probing going through the proxy, it is wrong.** That is
the single error to avoid.

## The layout that expresses it

```
   ┌──────────────── LIVE PATH (passive) ────────────────┐
   │  MCP client  ⇄  Proxy  ⇄  Real MCP server           │
   │                   ↓                                  │
   │              Exchange log                            │
   └──────────────────────────────────────────────────────┘
                                    ⇅  (second, separate connection)
   ┌────────────── DETECTION PATH (scheduled) ───────────┐
   │  Daemon → Probe engine → Embedding                   │
   │              ⇅              ↓                        │
   │        Baseline store   Drift scorer ← Calibration   │
   │        Sandbox monitor ─────┘                        │
   └──────────────────────────────────────────────────────┘
                    ↓
        Alert log → Policy store ──→ back up to the Proxy
                    ↓
   ┌────────── CONTROL PLANE (loopback only) ────────────┐
   │           Control API  ⇄  Dashboard                  │
   └──────────────────────────────────────────────────────┘
```

Live path on top, detection below, control plane at the bottom. The server is
reached from **both** bands — that is the whole point.

---

# PART 2 — Method A: Mermaid (5 minutes)

## Step 1 — Open the editor

Go to **`https://mermaid.live`**. Delete whatever example is in the left pane.

## Step 2 — Paste this

This is complete and verified. Paste it exactly.

```
flowchart LR

  subgraph LIVE["Live data path — passive"]
    direction LR
    Client["MCP client<br/>Claude Desktop, Cursor"]
    Proxy["driftsentry run<br/>transparent proxy"]
    Server["Real MCP server<br/>third-party code"]
    Log[("Exchange log<br/>JSONL")]
  end

  subgraph DETECT["Detection path — out of band, scheduled"]
    direction TB
    Daemon["Daemon<br/>scheduler, 20 s"]
    Probes["Probe engine<br/>canary probes"]
    Sandbox["Side-effect monitor<br/>hosts, files"]
    Embed["Embedding backend<br/>all-MiniLM-L6-v2, 384-dim"]
    Store[("Baseline store<br/>JSON + ChromaDB")]
    Calib[("Calibration<br/>threshold")]
    Scorer["Drift scorer<br/>8 signals, no LLM"]
  end

  subgraph CONTROL["Control plane — loopback only"]
    API["Control API<br/>127.0.0.1:8787"]
    Dash["Dashboard"]
  end

  Alerts[("Alert log<br/>append-only")]
  Policy[("Policy store<br/>trust and enforce")]

  Client <-->|"MCP over stdio"| Proxy
  Proxy <-->|"MCP over stdio"| Server
  Proxy -->|"writes every message"| Log
  Policy -->|"read per call, if enforcing"| Proxy

  Daemon -->|"triggers on schedule"| Probes
  Probes <-->|"separate out-of-band session"| Server
  Probes -->|"response text"| Embed
  Embed -->|"384-dim vector"| Probes
  Probes -->|"writes baseline at approval"| Store
  Store -->|"reads stored probes"| Probes
  Sandbox -->|"observed hosts and files"| Probes
  Sandbox -.->|"observes process"| Server
  Probes -->|"measurement"| Scorer
  Calib -->|"threshold"| Scorer
  Scorer -->|"verdict and score"| Daemon
  Scorer -->|"on transition into alert"| Alerts
  Alerts -->|"marks quarantined"| Policy

  Daemon -->|"state snapshot"| API
  API -->|"commands"| Daemon
  Dash <-->|"HTTP on loopback"| API

  classDef store fill:#f4f4f4,stroke:#666
  class Log,Store,Calib,Alerts,Policy store
```

## Step 3 — Check it renders

The right pane updates as you type. If you see a syntax error, you have lost a
character while copying — paste again.

## Step 4 — Verify against the specification

Count these on the rendered image. Do not skip this.

| Check | Expected |
|---|---|
| Double-headed arrows (`⇄`) | **exactly 4** — Client↔Proxy, Proxy↔Server, Probes↔Server, Dash↔API |
| Dotted arrows | **exactly 1** — Sandbox to Server |
| Arrow from Proxy into Probes or Scorer | **none** — if you see one, the diagram is wrong |
| Cylinder shapes | 5 — Log, Store, Calib, Alerts, Policy |
| Subgraph boxes | 3 |

## Step 5 — Fix the layout if it is cramped

Mermaid lays out in **declaration order**. If two boxes overlap or a line takes a
strange route, move the node's declaration earlier or later in its subgraph. Do
not fight it with styling.

If the whole thing is too wide for a portrait page, change the first line to
`flowchart TB`.

## Step 6 — Export

**Actions** panel → **SVG**. Save as `figure_3_3_architecture.svg`.

SVG, not PNG: it is vector, so Word can scale it to any width without blurring.

---

# PART 3 — Method B: draw.io (45 minutes, full control)

Use this if Mermaid's automatic layout will not cooperate, or if your supervisor
prefers a hand-built diagram.

## Step 1 — Set up the canvas

1. Open **`https://app.diagrams.net`** → **Create New Diagram** → **Blank**
2. **File → Page Setup** → Paper size **A4**, orientation **Landscape**
3. Turn on **View → Grid** (10 pt) so boxes align without effort

## Step 2 — Place the three band containers first

Draw these as large rectangles, no fill, dashed border. They are the scaffolding
everything else sits inside.

| Container | Position (x, y) | Size (w × h) | Label |
|---|---|---|---|
| Live band | 40, 40 | 1000 × 200 | Live data path — passive |
| Detection band | 40, 280 | 1000 × 320 | Detection path — out of band, scheduled |
| Control band | 40, 640 | 1000 × 120 | Control plane — loopback only |

Put the label at the **top-left** of each container, not centred — centred labels
collide with the boxes inside.

## Step 3 — Live band boxes

Rounded rectangles, 180 × 60, white fill, 1 pt black border.

| Box | x | y |
|---|---|---|
| MCP client | 80 | 90 |
| driftsentry run (proxy) | 400 | 90 |
| Real MCP server | 760 | 90 |
| Exchange log *(cylinder)* | 400 | 175 |

For the cylinder: search the shape panel for **"cylinder"** and drag it in.

## Step 4 — Detection band boxes

| Box | x | y |
|---|---|---|
| Daemon (scheduler) | 80 | 320 |
| Probe engine | 330 | 320 |
| Side-effect monitor | 760 | 320 |
| Embedding backend | 330 | 420 |
| Baseline store *(cyl)* | 80 | 420 |
| Drift scorer | 580 | 490 |
| Calibration *(cyl)* | 330 | 520 |

## Step 5 — Output and control

| Box | x | y |
|---|---|---|
| Alert log *(cyl)* | 800 | 490 |
| Policy store *(cyl)* | 800 | 570 |
| Control API | 330 | 670 |
| Dashboard | 600 | 670 |

## Step 6 — Draw the four bidirectional arrows first

Do these **before** the single arrows. They are the ones readers look at, and
drawing them first means everything else routes around them.

Hover a box edge until a blue arrow appears, drag to the target. Then
right-click the line → **Edit Style** and set:

```
endArrow=classic;startArrow=classic;html=1;strokeWidth=1.5;
```

| From | To | Label |
|---|---|---|
| MCP client | Proxy | MCP over stdio |
| Proxy | Real MCP server | MCP over stdio |
| Probe engine | Real MCP server | separate out-of-band session |
| Dashboard | Control API | HTTP on loopback |

The **Probe engine → Real MCP server** arrow crosses band boundaries. That is
correct and intentional — it is what shows the second, separate connection. Route
it around the right-hand edge so it does not cut through other boxes.

## Step 7 — The single arrows

Default style, `strokeWidth=1`. Label every one.

| From | To | Label |
|---|---|---|
| Proxy | Exchange log | writes every message |
| Policy store | Proxy | read per call, if enforcing |
| Daemon | Probe engine | triggers on schedule |
| Probe engine | Embedding backend | response text |
| Embedding backend | Probe engine | 384-dim vector |
| Probe engine | Baseline store | writes baseline at approval |
| Baseline store | Probe engine | reads stored probes |
| Side-effect monitor | Probe engine | observed hosts and files |
| Probe engine | Drift scorer | measurement |
| Calibration | Drift scorer | threshold |
| Drift scorer | Daemon | verdict and score |
| Drift scorer | Alert log | on transition into alert |
| Alert log | Policy store | marks quarantined |
| Daemon | Control API | state snapshot |
| Control API | Daemon | commands |

## Step 8 — The one dotted arrow

**Side-effect monitor → Real MCP server**, labelled `observes process`.

Right-click → Edit Style:

```
dashed=1;endArrow=open;strokeWidth=1;
```

Dotted because **nothing is sent**. The monitor reads the operating system's view
of the process; it does not communicate with the server. If you draw this solid,
you are claiming a channel that does not exist.

## Step 9 — Tidy

1. Select all → **Arrange → Align → Left** for each column
2. Set every box to the same size: select all, **Arrange** tab, set Width 180,
   Height 60
3. Move labels off the lines where they overlap — click a label and drag
4. **Edit → Find/Replace** to check no placeholder text survives

## Step 10 — Export

**File → Export as → SVG**
- Zoom **100%**
- Border width **10**
- ✅ Transparent background
- ✅ Include a copy of my diagram *(lets you re-edit it later from the SVG)*

---

# PART 4 — Common mistakes

| Mistake | Why it is wrong | Fix |
|---|---|---|
| Probe arrow drawn through the proxy | The whole design point is that probing is out of band | Route it from the probe engine directly to the server |
| All arrows single-headed | MCP is JSON-RPC — requests and responses both directions | Four specific edges must be double-headed |
| Sandbox arrow drawn solid | Implies a channel that does not exist | Dotted, labelled `observes process` |
| A "database" box added | Everything is local files and an embedded store | Use cylinders labelled with the actual artefacts |
| An LLM box in the scoring path | The scorer is deterministic — this is a core claim | The only model is the embedding backend, and it feeds the probe engine |
| Boxes at different sizes | Reads as careless | Set them all to 180 × 60 |
| Labels missing on arrows | An unlabelled arrow says nothing | Every arrow carries a label |

---

# PART 5 — Caption and body text

## Caption (below the figure, using Word's caption tool)

> **Figure 3.3** — High-level architecture of the DriftSentry proxy, showing the
> passive live data path and the separate out-of-band detection path.

## Body text to write near it

The structure document requires a description for every diagram. Two or three
sentences, for example:

> Figure 3.3 shows the two paths by which DriftSentry reaches a monitored MCP
> server. The proxy occupies the live path between client and server, forwarding
> every JSON-RPC message unchanged and recording it, but never generating traffic
> of its own. Verification happens on a second, independent connection opened by
> the daemon on a schedule, so probe traffic adds no latency to real tool calls
> and the audit log remains a record of what the user's client actually did.

That paragraph is also the answer to *"why did you architect it this way?"* in
the viva, so it is worth writing carefully once.

---

# PART 6 — Reusing this for Figure 3.4

Figure 3.4 (data flow of the canary probe and drift check) uses the same tool and
the same workflow. Its brief is in `DIAGRAM_GUIDE_FULL.md`, Part 8.

Keep the two visually consistent — same box size, same fonts, same arrow weights.
A reader should see immediately that they describe the same system at different
levels of detail.
