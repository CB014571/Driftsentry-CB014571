# Complete diagram guide — Figures 1.1 to 3.4

Detailed briefs for all eight diagrams needed to Chapter 5. Each is paste-ready:
copy the block between the lines into ChatGPT or Claude.

Includes the five you already have, so you can verify or regenerate them to a
consistent style.

---

# PART 0 — Technique

## Ask for code, not a picture

| | |
|---|---|
| ❌ "Draw me an architecture diagram" | Garbled labels, wrong arrowheads, unfixable |
| ✅ "Output Mermaid `flowchart LR` code" | Renders cleanly, editable, exports as vector |

Image generators cannot render text reliably. A diagram whose entire meaning
lives in its labels and arrow directions is the worst possible case for them.

## The workflow

1. Paste a brief below into ChatGPT or Claude
2. Copy the Mermaid code it returns
3. Paste at **`https://mermaid.live`**
4. Check against the verification list in that brief
5. Export **SVG** (Actions → SVG)
6. Insert into Word → right-click → **Insert Caption** → Below selected item

## Why SVG, not PNG

SVG is vector — it stays sharp at any size, and Word scales it without blur.
Only fall back to PNG at 2× resolution if your template rejects SVG.

## When a model gets it wrong

Do not re-prompt from scratch. Say:

> The arrow between X and Y should point the other way. Also remove the Z box —
> I did not ask for it. Regenerate with those two corrections only.

Models over-correct when asked to "try again", and you lose the parts that were
right.

## The rule you must not breach

The structure document says: *"Do not put any table/figure that is not done by
you."* Generating Mermaid from your own specification and rendering it is your
own work. Downloading a diagram from a paper or a blog is not — and Figure 3.1
is where students most often slip.

---

# PART 1 — Figure 1.1: How an LLM agent calls tools via MCP

**Section 1.2.1** · Establishes what MCP is before you attack it.

---

Output **Mermaid `flowchart LR` code** for a diagram explaining how an AI
assistant calls external tools through the Model Context Protocol. This is for
the introduction of a dissertation, so it must be simple enough for a reader who
has never heard of MCP.

## Nodes

- `User` — User
- `Assistant` — AI assistant (LLM)
- `Client` — MCP client (e.g. Claude Desktop)
- `Server` — MCP server
- `Tool` — Tool implementation

## Edges, in order

| From | To | Label |
|---|---|---|
| `User` | `Assistant` | 1. request in natural language |
| `Assistant` | `Client` | 2. decides a tool is needed |
| `Client` | `Server` | 3. tools/call over JSON-RPC |
| `Server` | `Tool` | 4. executes |
| `Tool` | `Server` | 5. result |
| `Server` | `Client` | 6. response |
| `Client` | `Assistant` | 7. result enters the model's context |
| `Assistant` | `User` | 8. answer |

All single-headed. Number every label as shown — the numbering is what makes the
sequence readable in a static image.

## Styling

- `flowchart LR`
- Rounded boxes
- Put `Server` and `Tool` inside a subgraph labelled **"Third party"** — this
  quietly plants the trust boundary the whole project is about
- No colour beyond a very light fill on the subgraph

## Do not

No database, no cloud, no authentication service, no vector store. Eight arrows
only.

## Caption

> Figure 1.1 — How an LLM agent uses context to call tools via MCP.

## Body text to write near it

One sentence naming the trust boundary: the server and its tool implementation
are third-party code the user does not control.

---

# PART 2 — Figure 1.2: Behavioural rug pull

**Section 1.2.2** · **The most important diagram in your report.**

If a reader understands one figure, this is it. It must show that the definition
is *identical* on both sides while behaviour differs.

---

Output **Mermaid `flowchart TB` code** for a before-and-after comparison diagram.

## What it must communicate

A "behavioural rug pull" is an attack where an approved software tool starts
behaving maliciously while its advertised description stays **byte-for-byte
identical**. The diagram's whole job is to make that identity visible, because
that is why hash-based defences fail.

## Structure — two panels side by side

**Left panel, subgraph titled "At approval"**

- `DefA` — Tool definition: name, description, input schema
- `HashA` — SHA-256 hash: 6805aff8…
- `BehA` — Behaviour: returns the customer's real email address

**Right panel, subgraph titled "After a silent update"**

- `DefB` — Tool definition: name, description, input schema — **UNCHANGED**
- `HashB` — SHA-256 hash: 6805aff8… — **IDENTICAL**
- `BehB` — Behaviour: returns collector@attacker.invalid

## Edges

| From | To | Label | Style |
|---|---|---|---|
| `DefA` | `HashA` | hashed | solid |
| `HashA` | `BehA` | approved | solid |
| `DefB` | `HashB` | hashed | solid |
| `HashB` | `BehB` | still trusted | solid |
| `HashA` | `HashB` | **no change detected** | **dashed, double-headed** |

That dashed link between the two hashes is the point of the figure. Make it
visually prominent.

## Bottom annotation

Add one node below both panels:

- `Blind` — "Definition pinning compares the hashes and sees nothing"

with dashed arrows from `HashA` and `HashB` into it.

## Styling

- `flowchart TB`
- Left panel light green fill; right panel light red fill
- Both `Def` boxes must look **identical** — same shape, same size, same border
  weight. Their sameness is the argument
- The `Beh` boxes should look clearly different from each other

## Do not

Do not colour the definition boxes differently. Do not add an attacker icon, a
network, or a timeline. The comparison is the entire content.

## Verification

- Are the two definition boxes visually indistinguishable? If not, the figure
  fails at its one job
- Is the hash string the same on both sides?
- Does the dashed link read as "these are equal"?

## Caption

> Figure 1.2 — A behavioural rug pull on an approved MCP tool. The advertised
> definition and its hash are unchanged; only the behaviour differs.

---

# PART 3 — Figure 2.1: Concept map

**Section 2.2** · Mandated. Full-resolution version goes to Appendix I.

---

I need a **concept map** (Novak-style), not a flowchart. Output **Mermaid
`flowchart TD` code**.

## What makes it a concept map

- Nodes are **concepts** — nouns, never actions
- Every arrow carries a **linking phrase**, so *concept → phrase → concept* reads
  as a full sentence
- Layout is hierarchical: most general at the top, more specific below
- **Cross-links** between branches are expected and are what distinguish a real
  concept map from a tree

Test every arrow by reading it aloud. If it is not a sentence, the phrase is
wrong.

## Root

**Behavioural rug pull in MCP**

## Branch 1 — the threat

- Behavioural rug pull in MCP → *is a* → Post-approval attack
- Post-approval attack → *exploits* → Trust On First Use
- Behavioural rug pull in MCP → *keeps unchanged* → Tool definition
- Tool definition → *is verified by* → Hash pinning
- Hash pinning → *is therefore blind to* → Behavioural rug pull in MCP **(cross-link, dashed)**

## Branch 2 — the detection mechanism

- Behavioural rug pull in MCP → *is detected by* → Behavioural baseline
- Behavioural baseline → *is captured at* → Approval time
- Behavioural baseline → *is built from* → Canary probes
- Canary probes → *are derived from* → Tool JSON Schema
- Canary probes → *are made unpredictable by* → Keyed generation
- Behavioural baseline → *models* → Benign variance
- Benign variance → *is estimated by* → Leave-one-out cross-validation
- Behavioural baseline → *is re-verified by* → Scheduled re-probing

## Branch 3 — turning observation into a decision

- Scheduled re-probing → *produces* → Drift score
- Drift score → *combines* → Embedding distance
- Drift score → *combines* → Security rules
- Drift score → *combines* → Side-effect evidence
- Embedding distance → *is scaled by* → Benign variance **(cross-link, dashed)**
- Security rules → *fire only on* → Behaviour new since baseline
- Drift score → *is compared against* → Calibrated threshold
- Calibrated threshold → *is derived only from* → Benign traffic
- Benign traffic → *must include* → Benign updates

## Branch 4 — limits

- Behavioural baseline → *cannot detect* → Server malicious from the start
- Server malicious from the start → *is a consequence of* → Trust On First Use **(cross-link, dashed)**
- Canary probes → *can be recognised by* → Probe-aware attacker
- Probe-aware attacker → *is countered by* → Keyed generation **(cross-link, dashed)**

## Styling

- `flowchart TD`
- Rounded boxes; linking phrases as edge labels only, never inside a box
- Four cross-links dashed (`-.->`) so they stand out from the hierarchy
- Subtly different fills per branch; print-safe

## Do not

Do not add concepts I have not listed. Do not turn linking phrases into boxes.

---

# PART 4 — Figure 2.2: Conceptual architecture ⬜ NEW

**Section 2.3.4** · Mandated. This one does not exist yet.

---

I need a **conceptual** architecture diagram closing a literature-review chapter.
Output **Mermaid `flowchart TD` code**.

## Context

DriftSentry detects behavioural rug pulls in the Model Context Protocol. A user
approves a tool once; a malicious server later changes what the tool does while
keeping its advertised definition byte-for-byte identical.

## What this is NOT

This is the **positioning** diagram — the bridge from "here are the domain
challenges" to "here is the shape of my answer". A separate, detailed system
architecture appears later in the methodology chapter.

So: **no** file names, module names, class names, library names, data formats or
protocol details. Four conceptual layers. Graspable in ten seconds.

## The four capability layers

Top to bottom, each a box, single arrows down the chain:

1. `L1` — Observation point in the tool-invocation path
2. `L2` — Behavioural baseline captured at approval
3. `L3` — Periodic re-verification
4. `L4` — Deterministic scoring and attributable alerting

## The four domain challenges

A separate vertical group on the left:

- `C1` — Advertised definition is not the behaviour
- `C2` — Approval happens once; behaviour keeps changing
- `C3` — Legitimate updates resemble attacks
- `C4` — Verification can itself be recognised

## Cross edges — all dashed, labelled `addresses`

| From | To |
|---|---|
| `C1` | `L2` |
| `C2` | `L3` |
| `C3` | `L4` |
| `C4` | `L3` |

## Styling

- `flowchart TD`
- Challenges in a subgraph titled **"Domain challenges"**
- Layers in a subgraph titled **"Proposed approach"**
- Solid arrows down the layer chain; dashed for `addresses`
- Rounded boxes, very light fills
- Every label five words or fewer

## Do not

No database, no cloud service, no user icon, no LLM box, no named technology, no
arrow beyond those listed.

## Verification

- Is there any implementation detail? There must be none
- Exactly four layers and four challenges?
- Do the two subgraphs read as two distinct groups?

---

# PART 5 — Figure 3.1: Saunders' research onion 🔶 VERIFY OR REDRAW

**Section 3.2** · Mermaid **cannot** draw concentric circles. Use one of these.

## Option A — draw.io (recommended, ~20 min)

1. Open `app.diagrams.net`
2. Draw six concentric circles: **Ellipse** shape, hold **Shift** to keep them
   circular. Largest first, each ~120 px smaller in diameter
3. Right-click each → **Edit Style** → set `fillColor=none;strokeWidth=1.5`
4. Send each smaller circle **to front** so labels are not hidden
5. Add a text label at the top edge of each ring
6. Place your choices in **bold** on each ring; rejected alternatives in grey
7. **File → Export as → SVG**, transparent background

## Option B — ask a model for raw SVG

> Generate a single SVG file: six concentric circles centred in a 900×900
> viewBox, radii 430, 360, 290, 220, 150 and 80. No fill, black stroke 1.5 px.
> Above each circle's top edge place a centred label in 15 px serif: Philosophy,
> Approach, Strategy, Methodological choice, Time horizon, Techniques and
> procedures. Leave the interior of each ring empty for text I will add. Output
> raw SVG only, no explanation.

Then open the SVG in a text editor or Inkscape and type your choices in.

## What goes on each ring

Use whatever your proposal already states. If undecided, these are defensible —
but **only claim what you can defend aloud**:

| Ring | Your choice | Justification |
|---|---|---|
| Philosophy | **Positivism** | Measurements are objective and numeric; the detector is deterministic by design, so repeated runs give identical scores |
| Approach | **Deductive** | A stated hypothesis — approval-time behavioural baselining detects definition-invariant rug pulls — tested by controlled experiment |
| Strategy | **Experiment** | Controlled comparison against a hash-only control on identical traffic, with an independent ground-truth oracle |
| Methodological choice | **Mono-method quantitative** | Recall, false-alarm rate, time-to-detection. No qualitative instrument, no user study |
| Time horizon | **Cross-sectional** | Measured over a fixed experimental window rather than tracking servers over months |
| Techniques | **Synthetic adversarial data generation; controlled experiments; automated regression testing** | Ground truth from an adversarial server; 177 automated tests; results written per row to CSV |

## The thing that matters

**Highlight only your choices.** A generic onion reproducing the textbook adds
nothing, and it is exactly the figure an examiner suspects was copied. Yours
should make your six decisions visible at a glance, with alternatives greyed.

Cite `Saunders et al. (2019)` in the caption, beneath **your own** drawing.

---

# PART 6 — Figure 3.2: Phase-gated development model ⬜ NEW

**Section 3.3** · Justifies your development methodology.

---

Output **Mermaid `flowchart LR` code** for a phase-gated software development
model.

## What it shows

The project was built in ten sequential phases. Each phase has an **executable
definition-of-done check** — a script exercising the real code end to end — and a
phase is not complete until its check passes. The diagram shows that structure
and current position.

## Phases

| ID | Label | Group |
|---|---|---|
| `P0` | 0. Environment and protocol verification | Complete |
| `P1` | 1. Transparent interception proxy | Complete |
| `P2` | 2. Client configuration ingestion | Complete |
| `P3` | 3. Behavioural baseline capture | Complete |
| `P4` | 4. Drift scoring and calibration | Complete |
| `P5` | 5. Alerting and mitigation | Complete |
| `P6` | 6. Monitoring daemon and interface | Complete |
| `P7` | 7. Adversarial server | Complete |
| `P8` | 8. Labelled corpus construction | In progress |
| `P9` | 9. Controlled experiments | In progress |
| `P10` | 10. Analysis and write-up | Remaining |

## Layout

- Left to right, `P0` through `P10` in sequence
- A **diamond** gate between `P0` and `P1` only, labelled
  `definition-of-done check`
- Plain arrows for the remaining transitions, plus a note stating the same gate
  applies at every boundary — eleven gates would clutter it
- Three subgraphs: **Complete** (P0–P7), **In progress** (P8–P9),
  **Remaining** (P10)

## Styling

- `flowchart LR`
- Light green / light amber / light grey fills for the three groups
- Phase labels four words maximum

## Do not

**No feedback loops, no iteration arrows, no spiral.** This is a linear
phase-gated model, not Agile — that distinction is the point of the figure and
models will add loops unless told not to.

## Verification

- Are there exactly eleven phase boxes?
- Any arrow pointing backwards? There must be none
- Do the three groups read as distinct?

---

# PART 7 — Figure 3.3: High-level architecture

**Section 3.5.1** · The detailed counterpart to Figure 2.2.

---

Output **Mermaid `flowchart LR` code** for a system architecture diagram.

## The structural fact this must convey

There are **two separate paths to the same MCP server**:

1. **Live path** — a transparent proxy between the client and the server,
   forwarding and logging. It is passive; it never probes.
2. **Detection path** — a daemon opening its own out-of-band connection on a
   schedule, doing all the probing.

Probe traffic stays off the live path so real tool calls get no added latency. If
the diagram shows probing through the proxy, it is wrong.

Draw the live path along the top, the detection path below.

## Nodes

**Live path**
`Client` MCP client · `Proxy` driftsentry run · `Server` real MCP server ·
`Log` exchange log (JSONL)

**Detection path**
`Daemon` scheduler · `Probes` probe engine · `Sandbox` side-effect monitor ·
`Embed` embedding backend · `Store` baseline store · `Calib` calibration ·
`Scorer` drift scorer

**Output**
`Alerts` alert log · `Policy` policy store · `API` control API · `Dash` dashboard

## Bidirectional edges — `<-->` — exactly four

| From | To | Label | Why bidirectional |
|---|---|---|---|
| `Client` | `Proxy` | MCP over stdio | JSON-RPC both ways; the proxy runs two independent forwarding loops |
| `Proxy` | `Server` | MCP over stdio | The proxy is a client to the real server |
| `Probes` | `Server` | separate out-of-band session | The probe engine is itself an MCP client |
| `Dash` | `API` | HTTP on loopback | Request/response |

## Single arrows — `-->`

| From | To | Label |
|---|---|---|
| `Proxy` | `Log` | writes every message |
| `Policy` | `Proxy` | read per call (if enforcing) |
| `Daemon` | `Probes` | triggers on schedule |
| `Probes` | `Embed` | response text |
| `Embed` | `Probes` | vector |
| `Probes` | `Store` | writes baseline at approval |
| `Store` | `Probes` | reads stored probes at re-check |
| `Sandbox` | `Probes` | hosts contacted, files opened |
| `Probes` | `Scorer` | measurement |
| `Calib` | `Scorer` | threshold |
| `Scorer` | `Alerts` | on transition into alert |
| `Scorer` | `Daemon` | verdict and score |
| `Alerts` | `Policy` | marks server quarantined |
| `Daemon` | `API` | state snapshot |
| `API` | `Daemon` | commands |

## Dotted arrow — `-.->` — exactly one

`Sandbox` -.-> `Server`, labelled `observes process`. Nothing is sent; it is pure
observation.

## Styling

- `flowchart LR`
- Subgraph **"Live data path (passive)"** for the top row
- Subgraph **"Detection path (out of band)"** for the middle
- Subgraph **"Control plane (loopback only)"** for `API` and `Dash`
- Datastores (`Log`, `Store`, `Calib`, `Alerts`, `Policy`) as cylinders: `[( )]`

## Do not

No cloud, no database server, no load balancer, no message queue, no
authentication service — everything runs as local processes on one machine. No
LLM box in the scoring path; the detector is deterministic. Do not draw an arrow
from `Proxy` to `Probes` or `Scorer`.

## Verification

- Exactly four double-headed arrows?
- Exactly one dotted arrow?
- Is the proxy visually separate from the detection path?

---

# PART 8 — Figure 3.4: Data flow of the canary probe and drift check

**Section 3.5.3** · The mechanism, step by step.

---

Output **Mermaid `flowchart TD` code** showing the data flow of one verification
cycle.

## Two phases, in two subgraphs

**Subgraph "At approval (once)"**

| ID | Label |
|---|---|
| `A1` | List the server's tools |
| `A2` | Classify each tool safe or side-effecting |
| `A3` | Generate probes from the JSON Schema |
| `A4` | Fire each probe N times |
| `A5` | Normalise response: text, structure, error state |
| `A6` | Embed to a 384-dimension vector |
| `A7` | Learn the benign variance band |
| `A8` | Store baseline |

Chain them `A1 --> A2 --> ... --> A8`, with a note on `A2` that side-effecting
tools are never probed.

**Subgraph "Every cycle (scheduled)"**

| ID | Label |
|---|---|
| `B1` | Re-generate probes for this cycle |
| `B2` | Fire them at the live server |
| `B3` | Normalise and embed the responses |
| `B4` | Distance from the stored baseline |
| `B5` | Divide by the tool's own variance band |
| `B6` | Divide by the calibrated threshold |
| `B7` | Take the strongest single signal |
| `B8` | Verdict: OK, watch or alert |

Chain `B1 --> B2 --> ... --> B8`.

## Cross edges

| From | To | Label | Style |
|---|---|---|---|
| `A8` | `B4` | stored centroid and band | dashed |
| `Side` | `B7` | side-effect and rule evidence | dashed |

Add one node `Side` labelled "Process monitor: hosts contacted, files opened",
sitting beside `B2`, with a solid arrow `B2 --> Side`.

## Styling

- `flowchart TD`
- Approval subgraph light blue; cycle subgraph light grey
- Make the `A8 -.-> B4` link prominent — it is what connects the two phases and
  the whole method depends on it

## Do not

Do not merge the two phases into one chain. Their separation — captured once,
checked repeatedly — is the mechanism.

## Verification

- Are the two phases clearly separate?
- Does the dashed baseline link connect them?
- Exactly eight steps in each phase?

---

# PART 9 — Putting them into Word

## Insert

1. **Insert → Pictures → This Device**, choose the SVG
2. Right-click → **Size and Position** → set width, same for every figure
3. Right-click → **Insert Caption** → position **Below selected item**
4. Type the caption exactly as it appears in your List of Figures

## Numbering

Use Word's caption feature with chapter numbering: **Insert Caption →
Numbering → Include chapter number**. Figures renumber themselves when you add
one.

## The List of Figures

**References → Insert Table of Figures**. After adding all eight, right-click it
→ **Update Field → Update entire table**.

## Required by the structure document

*"All diagrams must have a small description describing what it illustrates."*
A caption is not enough — write one or two sentences of body text near each
figure explaining what the reader should take from it.

---

# PART 10 — Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Boxes you did not ask for | The model added plausible-looking components | List them and say "remove these; regenerate with no other changes" |
| Arrows point the wrong way | Most common silent error | Check every arrow against the brief's table before accepting |
| Diagram too wide for the page | Too many nodes on one row | Switch `LR` to `TD`, or split into subgraphs |
| Text unreadable when printed | Too many nodes | Reduce node count; do not shrink the font |
| Mermaid syntax error | Special characters in labels | Wrap labels in quotes: `A["text (with parens)"]` |
| Nodes in a strange order | Mermaid lays out in declaration order | Reorder your node declarations |
| Blurry in Word | PNG instead of SVG | Re-export as SVG |

## Final check before submission

- [ ] All eight figures use the same visual style
- [ ] All the same width in Word
- [ ] Every one has a caption below it
- [ ] Every one has a sentence or two of explanation nearby
- [ ] List of Figures updated and page numbers correct
- [ ] Figure 3.1 is **your own drawing**, with Saunders et al. (2019) cited
- [ ] Figure 1.2's two definition boxes are visually identical
- [ ] Figure 3.3 has exactly four double-headed arrows
- [ ] Figure 3.2 has no backward arrows
