# Briefs for generating the DriftSentry diagrams

Two self-contained prompts. Paste one at a time into ChatGPT (or any model).
Everything in them is taken from the real codebase, so the diagram will match
the system you actually built.

**Ask for Mermaid or Graphviz code, not a picture.** Image generation garbles
labels and arrowheads, which is fatal for a diagram whose whole point is
direction. Generated Mermaid can be rendered at `mermaid.live` and exported as
SVG/PNG at any resolution — vector output that stays sharp in print.

---

# BRIEF A — Architecture diagram

> Copy everything between the lines into ChatGPT.

---

I need a system architecture diagram. Please output it as **Mermaid `flowchart LR`
code** (not an image). Follow my node and edge lists exactly — do not add,
rename, merge or invent components, and do not change any arrow direction.

## What the system is

DriftSentry is a desktop security tool that detects "behavioural rug pull"
attacks against Model Context Protocol (MCP) servers. An MCP server advertises
tools to an AI assistant; the user approves those tools once. A malicious server
can later change what a tool *does* while keeping its advertised definition
byte-for-byte identical, so hash-based defences are blind to it. DriftSentry
captures a behavioural baseline at approval time and re-verifies it on a
schedule.

## The single most important structural fact

There are **two separate paths to the MCP server**, and the diagram must make
that obvious:

1. **The live path** — the proxy sits between the MCP client and the real
   server, forwarding every message. It is passive: it logs but does not probe.
2. **The detection path** — the daemon opens its *own, separate* connection to
   the same server, out of band, on a schedule. It never runs through the proxy.

This separation is a deliberate design decision (it keeps probe traffic off the
live path so real tool calls get no added latency). If the diagram shows probing
happening through the proxy, it is wrong.

Draw the live path along the top and the detection path below it, so the two are
visually distinct.

## Nodes

**Live path (top row)**
- `Client` — MCP client (Claude Desktop / Cursor / VS Code)
- `Proxy` — driftsentry run (transparent stdio proxy)
- `Server` — Real MCP server (stdio subprocess)
- `ExchangeLog` — Exchange log (JSONL)

**Detection path (middle)**
- `Daemon` — Daemon (scheduler, 20 s interval)
- `Probes` — Probe engine (seeded canaries)
- `Sandbox` — Sandbox monitor (psutil)
- `Embed` — Embedding backend (ONNX all-MiniLM-L6-v2, 384-dim)
- `Store` — Baseline store (JSON + ChromaDB)
- `Calib` — Calibration record (threshold)
- `Scorer` — Drift scorer + security rules

**Output and control (right / bottom)**
- `Alerts` — Alert log (JSONL, append-only)
- `Policy` — Policy store (trust + enforce)
- `API` — Control API (FastAPI, 127.0.0.1 only)
- `Dash` — Dashboard (pywebview window)

## Edges — direction matters, copy exactly

Use **bidirectional arrows (`<-->`) ONLY** for these four, because each is a real
request/response protocol running in both directions:

| From | To | Label | Why bidirectional |
|---|---|---|---|
| `Client` | `Proxy` | `MCP over stdio` | JSON-RPC: client sends requests, server sends responses and notifications back. The proxy runs two independent forwarding loops, one per direction |
| `Proxy` | `Server` | `MCP over stdio` | Same reason — the proxy is a client to the real server |
| `Probes` | `Server` | `separate out-of-band session` | The probe engine is itself an MCP client: it sends `tools/call`, the server replies |
| `Dash` | `API` | `HTTP on loopback` | Request/response over HTTP |

Use **single arrows (`-->`)** for everything else. Direction is the direction
data actually moves:

| From | To | Label |
|---|---|---|
| `Proxy` | `ExchangeLog` | `writes every message` |
| `Policy` | `Proxy` | `read per call (only if enforce=on)` |
| `Daemon` | `Probes` | `triggers on schedule` |
| `Probes` | `Embed` | `response text` |
| `Embed` | `Probes` | `384-dim vector` |
| `Probes` | `Store` | `writes baseline at approval` |
| `Store` | `Probes` | `reads stored probes at re-check` |
| `Probes` | `Scorer` | `measurement` |
| `Sandbox` | `Probes` | `hosts contacted, files opened` |
| `Calib` | `Scorer` | `threshold` |
| `Scorer` | `Alerts` | `on transition into alert` |
| `Scorer` | `Daemon` | `verdict + score` |
| `Alerts` | `Policy` | `marks server quarantined` |
| `Daemon` | `API` | `state snapshot` |
| `API` | `Daemon` | `commands` |

Use a **dotted arrow (`-.->`)** for exactly one edge, because nothing is sent —
it is pure observation:

| From | To | Label |
|---|---|---|
| `Sandbox` | `Server` | `observes process` |

## Layout and styling

- `flowchart LR`, left to right.
- Put the live path in a subgraph labelled **"Live data path (passive)"**.
- Put the detection path in a subgraph labelled **"Detection path (out of band, scheduled)"**.
- Put `API` and `Dash` in a subgraph labelled **"Control plane (loopback only)"**.
- Draw the four datastores (`ExchangeLog`, `Store`, `Calib`, `Alerts`, `Policy`)
  with a distinct shape — use `[(cylinder)]` notation.
- Keep every label short. No sentences inside boxes.
- No colours beyond light fills; this is going in a printed dissertation.

## Do not

- Do not add a database server, cloud service, load balancer, message queue,
  authentication service or user icon. None exists. Everything runs as local
  processes on one machine.
- Do not add an LLM or AI model box anywhere in the scoring path. The detector
  is deterministic — arithmetic and regular expressions only. The only model is
  the sentence-embedding model, already listed as `Embed`.
- Do not merge the proxy and the daemon. They are separate and the separation is
  the point.
- Do not draw an arrow from `Proxy` to `Probes` or `Scorer`. The proxy feeds only
  the exchange log.

---

# BRIEF B — Concept map

> Copy everything between the lines into ChatGPT.

---

I need a **concept map** (Novak-style), not a flowchart and not an architecture
diagram. Please output it as **Mermaid `flowchart TD` code**.

## What makes this a concept map, not a flowchart

- Nodes are **concepts** — nouns or noun phrases, never actions or steps.
- Every arrow carries a **linking phrase** so that *concept → linking phrase →
  concept* reads as a complete sentence (a "proposition").
- Layout is **hierarchical**: the most general concept at the top, becoming more
  specific downward.
- **Cross-links** between different branches are expected and valuable — they
  show integrated understanding rather than a simple tree.

Test every arrow by reading it aloud as a sentence. If it doesn't read as one,
the linking phrase is wrong.

## Root concept

**Behavioural rug pull in MCP** — at the top.

## The four branches, and their propositions

Build these exact propositions. Keep the linking phrases on the arrows.

**Branch 1 — the threat**
- Behavioural rug pull in MCP → *is a* → Post-approval attack
- Post-approval attack → *exploits* → Trust On First Use
- Behavioural rug pull in MCP → *keeps unchanged* → Tool definition
- Tool definition → *is verified by* → Hash pinning
- Hash pinning → *is therefore blind to* → Behavioural rug pull in MCP  (this is a cross-link back to the root — draw it as a dashed arrow)

**Branch 2 — the detection mechanism**
- Behavioural rug pull in MCP → *is detected by* → Behavioural baseline
- Behavioural baseline → *is captured at* → Approval time
- Behavioural baseline → *is built from* → Canary probes
- Canary probes → *are derived from* → Tool JSON Schema
- Canary probes → *are made reproducible by* → Seeding
- Behavioural baseline → *models* → Benign variance
- Benign variance → *is estimated by* → Leave-one-out cross-validation
- Behavioural baseline → *is re-verified by* → Scheduled re-probing

**Branch 3 — turning observation into a decision**
- Scheduled re-probing → *produces* → Drift score
- Drift score → *combines* → Embedding distance
- Drift score → *combines* → Security rules
- Drift score → *combines* → Side-effect evidence
- Embedding distance → *is scaled by* → Benign variance  (cross-link to branch 2, dashed)
- Security rules → *fire only on* → Behaviour new since baseline
- Drift score → *is compared against* → Calibrated threshold
- Calibrated threshold → *is derived only from* → Benign traffic
- Benign traffic → *must include* → Benign updates
- Drift score → *combines signals by* → Maximum, not sum

**Branch 4 — limits**
- Behavioural baseline → *cannot detect* → Server malicious from the start
- Server malicious from the start → *is a consequence of* → Trust On First Use
  (cross-link to branch 1, dashed)
- Canary probes → *can be recognised by* → Probe-aware attacker
- Probe-aware attacker → *is mitigated by* → Randomised probe templates
- Randomised probe templates → *are* → Not yet implemented

## Styling

- `flowchart TD`.
- Concepts in rounded boxes. Linking phrases as edge labels only — never inside a box.
- Draw the five cross-links with dashed arrows (`-.->`) so they are visually
  distinct from the main hierarchy.
- Give the four branches subtly different fills; keep it print-safe.
- Do not add concepts I have not listed.

---

## After you have the Mermaid code

1. Paste it at `https://mermaid.live`
2. Fix any layout crowding by reordering node declarations (Mermaid lays out in
   declaration order)
3. Export as **SVG** for the dissertation — it stays sharp at any zoom. Export
   PNG at 2× only if your template refuses SVG.
4. Caption both figures properly: *Figure 5.1 — DriftSentry system architecture*,
   *Figure 2.1 — Concept map of behavioural rug-pull detection*. The concept map
   usually belongs in the literature review or introduction, not Chapter 5.

## If you have a reference image you want matched

Attach it and add: *"Match the visual style of the attached image — same box
shapes, arrow weight, and label placement — but use my node and edge lists, not
the content in the image."* Models copy style far more reliably than they invent
it.
