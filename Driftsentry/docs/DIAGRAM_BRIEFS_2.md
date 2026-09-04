# Diagram briefs — Figures 2.2, 3.1 and 3.2

Companion to `DIAGRAM_BRIEFS.md`, which already covers Figure 2.1 (concept map)
and Figure 3.3 (detailed architecture).

**Ask for Mermaid code, not a picture.** Image generation garbles labels and
arrowheads. Generated Mermaid renders at `mermaid.live` and exports as SVG, which
stays sharp at any size in Word. The one exception is Figure 3.1 — see below.

**Rule from the structure document:** *"Do not put any table/figure that is not
done by you."* Generating the code yourself and rendering it counts as your own
work. Downloading someone's diagram does not.

---

# BRIEF A — Figure 2.2: Proposed conceptual architecture

> Copy everything between the lines into ChatGPT or Claude.

---

I need a **conceptual** architecture diagram for a literature review chapter.
Output **Mermaid `flowchart TD` code**, not an image.

## Context

My project, DriftSentry, detects "behavioural rug pull" attacks against Model
Context Protocol servers. A user approves a tool once, based on its advertised
name, description and input schema. A malicious server can later change what the
tool *does* while keeping that advertised definition byte-for-byte identical, so
every existing defence — which pins the definition — is blind to it.

## What this diagram is, and is NOT

This is the **positioning** diagram that closes my problem-domain review. It
bridges from "here are the challenges in this domain" to "here is the shape of my
answer". It is deliberately abstract.

It is **NOT** a system architecture diagram. A separate, detailed one appears in
my methodology chapter. So:

- **No** file names, class names, module names or library names
- **No** implementation detail, no data formats, no protocols
- Four or five conceptual layers only
- A reader should grasp it in about ten seconds

## Structure — four capability layers

Draw these top to bottom, each as a labelled box, with a downward arrow between
consecutive layers:

1. **Observation point** — a transparent position in the tool-invocation path
2. **Approval-time behavioural baseline** — what the tool did when it was trusted
3. **Periodic re-verification** — checking that behaviour still holds
4. **Deterministic scoring and alerting** — a reproducible, attributable verdict

## The domain challenges, on the left

Put these four in a separate vertical group to the left, and draw one dashed
arrow from each challenge to the layer that addresses it:

| Challenge | Addresses |
|---|---|
| The advertised definition is not the behaviour | Layer 2 |
| Approval happens once; behaviour continues to change | Layer 3 |
| Legitimate updates resemble attacks | Layer 4 |
| Verification itself can be recognised and evaded | Layer 3 |

Label each dashed arrow with the single word `addresses`.

## Styling

- `flowchart TD`
- Group the four challenges in a subgraph titled **"Domain challenges"**
- Group the four layers in a subgraph titled **"Proposed approach"**
- Solid arrows for the vertical flow between layers; dashed for `addresses`
- Rounded boxes; no colour beyond very light fills — this is printed in a
  dissertation
- Keep every label to at most five words

## Do not

Do not add: a database, a cloud service, a user icon, an LLM box, any named
technology, or any arrow I have not specified.

---

# BRIEF B — Figure 3.2: Phase-gated development model

> Copy everything between the lines.

---

I need a diagram of a phase-gated software development model for a methodology
chapter. Output **Mermaid `flowchart LR` code**, not an image.

## What it shows

My project was built in ten sequential phases. Each phase has an **executable
definition-of-done check** — a script that exercises the real code end to end —
and a phase is not complete until its check passes. This diagram shows that
structure and my current position in it.

## The phases

| # | Phase | Status |
|---|---|---|
| 0 | Environment and protocol verification | complete |
| 1 | Transparent interception proxy | complete |
| 2 | Client configuration ingestion | complete |
| 3 | Behavioural baseline capture | complete |
| 4 | Drift scoring and calibration | complete |
| 5 | Alerting and mitigation | complete |
| 6 | Monitoring daemon and interface | complete |
| 7 | Adversarial server | complete |
| 8 | Labelled corpus construction | in progress |
| 9 | Controlled experiments | in progress |
| 10 | Analysis and write-up | not started |

## Layout

- Left to right, phases 0 through 10 in sequence, one box each
- A small gate symbol or diamond between consecutive phases, labelled
  `definition-of-done check`
- Rather than eleven gates cluttering the diagram, draw the gate **once** between
  phases 0 and 1, then use a plain arrow for the rest, and add a note that the
  same gate applies throughout
- Wrap phases 0–7 in a subgraph titled **"Complete"**
- Wrap phases 8–9 in a subgraph titled **"In progress"**
- Phase 10 stands alone, titled **"Remaining"**

## Styling

- `flowchart LR`
- Distinguish the three groups by fill only — light green, light amber, light
  grey — no bright colours
- Phase names abbreviated to at most four words
- Include the phase number in each box

## Do not

Do not add feedback loops, iteration arrows or a spiral. This is a linear
phase-gated model, not Agile — that distinction is the point of the figure.

---

# BRIEF C — Figure 3.1: Saunders' research onion

**Mermaid cannot draw concentric rings.** Do not try. Use one of these instead.

## Option 1 — draw.io (recommended, ~20 minutes)

1. Go to `app.diagrams.net`
2. Draw six concentric circles, largest first, using **Ellipse** with
   Shift held to keep them circular
3. Set each to no fill, 1.5 pt outline
4. Label each ring at its top edge with the layer name
5. Place your own choice on the ring, in **bold**, and the alternatives you
   rejected in grey around it
6. Export as **SVG**

## Option 2 — ask a model for SVG

> Generate an SVG of six concentric circles forming a research-onion diagram.
> Outer to inner: Philosophy, Approach, Strategy, Methodological choice, Time
> horizon, Techniques and procedures. Each ring labelled at its top edge, with
> space for three or four short text items positioned around the ring. No fill,
> 1.5 pt black outlines, 900 × 900 viewBox, text in a serif font at 14 px.
> Output raw SVG only.

Then edit the text in any editor to insert your own choices.

## What to put on each ring

Use whatever you already wrote in your proposal. If you have not decided, these
are defensible for this project — but **only claim what you can justify aloud**:

| Ring | Likely choice | Why it fits |
|---|---|---|
| Philosophy | Positivism | Measurements are objective, numeric and reproducible; the detector is deterministic by design |
| Approach | Deductive | A stated hypothesis — behavioural baselining detects definition-invariant rug pulls — tested by controlled experiment |
| Strategy | Experiment | Controlled comparison against a hash-only control on identical traffic |
| Methodological choice | Mono-method quantitative | Recall, false-alarm rate, time-to-detection; no qualitative instrument |
| Time horizon | Cross-sectional | Measured over a fixed experimental window, not longitudinally |
| Techniques | Synthetic adversarial data generation; controlled experiments; unit and regression testing | Ground truth generated by an adversarial server; 177 automated tests |

## The important part

**Highlight only your choices.** A generic onion reproducing the textbook adds
nothing and risks being read as copied. Yours should make your six decisions
visible at a glance, with the rejected alternatives greyed out around them.

Cite `Saunders et al. (2019)` in the caption, beneath your own drawing.

---

# After generating any of these

1. Paste the Mermaid at `https://mermaid.live`
2. If it looks crowded, reorder the node declarations — Mermaid lays out in
   declaration order
3. Export **SVG** for Word; PNG at 2× only if your template refuses SVG
4. In Word: right-click the image → **Insert Caption** → **Below selected item**
5. Add two sentences of body text near the figure explaining what it shows —
   the structure document requires this for every diagram

## Check before you accept the output

| Check | Why |
|---|---|
| Every box I specified is present, nothing extra | Models add plausible-looking boxes you did not ask for |
| Arrow directions match the brief exactly | The most common silent error |
| No implementation detail in Figure 2.2 | It is a conceptual diagram; detail belongs in 3.3 |
| No iteration loops in Figure 3.2 | Phase-gated, not Agile |
| Text is readable when the figure is one page wide | Print one page and look at it |
