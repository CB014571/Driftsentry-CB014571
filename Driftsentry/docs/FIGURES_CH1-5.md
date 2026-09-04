# Figures and tables required to Chapter 5

Mapped from *FYP Report Structure — Implementation Project* onto DriftSentry.

**M** = mandated by the structure document · **R** = strongly recommended for
this project · **O** = optional if space allows

Status: ✅ you already have it · 🔶 exists but needs rework · ⬜ must create

---

## Three rules from the structure document that change what you can use

**1. "Do not put any table/figure that is not done by you."**
This kills any copied diagram. **Saunders' Research Onion must be redrawn by
you**, not lifted from the paper — cite Saunders et al. (2019) beneath your own
version. Same for any architecture diagram taken from a paper.

**2. "All diagrams must have a small description describing what it
illustrates."** Not just a caption — a sentence or two of body text near the
figure explaining what the reader should take from it.

**3. "Do not put important things in the appendix. Examiners usually do not even
look at the appendix."**
Only the *full-resolution* concept map goes to Appendix I, with a readable
version in Chapter 2. Nothing else that matters should be exiled there.

---

## Numbering — decide this before you start

Your current proposal uses **flat numbering** (Figure 1 … Figure 12). The
structure document uses **chapter-based numbering** (Figure 2.1, Table 3.2,
Figure 5.1).

**Switch to chapter-based.** It matches the structure document, it survives
insertion of a new figure without renumbering everything, and Word's caption
feature handles it automatically.

Mapping from what you have now:

| Now | Becomes |
|---|---|
| Figure 1 | Figure 1.1 |
| Figure 2 | Figure 1.2 |
| Figure 3 | Figure 2.1 |
| Figure 4 | Figure 3.1 |
| Figure 5 | Figure 3.3 |
| Figure 6 | Figure 3.4 |
| Figures 7–12 | Chapter 5 (renumbered below) |

---

## CHAPTER 1 — INTRODUCTION (~4–5 pages)

The structure mandates **no** figures here. At 4–5 pages, two is the sensible
maximum — more and the chapter becomes illustrations with captions.

| ID | Title | Type | Section | Pri | Status |
|---|---|---|---|---|---|
| Figure 1.1 | How an LLM agent uses context to call tools via MCP | Diagram | 1.2.1 | R | ✅ |
| Figure 1.2 | Behavioural rug pull on an approved MCP tool | Diagram | 1.2.2 | R | ✅ |

**Figure 1.2 is doing the heavy lifting in your whole report.** It must show the
tool definition staying identical while behaviour changes. If a reader
understands only one diagram, this is the one that has to work.

Nothing else. Research questions, gaps and objectives are lists, not figures.

---

## CHAPTER 2 — LITERATURE REVIEW (~15 pages)

| ID | Title | Type | Section | Pri | Status |
|---|---|---|---|---|---|
| Figure 2.1 | Concept map of the research domain | Diagram | 2.2 | **M** | ✅ |
| Figure 2.2 | Proposed conceptual architecture | Diagram | 2.3.4 | **M** | ⬜ |
| Table 2.1 | Comparison of existing MCP security defences | Table | 2.5.3 | **R** | ⬜ |
| Table 2.2 | Evaluation approaches and datasets in prior work | Table | 2.6 | **R** | ⬜ |
| Figure 2.3 | Taxonomy of rug-pull types | Diagram | 2.3.1 | O | ⬜ |

### Figure 2.1 — Concept map
You have this. Section 2.2 says insert a readable version here and cross-
reference the full-resolution one in Appendix I. Do exactly that.

### Figure 2.2 — Proposed conceptual architecture ⬜
**This is not the same as your Chapter 3 architecture diagram.** Section 2.3.4
wants a *conceptual* positioning diagram — the bridge from "here are the domain
challenges" to "here is my shape of answer". Boxes and relationships, no file
names, no implementation detail. Chapter 3's version is the detailed one.

### Table 2.1 — Comparison of existing defences ⬜
Your strongest table in the whole report. Suggested columns:

| System | Approach | Verifies | Blind to behavioural rug pull? |
|---|---|---|---|
| mcp-scan | Definition hash pinning | Declaration | Yes |
| ETDI | OAuth + immutable versioned definitions | Declaration | Yes |
| MCP-SandboxScan | WASM runtime analysis | Runtime, one-shot | Yes — no temporal baseline |
| Runtime Skill Audit | Runtime probing of agent skills | Runtime, classification | Different substrate |
| MCP Manager (commercial) | Metadata pinning | Declaration | Yes |
| **DriftSentry** | Approval-time behavioural baseline | Behaviour over time | — |

That last column is your research gap made visible in one glance.

### Table 2.2 — Evaluation approaches ⬜
Section 2.6 asks you to critically assess how existing work is evaluated —
datasets, benchmarks, metrics, limitations. A table makes the absence of any
shared MCP rug-pull dataset obvious, which is gap G3.

---

## CHAPTER 3 — METHODOLOGY (~6 pages)

Six pages is tight. Be disciplined — the resource lists can be bullets rather
than tables if space runs short.

| ID | Title | Type | Section | Pri | Status |
|---|---|---|---|---|---|
| Figure 3.1 | Saunders' research onion applied to this project | Diagram | 3.2 | **M** | 🔶 |
| Figure 3.2 | Phase-gated development model | Diagram | 3.3 | R | ⬜ |
| Table 3.1 | Project schedule (Gantt) | Table | 3.4.1 | **M** | ⬜ |
| Table 3.2 | Deliverables and dates | Table | 3.4.2 | **M** | ⬜ |
| Table 3.3 | Hardware resources | Table | 3.4.3.1 | R | ⬜ |
| Table 3.4 | Software resources | Table | 3.4.3.2 | R | ⬜ |
| Table 3.5 | New technical skills acquired | Table | 3.4.3.3 | O | ⬜ |
| Table 3.6 | Data requirements | Table | 3.4.4 | R | ⬜ |
| Table 3.7 | Risks and mitigation | Table | 3.4.5 | **M** | ⬜ |
| Figure 3.3 | High-level architecture of the DriftSentry proxy | Diagram | 3.5.1 | **M** | ✅ |
| Figure 3.4 | Data flow of the canary probe and drift check | Diagram | 3.5.3 | **M** | ✅ |
| Figure 3.5 | Worked example: benign check versus rug-pull check | Sequence | 3.5.6 | R | ⬜ |

### Figure 3.1 — Saunders' onion 🔶
You have one, but **check you drew it yourself**. If it came from the textbook or
a lecture slide, redraw it. The structure document treats copied figures as an
attempt to cheat. Your version should show only *your* choices highlighted on
each layer, with Saunders et al. (2019) cited beneath.

### Table 3.3 — Hardware ⬜
Straight from your machine:

| Component | Specification |
|---|---|
| Machine | LENOVO 83F2 |
| CPU | AMD Ryzen 9 9955HX, 16 cores / 32 threads |
| Memory | 31.3 GB |
| OS | Windows 11 Home Single Language 10.0.26200, x64 |
| Storage | Local SSD; no cloud or GPU resources used |

**Note the absence of a GPU deliberately** — it supports your claim that the
system runs on ordinary hardware.

### Table 3.4 — Software ⬜
Python 3.14.6, `mcp` 1.28.1, `chromadb` 1.5.9, `numpy` 2.5.1, `httpx` 0.28.1,
`rich` 15.0.0, `psutil` 7.2.2, `fastapi` 0.140.13, `pywebview` 6.2.1,
`onnxruntime` 1.27.0, `pytest` 9.1.1, Git, VS Code.

### Table 3.6 — Data requirements ⬜
Important for your project because you have **no external dataset**. Say so
explicitly: all data is synthetic and generated by your own adversarial server —
which removes GDPR and licensing concerns entirely, and is worth stating as a
strength rather than an omission.

### Table 3.7 — Risks ⬜
Use real ones from your project, not generic filler:

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Experiments do not complete before deadline | High | High | Harness runs unattended; quick-sweep mode gives a complete summary in minutes |
| Calibration too weak to quote | **Occurred** | Medium | Tool self-flags `weak`; collect ≥3 servers |
| Adaptive attacker evades detection | **Occurred** | High | Measured, then closed with keyed probes |
| False alarms rise as signals are added | Medium | High | Signals added one at a time, each calibrated separately |
| Hardware failure loses experimental data | Medium | Medium | Results flushed to CSV per row; Git |

Two of those already happened. Saying so is far stronger than a hypothetical
risk register — it shows the register was real.

---

## CHAPTER 4 — LESP (~2 pages)

Two pages. The structure mandates **no** figures.

| ID | Title | Type | Section | Pri | Status |
|---|---|---|---|---|---|
| Table 4.1 | LESP issues, implications and mitigations | Table | 4.7 | O | ⬜ |

One optional summary table at most. If you include anything visual, make it a
short code excerpt showing the closed-loop safety design — `DECOY_HOST =
"127.0.0.2"` and the obviously-fake credentials — since that is the concrete
evidence behind your ethics claim.

---

## CHAPTER 5 — IMPLEMENTATION (~10 pages)

The structure mandates three items. Your project needs more, but **stay under
about twelve** or the chapter becomes an album.

| ID | Title | Type | Section | Pri | Status |
|---|---|---|---|---|---|
| Table 5.1 | Technology stack summary | Table | 5.2 | **M** | ⬜ |
| Table 5.2 | Attack families and their mechanisms | Table | 5.3 | **R** | ⬜ |
| Table 5.3 | Complexity levels L1–L5 | Table | 5.3 | **R** | ⬜ |
| Figure 5.1 | Scenario file structure (real example) | Listing | 5.3 | R | ⬜ |
| Figure 5.2 | Proxy interception — two-pump forwarding | Code | 5.4.1 | **M** | ⬜ |
| Figure 5.3 | Baseline record schema (real JSON) | Listing | 5.4.2 | R | ⬜ |
| Figure 5.4 | Leave-one-out variance estimation | Code | 5.4.2 | R | ⬜ |
| Table 5.4 | Drift signal weights | Table | 5.4.3 | **R** | ⬜ |
| Figure 5.5 | Calibration record showing the weak flag | Listing | 5.4.3 | R | ⬜ |
| Figure 5.6 | Dashboard overview, normal state | Screenshot | 5.5 | **M** | ⬜ |
| Figure 5.7 | Drift graph across attack and recovery | Screenshot | 5.5 | **R** | ⬜ |
| Figure 5.8 | Opened alert with before/after | Screenshot | 5.5 | R | ⬜ |
| Figure 5.9 | Full detector vs hash-only control | Terminal | 5.4.5 | **R** | ⬜ |
| Figure 5.10 | Self-test and unit test suite | Terminal | 5.4.6 | R | ⬜ |
| Figure 5.11 | Evaluation harness classifying episodes | Terminal | 5.4.6 | R | ⬜ |
| Table 5.5 | Implementation status by component | Table | 5.8 | **R** | ⬜ |

### Table 5.1 — Technology stack (mandated)
Component · Name and version · Role · Justification. The justification column is
what earns marks — it is where you show you compared alternatives.

### Figure 5.9 — Hash-only vs full detector ⬜
**The single most important figure in your report.** Same server, same traffic,
same code path — the control reports nothing, the detector alerts. If you have
time for only one Chapter 5 screenshot, make it this one.

### Figures 5.6–5.11
These are the six screenshots from your earlier guide, renumbered. The capture
instructions in `SCREENSHOT_GUIDE.md` still apply.

### Table 5.5 — Implementation status ⬜
Built / Partial / Not built, one line of evidence each. Given the midpoint
framing, this table is doing real work — it is where you are honest about the
evaluation being incomplete, in a form an examiner can scan.

---

## Totals and page budget

| Chapter | Figures | Tables | Pages | Rough space |
|---|---|---|---|---|
| 1 | 2 | 0 | 4–5 | ~⅔ page |
| 2 | 2–3 | 2 | 15 | ~2 pages |
| 3 | 3–4 | 5–7 | 6 | ~2½ pages |
| 4 | 0 | 0–1 | 2 | minimal |
| 5 | 8–10 | 5 | 10 | ~4 pages |
| **To Ch5** | **15–19** | **12–15** | **~37** | **~9 pages** |

You have a **60-page budget** for introduction to conclusion. Chapters 1–5 take
roughly 37, leaving about 23 for Chapters 6 and 7 — which is enough, but only if
figures stay disciplined. Every figure you add past this list costs you space in
the results chapter, which is where the marks are.

---

## What to create, in priority order

**Must create before submission (mandated):**
1. Figure 2.2 — conceptual architecture
2. Table 3.1 — Gantt chart
3. Table 3.2 — deliverables and dates
4. Table 3.7 — risks and mitigation
5. Table 5.1 — technology stack
6. Figures 5.2 — code snippet
7. Figure 5.6 — UI screenshot

**High value, create next:**
8. Table 2.1 — comparison of existing defences *(your research gap in one table)*
9. Figure 5.9 — hash-only vs full *(your strongest evidence)*
10. Table 5.4 — signal weights
11. Table 5.5 — implementation status

**Check, do not assume:**
12. Figure 3.1 — Saunders' onion. **Confirm you drew it.** A copied version is
    treated as cheating under the structure document's own wording.

---

## Two traps specific to your report

**Your existing Figure 5 may need splitting.** The structure wants a *conceptual*
architecture in Chapter 2 (Figure 2.2) and a *detailed* one in Chapter 3
(Figure 3.3). Reusing the identical image in both places wastes a figure slot and
reads as padding. Make the Chapter 2 version simpler — four or five boxes.

**Chapter 4 at two pages cannot carry figures.** Resist adding them. Your LESP
evidence is prose plus at most one short code excerpt showing the closed-loop
design.
