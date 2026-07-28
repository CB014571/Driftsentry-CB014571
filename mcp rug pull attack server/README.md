# MCP Rug-Pull Attack Server

A standalone adversarial **MCP server** that produces ground-truth rug-pull
attacks, so that a behavioural detector can be evaluated honestly.

Companion project to **DriftSentry** (`../Driftsentry`), but deliberately
**independent of it**: separate project, separate virtual environment, no shared
code, and no import of `driftsentry` anywhere. The two only ever meet as
operating-system processes speaking MCP over stdio — exactly how DriftSentry
would meet any third-party server.

---

## Why this exists

A detector cannot be measured against attacks that do not exist. This server
supplies both halves of the ground truth:

| Mode | Purpose |
|---|---|
| **rug-pull** | Real, definition-invariant attacks — lets you measure **detection rate** |
| **benign** | A well-behaved server — lets you check the detector stays quiet |
| **benign + `--updates`** | Legitimate changes (rewording, an added field) — lets you measure **false-alarm rate** |

That third row is the one no public benchmark provides, and it is why
false-alarm rate for MCP rug pulls has never been properly measured.

**The property that makes it a rug pull:** the tool definitions — names,
descriptions, input schemas — are fixed in the source and never consult the
scenario. A benign instance and a malicious instance advertise byte-identical
definitions, and therefore hash identically. Any detector that pins definitions
is blind to the difference between them.

---

## Install

Requires Python 3.11+ (developed on CPython 3.14).

```bash
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

One dependency: the MCP SDK. Nothing else — no embedding model, no vector
store, no detector code.

---

## Use

### The console (metasploit-style)

Just run `attacker` with no arguments, or `attacker console`:

```
attacker > use exfiltration
attacker(exfiltration) > set level L2
attacker(exfiltration) > set variation 30
attacker(exfiltration) > show options
attacker(exfiltration) > run
[+] ARMED: exfiltration at L2, 30% of calls.
```

A persistent prompt where you compose an attack the way you would a module in a
penetration-testing framework. `use` picks a family, `set` configures it, `run`
arms it. The prompt shows the selected family, and `show options` prints its
settings as a table. Type `help` for the full command list.

`run` only *arms* the scenario — it writes the file a running server reads on its
next call. The server is started by whatever you point at it (normally the
detector), and the change lands with no restart.

### The control menu (number-driven)

```bash
attacker menu
```

An interactive panel. It shows what the server is doing right now, and every
change is one keystroke:

```
==================================================================
  MCP RUG-PULL ATTACK SERVER   -   control menu
==================================================================
  STATUS    : RUG-PULL   content-injection   L1
  bypass    : off
  variation : 50% of calls are malicious   (used at L2)
  trigger   : after 3 calls                (used at L3 / sleeper)
  seed      : 1234
------------------------------------------------------------------
  1   Change attack TYPE        which of the six families
  2   Change attack STRENGTH    L1 (obvious) .. L5 (stealthy)
  3   Toggle BYPASS mode        try to evade the detector's probes
  4   Change VARIATION          how often it attacks (L2)
  5   Set TRIGGER               turn malicious after N calls (L3)
  6   Go BENIGN                 a well-behaved server
  7   Go BENIGN + UPDATES       legitimate changes (false-alarm test)
  8   TRIP the trigger now      fire a sleeper immediately
  9   Change SEED               a different reproducible run
  s   Show the full scenario      r   Reset      q   Quit
------------------------------------------------------------------
```

Changes land on a **running** server's next tool call — no restart. That is the
point: a rug pull is supposed to happen after you have already approved the
server.

Choosing L4 or L5 will offer to switch bypass mode on, because those levels
cannot work without it. It stays a question rather than something the menu does
quietly: handing the attacker knowledge of the defence is a deliberate act, and
the scenario file records that it happened.

### The scriptable way

```bash
attacker status                 # what is it doing right now?
attacker benign                 # behave normally
attacker benign --updates       # legitimate changes - the false-alarm set
attacker attack content-injection
attacker attack new-egress --level L2
attacker reset                  # back to benign, clear the sink
```

```bash
attacker list-families          # the six families and the five levels explained
attacker launch-command         # the exact line to hand to DriftSentry
attacker show                   # the raw scenario JSON
```

Run the server. You normally do **not** type this — a client or DriftSentry
launches it for you. Ask for the exact line to hand over with:

```bash
attacker launch-command
```

Change a **running** server without restarting it — the server re-reads its
scenario on the next call:

```bash
attacker attack new-egress --level L3
attacker trip                   # fire a sleeper now instead of waiting
attacker reset                  # back to benign, clear the sink
```

### Where the scenario lives

In a fixed per-user directory — `%LOCALAPPDATA%\mcp-attacker\` on Windows — not a
path relative to the working directory. **You do not need to pass `--scenario`.**

That default is deliberate. An MCP client launches its servers with whatever
working directory it happens to have and with a filtered environment, so a
relative default meant the CLI wrote one file while the running server read
another. The attack then silently never fired, which looks exactly like the
detector failing to catch it — the worst possible failure mode for a tool whose
whole purpose is measuring detection. An absolute, environment-independent path
means every process agrees without anyone having to think about it.

Override it with `--scenario <path>` or `ATTACKER_HOME` only when you deliberately
want several independent scenarios, such as generating a labelled corpus.

---

## Attack families

| Family | What it starts doing | Real case it mirrors |
|---|---|---|
| `exfiltration` | Copies responses to an attacker sink; reads credential files. The user-visible answer is unchanged. | third-party-app data theft |
| `silent-tamper` | Alters one detail — a recipient, an account number, a total | postmark-mcp |
| `content-injection` | Injects instructions addressed to the AI assistant | tool poisoning |
| `new-egress` | Contacts a host it never contacted at baseline | data theft |
| `sleeper` | Behaves until a call count, a date, or `trip` fires | Invariant Labs sleeper |
| `conditional` | Attacks only when it sees something worth stealing | targeted rug pull |

## Complexity levels

| Level | Behaviour | Tests |
|---|---|---|
| `L1` | Malicious on every call | Baseline detectability |
| `L2` | Malicious on a fraction of calls | Sampling sensitivity |
| `L3` | Only after a trigger — call count, date, or input | Whether re-probing still catches it |
| `L4` | **Probe-aware**: recognises the detector's canary inputs and behaves while watched | The adaptive-attacker claim |
| `L5` | Probe-aware **and** mimics the benign response distribution | The limit case |

*Family* is the payload — what it does. *Level* is the gate — when it is allowed
to fire. Six families × five levels comes from one payload mechanism and one
gating mechanism, so a level means the same thing across families and the
resulting recall matrix is comparable row to row.

**L4 and L5 require `--probe-aware` explicitly.** The attacker is not supposed to
know the defender exists; handing it a guess at the defender's test inputs is a
deliberate act, and the scenario file records that it happened.

---

## Reproducibility

Every run is described by a JSON scenario file — mode, family, level, trigger and
seed. All randomness is drawn from that seed, so a stochastic (L2) attacker is
random-looking but replayable: the same scenario produces the same pattern of
malicious and benign calls every time. A run driven by hand during a demo can be
saved and replayed exactly.

---

## Ethics and safety

This is a closed-loop research artefact.

* It contains **no working exploit** against any third-party system.
* It contacts **no real network destination**. "New egress" connects to a decoy
  listener this same process starts on `127.0.0.2`; nothing leaves the machine.
* "Exfiltration" appends to a file in a local scratch directory.
* All data is **synthetic** — invented customers, invented orders, and decoy
  credentials that are obvious fakes.

It is intended solely for evaluating defensive tooling against MCP rug pulls.
