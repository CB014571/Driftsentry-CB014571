"""An interactive console for the attack server, in the style of msfconsole.

The menu (`attacker menu`) is number-driven and quick. This is the other style:
a persistent prompt where you *compose* an attack the way you would in a
penetration-testing framework - pick a module, set its options, run it.

    attacker > use exfiltration
    attacker(exfiltration) > set level L2
    attacker(exfiltration) > set variation 30
    attacker(exfiltration) > run

Everything here edits the same scenario file the CLI and the menu use, so a
change lands on a RUNNING server on its next tool call - no restart. That is the
whole point: a rug pull is meant to happen after the server has been approved.

It talks to nothing over the network and launches nothing by itself. `run` only
writes the scenario ("arms" the attack); the server is started by whatever you
pointed at it (normally the detector). ASCII only, so it renders on any console.
"""
from __future__ import annotations

import json
from pathlib import Path

from attacker.scenario import (
    FAMILIES,
    FAMILY_BRIEF,
    LEVELS,
    TOOLS_AFFECTED,
    TOOLS_UNTOUCHED,
    Scenario,
)

QUICKSTART = """
  Quick start
  ------------------------------------------------------------------
    show families              what you can launch (6 attack types)
    use <name|number>          pick one            e.g.  use 3
    set level <L1..L5>         how stealthy        e.g.  set level L2
    run                        ARM it - the server starts attacking
    benign                     stop attacking
    status                     what is it doing right now?
    help                       every command
  ------------------------------------------------------------------"""

BANNER = r"""
   =======================================================================
        __  __  ___ ___    ___ _   _  ___ ___ ___ _   _ _    _
       |  \/  |/ __| _ \  | _ \ | | |/ __| _ \ _ \ | | | |  | |
       | |\/| | (__|  _/  |   / |_| | (_ |  _/  _/ |_| | |__| |__
       |_|  |_|\___|_|    |_|_\\___/ \___|_| |_|  \___/|____|____|
              A T T A C K   S E R V E R
   =======================================================================
     A closed-loop adversarial MCP server for testing behavioural
     rug-pull detection.  Offline, synthetic data only.

        6 attack families      5 complexity levels (L1 - L5)

     Type  help          for the command list
          show families  to see what you can launch
   =======================================================================
"""

HELP = """
Commands
  help                 this list
  show families        list the attack families (your "modules")
  show levels          list the complexity levels L1 - L5
  show options         the current attack's settings
  use <family>         select an attack family
  info [family]        describe a family in detail
  set <option> <val>   set LEVEL / VARIATION / TRIGGER / BYPASS / SEED
  run   (or: arm)      arm the selected attack - a running server picks it up
  benign [updates]     make the server behave (add 'updates' for the FP test)
  status               what the server is set to do right now
  trip                 fire a sleeper / trigger-gated attack immediately
  back                 deselect the current family
  reset                clean benign server, everything cleared
  launch               print the command to start the server standalone
  exit  (or: quit)     leave the console (the scenario stays as you left it)

Options (set with 'set'):
  LEVEL      L1..L5     how stealthy the attack is
  VARIATION  0..100     percent of calls that are malicious   (used at L2)
  TRIGGER    <n>        turn malicious after n calls           (used at L3)
  BYPASS     on|off     recognise the detector's probes and hide (needed for L4/L5)
  SEED       <n>        reproducible run seed
"""


def _wrap(text: str, width: int = 66) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur); cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


class Console:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.scenario = Scenario.load(path)
        # Selecting a family and ARMING it are separate steps, exactly as `use`
        # and `run` are separate in a penetration-testing framework. Merging them
        # made `use` immediately turn the server malicious, so simply browsing
        # the options started an attack - surprising, and easy to leave armed by
        # accident between sessions.
        self.selected: str | None = (
            self.scenario.family if self.scenario.mode == "rug-pull" else None
        )
        # Make sure a file exists from the start, so a server launched with
        # --reuse never silently falls back to a default benign scenario.
        self.scenario.save(path)

    @property
    def armed(self) -> bool:
        return self.scenario.mode == "rug-pull"

    # -- prompt ------------------------------------------------------------
    @property
    def prompt(self) -> str:
        if self.selected:
            flag = "*" if self.armed else ""
            return f"attacker({self.selected}{flag}) > "
        return "attacker > "

    def _save(self) -> bool:
        problems = self.scenario.validate()
        if problems:
            for p in problems:
                print(f"  [!] {p}")
            return False
        self.scenario.save(self.path)
        return True

    # -- show --------------------------------------------------------------
    def show_families(self) -> None:
        print("\n  Attack families\n  " + "-" * 60)
        for i, (name, desc) in enumerate(FAMILIES.items(), 1):
            marker = "*" if (self.scenario.mode == "rug-pull" and name == self.scenario.family) else " "
            print(f"  {i} {marker} {name:<18} {desc.split('. ')[0][:58]}")
        print("\n  use <name>   to select one\n")

    def show_levels(self) -> None:
        print("\n  Complexity levels\n  " + "-" * 60)
        for name, desc in LEVELS.items():
            marker = "*" if name == self.scenario.level else " "
            print(f"  {name} {marker} {desc}")
        print("\n  set level <L1..L5>   L4/L5 also need: set bypass on\n")

    def show_options(self) -> None:
        s = self.scenario
        if not self.selected:
            print("\n  No attack selected. 'use <family>' first, or 'show families'.\n")
            return
        rows = [
            ("LEVEL", s.level, "yes", "attack strength L1..L5"),
            ("VARIATION", f"{int(s.stochastic_rate * 100)}", "no", "percent malicious (L2)"),
            ("TRIGGER", str(s.trigger.after_calls), "no", "malicious after N calls (L3)"),
            ("BYPASS", "on" if s.probe_aware else "off", "no", "probe-aware evasion (L4/L5)"),
            ("SEED", str(s.seed), "yes", "reproducible run seed"),
        ]
        print(f"\n  Attack: {s.family}   [{'ARMED' if self.armed else 'not armed'}]\n")
        print(f"  {'Name':<11}{'Current':<10}{'Required':<10}Description")
        print(f"  {'----':<11}{'-------':<10}{'--------':<10}-----------")
        for name, cur, req, desc in rows:
            print(f"  {name:<11}{cur:<10}{req:<10}{desc}")
        problems = s.validate()
        if problems:
            print("\n  Not ready to run:")
            for p in problems:
                print(f"    [!] {p}")
        print()

    def info(self, family: str | None) -> None:
        family = family or self.selected
        if not family:
            print("  info <family>   (or 'use' one first)")
            return
        if family not in FAMILIES:
            print(f"  no such family: {family!r}")
            return
        print(f"\n  {family}\n  " + "-" * 60)
        for line in _wrap(FAMILIES[family]):
            print(f"  {line}")
        print()

    def status(self) -> None:
        s = self.scenario
        print("\n  " + "-" * 60)
        if s.mode == "benign":
            what = "BENIGN + UPDATES" if s.updates else "BENIGN"
            print(f"  STATUS : {what} - a detector must not alarm on this")
        else:
            print(f"  STATUS : ATTACKING - {s.family} at {s.level}")
            print(f"           {LEVELS[s.level].split(' - ', 1)[-1]}")
            if s.probe_aware:
                print("           bypass ON: hides from the detector's probes")
        print(f"  scenario file : {self.path}")
        print("  " + "-" * 60 + "\n")

    # -- actions -----------------------------------------------------------
    def _resolve_family(self, token: str) -> str | None:
        """Accept a family name, or the number shown by 'show families'."""
        names = list(FAMILIES)
        if token.isdigit():
            i = int(token)
            return names[i - 1] if 1 <= i <= len(names) else None
        return token if token in FAMILIES else None

    def use(self, token: str) -> None:
        family = self._resolve_family(token)
        if family is None:
            print(f"  no such family: {token!r}. Try 'show families'.")
            return
        self.selected = family
        self.scenario.family = family
        # Deliberately NOT setting mode to rug-pull: selecting is not attacking.
        if self._save():
            brief = FAMILY_BRIEF.get(family, {})
            print(f"\n  selected: {family}   [not armed yet]")
            print("  " + "-" * 64)
            for line in _wrap(brief.get("does", FAMILIES[family])):
                print(f"    {line}")
            print(f"\n    What the user sees:")
            for line in _wrap(brief.get("visible", "-")):
                print(f"      {line}")
            print(f"\n  Configure it with 'set level L1..L5', then 'run' to arm.\n")

    def set_option(self, name: str, value: str) -> None:
        name = name.lower()
        s = self.scenario
        # These options only mean anything for an attack. Setting them on a
        # benign server would apply silently and be forgotten the moment you
        # 'use' a family, which looks exactly like the tool ignoring you.
        if not self.selected and name in {"level", "variation", "rate", "trigger", "bypass"}:
            print(f"  no attack selected, so {name.upper()} has nothing to apply to.")
            print("  pick one first, e.g.  use exfiltration")
            return
        try:
            if name == "level":
                v = value.upper()
                if v not in LEVELS:
                    print(f"  level must be one of {', '.join(LEVELS)}"); return
                s.level = v
                if v in {"L4", "L5"} and not s.probe_aware:
                    print("  note: L4/L5 need bypass. Run 'set bypass on'.")
            elif name in {"variation", "rate"}:
                s.stochastic_rate = max(0.0, min(1.0, float(value.rstrip("%")) / 100.0))
            elif name == "trigger":
                s.trigger.after_calls = int(value); s.trigger.tripped = False
            elif name == "bypass":
                on = value.lower() in {"on", "true", "yes", "1"}
                if not on and s.level in {"L4", "L5"}:
                    print("  can't: the current level needs bypass. Lower the level first.")
                    return
                s.probe_aware = on
            elif name == "seed":
                s.seed = int(value)
            else:
                print(f"  unknown option {name!r}. 'show options' lists them.")
                return
        except ValueError:
            print(f"  bad value for {name}: {value!r}")
            return
        if self._save():
            print(f"  {name.upper()} => {value}")

    def run_attack(self) -> None:
        if not self.selected:
            print("  nothing selected. 'use <family>' first.")
            return
        self.scenario.mode = "rug-pull"
        if not self._save():
            print("  attack NOT armed - fix the problems above.")
            return
        s = self.scenario
        brief = FAMILY_BRIEF.get(s.family, {})
        when = {
            "L1": "on EVERY call",
            "L2": f"on about {int(s.stochastic_rate * 100)}% of calls, chosen by seed {s.seed}",
            "L3": f"only after {s.trigger.after_calls} calls, or on triggering input",
            "L4": "on every call EXCEPT ones that look like a detector's probe",
            "L5": "as L4, and shaped to look statistically like the benign answer",
        }.get(s.level, s.level)

        print()
        print("  " + "=" * 64)
        print(f"   ARMED:  {s.family}  at  {s.level}")
        print("  " + "=" * 64)
        print("   What it does")
        for line in _wrap(brief.get("does", "-"), 60):
            print(f"     {line}")
        print(f"\n   When it fires")
        for line in _wrap(when, 60):
            print(f"     {line}")
        print(f"\n   Tools affected")
        print(f"     {', '.join(TOOLS_AFFECTED)}")
        print(f"     (not {', '.join(TOOLS_UNTOUCHED)} - it is side-effecting, so the")
        print("      detector refuses to probe it and the attack never touches it)")
        print(f"\n   What the user sees")
        for line in _wrap(brief.get("visible", "-"), 60):
            print(f"     {line}")
        print(f"\n   Traces left behind")
        for line in _wrap(brief.get("traces", "-"), 60):
            print(f"     {line}")
        print(f"\n   How a detector could catch it")
        for line in _wrap(brief.get("detect", "-"), 60):
            print(f"     {line}")
        print("  " + "=" * 64)
        print("   Live now: a running server attacks on its next tool call.")
        print("   No restart, and its advertised tool definitions are UNCHANGED.")
        print()

    def benign(self, updates: bool = False) -> None:
        self.scenario.mode = "benign"
        self.scenario.updates = updates
        if self._save():
            if updates:
                print("  [+] BENIGN + UPDATES: legitimate changes only (the false-alarm test).")
            else:
                print("  [+] BENIGN: the server behaves. A detector should stay quiet.")

    def trip(self) -> None:
        self.scenario.trigger.tripped = True
        self.scenario.mode = "rug-pull"
        if self._save():
            print("  [+] trigger fired - a sleeper attack starts on the next call.")

    def back(self) -> None:
        self.selected = None
        self.benign()
        print("  (deselected)")

    def reset(self) -> None:
        self.selected = None
        seed = self.scenario.seed
        self.scenario = Scenario(seed=seed)
        self._save()
        print("  [+] reset: clean benign server.")

    def launch(self) -> None:
        import sys
        py = Path(sys.executable)
        print("\n  Start the server standalone with:")
        print(f'    "{py}" -m attacker serve\n')
        print("  Normally the detector launches it. Ask the detector to:")
        print(f'    driftsentry baseline --server acme --exec "{py}" -m attacker serve\n')

    # -- loop --------------------------------------------------------------
    def dispatch(self, line: str) -> bool:  # returns False to exit
        parts = line.split()
        if not parts:
            return True
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in {"exit", "quit"}:
            print("  scenario left as-is. bye.")
            return False
        if cmd in {"help", "?"}:
            print(HELP)
        elif cmd == "show":
            what = args[0].lower() if args else "options"
            {"families": self.show_families, "family": self.show_families,
             "levels": self.show_levels, "level": self.show_levels,
             "options": self.show_options, "status": self.status,
             }.get(what, lambda: print(f"  show what? try: families | levels | options"))()
        elif cmd == "use":
            self.use(args[0]) if args else print("  use <family>")
        elif cmd == "info":
            self.info(args[0] if args else None)
        elif cmd == "set":
            self.set_option(args[0], args[1]) if len(args) >= 2 else print("  set <option> <value>")
        elif cmd in {"run", "arm", "exploit"}:
            self.run_attack()
        elif cmd in {"benign", "disarm"}:
            self.benign("updates" in [a.lower() for a in args])
        elif cmd == "status":
            self.status()
        elif cmd == "trip":
            self.trip()
        elif cmd == "back":
            self.back()
        elif cmd == "reset":
            self.reset()
        elif cmd == "launch":
            self.launch()
        else:
            print(f"  unknown command: {cmd!r}. type 'help'.")
        return True


def run(path: Path) -> int:
    console = Console(path)
    print(BANNER)
    console.status()
    print(QUICKSTART)
    while True:
        try:
            line = input(console.prompt)
        except (EOFError, KeyboardInterrupt):
            print("\n  scenario left as-is. bye.")
            return 0
        if not console.dispatch(line):
            return 0
