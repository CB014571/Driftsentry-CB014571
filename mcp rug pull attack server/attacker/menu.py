"""Interactive control menu for the attack server.

Typing long flag combinations with an absolute `--scenario` path is fine for
scripting and awful for a live demonstration: it is slow, it is easy to fumble,
and the audience watches you type instead of watching the result. This menu keeps
the scenario path in one place and turns every change into a single keystroke.

It edits the same scenario file the CLI does, so a server that is already running
picks the change up on its very next tool call - no restart, which is exactly the
behaviour a rug pull is supposed to have.

Output is deliberately plain ASCII: it has to render correctly in cmd.exe on a
projector, where a UTF-8 box-drawing character shows up as a question mark.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from attacker.scenario import FAMILIES, LEVELS, Scenario

WIDTH = 66


def _rule(char: str = "=") -> str:
    return char * WIDTH


def _prompt(text: str) -> str:
    """Read a line, treating Ctrl-C / EOF as 'quit' rather than a crash."""
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "q"


def _confirm(text: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = _prompt(f"{text} {suffix} ").lower()
    if not answer:
        return default
    return answer.startswith("y")


def _status_block(scenario: Scenario, path: Path) -> str:
    if scenario.mode == "benign":
        status = "BENIGN + UPDATES" if scenario.updates else "BENIGN"
        detail = "the server is behaving; nothing should alarm"
    else:
        status = f"RUG-PULL   {scenario.family}   {scenario.level}"
        detail = LEVELS[scenario.level].split(" - ", 1)[-1]

    lines = [
        _rule(),
        "  MCP RUG-PULL ATTACK SERVER   -   control menu",
        _rule(),
        f"  scenario  : {path}",
        f"  STATUS    : {status}",
        f"              {detail}",
        f"  bypass    : {'ON  - hides from the detector probes' if scenario.probe_aware else 'off'}",
        f"  variation : {scenario.stochastic_rate:.0%} of calls are malicious   (used at L2)",
        f"  trigger   : after {scenario.trigger.after_calls} calls"
        + ("   [ALREADY TRIPPED]" if scenario.trigger.tripped else "")
        + "   (used at L3 / sleeper)",
        f"  seed      : {scenario.seed}",
    ]
    return "\n".join(lines)


MENU = """
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
  s   Show the full scenario
  r   Reset to a clean benign server
  q   Quit
------------------------------------------------------------------"""


def _choose_family(scenario: Scenario) -> None:
    print("\n  Attack type\n" + _rule("-"))
    names = list(FAMILIES)
    for i, name in enumerate(names, 1):
        marker = " *" if name == scenario.family else "  "
        first_sentence = FAMILIES[name].split(". ")[0]
        print(f"  {i}{marker} {name:<18} {first_sentence[:60]}")
    choice = _prompt("\n  Number (blank to cancel): ")
    if not choice:
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(names)):
        print("  Not a valid choice.")
        return
    scenario.family = names[int(choice) - 1]
    scenario.mode = "rug-pull"
    print(f"  -> attack type is now {scenario.family}, and the server is MALICIOUS.")


def _choose_level(scenario: Scenario) -> None:
    print("\n  Attack strength\n" + _rule("-"))
    names = list(LEVELS)
    for i, name in enumerate(names, 1):
        marker = " *" if name == scenario.level else "  "
        print(f"  {i}{marker} {name}   {LEVELS[name]}")
    choice = _prompt("\n  Number (blank to cancel): ")
    if not choice:
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(names)):
        print("  Not a valid choice.")
        return
    level = names[int(choice) - 1]

    # L4 and L5 are probe-aware attacks. The attacker is not meant to know the
    # defender exists, so being handed knowledge of it stays an explicit choice
    # rather than something the menu switches on quietly.
    if level in {"L4", "L5"} and not scenario.probe_aware:
        print(f"\n  {level} is a probe-aware attack: it needs to know what the")
        print("  detector's test inputs look like, so bypass mode must be on.")
        if not _confirm("  Enable bypass mode as well?"):
            print("  Level unchanged.")
            return
        scenario.probe_aware = True

    scenario.level = level
    scenario.mode = "rug-pull"
    print(f"  -> attack strength is now {scenario.level}.")


def _toggle_bypass(scenario: Scenario) -> None:
    if scenario.probe_aware:
        if scenario.level in {"L4", "L5"}:
            print(f"\n  {scenario.level} depends on bypass mode. Turning it off would make")
            print("  the scenario invalid, so the level will drop to L1.")
            if not _confirm("  Continue?", default=False):
                return
            scenario.level = "L1"
        scenario.probe_aware = False
        print("  -> bypass mode OFF. The attack no longer hides from probes.")
    else:
        scenario.probe_aware = True
        print("  -> bypass mode ON. The server will now recognise the detector's")
        print("     canary inputs and behave itself whenever it thinks it is being")
        print("     tested. This is what defeats fixed probe templates.")


def _set_variation(scenario: Scenario) -> None:
    print("\n  What fraction of calls should be malicious? (used at level L2)")
    print("  Lower means stealthier and harder to catch by sampling.")
    value = _prompt(f"  Percentage 0-100 (currently {scenario.stochastic_rate:.0%}): ")
    if not value:
        return
    try:
        rate = float(value.rstrip("%")) / 100.0
    except ValueError:
        print("  Not a number.")
        return
    if not 0.0 <= rate <= 1.0:
        print("  Must be between 0 and 100.")
        return
    scenario.stochastic_rate = rate
    print(f"  -> {rate:.0%} of calls will be malicious at L2.")


def _set_trigger(scenario: Scenario) -> None:
    print("\n  Turn malicious only after a number of calls (used at L3 and sleeper).")
    value = _prompt(f"  Number of calls (currently {scenario.trigger.after_calls}): ")
    if not value:
        return
    if not value.isdigit():
        print("  Not a number.")
        return
    scenario.trigger.after_calls = int(value)
    scenario.trigger.tripped = False
    print(f"  -> the attack starts after {scenario.trigger.after_calls} calls.")


def _set_seed(scenario: Scenario) -> None:
    value = _prompt(f"\n  New seed (currently {scenario.seed}): ")
    if not value:
        return
    if not (value.isdigit() or (value.startswith("-") and value[1:].isdigit())):
        print("  Not a number.")
        return
    scenario.seed = int(value)
    print(f"  -> seed is now {scenario.seed}. The same seed replays the same run exactly.")


def run(path: Path) -> int:
    """Run the interactive menu against the scenario file at ``path``."""
    scenario = Scenario.load(path)
    # Make sure the file exists from the start, so a server launched with
    # --reuse never falls back to a default and silently refuses to attack.
    scenario.save(path)

    print("\n  Changes take effect on a RUNNING server's next tool call.")
    print("  Point the detector at this same scenario file.\n")

    while True:
        print("\n" + _status_block(scenario, path))
        print(MENU)
        choice = _prompt("  Choice: ").lower()

        if choice == "q":
            print("\n  Leaving the scenario as it is. The server keeps using it.\n")
            return 0
        if choice == "1":
            _choose_family(scenario)
        elif choice == "2":
            _choose_level(scenario)
        elif choice == "3":
            _toggle_bypass(scenario)
        elif choice == "4":
            _set_variation(scenario)
        elif choice == "5":
            _set_trigger(scenario)
        elif choice == "6":
            scenario.mode, scenario.updates = "benign", False
            print("  -> the server is now BENIGN. A detector should stay quiet.")
        elif choice == "7":
            scenario.mode, scenario.updates = "benign", True
            print("  -> BENIGN WITH UPDATES: legitimate changes only - reworded")
            print("     answers, an added field. A detector that alarms on these")
            print("     is unusable, so this is the false-alarm test.")
        elif choice == "8":
            scenario.trigger.tripped = True
            scenario.mode = "rug-pull"
            print("  -> trigger fired. A sleeper attack starts on the next call.")
        elif choice == "9":
            _set_seed(scenario)
        elif choice == "s":
            print()
            print(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2))
            continue
        elif choice == "r":
            scenario = Scenario(seed=scenario.seed)
            print("  -> reset: benign server, no bypass, trigger cleared.")
        elif not choice:
            continue
        else:
            print("  Unrecognised choice.")
            continue

        problems = scenario.validate()
        if problems:
            for problem in problems:
                print(f"  cannot save: {problem}", file=sys.stderr)
            scenario = Scenario.load(path)
            continue
        scenario.save(path)
