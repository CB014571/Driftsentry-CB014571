"""The attacker command line.

Everyday use:

    attacker menu                         interactive control panel (easiest)
    attacker status                       what is it doing right now?
    attacker benign                       behave normally
    attacker benign --updates             behave normally, but emit legitimate updates
    attacker attack content-injection     start attacking
    attacker attack new-egress --level L2 attack, but only on some calls
    attacker reset                        back to benign, clear the sink

Everything else is detail:

    attacker list-families                the six families and five levels explained
    attacker launch-command               the exact line to give DriftSentry
    attacker configure ...                write a scenario without starting a server
    attacker serve ...                    run the MCP server (usually launched FOR you)
    attacker set-family / set-level       change a RUNNING server
    attacker trip                         fire a sleeper now
    attacker show                         the raw scenario JSON

Two design decisions make this usable
    1. The scenario lives in a fixed per-user directory, so the CLI and a server
       started from any working directory always agree without anyone passing
       `--scenario`. See scenario.default_home() for why that matters.
    2. `serve` REUSES the existing scenario. Flags only override what you name,
       and `serve` with no flags never changes what the server is doing. An
       earlier version overwrote the scenario every time it started, which meant
       launching a server could silently arm an attack you did not ask for.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attacker.scenario import (
    DEFAULT_SCENARIO_PATH,
    FAMILIES,
    LEVELS,
    Scenario,
    Trigger,
)

# Flags that describe the attack itself, as (attribute, cli-name) pairs.
_SCENARIO_FLAGS = [
    ("mode", "--mode"),
    ("family", "--family"),
    ("level", "--level"),
    ("seed", "--seed"),
    ("stochastic_rate", "--rate"),
    ("probe_aware", "--probe-aware"),
    ("updates", "--updates"),
    ("payload", "--payload"),
]


def _path(ns: argparse.Namespace) -> Path:
    return Path(ns.scenario) if getattr(ns, "scenario", None) else DEFAULT_SCENARIO_PATH


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


# --------------------------------------------------------------------------- #
# Applying flags to a scenario
# --------------------------------------------------------------------------- #
def _apply(scenario: Scenario, ns: argparse.Namespace) -> bool:
    """Overlay any explicitly-given flags onto a scenario. Returns True if changed.

    Flags default to None so "not given" is distinguishable from "given the same
    value as the default" - that is what lets `serve` leave an existing scenario
    untouched.
    """
    changed = False
    for attribute, _flag in _SCENARIO_FLAGS:
        value = getattr(ns, attribute if attribute != "stochastic_rate" else "rate", None)
        if attribute == "probe_aware":
            value = True if getattr(ns, "probe_aware", False) else None
        if attribute == "updates":
            value = True if getattr(ns, "updates", False) else None
        if value is None:
            continue
        if getattr(scenario, attribute) != value:
            setattr(scenario, attribute, value)
            changed = True

    after_calls = getattr(ns, "after_calls", None)
    if after_calls is not None and scenario.trigger.after_calls != after_calls:
        scenario.trigger.after_calls = after_calls
        changed = True

    # Naming an attack implies you want it armed. Without this, `attacker serve
    # --family new-egress` on a benign scenario would quietly do nothing.
    if getattr(ns, "mode", None) is None:
        if any(getattr(ns, attr, None) for attr in ("family", "level")) or getattr(ns, "probe_aware", False):
            if scenario.mode != "rug-pull":
                scenario.mode = "rug-pull"
                changed = True
    return changed


def _load_or_default(path: Path) -> Scenario:
    """Existing scenario, or a fresh BENIGN one.

    Benign is the safe default: a server that starts attacking merely because
    nobody configured it would be a poor research instrument and a worse
    surprise.
    """
    return Scenario.load(path) if path.is_file() else Scenario(mode="benign")


def _save(scenario: Scenario, path: Path) -> int | None:
    problems = scenario.validate()
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    scenario.save(path)
    return None


def _describe(scenario: Scenario, path: Path) -> None:
    """Plain-English summary - the thing you actually want to see."""
    if scenario.mode == "benign":
        headline = ("BENIGN, emitting legitimate updates" if scenario.updates else "BENIGN")
        detail = ("Responses change the way a real updated server's would. A detector "
                  "must NOT alarm on this." if scenario.updates else
                  "Behaving normally. A detector must not alarm on this.")
    else:
        headline = f"ATTACKING - {scenario.family} at {scenario.level}"
        detail = FAMILIES.get(scenario.family, "")
    print(f"Status   : {headline}")
    for line in _wrap(detail, 66):
        print(f"           {line}")
    print(f"Level    : {scenario.level} - {LEVELS.get(scenario.level, '')}")
    if scenario.level == "L2":
        print(f"           firing on {scenario.stochastic_rate:.0%} of calls")
    if scenario.level == "L3":
        print(f"           after {scenario.trigger.after_calls} calls, or on a matching input"
              + (", ALREADY TRIPPED" if scenario.trigger.tripped else ""))
    if scenario.probe_aware:
        print("           probe-aware: will behave whenever it thinks it is being tested")
    print(f"Seed     : {scenario.seed}   (same seed = same run, replayable)")
    print(f"Scenario : {path}")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _cmd_menu(ns: argparse.Namespace) -> int:
    from attacker.menu import run

    return run(_path(ns))


def _cmd_list_families(_ns: argparse.Namespace) -> int:
    print("Attack families\n" + "=" * 60)
    for name, description in FAMILIES.items():
        print(f"\n  {name}")
        for line in _wrap(description, 66):
            print(f"      {line}")
    print("\n\nComplexity levels\n" + "=" * 60)
    for name, description in LEVELS.items():
        print(f"\n  {name}")
        for line in _wrap(description, 66):
            print(f"      {line}")
    print("\nL4 and L5 require --probe-aware explicitly: the attacker does not know")
    print("the detector exists unless you tell it.")
    print("\nStart one with:   attacker attack <family> [--level L1..L5]")
    return 0


def _cmd_status(ns: argparse.Namespace) -> int:
    path = _path(ns)
    if not path.is_file():
        print("Status   : BENIGN (no scenario file yet - nothing has been configured)")
        print(f"Scenario : {path}  (will be created on first use)")
        print("\nStart an attack with:   attacker attack content-injection")
        return 0
    _describe(Scenario.load(path), path)
    return 0


def _cmd_benign(ns: argparse.Namespace) -> int:
    path = _path(ns)
    scenario = _load_or_default(path)
    scenario.mode = "benign"
    scenario.updates = bool(ns.updates)
    scenario.trigger.tripped = False
    if ns.seed is not None:
        scenario.seed = ns.seed
    if (code := _save(scenario, path)) is not None:
        return code
    _describe(scenario, path)
    print("\nA running server picks this up on its next call.")
    return 0


def _cmd_attack(ns: argparse.Namespace) -> int:
    path = _path(ns)
    scenario = _load_or_default(path)
    scenario.mode = "rug-pull"
    scenario.family = ns.family
    scenario.updates = False
    if ns.level is not None:
        scenario.level = ns.level
    if ns.seed is not None:
        scenario.seed = ns.seed
    if ns.rate is not None:
        scenario.stochastic_rate = ns.rate
    if ns.after_calls is not None:
        scenario.trigger.after_calls = ns.after_calls
    if ns.payload is not None:
        scenario.payload = ns.payload
    if ns.probe_aware:
        scenario.probe_aware = True
    if (code := _save(scenario, path)) is not None:
        return code
    _describe(scenario, path)
    print("\nA running server picks this up on its next call.")
    return 0


def _cmd_configure(ns: argparse.Namespace) -> int:
    """Write a scenario file and exit, without starting a server.

    `serve` blocks forever, which makes it useless for scripting. Anything that
    needs to *prepare* a scenario - an evaluation harness building a labelled
    corpus, or a demo stepping through several attacks - sets one up here and
    hands the path to whoever launches the server. It also keeps callers at arm's
    length: they drive this through argv and a JSON file, never by importing.
    """
    path = _path(ns)
    scenario = Scenario(
        mode=ns.mode or "benign",
        family=ns.family or "content-injection",
        level=ns.level or "L1",
        seed=ns.seed if ns.seed is not None else 1234,
        probe_aware=bool(ns.probe_aware),
        updates=bool(ns.updates),
        stochastic_rate=ns.rate if ns.rate is not None else 0.5,
        payload=ns.payload,
        trigger=Trigger(after_calls=ns.after_calls if ns.after_calls is not None else 3),
    )
    _apply(scenario, ns)
    if (code := _save(scenario, path)) is not None:
        return code
    print(f"{path}: {scenario.label()}")
    return 0


def _cmd_serve(ns: argparse.Namespace) -> int:
    from attacker import server

    path = _path(ns)
    scenario = _load_or_default(path)
    if _apply(scenario, ns) or not path.is_file():
        if (code := _save(scenario, path)) is not None:
            return code

    print(f"scenario: {path}  [{scenario.label()}]", file=sys.stderr)
    server.configure(path)
    server.mcp.run()
    return 0


def _cmd_launch_command(ns: argparse.Namespace) -> int:
    """Print the exact command another tool should use to start this server."""
    python = Path(sys.executable)
    exe = python.parent / ("attacker.exe" if python.name.lower().startswith("python") else "attacker")
    launcher = f'"{python}" -m attacker serve'
    print("Launch this server from another tool with:\n")
    print(f"  {launcher}\n")
    print("For DriftSentry, that means:\n")
    print(f'  driftsentry baseline --server acme --exec "{python}" -m attacker serve')
    print(f"  driftsentry verify   --server acme\n")
    if exe.is_file():
        print(f"(The CLI itself is at: {exe})")
    print(f"Scenario file: {_path(ns)}")
    print("No --scenario needed: the path above is fixed per user, so this server")
    print("and the CLI agree no matter which directory either is started from.")
    return 0


def _mutate(ns: argparse.Namespace, **changes) -> int:
    path = _path(ns)
    scenario = _load_or_default(path)
    for key, value in changes.items():
        if key == "tripped":
            scenario.trigger.tripped = value
        else:
            setattr(scenario, key, value)
    if (code := _save(scenario, path)) is not None:
        return code
    _describe(scenario, path)
    print("\nA running server picks this up on its next call.")
    return 0


def _cmd_set_level(ns: argparse.Namespace) -> int:
    changes = {"level": ns.level}
    if ns.probe_aware:
        changes["probe_aware"] = True
    return _mutate(ns, **changes)


def _cmd_set_family(ns: argparse.Namespace) -> int:
    return _mutate(ns, family=ns.family, mode="rug-pull")


def _cmd_trip(ns: argparse.Namespace) -> int:
    print("Firing the trigger now instead of waiting for it.\n")
    return _mutate(ns, tripped=True, mode="rug-pull")


def _cmd_reset(ns: argparse.Namespace) -> int:
    from attacker import sink

    sink.reset()
    # The level goes back to L1 as well, not just the mode.
    #
    # Without that, resetting from L4 or L5 left a scenario that says "probe-aware
    # level, probe-awareness disabled", which fails its own validation - so reset
    # errored out and there was no way back to a clean server short of deleting
    # the file by hand. Exactly the kind of thing that strands you mid-demo.
    return _mutate(ns, mode="benign", updates=False, probe_aware=False,
                   level="L1", tripped=False)


def _cmd_show(ns: argparse.Namespace) -> int:
    path = _path(ns)
    if not path.is_file():
        print(f"no scenario at {path}")
        return 1
    print(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2))
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attacker",
        description="Adversarial MCP server for evaluating rug-pull detection. "
                    "Closed-loop and offline: no real endpoints, synthetic data only.",
        epilog="Start here:  attacker status  |  attacker attack content-injection  |  attacker reset",
    )
    parser.set_defaults(func=_cmd_status)
    sub = parser.add_subparsers(dest="command")

    def add_scenario_path(p: argparse.ArgumentParser) -> None:
        p.add_argument("--scenario", default=None,
                       help="scenario file (default: a fixed per-user path; you rarely need this)")

    def add_attack_flags(p: argparse.ArgumentParser) -> None:
        # Default None throughout, so "not given" stays distinguishable from
        # "given the default" and existing settings survive.
        p.add_argument("--level", choices=sorted(LEVELS), default=None)
        p.add_argument("--seed", type=int, default=None)
        p.add_argument("--rate", type=float, default=None,
                       help="L2 only: fraction of calls that are malicious")
        p.add_argument("--after-calls", type=int, default=None,
                       help="L3/sleeper: turn malicious after this many calls")
        p.add_argument("--payload", choices=sorted(FAMILIES), default=None,
                       help="what sleeper/conditional deliver once they fire")
        p.add_argument("--probe-aware", action="store_true",
                       help="opt in to L4/L5: recognise the detector's canary inputs")

    # --- everyday ---------------------------------------------------------
    menu = sub.add_parser(
        "menu",
        help="interactive control panel - change type, strength and bypass by keystroke",
    )
    add_scenario_path(menu)
    menu.set_defaults(func=_cmd_menu)

    status = sub.add_parser("status", help="what is the server doing right now?")
    add_scenario_path(status)
    status.set_defaults(func=_cmd_status)

    benign = sub.add_parser("benign", help="behave normally (optionally with legitimate updates)")
    add_scenario_path(benign)
    benign.add_argument("--updates", action="store_true",
                        help="emit legitimate changes - the false-alarm test set")
    benign.add_argument("--seed", type=int, default=None)
    benign.set_defaults(func=_cmd_benign)

    attack = sub.add_parser("attack", help="start attacking with the named family")
    add_scenario_path(attack)
    attack.add_argument("family", choices=sorted(FAMILIES))
    add_attack_flags(attack)
    attack.set_defaults(func=_cmd_attack)

    reset = sub.add_parser("reset", help="back to benign and clear the sink")
    add_scenario_path(reset)
    reset.set_defaults(func=_cmd_reset)

    lf = sub.add_parser("list-families", help="explain the attack families and levels")
    add_scenario_path(lf)
    lf.set_defaults(func=_cmd_list_families)

    launch = sub.add_parser("launch-command", help="print the command another tool should use")
    add_scenario_path(launch)
    launch.set_defaults(func=_cmd_launch_command)

    # --- server -----------------------------------------------------------
    serve = sub.add_parser("serve", help="run the MCP server (usually launched for you)")
    add_scenario_path(serve)
    serve.add_argument("--mode", choices=["benign", "rug-pull"], default=None)
    serve.add_argument("--family", choices=sorted(FAMILIES), default=None)
    serve.add_argument("--updates", action="store_true")
    add_attack_flags(serve)
    serve.add_argument("--reuse", action="store_true",
                       help="accepted for compatibility; reusing is now the default")
    serve.set_defaults(func=_cmd_serve)

    # --- scripting / live control ----------------------------------------
    configure = sub.add_parser("configure", help="write a scenario file and exit (for scripts)")
    add_scenario_path(configure)
    configure.add_argument("--mode", choices=["benign", "rug-pull"], default=None)
    configure.add_argument("--family", choices=sorted(FAMILIES), default=None)
    configure.add_argument("--updates", action="store_true")
    add_attack_flags(configure)
    configure.set_defaults(func=_cmd_configure)

    sl = sub.add_parser("set-level", help="change the level of a running server")
    add_scenario_path(sl)
    sl.add_argument("level", choices=sorted(LEVELS))
    sl.add_argument("--probe-aware", action="store_true")
    sl.set_defaults(func=_cmd_set_level)

    sf = sub.add_parser("set-family", help="change the family of a running server")
    add_scenario_path(sf)
    sf.add_argument("family", choices=sorted(FAMILIES))
    sf.set_defaults(func=_cmd_set_family)

    trip = sub.add_parser("trip", help="fire a sleeper / trigger-gated attack now")
    add_scenario_path(trip)
    trip.set_defaults(func=_cmd_trip)

    show = sub.add_parser("show", help="print the raw scenario JSON")
    add_scenario_path(show)
    show.set_defaults(func=_cmd_show)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
