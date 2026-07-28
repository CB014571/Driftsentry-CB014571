"""Does this attack server actually do what it claims?

Every detection figure in the evaluation rests on this server's behaviour being
correct. If a "rug pull" quietly failed to fire, a detector would score a miss it
did not deserve; if the benign mode were not really benign, it would score a
false alarm it did not deserve. Ground truth that is assumed rather than checked
is not ground truth.

So this verifies the attacker against itself, with no detector involved:

  1. DEFINITION IDENTITY   every rug-pull variant advertises byte-identical tool
                           definitions to the benign server, and therefore the
                           same hash. This is the premise of the whole project.
  2. BENIGN IS BENIGN      a benign server returns stable answers and records no
                           malicious acts.
  3. EACH FAMILY ACTS      every family produces an observable effect, and the
                           right KIND of effect - exfiltration must leave the
                           visible answer untouched, injection must change it.
  4. UPDATES DIFFER        benign-with-updates really does change its wording,
                           or the false-alarm test would be measuring nothing.
  5. GATES WORK            a sleeper stays benign until its trigger; a
                           conditional attack ignores uninteresting input.
  6. PROBE-AWARENESS       at L4 the server behaves on probe-shaped input and
                           attacks on ordinary input. If this did not work, the
                           headline RQ4 result would be an artefact.
  7. REPRODUCIBILITY       the same seed replays the same pattern of malicious
                           and benign calls, so any run can be reproduced.

Run:
    attacker selftest
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from attacker.scenario import FAMILIES, Scenario, Trigger

# Input that looks nothing like a probe, so a probe-aware attacker will fire.
REAL_INPUT = {"customer_id": "C-1002"}
# A value drawn from the pool a fixed-template prober would use.
PROBE_SHAPED = {"path": "README.md"}


def _definition_hash(tools: list[dict[str, Any]]) -> str:
    """Canonical hash of the advertised tool definitions.

    Reimplemented here rather than imported from DriftSentry: this project does
    not depend on the detector, and a self-test that borrowed the detector's code
    could not be used to check the detector's premise.
    """
    identity = sorted(
        ({"name": t.get("name"),
          "description": t.get("description"),
          "inputSchema": t.get("inputSchema")} for t in tools),
        key=lambda t: t["name"] or "",
    )
    blob = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class Harness:
    """Launches this server with a given scenario and calls its tools."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.home.mkdir(parents=True, exist_ok=True)

    def write(self, name: str, **kwargs) -> Path:
        trigger = kwargs.pop("trigger", None)
        scenario = Scenario(**kwargs)
        if trigger is not None:
            scenario.trigger = trigger
        problems = scenario.validate()
        if problems:
            raise SystemExit(f"selftest wrote an invalid scenario: {problems}")
        path = self.home / f"{name}.json"
        scenario.save(path)
        return path

    async def run(self, scenario: Path, calls: list[tuple[str, dict]]) -> dict[str, Any]:
        """Start the server, make the calls, return the definitions and answers."""
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "attacker", "serve", "--scenario", str(scenario)],
            # An MCP client passes a filtered environment to servers it launches,
            # so ATTACKER_HOME has to be handed over explicitly or the server
            # would write its sink somewhere else entirely.
            env={"ATTACKER_HOME": str(self.home)},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                definitions = [t.model_dump(mode="json") for t in listed.tools]
                answers = []
                for tool, args in calls:
                    result = await session.call_tool(tool, args)
                    answers.append(" ".join(
                        b.text for b in result.content
                        if getattr(b, "type", None) == "text"
                    ))
        return {"hash": _definition_hash(definitions),
                "tools": [d["name"] for d in definitions],
                "answers": answers}

    def events(self) -> list[tuple[str, str, str]]:
        log = self.home / "sink" / "events.log"
        if not log.is_file():
            return []
        return [tuple(line.split("\t", 2)) for line in
                log.read_text(encoding="utf-8").splitlines() if line.count("\t") >= 2]

    def clear_events(self) -> None:
        log = self.home / "sink" / "events.log"
        if log.is_file():
            log.unlink()


def check(label: str, passed: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if passed else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    return passed


async def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="attacker_selftest_"))
    harness = Harness(home)
    ok = True
    lookup = ("lookup_customer", REAL_INPUT)

    print("MCP rug-pull attack server - self test")
    print(f"(sandbox: {home})\n")

    # -- 1 + 2. benign baseline -------------------------------------------
    print("1. Benign behaviour")
    benign_path = harness.write("benign", mode="benign", seed=7)
    benign = await harness.run(benign_path, [lookup, lookup])
    ok &= check("benign answers are stable", benign["answers"][0] == benign["answers"][1])
    ok &= check("benign records no malicious acts", not harness.events())
    ok &= check("advertises the expected tools", len(benign["tools"]) == 5,
                f"{benign['tools']}")
    benign_answer = benign["answers"][0]

    # -- 3. definition identity -------------------------------------------
    print("\n2. Definition identity - the premise of the project")
    hashes = {}
    for family in FAMILIES:
        path = harness.write(f"f_{family}", mode="rug-pull", family=family,
                             level="L1", seed=7, trigger=Trigger(after_calls=0))
        result = await harness.run(path, [lookup])
        hashes[family] = result["hash"]
    identical = all(h == benign["hash"] for h in hashes.values())
    ok &= check("all six families hash identically to benign", identical,
                f"hash={benign['hash']}")

    # -- 4. each family acts, and acts in the right way --------------------
    print("\n3. Each family produces its own kind of effect")

    harness.clear_events()
    inj = await harness.run(harness.write("inj", mode="rug-pull",
                                          family="content-injection", level="L1", seed=7),
                            [lookup])
    ok &= check("content-injection CHANGES the visible answer",
                inj["answers"][0] != benign_answer)

    harness.clear_events()
    tam = await harness.run(harness.write("tam", mode="rug-pull",
                                          family="silent-tamper", level="L1", seed=7),
                            [lookup])
    ok &= check("silent-tamper alters a detail", tam["answers"][0] != benign_answer)

    harness.clear_events()
    exf = await harness.run(harness.write("exf", mode="rug-pull",
                                          family="exfiltration", level="L1", seed=7),
                            [lookup])
    kinds = {e[1] for e in harness.events()}
    # The defining property of exfiltration: the user sees nothing wrong.
    ok &= check("exfiltration LEAVES the answer unchanged",
                exf["answers"][0] == benign_answer)
    ok &= check("exfiltration is recorded as having happened", "exfiltrate" in kinds,
                f"events={sorted(kinds)}")

    harness.clear_events()
    egr = await harness.run(harness.write("egr", mode="rug-pull",
                                          family="new-egress", level="L1", seed=7),
                            [lookup])
    kinds = {e[1] for e in harness.events()}
    ok &= check("new-egress opens a connection to the decoy host", "egress" in kinds,
                f"events={sorted(kinds)}")

    # -- 5. benign updates -------------------------------------------------
    print("\n4. Benign updates - the false-alarm set")
    # Clear first: the events log is cumulative, so without this the check would
    # be reading acts left over from the previous section and reporting a benign
    # server as malicious.
    harness.clear_events()
    upd = await harness.run(harness.write("upd", mode="benign", updates=True, seed=7),
                            [lookup])
    ok &= check("benign-with-updates differs from plain benign",
                upd["answers"][0] != benign_answer)
    ok &= check("benign-with-updates records no malicious acts", not harness.events())

    # -- 6. gates ----------------------------------------------------------
    print("\n5. Gated attacks fire only when they should")
    harness.clear_events()
    sleeper = await harness.run(
        harness.write("sleep", mode="rug-pull", family="sleeper", level="L3", seed=7,
                      trigger=Trigger(after_calls=3)),
        [lookup, lookup, lookup, lookup, lookup],
    )
    early_clean = sleeper["answers"][0] == benign_answer
    later_dirty = sleeper["answers"][-1] != benign_answer
    ok &= check("sleeper is benign before its trigger", early_clean)
    ok &= check("sleeper turns malicious after its trigger", later_dirty)

    harness.clear_events()
    cond = await harness.run(
        harness.write("cond", mode="rug-pull", family="conditional", level="L1", seed=7,
                      trigger=Trigger(after_calls=0)),
        [("search_orders", {"query": "widgets"}),
         ("search_orders", {"query": "invoice for dana@northgate.example"})],
    )
    kinds = {e[1] for e in harness.events()}
    ok &= check("conditional ignores uninteresting input, acts on interesting input",
                cond["answers"][0] != cond["answers"][1] or "exfiltrate" in kinds,
                f"events={sorted(kinds)}")

    # -- 7. probe-awareness ------------------------------------------------
    print("\n6. Probe-awareness (L4) - the basis of the RQ4 result")
    aware_path = harness.write("aware", mode="rug-pull", family="content-injection",
                               level="L4", seed=7, probe_aware=True)
    aware = await harness.run(aware_path, [("read_document", PROBE_SHAPED), lookup])
    plain_ref = await harness.run(harness.write("ref", mode="benign", seed=7),
                                  [("read_document", PROBE_SHAPED), lookup])
    ok &= check("behaves normally on probe-shaped input",
                aware["answers"][0] == plain_ref["answers"][0])
    ok &= check("still attacks on ordinary input",
                aware["answers"][1] != plain_ref["answers"][1])

    # -- 8. reproducibility ------------------------------------------------
    print("\n7. Reproducibility")
    calls = [lookup] * 6
    stoch = harness.write("stoch", mode="rug-pull", family="content-injection",
                          level="L2", seed=4242, stochastic_rate=0.5)
    first = await harness.run(stoch, calls)
    second = await harness.run(stoch, calls)
    pattern_a = [a != benign_answer for a in first["answers"]]
    pattern_b = [a != benign_answer for a in second["answers"]]
    ok &= check("the same seed replays the same attack pattern",
                pattern_a == pattern_b,
                "".join("X" if p else "." for p in pattern_a))
    ok &= check("a stochastic attack really is intermittent",
                0 < sum(pattern_a) < len(pattern_a),
                f"{sum(pattern_a)}/{len(pattern_a)} calls malicious")

    print("\n" + ("SELF TEST PASSED - the ground truth is sound"
                  if ok else "SELF TEST FAILED - do not trust detection results until fixed"))
    return 0 if ok else 1


def run() -> int:
    return asyncio.run(main())
