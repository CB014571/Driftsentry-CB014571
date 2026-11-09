"""The Gap 3 driver: baseline an old release, upgrade, re-probe.

`eval/real_upgrades.py` holds the measurement and `eval/real_envs.py` builds
the environments. Neither of them runs anything. The first Gap 3 results were
produced from a script that was never committed, so the two servers that
worked have numbers nobody can reproduce and the two that failed have an
error message nobody can retry. This is that script, committed.

The shape, per server:

    build OLD release in its own environment
    confirm its tool list by introspection, and keep only tools the safety
      classifier positively says are read-only
    capture a baseline on OLD
    probe OLD n times              <- the noise floor. Any alarm here is the
                                      detector disagreeing with itself, not
                                      with an upgrade.
    build NEW release in a SECOND environment
    probe NEW n times              <- the upgrade. Any alarm here is a false
                                      alarm, because nothing malicious
                                      happened.

Two environments rather than one upgraded in place, because pip uninstalling
and reinstalling leaves the old package's artefacts behind often enough to
matter, and a baseline captured against a half-replaced install is not a
baseline of the old release.

The noise phase is not optional. A detector that alarms on the same release
it was baselined on has no false-alarm rate to report on upgrades - the
number would be measuring its own instability. mcp-server-git is exactly
that case: it alarms 3/3 on its own release, because git_log and git_diff
return commit hashes and timestamps that move between calls.
"""
from __future__ import annotations

import json
import sys
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from eval.real_envs import EnvError, Installed, build, starts_and_lists, tool_names
from eval.real_upgrades import UpgradeResult, launch_for, probe_phase, save

log = logging.getLogger("eval.real_run")

SERVERS_JSON = Path(__file__).with_name("real_servers.json")


class ToolsUnconfirmed(RuntimeError):
    """No tool could be positively confirmed read-only, so nothing is probed."""


@dataclass
class ServerRun:
    """Everything one server produced, including why it produced nothing."""

    name: str
    old_version: str = ""
    new_version: str = ""
    probed_tools: list[str] = field(default_factory=list)
    withheld_tools: dict[str, str] = field(default_factory=dict)
    environments: list[dict[str, Any]] = field(default_factory=list)
    results: list[UpgradeResult] = field(default_factory=list)
    error: str | None = None
    # T29. Both releases' tools/list as each advertised it, and what the
    # update declared between them.
    tools_old: list[dict[str, Any]] = field(default_factory=list)
    tools_new: list[dict[str, Any]] = field(default_factory=list)
    declared: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "probed_tools": self.probed_tools,
            "withheld_tools": self.withheld_tools,
            "environments": self.environments,
            "declared": self.declared,
            "error": self.error,
            "runs": [r.to_dict() for r in self.results],
        }


# --------------------------------------------------------------------------- #
# What may be probed
# --------------------------------------------------------------------------- #
def confirm_read_only(python: Path, entry: Sequence[str],
                      *, cwd: str | None = None,
                      env: dict[str, str] | None = None,
                      declared: Sequence[str] = ()) -> tuple[list[str], dict[str, str]]:
    """Ask the server what it offers, then ask the classifier what is safe.

    Both halves are needed. The declared list in real_servers.json is a guess
    read off a package summary - the file says so on every entry - and a guess
    is not good enough when being wrong means writing to someone's data. The
    classifier runs in strict mode, so a tool is probed only on positive
    evidence that it is read-only.

    Returns (probed, withheld), withheld mapping each skipped tool to the
    classifier's own reason, so the write-up can say what was left out and
    why rather than reporting a tool count with no provenance.
    """
    from driftsentry.probes import classify_tool_safety

    ok, detail = starts_and_lists(python, entry, cwd=cwd, env=env)
    if not ok:
        raise EnvError(f"could not list tools: {detail}")

    offered = tool_names(detail)
    schemas = _tool_schemas(python, entry, cwd=cwd, env=env)

    probed: list[str] = []
    withheld: dict[str, str] = {}
    for name in offered:
        tool = schemas.get(name) or {"name": name}
        safety, why = classify_tool_safety(tool, policy="strict")
        if safety == "safe":
            probed.append(name)
        else:
            withheld[name] = why

    if declared:
        # Not used to widen the set, only to report disagreement: a tool the
        # proposal guessed was read-only and the classifier refuses is worth
        # seeing, because it means the guess would have caused a write.
        for name in declared:
            if name in withheld:
                log.warning("real_servers.json guessed %s read-only; the "
                            "classifier refuses it: %s", name, withheld[name])
    if not probed:
        raise ToolsUnconfirmed(
            f"no tool confirmed read-only out of {len(offered)} offered")
    return probed, withheld


def _tool_schemas(python: Path, entry: Sequence[str],
                  *, cwd: str | None = None,
                  env: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """Full tool dicts, annotations included.

    Separate from starts_and_lists because that one answers a yes/no question
    about the environment and must stay cheap. The classifier needs the
    annotations, and readOnlyHint is the only positive evidence some servers
    give.
    """
    import subprocess

    script = (
        "import anyio, json, sys\n"
        "from mcp import ClientSession, StdioServerParameters\n"
        "from mcp.client.stdio import stdio_client\n"
        "async def main():\n"
        "    params = StdioServerParameters(command=sys.argv[1],\n"
        "                                   args=json.loads(sys.argv[2]),\n"
        "                                   cwd=(sys.argv[3] or None),\n"
        "                                   env=json.loads(sys.argv[4]))\n"
        "    async with stdio_client(params) as (r, w):\n"
        "        async with ClientSession(r, w) as session:\n"
            "            await session.initialize()\n"
        "            tools = await session.list_tools()\n"
        "            print(json.dumps([t.model_dump(mode='json')\n"
        "                              for t in tools.tools]))\n"
        "anyio.run(main)\n"
    )
    done = subprocess.run([str(python), "-c", script, str(python),
                           json.dumps(list(entry)), cwd or "", json.dumps(env or {})],
                          capture_output=True, text=True, timeout=60,
                          check=False)
    if done.returncode != 0:
        return {}
    try:
        payload = json.loads(done.stdout.strip())
    except ValueError:
        return {}
    return {t.get("name", ""): t for t in payload if isinstance(t, dict)}


# --------------------------------------------------------------------------- #
# The throwaway database a server is pointed at
# --------------------------------------------------------------------------- #
# Small and fixed. Both releases read the SAME file, opened read-only where the
# server allows it, so the upgrade is the only thing that differs between the
# two phases. A database that changed between them would be measured as drift.
_FIXTURE_SQL = [
    "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, city TEXT, account TEXT)",
    "INSERT INTO customers VALUES (1, 'Dana Whitfield', 'Leeds', 'ACC-44120')",
    "INSERT INTO customers VALUES (2, 'Marcus Silva', 'Bristol', 'ACC-44121')",
    "INSERT INTO customers VALUES (3, 'Priya Raman', 'Cardiff', 'ACC-44122')",
    "CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id INTEGER, item TEXT, total REAL)",
    "INSERT INTO orders VALUES ('ORD-8801', 1, 'hex bolts', 42.50)",
    "INSERT INTO orders VALUES ('ORD-8802', 2, 'drive belt', 118.00)",
]


def make_fixture(kind: str, directory: Path, python: Path) -> Path:
    """Create the throwaway database once, before either release runs.

    duckdb files are written with the OLD release's own duckdb: a newer duckdb
    reads an older file, but an older one cannot read a newer file, so writing
    with the newer version could fail the old phase for a reason that has
    nothing to do with the server.
    """
    import sqlite3
    import subprocess

    directory.mkdir(parents=True, exist_ok=True)
    if kind == "sqlite":
        path = directory / "fixture.sqlite"
        if not path.exists():
            con = sqlite3.connect(path)
            for stmt in _FIXTURE_SQL:
                con.execute(stmt)
            con.commit()
            con.close()
        return path
    if kind == "duckdb":
        path = directory / "fixture.duckdb"
        if not path.exists():
            script = ("import duckdb, json, sys\n"
                      "con = duckdb.connect(sys.argv[1])\n"
                      "for stmt in json.loads(sys.argv[2]):\n"
                      "    con.execute(stmt)\n"
                      "con.close()\n")
            done = subprocess.run([str(python), "-c", script, str(path),
                                   json.dumps(_FIXTURE_SQL)],
                                  capture_output=True, text=True, timeout=120,
                                  check=False)
            if done.returncode != 0:
                raise EnvError(f"duckdb fixture failed: {done.stderr.strip()[-400:]}")
        return path
    raise EnvError(f"unknown fixture kind {kind!r}")


def _fill(value: Any, db: Path | None) -> Any:
    """Substitute {db} in a launch argument or environment value."""
    if db is None or not isinstance(value, str):
        return value
    return (value.replace("{db_posix}", db.as_posix())
                 .replace("{db_dir}", str(db.parent))
                 .replace("{db}", str(db)))


# --------------------------------------------------------------------------- #
# One server
# --------------------------------------------------------------------------- #
async def run_server(
    entry_spec: dict[str, Any],
    workspace: Path,
    *,
    runs: int = 3,
    samples_per_probe: int = 2,
    cwd: str | None = None,
    sdk_old: str | None = None,
    sdk_new: str | None = None,
    resolve: bool = True,
    clean: bool = False,
) -> ServerRun:
    """Build both releases, baseline the old one, probe both."""
    from driftsentry.baseline import capture_baseline

    name = entry_spec["name"]
    short = name.replace("mcp-server-", "").replace("mcp-", "")
    out = ServerRun(name=short,
                    old_version=entry_spec["old"],
                    new_version=entry_spec["new"])
    package = entry_spec["package"]
    raw_entry = list(entry_spec["entry"])
    raw_env = dict(entry_spec.get("env") or {})
    fixture_kind = entry_spec.get("fixture")
    fixture_dir = workspace / f"{short}-fixture"
    db: Path | None = None
    if fixture_kind == "sqlite":
        db = make_fixture("sqlite", fixture_dir, Path(sys.executable))
    elif fixture_kind == "duckdb":
        # Seeded by the old release's own duckdb, so install that first.
        from eval.real_envs import create_venv, pip_install
        try:
            seed_python = create_venv(workspace / f"{short}-old", clean=clean)
            pip_install(seed_python, [f"{package}=={entry_spec['old']}"])
            db = make_fixture("duckdb", fixture_dir, seed_python)
        except EnvError as exc:
            out.error = f"fixture: {exc}"
            return out
    entry = [_fill(a, db) for a in raw_entry]
    env = {k: _fill(v, db) for k, v in raw_env.items()}

    try:
        old_env = build(short, package, entry_spec["old"], entry,
                        workspace / f"{short}-old", cwd=cwd, sdk=sdk_old,
                        resolve=resolve,
                        clean=clean and fixture_kind != "duckdb", env=env)
        out.environments.append(old_env.to_dict())
    except EnvError as exc:
        out.error = f"old release: {exc}"
        return out

    try:
        probed, withheld = confirm_read_only(
            old_env.python, entry, cwd=cwd, env=env,
            declared=entry_spec.get("read_only_tools") or ())
    except (EnvError, ToolsUnconfirmed) as exc:
        out.error = f"tool confirmation: {exc}"
        return out
    out.probed_tools, out.withheld_tools = probed, withheld

    launch_old = launch_for(old_env.python, entry, cwd=cwd, env=env)
    try:
        baseline = await capture_baseline(
            short, launch_old["command"], launch_old["args"],
            cwd=cwd, env={}, safety_policy="strict", monitor_sandbox=True,
            probe_mode="fixed")
    except Exception as exc:                                  # noqa: BLE001
        out.error = f"baseline: {type(exc).__name__}: {exc}"
        return out

    for run in range(1, runs + 1):
        out.results.append(await probe_phase(
            short, baseline, launch_old, phase="old", run=run,
            samples_per_probe=samples_per_probe, cycle=run))

    # The new release gets its own environment, and its own SDK resolution:
    # the pin the old release needed is not necessarily one the new release
    # can run on, and forcing it would make the phases differ by the SDK as
    # well as by the upgrade.
    try:
        new_env = build(short, package, entry_spec["new"], entry,
                        workspace / f"{short}-new", cwd=cwd, sdk=sdk_new,
                        resolve=resolve, clean=clean, env=env)
        out.environments.append(new_env.to_dict())
    except EnvError as exc:
        out.error = f"new release: {exc}"
        return out

    # T29: what the update declared, from the two tool lists as advertised.
    from driftsentry.declared_diff import diff_definitions

    out.tools_old = list(_tool_schemas(old_env.python, entry, cwd=cwd, env=env).values())
    out.tools_new = list(_tool_schemas(new_env.python, entry, cwd=cwd, env=env).values())
    out.declared = diff_definitions(out.tools_old, out.tools_new).to_dict()

    # The new phase is scored as an UPDATE (RQ3b); the old phase above stays
    # the plain detector, because it is the noise floor - the same release
    # against its own baseline, where nothing was declared or changed.
    launch_new = launch_for(new_env.python, entry, cwd=cwd, env=env)
    for run in range(1, runs + 1):
        out.results.append(await probe_phase(
            short, baseline, launch_new, phase="new", run=run,
            samples_per_probe=samples_per_probe, cycle=runs + run,
            update_check=True))
    return out


# --------------------------------------------------------------------------- #
# All of them
# --------------------------------------------------------------------------- #
def load_specs(path: Path = SERVERS_JSON,
               only: Sequence[str] = ()) -> list[dict[str, Any]]:
    """The candidate list, optionally narrowed by short name."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    specs = payload.get("servers") or []
    if not only:
        return specs
    wanted = {n.strip().lower() for n in only}
    picked = []
    for spec in specs:
        short = spec["name"].replace("mcp-server-", "").replace("mcp-", "")
        if short.lower() in wanted or spec["name"].lower() in wanted:
            picked.append(spec)
    missing = wanted - {
        s["name"].replace("mcp-server-", "").replace("mcp-", "").lower()
        for s in picked}
    if missing:
        raise KeyError(f"not in {path.name}: {sorted(missing)}")
    return picked


async def run_all(
    workspace: Path,
    out_dir: Path,
    *,
    only: Sequence[str] = (),
    runs: int = 3,
    resolve: bool = True,
    clean: bool = False,
) -> list[ServerRun]:
    """Every selected server, each written out as it finishes.

    Written per server rather than at the end, because the whole point of
    the first Gap 3 attempt failing on server three was that servers one and
    two were already measured and their numbers nearly went with it.
    """
    specs = load_specs(only=only)
    workspace.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    done: list[ServerRun] = []

    for i, spec in enumerate(specs, 1):
        short = spec["name"].replace("mcp-server-", "").replace("mcp-", "")
        print(f"[{i}/{len(specs)}] {spec['name']}  "
              f"{spec['old']} -> {spec['new']}", flush=True)
        result = await run_server(spec, workspace, runs=runs,
                                  resolve=resolve, clean=clean)
        done.append(result)

        if result.results:
            save(result.results, out_dir, name=f"rq1_{short}")
        if result.tools_old or result.tools_new:
            server_dir = out_dir / short
            server_dir.mkdir(parents=True, exist_ok=True)
            for name, tools in (("tools_old", result.tools_old),
                                ("tools_new", result.tools_new)):
                (server_dir / f"{name}.json").write_text(
                    json.dumps(tools, indent=2, sort_keys=True), encoding="utf-8")
        (out_dir / f"rq1_{short}_meta.json").write_text(
            json.dumps(result.to_dict(), indent=2, default=str),
            encoding="utf-8")

        if result.error:
            print(f"    NOT MEASURED: {result.error}", flush=True)
        else:
            verdicts = [r.residue_verdict for r in result.results if r.phase == "new"]
            alarms = sum(1 for r in result.results
                         if r.phase == "new" and r.alerted)
            noise = sum(1 for r in result.results
                        if r.phase == "old" and r.alerted)
            print(f"    same release {noise}/{runs} alerted, "
                  f"after upgrade {alarms}/{runs} alerted, "
                  f"tools probed {len(result.probed_tools)} "
                  f"of {len(result.probed_tools) + len(result.withheld_tools)}",
                  flush=True)
            print(f"    residue verdicts after upgrade: {verdicts}", flush=True)
    return done


def report(done: Sequence[ServerRun]) -> str:
    """Per server, beside what was not measured and why.

    A server that could not be built is listed, not dropped. Gap 3 asks for
    a false-alarm rate across real upgrades, and "two of the four candidates
    could not be installed" is part of that answer.
    """
    lines = ["", "=" * 78,
             "  GAP 3 - false alarms across real benign upgrades",
             "=" * 78,
             f"  {'server':<14}{'old':>12}{'new':>12}"
             f"{'noise':>10}{'upgrade':>10}{'hash':>8}{'tools':>8}"]

    measured = [d for d in done if d.results and not d.error]
    for d in done:
        if d.error:
            lines.append(f"  {d.name:<14}{d.old_version:>12}"
                         f"{d.new_version:>12}{'NOT MEASURED':>36}")
            continue
        old = [r for r in d.results if r.phase == "old"]
        new = [r for r in d.results if r.phase == "new"]
        noise = sum(1 for r in old if r.alerted)
        alarms = sum(1 for r in new if r.alerted)
        changed = sum(1 for r in new if r.definition_changed)
        lines.append(
            f"  {d.name:<14}{d.old_version:>12}{d.new_version:>12}"
            f"{f'{noise}/{len(old)}':>10}{f'{alarms}/{len(new)}':>10}"
            f"{f'{changed}/{len(new)}':>8}"
            f"{f'{len(d.probed_tools)}':>8}")

    not_measured = [d for d in done if d.error]
    if not_measured:
        lines += ["", "  not measured:"]
        for d in not_measured:
            lines.append(f"    {d.name:<14}{d.error}")

    if measured:
        from eval.stats import wilson
        new_runs = [r for d in measured for r in d.results if r.phase == "new"]
        old_runs = [r for d in measured for r in d.results if r.phase == "old"]
        for label, rows in (("same release", old_runs), ("after upgrade", new_runs)):
            if not rows:
                continue
            hits = sum(1 for r in rows if r.alerted)
            rate, low, high = wilson(hits, len(rows))
            lines.append(f"  pooled {label:<16}{rate:6.1%} "
                         f"[{low:.2f}, {high:.2f}]  {hits}/{len(rows)} runs")
        lines += ["",
                  "  Pooled over servers, which is a weaker figure than it",
                  "  looks: the servers differ in how non-deterministic their",
                  "  own output is, so the per-server rows above carry the",
                  "  result and the pool is context."]

    sdk_pins = [(d.name, e.get("version"), e.get("sdk_version"),
                 e.get("sdk_resolved_by"))
                for d in done for e in d.environments]
    walked = [p for p in sdk_pins if p[3] == "walk"]
    if walked:
        lines += ["", "  releases that needed an older SDK than pip resolves:"]
        for server, version, sdk, _ in walked:
            lines.append(f"    {server:<14}{version:<14}mcp=={sdk}")
        lines += ["  (a finding about the ecosystem, not a workaround: a "
                  "release whose",
                  "   dependency is unpinned stops running when its SDK moves "
                  "on)"]
    return "\n".join(lines)
