"""Console entry point for the `driftsentry` command.

The command surface is built up across phases (see the roadmap). Wired so far:
    run       Phase 1 - headless transparent proxy for one stdio MCP server
    init      Phase 2 - ingest a client config, rewrite it, and baseline servers
    restore   Phase 2 - take DriftSentry back out of the loop
    baseline  Phase 3 - capture a behavioural baseline for one server
    verify    Phase 3 - re-probe a server and measure drift against its baseline
Planned:
    daemon / ui / status / scan / report   Phase 6

The full CLI is rebuilt on Typer in Phase 6; this argparse version keeps the
commands usable now without pulling the whole command surface forward.
"""
from __future__ import annotations

import argparse
import logging
import os
import shlex
import shutil
import sys
from pathlib import Path

from driftsentry import __version__


def _configure_logging(verbose: bool = False) -> None:
    # Logs go to stderr - our stdout carries JSON-RPC frames to the client.
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(asctime)s [driftsentry] %(levelname)s %(message)s",
    )


def _split_command(raw: str) -> list[str]:
    """Split a quoted command string into argv, safely on Windows.

    ``shlex.split`` defaults to POSIX rules, where a backslash is an escape
    character - so a Windows path is quietly destroyed:
    ``C:\\Users\\me\\python.exe`` becomes ``C:Usersmepython.exe``. The command
    then fails, or worse, succeeds against the wrong path and the run looks
    fine while measuring nothing.

    Non-POSIX mode keeps backslashes but leaves the quotes attached to each
    token, so they are stripped afterwards.
    """
    tokens = shlex.split(raw, posix=(os.name != "nt"))
    cleaned = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        cleaned.append(token)
    return cleaned


def _resolve_exec(tokens: list[str]) -> list[str]:
    """Turn the ``--exec`` tokens into a [command, *args] list.

    Supports both forms:
      * separate tokens:   --exec python examples/echo_server.py   (path-safe)
      * one quoted string: --exec "python examples/echo_server.py"
    """
    if len(tokens) == 1 and " " in tokens[0]:
        return shlex.split(tokens[0], posix=(os.name != "nt"))
    return tokens


def _add_probe_options(parser: argparse.ArgumentParser) -> None:
    """Options shared by every command that captures or replays probes."""
    parser.add_argument("--probes", type=int, default=3, help="canary probes per tool (default 3)")
    parser.add_argument("--samples", type=int, default=8,
                        help="samples per probe when learning variance (default 8)")
    parser.add_argument("--seed", type=int, default=20260720,
                        help="probe seed; recorded in the baseline for reproducibility")
    parser.add_argument("--embedding", default="auto",
                        help="embedding backend: auto | hashing | onnx | ollama[:model]")
    parser.add_argument("--safety-policy", choices=["default", "strict"], default="default",
                        help="'strict' only probes tools proven read-only")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="disable file/network side-effect monitoring")


# --------------------------------------------------------------------------- #
# run (Phase 1)
# --------------------------------------------------------------------------- #
def _cmd_run(ns: argparse.Namespace) -> int:
    import anyio

    from driftsentry.proxy import run_stdio_proxy

    exec_tokens = _resolve_exec(ns.exec)
    if not exec_tokens:
        print("error: --exec requires the real server's launch command", file=sys.stderr)
        return 2
    command, args = exec_tokens[0], exec_tokens[1:]

    # Forward only the named variables down to the real server. The *values* come
    # from our own environment (the client set them on us), so secrets never
    # travel on the command line.
    env = None
    if ns.forward_env:
        env = {key: os.environ[key] for key in ns.forward_env if key in os.environ}
        missing = [key for key in ns.forward_env if key not in os.environ]
        if missing:
            print(f"warning: --forward-env keys not set: {', '.join(missing)}", file=sys.stderr)

    _configure_logging(verbose=True)

    async def _main() -> None:
        await run_stdio_proxy(ns.server, command, args, cwd=ns.cwd, env=env, enforce=ns.enforce)

    anyio.run(_main)
    return 0


# --------------------------------------------------------------------------- #
# baseline / verify (Phase 3)
# --------------------------------------------------------------------------- #
def _print_baseline(baseline) -> None:
    print(f"server          : {baseline.server}")
    print(f"definition hash : {baseline.definition_hash}")
    print(f"embedding       : {baseline.embedding_backend} (dim {baseline.embedding_dim})")
    print(f"seed            : {baseline.seed}   probes/tool: {baseline.n_probes}"
          f"   samples/probe: {baseline.n_samples}")
    print("tools:")
    for tool in baseline.tools:
        if not tool.probed:
            print(f"  - {tool.tool:<16} not probed ({tool.safety_reason})")
            continue
        bands = ", ".join(f"{p.band:.4f}" for p in tool.probes)
        print(f"  - {tool.tool:<16} {len(tool.probes)} probes, variance bands [{bands}]")


def _cmd_baseline(ns: argparse.Namespace) -> int:
    import anyio

    from driftsentry.baseline import capture_baseline
    from driftsentry.store import BaselineStore

    exec_tokens = _resolve_exec(ns.exec)
    if not exec_tokens:
        print("error: --exec requires the real server's launch command", file=sys.stderr)
        return 2
    command, args = exec_tokens[0], exec_tokens[1:]
    _configure_logging(verbose=ns.verbose)

    async def _main():
        return await capture_baseline(
            ns.server, command, args, cwd=ns.cwd,
            n_probes=ns.probes, n_samples=ns.samples, seed=ns.seed,
            backend_name=ns.embedding, safety_policy=ns.safety_policy,
            monitor_sandbox=not ns.no_sandbox,
        )

    baseline = anyio.run(_main)
    path = BaselineStore().save(baseline)
    _print_baseline(baseline)
    print(f"\nbaseline saved: {path}")
    return 0


_VERDICT_LABEL = {"ok": "OK", "watch": "WATCH", "alert": "ALERT"}


def _print_drift_report(report, show_probes: bool = True) -> None:
    print(f"server     : {report.server}")
    print(f"mode       : {report.mode}    embedding: {report.embedding_backend}")
    print(f"threshold  : ratio >= {report.threshold_ratio:.3f}  ({report.calibration_source})")
    print(f"definition : {'CHANGED' if report.definition_changed else 'unchanged'}")
    print()
    print(f"VERDICT: {_VERDICT_LABEL[report.verdict]}   score {report.score:.2f} "
          f"(alert at 1.00)" + (f"   triggered by: {report.triggered_by}" if report.triggered_by else ""))

    if not report.tools:
        print("\nNo probeable tools in this baseline.")
        return

    print("\nper tool:")
    for tool in report.tools:
        print(f"  [{_VERDICT_LABEL[tool.verdict]:<5}] {tool.tool:<18} score={tool.score:.2f}"
              + (f"  <- {tool.triggered_by}" if tool.triggered_by else ""))
        for signal in tool.signals:
            print(f"            - {signal.name} ({signal.severity}, {signal.score:.2f}): {signal.detail}")
        if show_probes and tool.verdict != "ok":
            for probe in tool.probes:
                if probe.score >= 0.5:
                    print(f"            probe {probe.probe_id}: dist={probe.distance:.4f} "
                          f"band={probe.band:.4f} ratio={probe.ratio:.2f}")


def _cmd_verify(ns: argparse.Namespace) -> int:
    import anyio

    from driftsentry.store import BaselineStore
    from driftsentry.verify import verify_server

    store = BaselineStore()
    baseline = store.load(ns.server)
    if baseline is None:
        print(f"error: no baseline for {ns.server!r}. Run `driftsentry baseline` first.", file=sys.stderr)
        return 2

    launch = None
    if ns.exec:
        exec_tokens = _resolve_exec(ns.exec)
        launch = {"command": exec_tokens[0], "args": exec_tokens[1:], "cwd": ns.cwd}
    _configure_logging(verbose=ns.verbose)

    async def _main():
        return await verify_server(
            baseline,
            launch=launch,
            samples_per_probe=ns.samples_per_probe,
            monitor_sandbox=not ns.no_sandbox,
            mode="hash-only" if ns.hash_only else "full",
            threshold_ratio=ns.threshold,
        )

    try:
        report = anyio.run(_main)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_drift_report(report)

    if ns.json:
        import json as _json

        Path(ns.json).write_text(_json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nstructured report: {ns.json}")

    # Phase 5: a crossed threshold becomes an actionable alert, not just a number.
    if report.verdict == "alert" and not ns.no_alert:
        from driftsentry.alerts import AlertStore, build_alerts, render
        from driftsentry.policy import PolicyStore

        alert_store = AlertStore()
        alerts = build_alerts(report)
        print()
        for alert in alerts:
            render(alert, use_rich=not ns.plain)
            path = alert_store.append(alert)
        print(f"alert record: {path}")

        # Record the finding as policy state. Enforcement stays OFF unless the
        # user opts in, so this marks the server without changing its behaviour.
        PolicyStore().update(
            report.server,
            status="quarantined",
            reason=alerts[0].cause,
            flagged_tools=[a.tool for a in alerts],
        )
        print(f"policy: {report.server} marked QUARANTINED "
              f"(advisory only - enable blocking with `driftsentry run --enforce`)")

    # Exit code doubles as a scriptable signal: 0 clean, 1 drift detected.
    return 0 if report.verdict != "alert" else 1


def _watch_line(report) -> str:
    """One compact status line per check, for the live monitor."""
    from datetime import datetime

    stamp = datetime.now().strftime("%H:%M:%S")
    verdict = report.verdict.upper()
    tag = {"OK": "  OK  ", "WATCH": " WATCH", "ALERT": "ALERT!"}.get(verdict, verdict)
    line = f"  {stamp}   {report.server:<10} [{tag}]  score {report.score:5.2f}"
    if report.triggered_by:
        line += f"   <- {report.triggered_by}"
    return line


def _cmd_ui(ns: argparse.Namespace) -> int:
    """Start the daemon and open the desktop dashboard.

    The window is the control plane: it reads daemon state and issues commands,
    and it holds no detection logic of its own. That separation is deliberate -
    the numbers on screen are produced by exactly the same code path the CLI and
    the evaluation use, so a good-looking dashboard cannot flatter the results.
    """
    import threading

    import uvicorn

    from driftsentry.api import create_app
    from driftsentry.daemon import Daemon

    _configure_logging(verbose=ns.verbose)

    daemon = Daemon(interval=ns.interval, samples_per_probe=ns.samples_per_probe,
                    monitor_sandbox=not ns.no_sandbox)
    # Starting with no servers is fine: the dashboard's "Add server" page is now
    # the primary way to connect one, so refusing to open the window here would
    # leave a new user with no route in at all.
    if not daemon.servers:
        print("No servers connected yet - use the 'Add server' page in the dashboard.")

    daemon.start()
    app = create_app(daemon)
    url = f"http://127.0.0.1:{ns.port}"

    # Bound to loopback on purpose: this API can quarantine a user's tooling, so
    # it must not be reachable from the network.
    config = uvicorn.Config(app, host="127.0.0.1", port=ns.port, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, name="driftsentry-api", daemon=True).start()

    print(f"DriftSentry is monitoring {len(daemon.servers)} server(s) every {ns.interval:.0f}s.")
    print(f"Dashboard: {url}")

    if ns.no_window:
        print("Press Ctrl-C to stop.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print("\nstopped.")
        return 0

    try:
        import webview  # pywebview: a real window rather than a browser tab

        webview.create_window("DriftSentry", url, width=1280, height=860,
                              background_color="#0b0f14")
        webview.start()
        return 0
    except Exception as exc:  # noqa: BLE001 - fall back rather than fail
        log = logging.getLogger("driftsentry.ui")
        log.info("native window unavailable (%s); opening a browser instead", exc)
        import webbrowser

        webbrowser.open(url)
        print("Press Ctrl-C to stop.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print("\nstopped.")
        return 0


def _cmd_watch(ns: argparse.Namespace) -> int:
    """Re-verify a server on a schedule and alert the moment drift appears.

    This is the resident behaviour that separates DriftSentry from a one-shot
    scanner: nothing about a rug pull shows up at install time, so the detector
    has to keep looking. `verify` checks once; `watch` keeps checking, so an
    alert can surface on its own while you do something else - which is the whole
    point of monitoring after approval.

    It is a foreground loop, not the full daemon (that owns scheduling for many
    servers at once and backs the dashboard). But the schedule-and-alert core is
    the same, and this is enough to watch a rug pull get caught live.
    """
    import anyio

    from driftsentry.alerts import AlertStore, build_alerts, render
    from driftsentry.store import BaselineStore

    store = BaselineStore()
    baseline = store.load(ns.server)
    if baseline is None:
        print(f"error: no baseline for {ns.server!r}. Run `driftsentry baseline` first.", file=sys.stderr)
        return 2

    _configure_logging(verbose=False)
    print(f"Watching {ns.server!r} every {ns.interval}s - re-probing on a schedule.")
    print("This is the resident behaviour a one-shot scanner does not have.")
    print("Arm an attack in the attacker console and watch it get caught. Ctrl-C to stop.\n")

    alert_store = AlertStore()
    from driftsentry.verify import verify_server

    async def _loop() -> None:
        last = None
        checks = 0
        while True:
            try:
                report = await verify_server(
                    baseline,
                    samples_per_probe=ns.samples_per_probe,
                    monitor_sandbox=not ns.no_sandbox,
                )
            except Exception as exc:  # noqa: BLE001 - a bad cycle must not kill the monitor
                from datetime import datetime
                print(f"  {datetime.now():%H:%M:%S}   check failed: {exc}")
                await anyio.sleep(ns.interval)
                continue

            checks += 1
            print(_watch_line(report))

            # Show the full alert card only when the state CHANGES into alert, so
            # a sustained attack does not repeat the whole card every cycle.
            if report.verdict == "alert" and last != "alert":
                print()
                for alert in build_alerts(report):
                    render(alert, use_rich=not ns.plain)
                    alert_store.append(alert)
                print()
            elif report.verdict != "alert" and last == "alert":
                print("  -> recovered: the server is behaving again.\n")

            last = report.verdict
            if ns.once or (ns.max_checks and checks >= ns.max_checks):
                return
            await anyio.sleep(ns.interval)

    try:
        anyio.run(_loop)
    except KeyboardInterrupt:
        print("\nstopped watching.")
    return 0


def _cmd_report(ns: argparse.Namespace) -> int:
    from driftsentry.alerts import AlertStore, render, render_text
    from driftsentry.policy import PolicyStore

    store = AlertStore()
    servers = [ns.server] if ns.server else store.servers()
    if not servers:
        print("No alerts recorded yet.")
        return 0

    for server in servers:
        alerts = store.history(server, limit=ns.limit)
        policy = PolicyStore().get(server)
        print(f"\n{server}: status={policy.status}  enforce={policy.enforce}  "
              f"alerts={len(store.history(server))}")
        if not alerts:
            print("  (no alerts)")
            continue
        if ns.full:
            for alert in alerts:
                print()
                render(alert, use_rich=not ns.plain)
        else:
            for alert in alerts:
                print(f"  {alert.created_at[:19]}Z  [{alert.severity:<8}] {alert.tool:<16} "
                      f"score={alert.score:.2f}  {alert.triggered_by}")
            print(f"\n  Full detail: driftsentry report --server {server} --full")
    return 0


def _cmd_quarantine(ns: argparse.Namespace) -> int:
    from driftsentry.policy import PolicyStore

    policy = PolicyStore().update(
        ns.server,
        status="quarantined",
        reason=ns.reason or "quarantined by the user",
        enforce=True if ns.enforce else None,
    )
    print(f"{policy.server}: status={policy.status}  enforce={policy.enforce}")
    if not policy.enforce:
        print("This is advisory. To actually refuse calls, run the proxy with --enforce")
        print("(or re-run this command with --enforce).")
    else:
        print("Tool calls to this server will be REFUSED by any proxy started with --enforce.")
    return 0


def _cmd_trust(ns: argparse.Namespace) -> int:
    from driftsentry.policy import PolicyStore

    policy = PolicyStore().update(
        ns.server, status="trusted", enforce=False, reason=ns.reason or "restored by the user",
        flagged_tools=[],
    )
    print(f"{policy.server}: status={policy.status}  enforce={policy.enforce}")
    print("Note: this clears the policy flag only. If the server really did change "
          "behaviour, re-baseline it so DriftSentry learns the new normal.")
    return 0


def _cmd_calibrate(ns: argparse.Namespace) -> int:
    import anyio

    from driftsentry.calibration import save
    from driftsentry.store import BaselineStore
    from driftsentry.verify import calibrate_servers

    store = BaselineStore()
    servers = ns.server or store.list_servers()
    if not servers:
        print("error: no baselines to calibrate from. Run `driftsentry baseline` first.", file=sys.stderr)
        return 2

    # Additional BENIGN configurations of the same server - in practice, versions
    # that have legitimately been updated.
    #
    # Without these the threshold is fitted to a server that never changes, which
    # is not how software behaves. The first honest update then trips the alarm.
    # A detector that alarms on a legitimate update is unusable no matter how good
    # its recall looks, so the range of benign behaviour has to include change.
    variants: dict[str, list[dict]] = {}
    if ns.also_exec:
        if len(servers) != 1:
            print("error: --also-exec applies to one server; name it with --server",
                  file=sys.stderr)
            return 2
        parsed = []
        for raw in ns.also_exec:
            tokens = _split_command(raw) if isinstance(raw, str) else list(raw)
            if not tokens:
                print(f"error: empty --also-exec value: {raw!r}", file=sys.stderr)
                return 2
            # Fail loudly on a command that cannot start. A variant that silently
            # does not run still yields a threshold - just one fitted to less
            # benign variety than you think, which is invisible in the output.
            if not Path(tokens[0]).is_file() and shutil.which(tokens[0]) is None:
                print(f"error: --also-exec command not found: {tokens[0]!r}\n"
                      f"       parsed from: {raw!r}", file=sys.stderr)
                return 2
            parsed.append({"command": tokens[0], "args": tokens[1:], "cwd": None})
        variants[servers[0]] = parsed

    _configure_logging(verbose=ns.verbose)
    print("Calibrating the detection threshold on BENIGN servers only.")
    print(f"servers: {', '.join(servers)}   repeats: {ns.repeats}")
    if variants:
        print("plus these additional benign configurations "
              "(e.g. a legitimately updated version):")
        for entry in variants[servers[0]]:
            print(f"  {entry['command']} {' '.join(entry['args'])}")
    print()

    async def _main():
        return await calibrate_servers(
            servers,
            repeats=ns.repeats,
            samples_per_probe=ns.samples_per_probe,
            margin=ns.margin,
            target_far=ns.target_far,
            store=store,
            variants=variants or None,
        )

    try:
        calibration, per_server = anyio.run(_main)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for name, ratios in per_server.items():
        if ratios:
            print(f"  {name:<18} {len(ratios):>4} observations, "
                  f"max ratio {max(ratios):.3f}, mean {sum(ratios)/len(ratios):.3f}")
        else:
            print(f"  {name:<18} no usable observations")

    print(f"\nbenign distribution : mean {calibration.mean_benign_ratio:.3f}, "
          f"p99 {calibration.p99_benign_ratio:.3f}, max {calibration.max_benign_ratio:.3f}")
    print(f"method              : {calibration.method}")
    print(f"THRESHOLD           : ratio >= {calibration.threshold_ratio:.3f}")
    print(f"false-alarm rate    : {calibration.empirical_far:.1%} on the calibration set "
          f"(target {calibration.target_far:.1%})")
    for warning in calibration.warnings:
        print(f"  warning: {warning}")

    if ns.dry_run:
        print("\n--dry-run: not saved.")
        return 0

    path = save(calibration)
    print(f"\nsaved: {path}")
    print("This threshold was derived from benign servers only. Do not re-tune it "
          "after seeing test results.")
    return 0


# --------------------------------------------------------------------------- #
# init / restore (Phase 2)
# --------------------------------------------------------------------------- #
def _capture_baselines(ns: argparse.Namespace, parsed, server_names: list[str]) -> None:
    """Baseline each freshly-wrapped server: trust attaches to behaviour."""
    import anyio

    from driftsentry.baseline import capture_baseline
    from driftsentry.store import BaselineStore

    store = BaselineStore()
    print("\nCapturing behavioural baselines (trust attaches to behaviour, not to a hash):")
    for name in server_names:
        entry = parsed.servers[name]

        async def _main(entry=entry, name=name):
            return await capture_baseline(
                name, entry.command, entry.args, cwd=entry.cwd, env=entry.env or None,
                n_probes=ns.probes, n_samples=ns.samples, seed=ns.seed,
                backend_name=ns.embedding, safety_policy=ns.safety_policy,
                monitor_sandbox=not ns.no_sandbox,
            )

        try:
            baseline = anyio.run(_main)
        except Exception as exc:  # noqa: BLE001 - one bad server must not abort the rest
            print(f"  {name}: baseline FAILED ({type(exc).__name__}: {exc})")
            continue
        store.save(baseline)
        probed = sum(1 for t in baseline.tools if t.probed)
        skipped = len(baseline.tools) - probed
        print(f"  {name}: baselined {probed} tool(s), {skipped} left to observation "
              f"({baseline.definition_hash[:19]}...)")


def _cmd_init(ns: argparse.Namespace) -> int:
    from driftsentry.clientconfig import (
        diff_text,
        make_backup,
        parse_config,
        rewrite_config,
        write_config,
    )

    config_path = Path(ns.config).expanduser().resolve()
    if not config_path.is_file():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return 2

    try:
        parsed = parse_config(config_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    new_data, report = rewrite_config(parsed, only=ns.server or None)

    print(f"Config: {config_path}")
    print(f"Servers found under '{parsed.servers_key}': {len(parsed.servers)}")
    for line in report.summary_lines():
        print(line)

    if not report.wrapped_servers:
        print("\nNothing to rewrite. (Already wrapped, filtered out, or unsupported transport.)")
        return 0

    if not ns.no_diff:
        print("\nChanges:")
        print(diff_text(parsed.data, new_data, label=config_path.name))

    # Default is a NEW file: we never overwrite the user's config unless asked.
    if ns.in_place:
        backup = make_backup(config_path)
        write_config(config_path, new_data)
        target = config_path
        print(f"\nBackup written: {backup}")
    else:
        target = Path(ns.output).expanduser().resolve() if ns.output else config_path.with_name(
            f"{config_path.stem}.driftsentry{config_path.suffix}"
        )
        write_config(target, new_data)

    print(f"Rewritten config: {target}")
    print(f"Proxied servers: {', '.join(report.wrapped_servers)}")

    if not ns.no_baseline:
        _capture_baselines(ns, parsed, report.wrapped_servers)
    else:
        print("\nSkipped baseline capture (--no-baseline): servers are proxied but not yet baselined.")

    if not ns.in_place:
        print("\nNext: point your MCP client at the rewritten file, or re-run with "
              "--in-place to update the original (a backup is kept).")
    print("Undo at any time:  driftsentry restore --config " + str(target))
    return 0


def _cmd_restore(ns: argparse.Namespace) -> int:
    from driftsentry.clientconfig import (
        find_backups,
        make_backup,
        parse_config,
        unwrap_entry,
        write_config,
    )

    config_path = Path(ns.config).expanduser().resolve()
    if not config_path.is_file():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return 2

    if ns.unwrap:
        # No backup needed: reconstruct each original entry from its wrapper.
        parsed = parse_config(config_path)
        wrapped = [n for n, e in parsed.servers.items() if e.wrapped]
        if not wrapped:
            print("Nothing to unwrap: no DriftSentry-wrapped servers in this config.")
            return 0
        backup = make_backup(config_path)
        data = parsed.data
        for name in wrapped:
            data[parsed.servers_key][name] = unwrap_entry(parsed.servers[name].raw)
        write_config(config_path, data)
        print(f"Backup written: {backup}")
        print(f"Unwrapped: {', '.join(wrapped)}")
        print(f"DriftSentry removed from the loop in: {config_path}")
        return 0

    backup_path = Path(ns.backup).expanduser().resolve() if ns.backup else None
    if backup_path is None:
        backups = find_backups(config_path)
        if not backups:
            print(
                f"error: no backup found for {config_path}.\n"
                "       Use --backup <path>, or --unwrap to reconstruct the originals.",
                file=sys.stderr,
            )
            return 2
        backup_path = backups[0]

    if not backup_path.is_file():
        print(f"error: backup not found: {backup_path}", file=sys.stderr)
        return 2

    config_path.write_text(backup_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Restored {config_path}")
    print(f"     from {backup_path}")
    print("DriftSentry is no longer in the loop for this config.")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _default(_: argparse.Namespace) -> int:
    print(f"DriftSentry {__version__}")
    print("Behavioural rug-pull detector for the Model Context Protocol.")
    print()
    print("Commands:")
    print("  init      --config <path>            rewrite a client config + baseline its servers")
    print("  restore   --config <path>            take DriftSentry back out of the loop")
    print("  baseline  --server <name> --exec ..  capture a behavioural baseline")
    print("  calibrate                           set the threshold from benign servers only")
    print("  verify    --server <name>            re-probe, score, and alert on drift")
    print("  ui                                  open the desktop dashboard (recommended)")
    print("  watch     --server <name>            keep re-checking on a timer, alert live")
    print("  report    [--server <name>]          alert history and policy state")
    print("  quarantine/trust --server <name>     mark a server unsafe / safe again")
    print("  run       --server <name> --exec ..  headless proxy (your client launches this)")
    print()
    print("Demos:  python examples/{echo_client,proxy_demo,init_demo,baseline_demo,")
    print("                         scorer_demo,alert_demo}.py")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="driftsentry", add_help=True)
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.set_defaults(func=_default)
    sub = parser.add_subparsers(dest="command")

    # run ------------------------------------------------------------------
    run = sub.add_parser("run", help="headless transparent proxy for one stdio MCP server (Phase 1)")
    run.add_argument("--server", required=True, help="logical name for the server (used for its log file)")
    run.add_argument("--cwd", default=None, help="working directory for the real server")
    run.add_argument("--forward-env", action="append", default=[], metavar="KEY",
                     help="environment variable name to pass down to the real server (repeatable)")
    run.add_argument("--enforce", action="store_true",
                     help="opt-in: refuse tool calls to a quarantined server (detection is the "
                          "default; blocking is not)")
    run.add_argument("--exec", required=True, nargs=argparse.REMAINDER,
                     help="the real server's launch command, e.g. --exec python server.py (must be last)")
    run.set_defaults(func=_cmd_run)

    # baseline -------------------------------------------------------------
    baseline = sub.add_parser("baseline", help="capture a behavioural baseline for one server (Phase 3)")
    baseline.add_argument("--server", required=True, help="name to store the baseline under")
    baseline.add_argument("--cwd", default=None, help="working directory for the server")
    baseline.add_argument("--verbose", action="store_true", help="log probe progress")
    _add_probe_options(baseline)
    baseline.add_argument("--exec", required=True, nargs=argparse.REMAINDER,
                          help="the server's launch command (must be last)")
    baseline.set_defaults(func=_cmd_baseline)

    # verify ---------------------------------------------------------------
    verify = sub.add_parser("verify", help="re-probe a server and score it against its baseline (Phase 4)")
    verify.add_argument("--server", required=True, help="name of the stored baseline")
    verify.add_argument("--cwd", default=None, help="working directory for the server")
    verify.add_argument("--samples-per-probe", type=int, default=2,
                        help="samples per probe when re-checking (default 2)")
    verify.add_argument("--no-sandbox", action="store_true", help="disable side-effect monitoring")
    verify.add_argument("--hash-only", action="store_true",
                        help="control condition: score using the definition hash alone, "
                             "as mcp-scan-style pinning does")
    verify.add_argument("--threshold", type=float, default=None,
                        help="override the calibrated drift ratio threshold")
    verify.add_argument("--json", default=None, metavar="PATH", help="write the structured report here")
    verify.add_argument("--no-alert", action="store_true",
                        help="score only; do not raise or record an alert")
    verify.add_argument("--plain", action="store_true", help="plain-text alerts, no colour")
    verify.add_argument("--verbose", action="store_true", help="log probe progress")
    verify.add_argument("--exec", nargs=argparse.REMAINDER, default=[],
                        help="launch command override; defaults to the one stored in the baseline")
    verify.set_defaults(func=_cmd_verify)

    # ui -------------------------------------------------------------------
    ui = sub.add_parser(
        "ui",
        help="open the desktop dashboard, with the monitoring daemon behind it (Phase 6)",
    )
    ui.add_argument("--interval", type=float, default=20.0,
                    help="seconds between scheduled checks (default 20)")
    ui.add_argument("--samples-per-probe", type=int, default=1,
                    help="samples per probe each cycle (default 1)")
    ui.add_argument("--port", type=int, default=8787, help="localhost port (default 8787)")
    ui.add_argument("--no-window", action="store_true",
                    help="serve only; do not open a window")
    ui.add_argument("--no-sandbox", action="store_true", help="disable side-effect monitoring")
    ui.add_argument("--verbose", action="store_true", help="log daemon activity")
    ui.set_defaults(func=_cmd_ui)

    # watch ----------------------------------------------------------------
    watch = sub.add_parser(
        "watch",
        help="re-verify a server on a schedule and alert live when drift appears (Phase 6 preview)",
    )
    watch.add_argument("--server", required=True, help="name of the stored baseline")
    watch.add_argument("--interval", type=float, default=12.0,
                       help="seconds between checks (default 12)")
    watch.add_argument("--samples-per-probe", type=int, default=1,
                       help="samples per probe each cycle (default 1, for responsiveness)")
    watch.add_argument("--no-sandbox", action="store_true", help="disable side-effect monitoring")
    watch.add_argument("--plain", action="store_true", help="plain-text alerts, no colour")
    watch.add_argument("--once", action="store_true", help="run a single check and exit")
    watch.add_argument("--max-checks", type=int, default=None, help="stop after this many checks")
    watch.set_defaults(func=_cmd_watch)

    # calibrate ------------------------------------------------------------
    calibrate = sub.add_parser(
        "calibrate",
        help="derive the detection threshold from benign servers only (Phase 4)",
    )
    calibrate.add_argument("--server", action="append", default=[], metavar="NAME",
                           help="benign server to calibrate on (repeatable); default is every baseline")
    calibrate.add_argument("--repeats", type=int, default=3,
                           help="re-probe rounds per server (default 3)")
    calibrate.add_argument("--samples-per-probe", type=int, default=2,
                           help="samples per probe in each round (default 2)")
    calibrate.add_argument("--margin", type=float, default=None,
                           help="headroom multiplier above the benign operating point (default 1.25)")
    calibrate.add_argument("--target-far", type=float, default=None,
                           help="accepted benign false-alarm rate (default 0.01)")
    calibrate.add_argument("--also-exec", action="append", default=[], metavar="COMMAND",
                           help="another BENIGN configuration of the same server to include, as a "
                                "quoted launch command (repeatable). Use this for a legitimately "
                                "updated version, so the threshold tolerates real updates.")
    calibrate.add_argument("--dry-run", action="store_true", help="compute and print, but do not save")
    calibrate.add_argument("--verbose", action="store_true", help="log probe progress")
    calibrate.set_defaults(func=_cmd_calibrate)

    # init -----------------------------------------------------------------
    init = sub.add_parser("init", help="ingest a client config, rewrite it, and baseline servers (Phase 2+3)")
    init.add_argument("--config", required=True, help="path to the MCP client config JSON")
    init.add_argument("--output", default=None, help="where to write the rewritten config")
    init.add_argument("--in-place", action="store_true",
                      help="update the original config (a timestamped backup is written first)")
    init.add_argument("--server", action="append", default=[], metavar="NAME",
                      help="only rewrite this server (repeatable); default is all supported servers")
    init.add_argument("--no-diff", action="store_true", help="do not print the diff")
    init.add_argument("--no-baseline", action="store_true",
                      help="rewrite only; skip Phase 3 behavioural baseline capture")
    init.add_argument("--verbose", action="store_true", help="log probe progress")
    _add_probe_options(init)
    init.set_defaults(func=_cmd_init)

    # report ---------------------------------------------------------------
    report = sub.add_parser("report", help="show alert history and policy state (Phase 5)")
    report.add_argument("--server", default=None, help="server to report on (default: all)")
    report.add_argument("--limit", type=int, default=10, help="most recent N alerts (default 10)")
    report.add_argument("--full", action="store_true", help="render each alert in full")
    report.add_argument("--plain", action="store_true", help="plain-text output, no colour")
    report.set_defaults(func=_cmd_report)

    # quarantine / trust ---------------------------------------------------
    quarantine = sub.add_parser("quarantine", help="mark a server as quarantined (Phase 5)")
    quarantine.add_argument("--server", required=True)
    quarantine.add_argument("--reason", default=None)
    quarantine.add_argument("--enforce", action="store_true",
                            help="also allow the proxy to refuse calls to this server")
    quarantine.set_defaults(func=_cmd_quarantine)

    trust = sub.add_parser("trust", help="clear a quarantine and trust a server again (Phase 5)")
    trust.add_argument("--server", required=True)
    trust.add_argument("--reason", default=None)
    trust.set_defaults(func=_cmd_trust)

    # restore --------------------------------------------------------------
    restore = sub.add_parser("restore", help="restore a config from backup, removing DriftSentry (Phase 2)")
    restore.add_argument("--config", required=True, help="path to the config to restore")
    restore.add_argument("--backup", default=None, help="specific backup file (default: newest)")
    restore.add_argument("--unwrap", action="store_true",
                         help="reconstruct the originals from the wrapped entries instead of using a backup")
    restore.set_defaults(func=_cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
