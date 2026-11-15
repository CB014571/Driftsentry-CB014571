# H3b amendment 1: how the held-out environments are built

**Written 15 November 2026, before any held-out upgrade had been measured.**
The pre-registration (`preregistration.json`, sha256 in `preregistration.sha256`)
is unchanged. This note records a change to how environments are *built*, not
to the hypothesis, thresholds, rules or analysis.

## What happened

The first held-out run (`held_out_console.log`) built all three servers on
CPython 3.12, as pre-registered. No upgrade was measured, because no old
release started:

| server | old release | outcome |
|---|---|---|
| mcp-server-calculator | 0.1.2 | no SDK installable beside it (conflicting dependencies) |
| mcp-server-sqlite | 0.6.2 | crashed in the handshake; the walk ended on an SDK beta |
| mcp-server-duckdb | 1.0.1 | no handshake within 60 s |

The installed versions show why. Each 2024 to 2025 release was installed with
**today's** transitive dependencies: pydantic 2.14, anyio 4.16, duckdb 2.0.

## The change

Each release, old and new alike, is installed with only the packages that had
been uploaded by two days after its own release date (pip 26.1,
`--uploaded-prior-to`, via `eval real --as-of-release`). That is the release as
it would have been deployed. The SDK walk uses the same date.

## Why this is not result-tuning

No held-out upgrade had produced any measurement under either build: all three
were NOT MEASURED. Nothing about the outcome was known when this was decided.
The pre-registration already provides for a server that still cannot start: it
is reported as unmeasurable and counted neither way.

## Amendment 2 (same day): the sqlite launch line

Re-run with dated installs, calculator was measured. sqlite still did not
start, and the reason was not the environment. Neither sqlite release (0.6.2
nor 2025.4.25) ships a `__main__` module, so the launch line in
`eval/real_servers.json`, `python -m mcp_server_sqlite`, could never start
either one. Both releases declare the console script
`mcp-server-sqlite = mcp_server_sqlite:main`, and the launch now calls that
`main()`, the same form duckdb already used. This was also part of why sqlite
was "unmeasurable" in the original RQ3b run.

duckdb's fixture step installed the old release without the date, and pip does
not downgrade what it already installed, so the dated install had no effect
there. That step is now dated too.

Both are launch and environment fixes. Neither touches the rules, thresholds or
analysis, and at the time of the change no held-out *upgrade* had been scored
except calculator's.

## Amendment 3 (same day): the start-check's empty environment

With the dated environments and the corrected launch line, sqlite 0.6.2 and
duckdb 1.0.1 both started and listed their tools when started by hand, yet the
runner still reported "no handshake within 60s". The runner's start-check
(`real_envs.starts_and_lists`) runs a small MCP client *inside the server's
own environment*, and passed `env={}` when the server needs no extra
variables. mcp 1.0 to 1.1 start the server with a literally empty
environment for `{}`; on Windows a process with no SYSTEMROOT hangs. Newer
SDKs merge `{}` with the defaults, which is why no current release ever showed
it. The check now passes `None`. DriftSentry's own client (mcp 1.28) already
merged, so nothing it measured was affected.

Again a harness fix, made before either server's upgrade was scored.
