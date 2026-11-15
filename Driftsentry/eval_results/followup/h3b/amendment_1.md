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
