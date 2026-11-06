"""Give an episode the recorded data its countermeasures need.

Both host mimicry and traffic mimicry imitate something real, and neither
invents it: mimic_host borrows the client identity the proxy actually saw,
and mimic_traffic draws its pauses from pauses that actually happened. That
is the right design, and it has a sharp edge in the harness.

Every episode runs in a fresh DRIFTSENTRY_HOME. A fresh home has no
recorded host profile and no learned traffic profile, so both countermeasures
fall back - with a log warning that the evaluation CLI silences - and run as
the control. The first T20 smoke run did exactly that: the 'all' condition,
with every countermeasure on, still had `client` as its strongest channel at
AUC 1.000, because nothing had been borrowed. Measured and reported, that
would have read as "the countermeasures do not work".

So the fixtures are committed and installed per episode, and a condition
whose data is missing raises instead of degrading. The fixtures are real
recordings, not constructions:

    host_profile.json     the client identity read from Claude Desktop's own
                          mcp.log, confirmed across seven identical
                          handshakes.
    traffic_profile.json  learned from the RQ3 collection's proxy log: 115
                          genuine sessions, 165 calls, and the 115 startup
                          think times whose median is 4.06 seconds.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOST_PROFILE = Path(__file__).with_name("host_profile.json")
TRAFFIC_PROFILE = Path(__file__).with_name("traffic_profile.json")


class ProfileMissing(RuntimeError):
    """A countermeasure was requested without the data it imitates.

    Raised rather than warned. A countermeasure that silently does nothing
    produces a number that looks like a measurement of the countermeasure and
    is a measurement of the control.
    """


def install(server: str, *, mimic_host: bool = False,
            mimic_traffic: bool = False) -> dict[str, Any]:
    """Write the fixtures into the current DRIFTSENTRY_HOME for one server.

    Called after DRIFTSENTRY_HOME is set, because the detector's paths module
    reads it at call time.
    """
    installed: dict[str, Any] = {}

    if mimic_host:
        from driftsentry.hostprofile import SDK_DEFAULT_NAME, profile_path

        if not HOST_PROFILE.is_file():
            raise ProfileMissing(
                f"mimic_host needs a recorded host identity and {HOST_PROFILE} "
                f"is absent. Without it the probe announces the SDK default, "
                f"which RQ3 measured at AUC 1.000 on its own.")
        recorded = json.loads(HOST_PROFILE.read_text(encoding="utf-8"))
        name = recorded.get("name")
        if not name or name == SDK_DEFAULT_NAME:
            raise ProfileMissing(
                f"the recorded host identity is {name!r}, which is the SDK's "
                f"own default - imitating it would be imitating a probe")
        profile_path(server).write_text(
            json.dumps({"name": name,
                        "version": recorded.get("version") or "unknown",
                        "cwd": None}, indent=2), encoding="utf-8")
        installed["host"] = name

    if mimic_traffic:
        from driftsentry.traffic import TrafficProfile, save

        if not TRAFFIC_PROFILE.is_file():
            raise ProfileMissing(
                f"mimic_traffic needs a learned traffic profile and "
                f"{TRAFFIC_PROFILE} is absent. Run driftsentry.traffic.learn "
                f"over a proxy exchange log first.")
        profile = TrafficProfile.from_dict(
            json.loads(TRAFFIC_PROFILE.read_text(encoding="utf-8")))
        profile.server = server
        if not profile.usable:
            raise ProfileMissing(
                f"the traffic profile has {profile.n_sessions} session(s), "
                f"which is not enough to imitate")
        if not profile.startup_s:
            raise ProfileMissing(
                "the traffic profile has no startup think times. Pacing the "
                "gaps between calls does not close the timing channel: their "
                "median is 5ms, while the feature that separates the classes "
                "is the 3.1-second pause before a genuine first call.")
        save(profile)
        installed["traffic"] = {"sessions": profile.n_sessions,
                                "median_startup_s": round(profile.median_startup(), 3)}

    return installed
