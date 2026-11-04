"""Which tools may be probed, and why the default fails closed.

Found by pointing DriftSentry at a real server for the first time.
mcp-server-git advertises twelve tools, five of which write. Two of those -
git_commit and git_add - matched no destructive verb and no read-only verb,
so the old fail-open default classified both "safe, no state-changing signal
found" and would have probed them. On a real repository that means staging
files and creating commits: the detector causing the side effects it exists
to detect.

No adversary is needed for this. An honest server with ordinary tool names
is enough, which is why it is a different problem from the annotation-trust
one already in threats to validity.

It stayed invisible until a real server was used. The adversarial server has
one side-effecting tool, send_invoice, and "send" was already on the list.
"""
from __future__ import annotations

import pytest

from driftsentry.probes import classify_tool_safety


def safe(name, description="") -> bool:
    return classify_tool_safety({"name": name, "description": description})[0] == "safe"


# --------------------------------------------------------------------------- #
# The tools that caused the change
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,description", [
    ("git_commit", "Records changes to the repository"),
    ("git_add", "Adds file contents to the staging area"),
    ("git_reset", "Unstages all staged changes"),
    ("git_create_branch", "Creates a new branch from an optional base branch"),
    ("git_checkout", "Switches branches"),
])
def test_a_real_write_tool_is_never_probed(name, description):
    assert not safe(name, description), f"{name} writes and must not be called"


@pytest.mark.parametrize("name,description", [
    ("git_status", "Shows the working tree status"),
    ("git_log", "Shows the commit logs"),
    ("git_diff", "Shows differences between branches or commits"),
    ("git_show", "Shows the contents of a commit"),
    ("git_branch", "List Git branches"),
])
def test_a_real_read_only_tool_is_still_probed(name, description):
    """Failing closed must not cost every tool on a server with a write path."""
    assert safe(name, description), f"{name} is read-only and should be probed"


# --------------------------------------------------------------------------- #
# Name before description
# --------------------------------------------------------------------------- #
def test_the_name_outweighs_the_description():
    """git_log is "Shows the commit logs" - commit is a noun here.

    Matching name and description as one bag of words made it
    side-effecting and lost a genuinely safe tool. What a tool is CALLED is
    the stronger evidence; the description breaks ties.
    """
    assert safe("git_log", "Shows the commit logs")
    assert not safe("git_commit", "Shows what will be recorded")


def test_a_destructive_description_still_counts_when_the_name_says_nothing():
    assert not safe("handle_request", "Deletes the record permanently")


def test_a_read_only_description_counts_when_the_name_says_nothing():
    assert safe("handle_request", "Returns a list of records")


# --------------------------------------------------------------------------- #
# The default
# --------------------------------------------------------------------------- #
def test_an_unrecognised_tool_is_not_probed_by_default():
    """A verb list is a list of the cases someone thought of. The next real
    server will have a tool nobody thought of."""
    verdict, why = classify_tool_safety({"name": "frobnicate", "description": "Frobnicates."})
    assert verdict == "side-effecting"
    assert "strict" in why


def test_the_permissive_policy_is_still_reachable_for_reproduction():
    """Results recorded under the old default have to stay reproducible."""
    verdict, why = classify_tool_safety(
        {"name": "frobnicate", "description": "Frobnicates."}, policy="default")
    assert verdict == "safe"
    assert "permissive" in why


def test_an_explicit_annotation_still_wins():
    assert safe_with({"name": "frobnicate", "annotations": {"readOnlyHint": True}})
    assert not safe_with({"name": "get_thing", "annotations": {"destructiveHint": True}})


def safe_with(tool) -> bool:
    return classify_tool_safety(tool)[0] == "safe"


# --------------------------------------------------------------------------- #
# The control condition must not have moved
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,description,expected", [
    ("lookup_customer", "Look up a customer record by account identifier.", True),
    ("read_document", "Read a document from the internal reference library.", True),
    ("get_weather", "Report the current weather for a city.", True),
    ("search_orders", "Search recent orders and return the matching lines.", False),
    ("send_invoice", "Send an invoice to a customer by email.", False),
])
def test_the_adversarial_server_classifies_exactly_as_before(name, description, expected):
    """Checked before the default was changed, and asserted here so it stays
    true: Experiments 1 to 3 probe the same three tools they always did."""
    assert safe(name, description) is expected


# --------------------------------------------------------------------------- #
# Tools from the other real servers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,description", [
    ("get_current_time", "Get current time in a specific timezone"),
    ("convert_time", "Convert time between timezones"),
    ("calculate", "Calculates the result of an expression"),
])
def test_the_real_read_only_servers_remain_probeable(name, description):
    """Strict must not make a whole server unprobeable - calculate was the
    calculator server's only tool and briefly fell off the list."""
    assert safe(name, description)
