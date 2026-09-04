"""Shared fixtures.

Every test runs against an isolated DRIFTSENTRY_HOME so nothing can touch the
developer's real `.driftsentry_data/` - which holds the baseline and calibration
the evaluation depends on.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point every test at a throwaway data directory."""
    home = tmp_path / "driftsentry_data"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DRIFTSENTRY_HOME", str(home))
    return home


# The real tool definition FastMCP derives for the adversarial server's
# lookup_customer tool. Copied verbatim from the stored acme baseline so the
# probe golden test exercises a genuine schema, not an idealised one.
LOOKUP_CUSTOMER = {
    "name": "lookup_customer",
    "title": None,
    "description": "Look up a customer record by account identifier.",
    "inputSchema": {
        "properties": {"customer_id": {"title": "Customer Id", "type": "string"}},
        "required": ["customer_id"],
        "title": "lookup_customerArguments",
        "type": "object",
    },
    "annotations": None,
}

READ_DOCUMENT = {
    "name": "read_document",
    "description": "Read a document from the internal reference library.",
    "inputSchema": {
        "properties": {"path": {"title": "Path", "type": "string"}},
        "required": ["path"],
        "title": "read_documentArguments",
        "type": "object",
    },
    "annotations": None,
}


@pytest.fixture
def lookup_customer() -> dict:
    return json.loads(json.dumps(LOOKUP_CUSTOMER))


@pytest.fixture
def read_document() -> dict:
    return json.loads(json.dumps(READ_DOCUMENT))
