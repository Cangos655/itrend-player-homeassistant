"""Gemeinsame Testhilfen. Die Testvektoren kommen aus docs/protocol (Kopie des Protokolls)."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "docs" / "protocol"
sys.path.insert(0, str(PROTO_DIR))

import reference as ref  # noqa: E402  (Referenzimplementierung = unabhaengige Gegenseite)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Custom-Integration in den Tests laden."""
    return enable_custom_integrations


@pytest.fixture(scope="session")
def vectors() -> dict:
    with open(PROTO_DIR / "vectors.json", encoding="utf-8") as f:
        return json.load(f)
