"""Shared fixtures for the arp_cli tests.

All keys are throwaway keys created in memory. Nothing here touches real
DNS or the network: DNS lookups and HTTP fetches are replaced per test.
"""

import base64
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import arp_cli  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def fixture_path(name):
    return os.path.join(FIXTURES, name)


def load_fixture(name):
    with open(fixture_path(name), "r", encoding="utf-8") as f:
        return json.load(f)


def txt_record(private_key, version="ARP1"):
    """DNS TXT value for the public half of private_key (SPEC §13.5)."""
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return f"v={version}; k=ed25519; p={base64.b64encode(raw).decode('ascii')}"


@pytest.fixture
def throwaway_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def fake_dns(monkeypatch):
    """Replace arp_cli.resolve_txt with a dict lookup.

    Values are a list of TXT strings or an exception instance to raise.
    Unknown names raise DNSNoRecord. The dict records every queried name
    under the key "__queries__".
    """
    zone = {"__queries__": []}

    def resolver(name):
        zone["__queries__"].append(name)
        value = zone.get(name)
        if value is None:
            raise arp_cli.DNSNoRecord(f"NXDOMAIN {name}")
        if isinstance(value, Exception):
            raise value
        return list(value)

    monkeypatch.setattr(arp_cli, "resolve_txt", resolver)
    return zone
