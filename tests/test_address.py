"""Adress-Kandidaten fuer den Einrichtungsdialog."""

from __future__ import annotations

import pytest

from custom_components.itrend_player.address import address_candidates


def cands(**kw):
    base = {"internal_url": None, "external_url": None, "server_port": 8123, "use_ssl": False,
            "local_ip": None}
    return address_candidates(**{**base, **kw})


def test_external_without_port_gets_port_variant_first():
    assert cands(external_url="https://cangos.duckdns.org") == [
        "https://cangos.duckdns.org:8123", "https://cangos.duckdns.org"]


def test_explicit_port_is_kept_and_not_duplicated():
    assert cands(external_url="https://x.example.org:8123/") == ["https://x.example.org:8123"]


def test_standard_ports_get_no_port_suffix():
    assert cands(external_url="https://x.example.org", server_port=443, use_ssl=True) == ["https://x.example.org"]
    assert cands(internal_url="http://ha.lan", server_port=80) == ["http://ha.lan"]
    assert cands(internal_url="http://ha.lan:80", server_port=80) == ["http://ha.lan"]


def test_https_default_port_dropped():
    assert cands(external_url="https://x.example.org:443", server_port=443) == ["https://x.example.org"]


def test_only_internal_url():
    assert cands(internal_url="http://192.168.1.5") == ["http://192.168.1.5:8123", "http://192.168.1.5"]


def test_both_urls_and_local_ip_without_ssl():
    assert cands(internal_url="http://192.168.1.5", external_url="https://x.example.org",
                 local_ip="192.168.1.5") == [
        "http://192.168.1.5:8123", "https://x.example.org:8123",
        "http://192.168.1.5", "https://x.example.org"]


def test_local_ip_only_without_ssl():
    assert cands(local_ip="192.168.1.5") == ["http://192.168.1.5:8123"]
    assert cands(local_ip="192.168.1.5", server_port=80) == ["http://192.168.1.5"]


def test_ssl_does_not_offer_http_ip():
    assert cands(local_ip="192.168.1.5", use_ssl=True) == []
    assert cands(external_url="https://x.example.org", local_ip="192.168.1.5", use_ssl=True) == [
        "https://x.example.org:8123", "https://x.example.org"]


def test_request_url_comes_first_and_is_deduplicated():
    assert cands(external_url="https://x.example.org", request_url="https://x.example.org:8123/") == [
        "https://x.example.org:8123", "https://x.example.org"]
    assert cands(request_url="http://ha.local:8123")[0] == "http://ha.local:8123"


@pytest.mark.parametrize("bad", ["", None, "ftp://x.org", "not a url", "https://u:p@x.org", "https://"])
def test_invalid_urls_ignored(bad):
    assert cands(external_url=bad) == []


def test_ipv6_and_path_prefix():
    assert cands(external_url="https://[2001:db8::1]/ha") == ["https://[2001:db8::1]:8123/ha", "https://[2001:db8::1]/ha"]


def test_no_server_port_known():
    assert cands(external_url="https://x.example.org", server_port=None) == ["https://x.example.org"]
