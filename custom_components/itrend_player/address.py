"""Adressen, die der Nutzer in der App eintippen kann (Basisadresse von Home Assistant)."""

from __future__ import annotations

from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize(url: str | None) -> tuple[str, str, int | None, str] | None:
    """(Schema, Host mit Klammern, expliziter Port, Pfad) oder None."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if scheme not in _DEFAULT_PORTS or not host or parts.username or parts.password:
        return None
    if ":" in host:
        host = f"[{host}]"
    return scheme, host, port, parts.path.rstrip("/")


def _build(scheme: str, host: str, port: int | None, path: str) -> str:
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def address_candidates(
    *,
    internal_url: str | None,
    external_url: str | None,
    server_port: int | None,
    use_ssl: bool,
    local_ip: str | None,
    request_url: str | None = None,
) -> list[str]:
    """Kandidaten, empfohlene Adresse zuerst.

    Reihenfolge: (0) Adresse der aktuellen Browseranfrage, falls bekannt; (b) bekannte URLs mit dem
    tatsaechlichen Server-Port, wenn er vom Standard (80/443) abweicht; (a) die URLs, wie HA sie
    kennt; (c) ohne SSL `http://<lokale IP>:<Port>`.
    """
    bases = [n for u in (internal_url, external_url) if (n := _normalize(u))]
    out: list[str] = []
    if (req := _normalize(request_url)) is not None:
        out.append(_build(*req))
    for scheme, host, port, path in bases:
        if port is None and server_port and server_port != _DEFAULT_PORTS[scheme]:
            out.append(_build(scheme, host, server_port, path))
    for scheme, host, port, path in bases:
        out.append(_build(scheme, host, port, path))
    if local_ip and server_port and not use_ssl:
        out.append(_build("http", f"[{local_ip}]" if ":" in local_ip else local_ip, server_port, ""))
    return list(dict.fromkeys(out))
