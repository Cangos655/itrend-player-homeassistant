"""Gemeinsame HTTP-Hilfen fuer Pairing-Views und Webhook."""

from __future__ import annotations

from typing import Any

from aiohttp import web

CORS_HEADERS = {"Access-Control-Allow-Origin": "*"}


async def read_limited(request: web.Request, limit: int) -> bytes | None:
    """Body lesen, hoechstens `limit` Byte; None bei Ueberschreitung."""
    if request.content_length is not None and request.content_length > limit:
        return None
    buf = bytearray()
    async for chunk in request.content.iter_chunked(8192):
        buf += chunk
        if len(buf) > limit:
            return None
    return bytes(buf)


def json_reply(
    status: int, data: dict[str, Any], headers: dict[str, str] | None = None
) -> web.Response:
    """JSON-Antwort mit CORS-Header (alle Antworten der Integration tragen ihn)."""
    response = web.json_response(data, status=status)
    response.headers.update(CORS_HEADERS)
    response.headers["Cache-Control"] = "no-store"
    if headers:
        response.headers.update(headers)
    return response


def source_of(request: web.Request) -> str:
    return request.remote or "unknown"
