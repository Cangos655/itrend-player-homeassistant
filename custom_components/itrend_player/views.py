"""Pairing-Endpunkte (ohne Authentifizierung, Code-Beweis im Protokoll)."""

from __future__ import annotations

import logging

from aiohttp import web
from homeassistant.components.http import KEY_HASS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView, request_handler_factory

from .const import DOMAIN, PAIR_FINISH_URL, PAIR_START_URL
from .http_util import CORS_HEADERS, json_reply, read_limited, source_of
from .pairing import PairingManager
from .protocol import MAX_PAIR_BODY

_LOGGER = logging.getLogger(__name__)

_PREFLIGHT_HEADERS = {
    **CORS_HEADERS,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
}


class _PairView(HomeAssistantView):
    """Basis: ohne Auth, eigene CORS-Antworten (PROTOCOL.md 2.1)."""

    requires_auth = False
    cors_allowed = False

    def register(self, hass, app, router) -> None:  # type: ignore[no-untyped-def]
        """Routen anlegen, aber NICHT bei der CORS-Konfiguration von HA anmelden.

        aiohttp_cors wuerde mit unserem eigenen OPTIONS-Handler kollidieren.
        """
        assert self.url is not None
        for method in ("post", "options"):
            handler = request_handler_factory(hass, self, getattr(self, method))
            router.add_route(method, self.url, handler)

    async def options(self, request: web.Request) -> web.Response:
        return web.Response(status=204, headers=_PREFLIGHT_HEADERS)

    def _manager(self, request: web.Request) -> PairingManager:
        return request.app[KEY_HASS].data[DOMAIN]["pairing"]


class PairStartView(_PairView):
    url = PAIR_START_URL
    name = "api:itrend_player:pair_start"

    async def post(self, request: web.Request) -> web.Response:
        try:
            body = await read_limited(request, MAX_PAIR_BODY)
            status, data, headers = await self._manager(request).async_handle_start(
                source_of(request), body, request.headers.get("Content-Type")
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Error in pair/start")
            return json_reply(500, {"error": "internal"})
        return json_reply(status, data, headers)


class PairFinishView(_PairView):
    url = PAIR_FINISH_URL
    name = "api:itrend_player:pair_finish"

    async def post(self, request: web.Request) -> web.Response:
        try:
            body = await read_limited(request, MAX_PAIR_BODY)
            status, data, headers = await self._manager(request).async_handle_finish(
                source_of(request), body, request.headers.get("Content-Type")
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Error in pair/finish")
            return json_reply(500, {"error": "internal"})
        return json_reply(status, data, headers)


def async_register_views(hass: HomeAssistant) -> None:
    hass.http.register_view(PairStartView())
    hass.http.register_view(PairFinishView())
