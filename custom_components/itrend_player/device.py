"""Laufzeitobjekt je gekoppeltem Fernseher: Webhook-Empfang und Zustand.

Datenschutz (PROTOCOL.md 5.7, 8.4, 8.5): Titel, Sender und andere Inhalte der
Nutzlast werden nie geloggt und nur im Arbeitsspeicher gehalten. Geheimnisse,
Signaturen und Beweise tauchen in keinem Log auf; die webhook_id wird hoechstens
mit vier Zeichen genannt.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from aiohttp import web
from homeassistant.components import webhook
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from . import protocol as proto
from .const import (
    AVAILABILITY_TIMEOUT,
    BAD_SIG_RATE_LIMIT,
    BAD_SIG_RATE_WINDOW,
    CLONE_JUMP,
    CLONE_MIN_EVENTS,
    CLONE_WINDOW,
    CONF_APP_VERSION,
    CONF_DEVICE_ID,
    CONF_K_A2H,
    CONF_K_H2A,
    CONF_NAME,
    CONF_PLATFORM,
    CONF_UNPAIRED,
    CONF_WEBHOOK_ID,
    DEVICE_RATE_LIMIT,
    DEVICE_RATE_WINDOW,
    DOMAIN,
    EVENT_ITREND,
    ISSUE_KEY_COPIED,
    ISSUE_UNPAIRED,
    MANUFACTURER,
    PLATFORM_MODELS,
    SEQ_RESERVE_AHEAD,
    STORAGE_VERSION,
)
from .http_util import json_reply, read_limited, source_of
from .ratelimit import SlidingWindowLimiter

_LOGGER = logging.getLogger(__name__)

_MAGIC_RE = re.compile(r"ITP/[0-9]+")
_SEQ_RE = re.compile(r"0|[1-9][0-9]{0,15}")


@dataclass
class DeviceState:
    """Letzter bekannter Zustand (nur Arbeitsspeicher)."""

    available: bool = False
    app_active: bool = False
    status: str | None = None
    media: dict[str, Any] | None = None
    media_updated_at: datetime | None = None
    rev: int | None = None
    app_version: str | None = None
    platform: str | None = None
    ws: bool | None = None
    sub_expires: date | None = None
    connections_active: int | None = None
    connections_max: int | None = None


class RateLimiters:
    """Gemeinsame Begrenzung je Quelladresse (alle Geraete)."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self.bad_sig = SlidingWindowLimiter(BAD_SIG_RATE_LIMIT, BAD_SIG_RATE_WINDOW, clock)


def _short(webhook_id: str) -> str:
    return webhook_id[:4]


class ITrendDevice:
    """Ein gekoppelter Fernseher."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        limiters: RateLimiters,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self._limiters = limiters
        self._clock: Callable[[], float] = clock or hass.loop.time
        data = entry.data
        self.name: str = data[CONF_NAME]
        self.device_id: str = data[CONF_DEVICE_ID]
        self.webhook_id: str = data[CONF_WEBHOOK_ID]
        self.paired: bool = not data.get(CONF_UNPAIRED, False)
        self._k_a2h = proto.b64u_dec(data[CONF_K_A2H]) if self.paired else b""
        self._k_h2a = proto.b64u_dec(data[CONF_K_H2A]) if self.paired else b""
        self.state = DeviceState(
            app_version=data.get(CONF_APP_VERSION), platform=data.get(CONF_PLATFORM)
        )
        self.registry_device_id: str | None = None
        self.last_seq = 0
        self.reserved = 0
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self._lock = asyncio.Lock()
        self._device_limiter = SlidingWindowLimiter(
            DEVICE_RATE_LIMIT, DEVICE_RATE_WINDOW, lambda: self._clock()
        )
        self._stale: deque[float] = deque()
        self._listeners: list[Callable[[], None]] = []
        self._watchdog: Callable[[], None] | None = None

    # ------------------------------------------------------- Lebenszyklus
    async def async_setup(self) -> None:
        stored = await self._store.async_load()
        reserved = stored.get("reserved", 0) if isinstance(stored, dict) else 0
        self.reserved = reserved if isinstance(reserved, int) and reserved >= 0 else 0
        # Nach einem Neustart gilt die Reservierung als zuletzt gesehene Sequenz.
        self.last_seq = self.reserved
        registry = dr.async_get(self.hass)
        device = registry.async_get_or_create(
            config_entry_id=self.entry.entry_id,
            identifiers={(DOMAIN, self.entry.entry_id)},
            manufacturer=MANUFACTURER,
            model=PLATFORM_MODELS.get(self.state.platform or "", None),
            name=f"iTrend Player ({self.name})",
            sw_version=self.state.app_version,
        )
        self.registry_device_id = device.id
        if self.paired:
            webhook.async_register(
                self.hass,
                DOMAIN,
                f"iTrend Player ({self.name})",
                self.webhook_id,
                self._handle_webhook,
                local_only=True,
                allowed_methods=["POST"],
            )
            _LOGGER.debug("Webhook %s... registered for %s", _short(self.webhook_id), self.name)

    @callback
    def async_shutdown(self) -> None:
        self._unregister_webhook()
        self._cancel_watchdog()
        self._listeners.clear()

    def _unregister_webhook(self) -> None:
        webhook.async_unregister(self.hass, self.webhook_id)

    async def async_remove_storage(self) -> None:
        await self._store.async_remove()

    # ---------------------------------------------------------- Listener
    @callback
    def async_add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(listener)

        @callback
        def _remove() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return _remove

    @callback
    def _notify(self) -> None:
        for listener in list(self._listeners):
            listener()

    # --------------------------------------------------------- Watchdog
    def _cancel_watchdog(self) -> None:
        if self._watchdog is not None:
            self._watchdog()
            self._watchdog = None

    def _arm_watchdog(self) -> None:
        self._cancel_watchdog()

        @callback
        def _fired(_now: datetime) -> None:
            self._watchdog = None
            st = self.state
            st.available = False
            st.app_active = False
            st.status = None
            st.media = None
            self._notify()

        self._watchdog = async_call_later(self.hass, AVAILABILITY_TIMEOUT, _fired)

    # ------------------------------------------------------------ Webhook
    async def _handle_webhook(
        self, hass: HomeAssistant, webhook_id: str, request: web.Request
    ) -> web.Response:
        try:
            return await self._handle(request)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Internal error while handling a message from %s", self.name)
            return json_reply(500, {"ok": False, "error": "internal"})

    @staticmethod
    def _error(status: int, code: str, **extra: Any) -> web.Response:
        headers = {"Retry-After": str(extra.pop("retry_after"))} if "retry_after" in extra else None
        return json_reply(status, {"ok": False, "error": code, **extra}, headers)

    async def _handle(self, request: web.Request) -> web.Response:
        source = source_of(request)
        if not self.paired or not self._k_a2h:
            # Kopplung beendet (z. B. laufende Anfrage waehrend `unpair`): nie mit leerem Schluessel pruefen.
            return self._error(401, "bad_signature")
        if self._limiters.bad_sig.blocked(source):
            return self._error(429, "rate_limited", retry_after=self._limiters.bad_sig.retry_after(source))
        body = await read_limited(request, proto.MAX_BODY)
        if body is None:
            return self._error(413, "payload_too_large")
        ctype = (request.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "text/plain":
            return self._error(400, "bad_request")

        parts = body.split(b"\n", 4)
        if len(parts) != 5:
            return self._error(400, "bad_request")
        try:
            magic, device_id, seq_s, sig_s = (p.decode("ascii") for p in parts[:4])
        except UnicodeDecodeError:
            return self._error(400, "bad_request")
        payload = parts[4]
        if magic != "ITP/1":
            if _MAGIC_RE.fullmatch(magic):
                return self._error(400, "unsupported_version", supported=[1])
            return self._error(400, "bad_request")
        if not _SEQ_RE.fullmatch(seq_s) or not 1 <= int(seq_s) <= proto.MAX_SEQ:
            return self._error(400, "bad_request")
        seq = int(seq_s)
        try:
            sig = proto.b64u_fixed(sig_s, 32)
        except ValueError:
            return self._error(400, "bad_request")

        # Signatur vor Sperre und vor dem Lesen der Nutzlast: wer den Schluessel
        # nicht hat, kann die Sperre nie halten (Abweichung zu 4.3: siehe DECISIONS.md).
        expected = proto.request_signature(
            self._k_a2h, "/api/webhook/" + self.webhook_id, device_id, seq, payload
        )
        id_ok = proto.ct_eq(device_id.encode("ascii"), self.device_id.encode("ascii"))
        if not (proto.ct_eq(sig, expected) and id_ok):
            self._limiters.bad_sig.record(source)
            return self._error(401, "bad_signature")

        async with self._lock:
            return await self._accept(source, device_id, seq, sig_s, payload)

    def _proof(self, seq: int, req_sig: str, code: str, last_seq: int, resync: bool) -> str:
        return proto.resp_proof(self._k_h2a, self.device_id, seq, req_sig, code, last_seq, resync)

    async def _accept(
        self, source: str, device_id: str, seq: int, sig_s: str, payload: bytes
    ) -> web.Response:
        if seq <= self.last_seq:
            self._limiters.bad_sig.record(source)
            self._note_stale()
            return json_reply(
                409,
                {
                    "ok": False,
                    "error": "seq_too_low",
                    "last_seq": self.last_seq,
                    "proof": self._proof(seq, sig_s, "seq_too_low", self.last_seq, False),
                },
            )
        if not self._device_limiter.hit(self.device_id):
            return self._error(429, "rate_limited", retry_after=self._device_limiter.retry_after(self.device_id))
        if seq > self.reserved:
            new_reserved = seq + SEQ_RESERVE_AHEAD
            await self._store.async_save({"reserved": new_reserved})  # erst speichern, dann annehmen
            self.reserved = new_reserved
        jump = seq - self.last_seq > CLONE_JUMP
        self.last_seq = seq  # ab hier verbraucht, auch bei 422
        if jump:
            self._flag_copied_key()

        if len(payload) > proto.MAX_PAYLOAD:
            return self._error(413, "payload_too_large")
        try:
            obj = proto.loads_strict(payload)
        except ValueError:
            return self._error(422, "bad_payload")
        reason = proto.validate_payload(obj)
        if reason == "unsupported_version":
            return self._error(400, "unsupported_version", supported=[1])
        if reason:
            return self._error(422, "bad_payload")

        resync = self._apply(obj)
        body: dict[str, Any] = {
            "ok": True,
            "code": "ok",
            "seq": seq,
            "resync": resync,
            "proof": self._proof(seq, sig_s, "ok", 0, resync),
        }
        if proto.is_ignored(obj):
            body["ignored"] = True
        response = json_reply(200, body)
        if obj.get("type") == "unpair":
            await self._async_unpaired_by_app()
        return response

    # ------------------------------------------------ Zustand uebernehmen
    @callback
    def _apply(self, obj: dict[str, Any]) -> bool:
        """Gueltige Nutzlast in den Zustand uebernehmen; gibt `resync` zurueck."""
        st = self.state
        kind = obj.get("type")
        resync = False
        if kind == "unpair":
            return False
        if kind == "state":
            st.rev = obj["rev"]
            st.status = obj["status"]
            media = obj.get("media")
            st.media = proto.clean_media(media) if isinstance(media, dict) else None
            st.media_updated_at = dt_util.utcnow()
            if st.status == "closed":
                # Ordentlich beendet: sofort aus, kein Herzschlag mehr erwartet.
                st.available = True
                st.app_active = False
                self._cancel_watchdog()
                self._notify()
                return False
        elif kind == "heartbeat":
            resync = obj["state_rev"] != st.rev
            self._apply_heartbeat(obj)
        elif kind == "event":
            self._fire_event(obj)
        if st.status == "closed":
            st.status = None  # App laeuft wieder, der naechste state folgt
        st.available = True
        st.app_active = True
        self._arm_watchdog()
        self._notify()
        return resync

    def _apply_heartbeat(self, obj: dict[str, Any]) -> None:
        st = self.state
        if st.app_version != obj["app_version"] or st.platform != obj["platform"]:
            st.app_version = obj["app_version"]
            st.platform = obj["platform"]
            if self.registry_device_id:
                dr.async_get(self.hass).async_update_device(
                    self.registry_device_id,
                    sw_version=st.app_version,
                    model=PLATFORM_MODELS.get(st.platform),
                )
        st.ws = obj.get("ws")
        sub = obj.get("sub") or {}
        expires = sub.get("expires")
        st.sub_expires = date.fromisoformat(expires) if isinstance(expires, str) else None
        st.connections_active = sub.get("connections_active")
        st.connections_max = sub.get("connections_max")

    def _fire_event(self, obj: dict[str, Any]) -> None:
        name = obj["name"]
        if name not in proto.EVENTS:
            return  # unbekannte Ereignisse: angenommen, ignoriert
        data: dict[str, Any] = {
            "device_id": self.registry_device_id,
            "entry_id": self.entry.entry_id,
            "type": name,
        }
        if "reason" in obj:
            data["reason"] = obj["reason"]
        if isinstance(obj.get("media"), dict):
            data["media"] = proto.clean_media(obj["media"])
        self.hass.bus.async_fire(EVENT_ITREND, data)

    # ----------------------------------------------------- Reparaturen
    def _note_stale(self) -> None:
        """Gueltig signierte Meldung mit seq <= last_seq (4.3, geklonter Schluessel)."""
        now = self._clock()
        self._stale.append(now)
        while self._stale and now - self._stale[0] >= CLONE_WINDOW:
            self._stale.popleft()
        if len(self._stale) >= CLONE_MIN_EVENTS:
            self._flag_copied_key()

    def _flag_copied_key(self) -> None:
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            ISSUE_KEY_COPIED.format(entry_id=self.entry.entry_id),
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="key_possibly_copied",
            translation_placeholders={"name": self.name},
        )

    async def _async_unpaired_by_app(self) -> None:
        """Die App hat die Kopplung beendet (7.2)."""
        _LOGGER.info("Device %s ended the pairing", self.name)
        self._unregister_webhook()
        self._cancel_watchdog()
        self.paired = False
        self._k_a2h = b""
        self._k_h2a = b""
        st = self.state
        st.available = False
        st.app_active = False
        st.status = None
        st.media = None
        self.hass.config_entries.async_update_entry(
            self.entry,
            data={**self.entry.data, CONF_K_A2H: "", CONF_K_H2A: "", CONF_UNPAIRED: True},
        )
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            ISSUE_UNPAIRED.format(entry_id=self.entry.entry_id),
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="unpaired_by_app",
            translation_placeholders={"name": self.name},
        )
        self._notify()
        self.entry.async_start_reauth(self.hass)
