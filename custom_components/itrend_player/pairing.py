"""Kopplung (SRP-6a) auf der HA-Seite: PROTOCOL.md Abschnitt 3.

Der Code, der Salt, der Verifier und alle Zwischenwerte leben nur im
Arbeitsspeicher und werden nie geloggt.
"""

from __future__ import annotations

import asyncio
import logging
import math
import secrets
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_call_later
from homeassistant.util import network as network_util

from . import protocol as proto
from .const import (
    ATTEMPT_LIFETIME,
    CODE_LIFETIME,
    LOCKOUT_COUNT,
    LOCKOUT_DURATION,
    LOCKOUT_WINDOW,
    MAX_ATTEMPTS_PER_SOURCE,
    MAX_ATTEMPTS_TOTAL,
    MAX_CONCURRENT_FINISH,
    MAX_FAILURES,
    PAIR_RATE_LIMIT,
    PAIR_RATE_WINDOW,
)
from .ratelimit import SlidingWindowLimiter

_LOGGER = logging.getLogger(__name__)

# (HTTP-Status, JSON-Koerper, zusaetzliche Header)
Reply = tuple[int, dict[str, Any], dict[str, str]]


class FailureReason(StrEnum):
    """Warum ein Code nicht mehr zur Kopplung taugt."""

    EXPIRED = "expired"
    LOCKED = "locked"
    REPLACED = "replaced"
    CANCELLED = "cancelled"


class PairingBlocked(Exception):
    """Kopplung wird nach mehreren gesperrten Codes vorerst nicht angeboten."""

    def __init__(self, retry_in: int) -> None:
        super().__init__("pairing blocked")
        self.retry_in = retry_in


@dataclass(frozen=True)
class PairingResult:
    """Ergebnis einer erfolgreichen Kopplung (enthaelt Schluessel!)."""

    device_id: str
    webhook_id: str
    k_a2h: bytes = field(repr=False)
    k_h2a: bytes = field(repr=False)
    name: str
    platform: str
    app_version: str
    remote: bool = False  # Kopplung kam von einer nicht-lokalen Quelladresse


@dataclass
class _Attempt:
    b: int = field(repr=False)
    big_b: int = field(repr=False)
    created: float
    source: str


@dataclass(eq=False)
class ActiveCode:
    """Ein aktiver Kopplungscode."""

    code: str = field(repr=False)
    salt: bytes = field(repr=False)
    verifier: int = field(repr=False)
    expires: float
    future: asyncio.Future[PairingResult | FailureReason]
    attempts: dict[str, _Attempt] = field(default_factory=dict)
    used: int = 0  # Versuche, die schon entnommen wurden (vor der Rechnung gezaehlt)
    failed: int = 0  # bestaetigt falsche Beweise
    closed: bool = False
    cancel_timer: Callable[[], None] | None = None

    @property
    def display_code(self) -> str:
        return f"{self.code[:3]} {self.code[3:]}"


def _is_local(source: str) -> bool:
    try:
        return network_util.is_local(ip_address(source))
    except ValueError:
        return False


def _err(status: int, code: str, **extra: Any) -> Reply:
    return status, {"error": code, **extra}, {}


def _rate_limited(retry_after: int) -> Reply:
    retry_after = max(1, retry_after)
    return 429, {"error": "rate_limited", "retry_after": retry_after}, {"Retry-After": str(retry_after)}


class PairingManager:
    """Verwaltet den einen aktiven Code und die offenen Versuche."""

    def __init__(self, hass: HomeAssistant, clock: Callable[[], float] | None = None) -> None:
        self.hass = hass
        self._clock: Callable[[], float] = clock or hass.loop.time
        # Zufallsquellen (nur Tests tauschen sie gegen feste Testwerte aus)
        self._token_bytes: Callable[[int], bytes] = secrets.token_bytes
        self._randbits: Callable[[int], int] = secrets.randbits
        self._randbelow: Callable[[int], int] = secrets.randbelow
        self.rate = SlidingWindowLimiter(
            PAIR_RATE_LIMIT, PAIR_RATE_WINDOW, lambda: self._clock()
        )
        self.active: ActiveCode | None = None
        self._inflight = 0
        self._lock_times: deque[float] = deque()
        self._blocked_until = 0.0

    # ------------------------------------------------------------ Code
    async def async_open_code(self) -> ActiveCode:
        """Neuen Code erzeugen (ersetzt einen alten)."""
        now = self._clock()
        if now < self._blocked_until:
            raise PairingBlocked(math.ceil(self._blocked_until - now))
        self._close(self.active, FailureReason.REPLACED)
        code = f"{self._randbelow(10**6):06d}"
        salt = self._token_bytes(16)
        verifier = await self.hass.async_add_executor_job(proto.srp_verifier, salt, code)
        # Falls waehrenddessen ein anderer Dialog einen Code geoeffnet hat.
        self._close(self.active, FailureReason.REPLACED)
        active = ActiveCode(
            code=code,
            salt=salt,
            verifier=verifier,
            expires=self._clock() + CODE_LIFETIME,
            future=self.hass.loop.create_future(),
        )

        @callback
        def _timeout(_now: Any) -> None:
            self._expire(active)

        active.cancel_timer = async_call_later(self.hass, CODE_LIFETIME, _timeout)
        self.active = active
        return active

    @callback
    def async_close_code(self, active: ActiveCode | None) -> None:
        """Dialog abgebrochen: Code loeschen."""
        self._close(active, FailureReason.CANCELLED)

    @callback
    def _expire(self, active: ActiveCode) -> None:
        self._close(active, FailureReason.EXPIRED)

    def _close(self, active: ActiveCode | None, reason: FailureReason) -> None:
        if active is None or active.closed:
            return
        active.closed = True
        active.attempts.clear()
        if active.cancel_timer is not None:
            active.cancel_timer()
            active.cancel_timer = None
        if self.active is active:
            self.active = None
        if not active.future.done():
            active.future.set_result(reason)

    def _current(self) -> ActiveCode | None:
        active = self.active
        if active is None:
            return None
        if self._clock() >= active.expires:
            self._close(active, FailureReason.EXPIRED)
            return None
        return active

    # --------------------------------------------------------- Versuche
    def _prune_attempts(self, active: ActiveCode, now: float) -> None:
        for key in [k for k, a in active.attempts.items() if now - a.created >= ATTEMPT_LIFETIME]:
            del active.attempts[key]

    def _make_room(self, active: ActiveCode, source: str, now: float) -> int | None:
        """Platz fuer einen Versuch schaffen. None = ok, sonst Retry-After."""
        self._prune_attempts(active, now)
        mine = [k for k, a in active.attempts.items() if a.source == source]
        while len(mine) >= MAX_ATTEMPTS_PER_SOURCE:
            del active.attempts[mine.pop(0)]  # aeltester Versuch dieser Adresse
        if len(active.attempts) >= MAX_ATTEMPTS_TOTAL:
            oldest = min(a.created for a in active.attempts.values())
            return max(1, math.ceil(ATTEMPT_LIFETIME - (now - oldest)))
        return None

    # ------------------------------------------------------- Anfragen
    @staticmethod
    def _parse(body: bytes | None, content_type: str | None) -> tuple[dict[str, Any] | None, Reply | None]:
        if body is None:
            return None, _err(413, "payload_too_large")
        ctype = (content_type or "").split(";")[0].strip().lower()
        if ctype not in ("text/plain", "application/json"):
            return None, _err(400, "bad_request")
        try:
            obj = proto.loads_strict(body)
        except ValueError:
            return None, _err(400, "bad_request")
        if not isinstance(obj, dict):
            return None, _err(400, "bad_request")
        v = obj.get("v")
        if not proto.is_int(v, 1, 1000):
            return None, _err(400, "bad_request")
        if v != 1:
            return None, _err(400, "unsupported_version", supported=[1])
        return obj, None

    async def async_handle_start(
        self, source: str, body: bytes | None, content_type: str | None
    ) -> Reply:
        """POST /api/itrend_player/pair/start."""
        if not self.rate.hit(source):
            return _rate_limited(self.rate.retry_after(source))
        _obj, error = self._parse(body, content_type)
        if error:
            return error
        active = self._current()
        if active is None:
            return _err(404, "pairing_unavailable")
        retry = self._make_room(active, source, self._clock())
        if retry is not None:
            return _rate_limited(retry)
        session = proto.b64u(self._token_bytes(16))
        big_b = 0
        b = 0
        for _ in range(3):
            b = self._randbits(256)
            big_b = await self.hass.async_add_executor_job(
                proto.srp_server_public, active.verifier, b
            )
            if proto.valid_public(big_b):
                break
        else:
            return _err(500, "internal")
        # Zustand kann sich waehrend der Rechnung geaendert haben.
        if self._current() is not active:
            return _err(404, "pairing_unavailable")
        now = self._clock()
        retry = self._make_room(active, source, now)
        if retry is not None:
            return _rate_limited(retry)
        active.attempts[session] = _Attempt(b=b, big_b=big_b, created=now, source=source)
        return (
            200,
            {
                "v": 1,
                "session": session,
                "salt": proto.b64u(active.salt),
                "B": proto.b64u(proto.pad(big_b)),
            },
            {},
        )

    async def async_handle_finish(
        self, source: str, body: bytes | None, content_type: str | None
    ) -> Reply:
        """POST /api/itrend_player/pair/finish."""
        if not self.rate.hit(source):
            return _rate_limited(self.rate.retry_after(source))
        obj, error = self._parse(body, content_type)
        if error or obj is None:
            return error or _err(400, "bad_request")
        # (1) Formate und Randwerte
        try:
            session = obj.get("session")
            proto.b64u_fixed(session, 16)
            a_pub = int.from_bytes(proto.b64u_fixed(obj.get("A"), proto.NLEN), "big")
            m1 = proto.b64u_fixed(obj.get("M1"), 32)
        except ValueError:
            return _err(400, "bad_request")
        name = obj.get("name")
        platform = obj.get("platform")
        app_version = obj.get("app_version")
        if (
            not proto.valid_public(a_pub)
            or not proto.valid_name(name)
            or platform not in proto.PLATFORMS
            or not proto.valid_app_version(app_version)
        ):
            return _err(400, "bad_request")
        assert isinstance(session, str)
        assert isinstance(name, str)
        assert isinstance(platform, str)
        assert isinstance(app_version, str)

        active = self._current()
        if active is None or active.used >= MAX_FAILURES:
            return _err(404, "pairing_unavailable")
        now = self._clock()
        attempt = active.attempts.get(session)
        if attempt is not None and now - attempt.created >= ATTEMPT_LIFETIME:
            del active.attempts[session]
            attempt = None
        if attempt is None:
            return _err(410, "session_expired")  # zaehlt nicht als Fehlversuch
        if self._inflight >= MAX_CONCURRENT_FINISH:
            return _rate_limited(1)  # Versuch bleibt erhalten
        # (2) atomar: Versuch entnehmen, Zaehler erhoehen, noch ohne Rechnung
        del active.attempts[session]
        active.used += 1
        attempts_left = max(0, MAX_FAILURES - active.used)
        device_id = proto.b64u(self._token_bytes(16))
        webhook_id = proto.b64u(self._token_bytes(32))
        self._inflight += 1
        try:
            # (3) Rechnung im Executor
            computed = await self.hass.async_add_executor_job(
                _compute_proof,
                active.verifier,
                attempt.b,
                attempt.big_b,
                a_pub,
                m1,
                name,
                platform,
                app_version,
                device_id,
                webhook_id,
            )
        finally:
            self._inflight -= 1
        if computed is None:  # u == 0
            return _err(400, "bad_request")
        matches, keys, m2 = computed
        if not matches:
            active.failed += 1
            if active.failed >= MAX_FAILURES and not active.closed:
                self._code_locked(active)
            return _err(403, "pairing_failed", attempts_left=attempts_left)
        # Einmalig: nur wer den Code noch gueltig vorfindet, gewinnt.
        if self._current() is not active:
            return _err(404, "pairing_unavailable")
        result = PairingResult(
            device_id=device_id,
            webhook_id=webhook_id,
            k_a2h=keys["K_a2h"],
            k_h2a=keys["K_h2a"],
            name=name,
            platform=platform,
            app_version=app_version,
            remote=not _is_local(source),
        )
        active.closed = True
        active.attempts.clear()
        if active.cancel_timer is not None:
            active.cancel_timer()
            active.cancel_timer = None
        self.active = None
        if not active.future.done():
            active.future.set_result(result)
        _LOGGER.info("Pairing completed for device %s", name)
        return (
            200,
            {"v": 1, "M2": proto.b64u(m2), "device_id": device_id, "webhook_id": webhook_id},
            {},
        )

    def _code_locked(self, active: ActiveCode) -> None:
        now = self._clock()
        self._lock_times.append(now)
        while self._lock_times and now - self._lock_times[0] >= LOCKOUT_WINDOW:
            self._lock_times.popleft()
        if len(self._lock_times) >= LOCKOUT_COUNT:
            self._blocked_until = now + LOCKOUT_DURATION
            self._lock_times.clear()
        _LOGGER.warning("Pairing code locked after %d failed attempts", MAX_FAILURES)
        self._close(active, FailureReason.LOCKED)


def _compute_proof(
    verifier: int,
    b: int,
    big_b: int,
    a_pub: int,
    m1: bytes,
    name: str,
    platform: str,
    app_version: str,
    device_id: str,
    webhook_id: str,
) -> tuple[bool, dict[str, bytes], bytes] | None:
    """Rechenintensiver Teil (laeuft im Executor)."""
    u = proto.srp_u(a_pub, big_b)
    if u == 0:
        return None
    secret = proto.srp_server_secret(a_pub, verifier, b, u)
    ctx = proto.ctx_bytes(name, platform, app_version)
    keys = proto.derive_keys(secret, a_pub, big_b, ctx, device_id, webhook_id)
    expected = proto.proof_m1(keys["K_proof"], a_pub, big_b, ctx)
    matches = proto.ct_eq(expected, m1)
    m2 = (
        proto.proof_m2(keys["K_proof"], a_pub, big_b, m1, device_id, webhook_id)
        if matches
        else b""
    )
    return matches, keys, m2
