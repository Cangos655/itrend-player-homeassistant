"""Testhelfer: App-Simulator (rechnet mit reference.py), Eintraege, Uhr."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json
from typing import Any

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.itrend_player import protocol as proto
from custom_components.itrend_player.const import (
    CONF_APP_VERSION,
    CONF_DEVICE_ID,
    CONF_K_A2H,
    CONF_K_H2A,
    CONF_NAME,
    CONF_PLATFORM,
    CONF_UNPAIRED,
    CONF_WEBHOOK_ID,
    DOMAIN,
)

import reference as ref

TEXT = {"Content-Type": "text/plain;charset=UTF-8"}


class FakeClock:
    """Monotone Testuhr fuer Manager und Geraet."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@dataclass
class AppSim:
    """Spielt die Rolle der App beim Koppeln (unabhaengig von der Integration)."""

    code: str
    name: str = "Wohnzimmer TV"
    platform: str = "tizen"
    app_version: str = "0.3.0"
    a: int | None = None

    async def pair(self, client, *, expect_ok: bool = True) -> dict[str, Any]:
        resp = await client.post("/api/itrend_player/pair/start", data=json.dumps({"v": 1}),
                                 headers=TEXT)
        assert resp.status == 200, await resp.text()
        start = await resp.json()
        salt = ref.b64u_dec(start["salt"])
        big_b = int.from_bytes(ref.b64u_dec(start["B"]), "big")
        a = self.a if self.a is not None else int.from_bytes(__import__("os").urandom(32), "big")
        big_a = pow(ref.G, a, ref.N)
        x = ref.srp_x(salt, self.code)
        u = ref.srp_u(big_a, big_b)
        s = pow((big_b - ref.srp_k() * pow(ref.G, x, ref.N)) % ref.N, a + u * x, ref.N)
        ctx = ref.ctx_bytes(self.name, self.platform, self.app_version)
        keys = ref.derive_keys(s, big_a, big_b, ctx, "x", "y")  # nur K_proof wird hier gebraucht
        m1 = ref.proof_m1(keys["K_proof"], big_a, big_b, ctx)
        body = {"v": 1, "session": start["session"], "A": ref.b64u(ref.pad(big_a)),
                "M1": ref.b64u(m1), "name": self.name, "platform": self.platform,
                "app_version": self.app_version}
        resp = await client.post("/api/itrend_player/pair/finish", data=json.dumps(body),
                                 headers=TEXT)
        out = {"status": resp.status, "json": await resp.json(), "start": start, "body": body}
        if resp.status == 200:
            fin = out["json"]
            keys = ref.derive_keys(s, big_a, big_b, ctx, fin["device_id"], fin["webhook_id"])
            exp_m2 = ref.proof_m2(keys["K_proof"], big_a, big_b, m1, fin["device_id"],
                                  fin["webhook_id"])
            assert ref.b64u_dec(fin["M2"]) == exp_m2  # App prueft M2
            out["keys"] = keys
        return out


class QueueRandom:
    """Ersetzt Zufallsquellen des Pairing-Managers durch feste Testwerte."""

    def __init__(self, manager, *, code: int, token_bytes: list[bytes], randbits: list[int]):
        self.token_bytes = deque(token_bytes)
        self.randbits = deque(randbits)
        manager._randbelow = lambda n: code
        manager._token_bytes = lambda n: self.token_bytes.popleft()
        manager._randbits = lambda n: self.randbits.popleft()


def entry_from_vectors(v: dict, **overrides: Any) -> MockConfigEntry:
    w = v["webhook"]
    p = v["pairing"]["inputs"]
    data = {
        CONF_DEVICE_ID: w["device_id"],
        CONF_WEBHOOK_ID: w["webhook_id"],
        CONF_K_A2H: proto.b64u(bytes.fromhex(w["K_a2h_hex"])),
        CONF_K_H2A: proto.b64u(bytes.fromhex(w["K_h2a_hex"])),
        CONF_NAME: p["name"],
        CONF_PLATFORM: p["platform"],
        CONF_APP_VERSION: p["app_version"],
        CONF_UNPAIRED: False,
    }
    data.update(overrides)
    return MockConfigEntry(domain=DOMAIN, data=data, title=data[CONF_NAME],
                           unique_id=data[CONF_DEVICE_ID])


class VectorApp:
    """Baut signierte Webhook-Bodies mit den Vektorschluesseln (Gegenseite = reference.py)."""

    def __init__(self, v: dict) -> None:
        w = v["webhook"]
        self.device_id = w["device_id"]
        self.webhook_id = w["webhook_id"]
        self.path = w["path"]
        self.k_a2h = bytes.fromhex(w["K_a2h_hex"])
        self.k_h2a = bytes.fromhex(w["K_h2a_hex"])

    def body(self, seq: int, payload: dict | bytes) -> bytes:
        raw = payload if isinstance(payload, bytes) else json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return ref.build_body(self.k_a2h, self.path, self.device_id, seq, raw)

    def sig_of(self, body: bytes) -> str:
        return body.split(b"\n", 4)[3].decode()

    def proof(self, seq: int, body: bytes, code: str = "ok", last_seq: int = 0,
              resync: bool = False) -> str:
        return ref.resp_proof(self.k_h2a, self.device_id, seq, self.sig_of(body), code,
                              last_seq, resync)

    async def post(self, client, body: bytes, headers=TEXT):
        return await client.post("/api/webhook/" + self.webhook_id, data=body, headers=headers)
