"""Kopplung: HTTP-Endpunkte, SRP, Sperren und Grenzen."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import json

import pytest

from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.itrend_player import protocol as proto
from custom_components.itrend_player.const import DOMAIN
from custom_components.itrend_player.pairing import FailureReason, PairingBlocked

from .helpers import TEXT, AppSim, FakeClock, QueueRandom

import reference as ref

START = "/api/itrend_player/pair/start"
FINISH = "/api/itrend_player/pair/finish"


@pytest.fixture
async def env(hass, hass_client_no_auth):
    assert await async_setup_component(hass, DOMAIN, {})
    manager = hass.data[DOMAIN]["pairing"]
    clock = FakeClock()
    manager._clock = clock
    client = await hass_client_no_auth()
    return manager, clock, client


async def post(client, path, obj, headers=TEXT):
    data = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
    return await client.post(path, data=data, headers=headers)


async def test_no_active_code(env):
    _, _, client = env
    resp = await post(client, START, {"v": 1})
    assert resp.status == 404
    assert (await resp.json())["error"] == "pairing_unavailable"
    assert resp.headers["Access-Control-Allow-Origin"] == "*"


async def test_vector_pairing_end_to_end(env, vectors):
    """Das SRP-Beispiel aus vectors.json: alle Nachrichten stimmen Byte fuer Byte."""
    manager, _, client = env
    pv = vectors["pairing"]
    i = pv["inputs"]
    QueueRandom(
        manager, code=int(i["code"]),
        token_bytes=[bytes.fromhex(i["salt_hex"]), ref.b64u_dec(i["session_b64u"]),
                     ref.b64u_dec(i["device_id"]), ref.b64u_dec(i["webhook_id"])],
        randbits=[int(i["b_hex"], 16)])
    active = await manager.async_open_code()
    assert active.display_code == "123 456"

    resp = await post(client, START, pv["messages"]["start_request"])
    assert resp.status == 200
    assert await resp.json() == pv["messages"]["start_response"]

    resp = await post(client, FINISH, pv["messages"]["finish_request"])
    assert resp.status == 200
    assert await resp.json() == pv["messages"]["finish_response"]
    result = await asyncio.wait_for(active.future, 1)
    assert result.k_a2h.hex() == pv["derived"]["K_a2h_hex"]
    assert result.k_h2a.hex() == pv["derived"]["K_h2a_hex"]
    # einmalig: danach ist kein Code mehr aktiv
    assert manager.active is None
    resp = await post(client, START, {"v": 1})
    assert resp.status == 404


async def test_wrong_code_vector_and_lockout(env, vectors):
    manager, _, client = env
    wrong = vectors["pairing"]["wrong_code"]["code"]
    active = await manager.async_open_code()
    manager._randbelow = lambda n: 0  # unbenutzt
    left = []
    for _ in range(3):
        out = await AppSim(code=wrong if wrong != active.code else "000000").pair(client)
        assert out["status"] == 403, out
        assert out["json"]["error"] == "pairing_failed"
        left.append(out["json"]["attempts_left"])
    assert left == [2, 1, 0]
    assert manager.active is None
    assert await asyncio.wait_for(active.future, 1) == FailureReason.LOCKED
    resp = await post(client, START, {"v": 1})
    assert resp.status == 404  # gesperrt


async def test_correct_code_with_random_values(env, hass):
    manager, _, client = env
    active = await manager.async_open_code()
    out = await AppSim(code=active.code, name="Schlafzimmer", platform="android",
                       app_version="1.2.3-beta.1").pair(client)
    assert out["status"] == 200
    result = await asyncio.wait_for(active.future, 1)
    assert result.name == "Schlafzimmer" and result.platform == "android"
    assert len(result.device_id) == 22 and len(result.webhook_id) == 43
    assert result.k_a2h != result.k_h2a


async def test_third_wrong_then_no_success_and_two_wrong_then_right(env):
    manager, _, client = env
    active = await manager.async_open_code()
    bad = "000000" if active.code != "000000" else "111111"
    for _ in range(2):
        assert (await AppSim(code=bad).pair(client))["status"] == 403
    out = await AppSim(code=active.code).pair(client)
    assert out["status"] == 200


async def test_session_single_use_and_expiry_do_not_count(env):
    manager, clock, client = env
    active = await manager.async_open_code()
    sim = AppSim(code=active.code)
    # Versuch ueber 60 s alt -> 410, kein Fehlversuch
    resp = await post(client, START, {"v": 1})
    start = await resp.json()
    clock.advance(61)
    body = {"v": 1, "session": start["session"], "A": ref.b64u(ref.pad(pow(2, 99, ref.N))),
            "M1": ref.b64u(b"\0" * 32), "name": "x", "platform": "tizen", "app_version": "0.3.0"}
    resp = await post(client, FINISH, body)
    assert resp.status == 410
    assert (await resp.json())["error"] == "session_expired"
    assert active.used == 0
    # Unbekannte Session ebenso
    body["session"] = proto.b64u(b"\1" * 16)
    assert (await post(client, FINISH, body)).status == 410
    # Danach klappt die Kopplung noch
    assert (await sim.pair(client))["status"] == 200


async def test_attempt_reuse_is_gone(env):
    manager, _, client = env
    active = await manager.async_open_code()
    out = await AppSim(code="000000" if active.code != "000000" else "111111").pair(client)
    assert out["status"] == 403
    resp = await post(client, FINISH, out["body"])  # dieselbe Session nochmal
    assert resp.status == 410
    assert active.used == 1


async def test_code_expires_after_five_minutes(env, hass):
    manager, clock, client = env
    active = await manager.async_open_code()
    clock.advance(301)
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=301))
    await hass.async_block_till_done()
    assert await active.future == FailureReason.EXPIRED
    assert (await post(client, START, {"v": 1})).status == 404


async def test_code_expiry_checked_lazily_too(env):
    manager, clock, client = env
    active = await manager.async_open_code()
    clock.advance(300)
    assert (await post(client, START, {"v": 1})).status == 404
    assert active.future.result() == FailureReason.EXPIRED


async def test_new_code_replaces_old(env):
    manager, _, _ = env
    first = await manager.async_open_code()
    second = await manager.async_open_code()
    assert first.future.result() == FailureReason.REPLACED
    assert manager.active is second


async def test_closing_code_makes_pairing_unavailable(env):
    manager, _, client = env
    active = await manager.async_open_code()
    manager.async_close_code(active)
    assert (await post(client, START, {"v": 1})).status == 404
    assert active.future.result() == FailureReason.CANCELLED


async def test_rate_limit_per_source(env):
    manager, clock, client = env
    await manager.async_open_code()
    codes = []
    for _ in range(12):
        resp = await post(client, START, {"v": 1})
        codes.append(resp.status)
    assert codes[:10].count(429) == 0
    assert codes[10:] == [429, 429]
    assert int(resp.headers["Retry-After"]) >= 1
    assert (await resp.json())["retry_after"] == int(resp.headers["Retry-After"])
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    clock.advance(61)
    assert (await post(client, START, {"v": 1})).status == 200


async def test_attempt_limits_per_source_and_total(env):
    manager, _, _ = env
    await manager.async_open_code()
    sess = {}
    for src in ("a", "a", "a"):
        status, body, _h = await manager.async_handle_start(src, b'{"v":1}', "text/plain")
        assert status == 200
        sess.setdefault(src, []).append(body["session"])
    # 3. Versuch von "a" hat den aeltesten von "a" verdraengt
    assert sorted(manager.active.attempts) == sorted(sess["a"][1:])
    for src in ("b", "b"):
        assert (await manager.async_handle_start(src, b'{"v":1}', "text/plain"))[0] == 200
    assert len(manager.active.attempts) == 4
    # Insgesamt 4: ein fremder Teilnehmer verdraengt nichts, sondern bekommt 429
    status, body, headers = await manager.async_handle_start("c", b'{"v":1}', "text/plain")
    assert status == 429 and "Retry-After" in headers
    assert len(manager.active.attempts) == 4
    # "a" darf weiter eigene verdraengen, nie die von "b"
    assert (await manager.async_handle_start("a", b'{"v":1}', "text/plain"))[0] == 200
    assert sum(1 for a in manager.active.attempts.values() if a.source == "b") == 2


async def test_old_attempts_expire_for_capacity(env):
    manager, clock, _ = env
    await manager.async_open_code()
    for src in ("a", "b"):
        for _ in range(2):
            await manager.async_handle_start(src, b'{"v":1}', "text/plain")
    clock.advance(61)
    assert (await manager.async_handle_start("c", b'{"v":1}', "text/plain"))[0] == 200


@pytest.mark.parametrize(
    ("value", "valid"),
    [(0, False), (1, False), (2, True), ("N-1", False), ("N", False), ("N+1", False),
     ("max", False)],
)
async def test_A_bounds_rejected_before_consuming(env, value, valid):
    manager, _, client = env
    active = await manager.async_open_code()
    resp = await post(client, START, {"v": 1})
    start = await resp.json()
    raw = {"N-1": ref.N - 1, "N": ref.N, "N+1": ref.N + 1, "max": 2**3072 - 1}.get(value, value)
    body = {"v": 1, "session": start["session"], "A": ref.b64u(raw.to_bytes(384, "big")),
            "M1": ref.b64u(b"\0" * 32), "name": "x", "platform": "tizen", "app_version": "0.3.0"}
    resp = await post(client, FINISH, body)
    if valid:
        assert resp.status == 403
        assert active.used == 1
    else:
        assert resp.status == 400
        assert (await resp.json())["error"] == "bad_request"
        assert active.used == 0 and start["session"] in active.attempts


@pytest.mark.parametrize(
    "change",
    [
        {"session": "short"}, {"session": 5}, {"A": "!" * 512}, {"A": "A" * 511},
        {"M1": "A" * 42}, {"M1": "A" * 42 + "B"}, {"name": ""}, {"name": "a" * 41},
        {"name": "a\tb"}, {"name": 5}, {"platform": "webos"}, {"platform": None},
        {"app_version": "0.3"}, {"app_version": "0.3.0\n"}, {"app_version": "1." * 20},
        {"v": "1"}, {"v": True}, {"v": 1.0},
    ],
)
async def test_finish_field_validation(env, change):
    manager, _, client = env
    active = await manager.async_open_code()
    start = await (await post(client, START, {"v": 1})).json()
    body = {"v": 1, "session": start["session"], "A": ref.b64u(ref.pad(pow(2, 99, ref.N))),
            "M1": ref.b64u(b"\0" * 32), "name": "x", "platform": "tizen", "app_version": "0.3.0"}
    body.update(change)
    resp = await post(client, FINISH, body)
    assert resp.status == 400
    assert active.used == 0


async def test_finish_missing_field_and_extra_fields(env):
    manager, _, client = env
    active = await manager.async_open_code()
    start = await (await post(client, START, {"v": 1})).json()
    body = {"v": 1, "session": start["session"], "A": ref.b64u(ref.pad(pow(2, 99, ref.N))),
            "M1": ref.b64u(b"\0" * 32), "name": "x", "platform": "tizen", "app_version": "0.3.0"}
    missing = dict(body)
    del missing["M1"]
    assert (await post(client, FINISH, missing)).status == 400
    body["future_field"] = [1]  # unbekannte Felder werden ignoriert
    assert (await post(client, FINISH, body)).status == 403
    assert active.used == 1


@pytest.mark.parametrize(
    ("raw", "headers", "status", "error"),
    [
        (b"not json", TEXT, 400, "bad_request"),
        (b"[1]", TEXT, 400, "bad_request"),
        (b'{"v":1,"v":1}', TEXT, 400, "bad_request"),
        (b'{"v":2}', TEXT, 400, "unsupported_version"),
        (b'{"v":1}', {"Content-Type": "application/x-www-form-urlencoded"}, 400, "bad_request"),
        (b'{"v":1}', {"Content-Type": "application/json"}, 200, None),
        (b'{"v":1}', {"Content-Type": "text/plain"}, 200, None),
        (b'{"v":1,"x":"' + b"a" * 5000 + b'"}', TEXT, 413, "payload_too_large"),
    ],
)
async def test_start_request_validation(env, raw, headers, status, error):
    manager, _, client = env
    await manager.async_open_code()
    resp = await post(client, START, raw, headers)
    assert resp.status == status
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    if error:
        assert (await resp.json())["error"] == error
    if error == "unsupported_version":
        assert (await resp.json())["supported"] == [1]


async def test_finish_body_too_large(env):
    manager, _, client = env
    await manager.async_open_code()
    resp = await post(client, FINISH, b"x" * 5000)
    assert resp.status == 413


async def test_preflight(env):
    _, _, client = env
    for path in (START, FINISH):
        resp = await client.options(path, headers={
            "Origin": "http://example.test", "Access-Control-Request-Method": "POST"})
        assert resp.status == 204
        assert resp.headers["Access-Control-Allow-Origin"] == "*"
        assert resp.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
        assert resp.headers["Access-Control-Allow-Headers"] == "Content-Type"
        assert resp.headers["Access-Control-Max-Age"] == "600"


async def test_cors_header_on_all_pairing_responses(env):
    manager, _, client = env
    for path in (START, FINISH):
        for raw in (b"x", b'{"v":1}'):
            resp = await post(client, path, raw)
            assert resp.headers["Access-Control-Allow-Origin"] == "*"


async def test_only_one_of_two_parallel_correct_attempts_wins(env):
    manager, _, client = env
    active = await manager.async_open_code()

    async def one():
        return await AppSim(code=active.code, name=f"TV").pair(client)

    results = await asyncio.gather(one(), one())
    statuses = sorted(r["status"] for r in results)
    assert statuses == [200, 404]


async def test_third_parallel_finish_gets_429_and_keeps_attempt(env):
    manager, _, client = env
    active = await manager.async_open_code()
    sessions = []
    for src in ("a", "b", "c"):
        _, body, _h = await manager.async_handle_start(src, b'{"v":1}', "text/plain")
        sessions.append(body["session"])
    manager._inflight = 2
    big_a = ref.b64u(ref.pad(pow(2, 99, ref.N)))
    status, _, headers = await manager.async_handle_finish("c", json.dumps({
        "v": 1, "session": sessions[2], "A": big_a, "M1": ref.b64u(b"\0" * 32), "name": "x",
        "platform": "tizen", "app_version": "0.3.0"}).encode(), "text/plain")
    assert status == 429 and "Retry-After" in headers
    assert sessions[2] in active.attempts and active.used == 0


async def test_lockout_after_three_locked_codes(env):
    manager, clock, client = env
    for round_ in range(3):
        active = await manager.async_open_code()
        bad = "000000" if active.code != "000000" else "111111"
        for _ in range(3):
            # eigene Quelladressen, damit das Rate-Limit nicht dazwischenfunkt
            clock.advance(61)
            assert (await AppSim(code=bad).pair(client))["status"] == 403
        assert active.future.result() == FailureReason.LOCKED
    with pytest.raises(PairingBlocked) as err:
        await manager.async_open_code()
    assert 0 < err.value.retry_in <= 600
    clock.advance(601)
    assert await manager.async_open_code()


async def test_no_secret_logging(env, caplog):
    manager, _, client = env
    caplog.set_level("DEBUG")
    active = await manager.async_open_code()
    out = await AppSim(code=active.code).pair(client)
    result = active.future.result()
    text = caplog.text
    assert active.code not in text
    for secret in (result.webhook_id, result.device_id, proto.b64u(result.k_a2h),
                   proto.b64u(result.k_h2a), out["json"]["M2"], out["body"]["M1"]):
        assert secret not in text
