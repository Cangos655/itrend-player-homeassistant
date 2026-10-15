"""Webhook: Signatur, Sequenz, Antworten, Grenzen (vectors.json und mehr)."""

from __future__ import annotations

import asyncio
import json

import pytest

from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import async_capture_events

from custom_components.itrend_player import protocol as proto
from custom_components.itrend_player.const import DOMAIN, EVENT_ITREND, ISSUE_KEY_COPIED

from .helpers import TEXT, FakeClock, VectorApp, entry_from_vectors

import reference as ref

HB = {"v": 1, "type": "heartbeat", "app_version": "0.3.0", "platform": "tizen", "state_rev": 7}
IDLE = {"v": 1, "type": "state", "rev": 8, "status": "idle"}


@pytest.fixture
async def env(hass, hass_client_no_auth, vectors):
    entry = entry_from_vectors(vectors)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    client = await hass_client_no_auth()
    device = entry.runtime_data
    clock = FakeClock()
    device._clock = clock
    hass.data[DOMAIN]["pairing"]._clock = clock
    return entry, device, VectorApp(vectors), client, clock


def _case_ids(vectors_json):
    return [c["name"] for c in vectors_json["webhook"]["cases"]]


def pytest_generate_tests(metafunc):
    if "case" in metafunc.fixturenames:
        import pathlib
        path = pathlib.Path(__file__).resolve().parent.parent / "docs/protocol/vectors.json"
        cases = json.loads(path.read_text(encoding="utf-8"))["webhook"]["cases"]
        metafunc.parametrize("case", cases, ids=[c["name"] for c in cases])


async def test_all_vector_cases(env, case):
    """Jeder Fall aus vectors.json: gleiche HTTP-Antwort, gleicher Fehlercode, gleiches last_seq."""
    _entry, device, app, client, _ = env
    device.last_seq = case["last_seq_before"]
    device.reserved = case["last_seq_before"]
    device.state.rev = case["ha_state_rev_before"]
    resp = await client.post("/api/webhook/" + app.webhook_id,
                             data=case["body"].encode("utf-8"), headers=TEXT)
    exp = case["expect"]
    assert resp.status == exp["http"], await resp.text()
    body = await resp.json()
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    if exp["http"] == 200:
        assert body["ok"] is True and body["code"] == exp["code"] == "ok"
        assert body["resync"] is exp["resync"]
        assert body["proof"] == exp["proof"]
        assert body.get("ignored", False) is exp.get("ignored", False)
        assert body["seq"] == int(case["body"].split("\n", 3)[2])
    else:
        assert body["ok"] is False and body["error"] == exp["code"]
        if exp["http"] == 409:
            assert body["last_seq"] == exp["last_seq"]
            assert body["proof"] == exp["proof"]
    assert device.last_seq == case["last_seq_after"]


async def test_signing_input_vectors(vectors):
    w = vectors["webhook"]
    for case in w["cases"]:
        if "signing_input_hex" not in case:
            continue
        parts = case["body"].encode("utf-8").split(b"\n", 4)
        si = proto.signing_input("POST", w["path"], w["device_id"], int(parts[2]), parts[4])
        assert si.hex() == case["signing_input_hex"]


async def test_valid_message_sets_state_and_events(hass, env):
    _entry, device, app, client, _ = env
    events = async_capture_events(hass, EVENT_ITREND)
    body = app.body(1, {"v": 1, "type": "event", "name": "channel_changed",
                        "media": {"kind": "live", "channel": "Beispielsender 1",
                                  "bogus": "x"}})
    resp = await app.post(client, body)
    assert resp.status == 200
    await hass.async_block_till_done()
    assert len(events) == 1
    data = events[0].data
    assert data["type"] == "channel_changed"
    assert data["media"] == {"kind": "live", "channel": "Beispielsender 1"}
    assert data["entry_id"] and data["device_id"] == device.registry_device_id
    assert set(data) == {"device_id", "entry_id", "type", "media"}


async def test_playback_stopped_event_has_reason(hass, env):
    _e, _d, app, client, _ = env
    events = async_capture_events(hass, EVENT_ITREND)
    await app.post(client, app.body(1, {"v": 1, "type": "event", "name": "playback_stopped",
                                        "reason": "ended"}))
    await hass.async_block_till_done()
    assert events[0].data["reason"] == "ended"


async def test_unknown_event_is_ignored_and_no_bus_event(hass, env):
    _e, _d, app, client, _ = env
    events = async_capture_events(hass, EVENT_ITREND)
    resp = await app.post(client, app.body(1, {"v": 1, "type": "event", "name": "something_new"}))
    assert resp.status == 200 and (await resp.json())["ignored"] is True
    await hass.async_block_till_done()
    assert events == []


# ------------------------------------------------------------------ Aufbau
@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b"",
        lambda b: b"hello",
        lambda b: b.replace(b"ITP/1", b"ITP/x", 1),
        lambda b: b.replace(b"\n", b"\r\n"),
        lambda b: b"ITP/1\n" + b.split(b"\n", 1)[1].replace(b"\n", b" ", 1),  # nur 4 Teile
        lambda b: b.replace(b"\n1\n", b"\n+1\n", 1),
        lambda b: b.replace(b"\n1\n", b"\n1.0\n", 1),
        lambda b: b.replace(b"\n1\n", b"\n12345678901234567\n", 1),  # 17 Stellen
        lambda b: b.replace(b"\n1\n", b"\n9007199254740992\n", 1),  # 2^53
        lambda b: b.replace(b"\n1\n", b"\n-1\n", 1),
        lambda b: b.replace(b"\n1\n", b"\n\xc3\xa4\n", 1),  # Nicht-ASCII im Kopf
    ],
)
async def test_malformed_bodies_get_400(env, mutate):
    _e, device, app, client, _ = env
    resp = await app.post(client, mutate(app.body(1, HB)))
    assert resp.status == 400
    assert device.last_seq == 0
    assert resp.headers["Access-Control-Allow-Origin"] == "*"


async def test_future_version_gets_unsupported_version(env):
    _e, _d, app, client, _ = env
    body = app.body(1, HB).replace(b"ITP/1", b"ITP/2", 1)
    resp = await app.post(client, body)
    assert resp.status == 400
    assert await resp.json() == {"ok": False, "error": "unsupported_version", "supported": [1]}


async def test_unsigned_requests_rejected(env):
    _e, device, app, client, _ = env
    unsigned = b"ITP/1\n%s\n1\n%s\n" % (app.device_id.encode(), b"A" * 43) + \
        json.dumps(HB).encode()
    resp = await app.post(client, unsigned)
    assert resp.status == 401
    assert (await resp.json())["error"] == "bad_signature"
    assert device.last_seq == 0
    assert device.state.available is False


async def test_unknown_device_and_bad_signature_look_the_same(env):
    _e, _d, app, client, _ = env
    good = app.body(1, HB)
    bad_sig = good.replace(good.split(b"\n")[3], b"A" * 43, 1)
    other_dev = ref.build_body(app.k_a2h, app.path, ref.b64u(b"\1" * 16), 1,
                               json.dumps(HB).encode())
    r1 = await app.post(client, bad_sig)
    r2 = await app.post(client, other_dev)
    assert r1.status == r2.status == 401
    assert await r1.json() == await r2.json()


async def test_signature_over_raw_bytes_not_canonical_json(env):
    """Beliebige JSON-Schreibweise (Leerzeichen, Reihenfolge) ist ok, wenn die Bytes signiert sind."""
    _e, _d, app, client, _ = env
    raw = b'{ "state_rev" : 7, "platform":"tizen", "app_version" : "0.3.0", "type":"heartbeat","v":1 }'
    resp = await app.post(client, app.body(1, raw))
    assert resp.status == 200


async def test_signature_covers_path(env):
    """Fuer einen anderen Webhook signiert -> ungueltig (PATH kommt aus der webhook_id)."""
    _e, _d, app, client, _ = env
    other = ref.build_body(app.k_a2h, "/api/webhook/other", app.device_id, 1,
                           json.dumps(HB).encode())
    assert (await app.post(client, other)).status == 401


@pytest.mark.parametrize(
    "headers",
    [{}, {"Content-Type": "application/json"}, {"Content-Type": "application/octet-stream"}],
)
async def test_wrong_content_type_rejected(env, headers):
    _e, device, app, client, _ = env
    resp = await client.post("/api/webhook/" + app.webhook_id, data=app.body(1, HB),
                             headers=headers or None, skip_auto_headers=["Content-Type"])
    assert resp.status == 400
    assert device.last_seq == 0


async def test_text_plain_without_charset_accepted(env):
    _e, _d, app, client, _ = env
    resp = await app.post(client, app.body(1, HB), headers={"Content-Type": "text/plain"})
    assert resp.status == 200


async def test_get_is_not_allowed(env):
    _e, _d, app, client, _ = env
    resp = await client.get("/api/webhook/" + app.webhook_id)
    assert resp.status == 405


# ---------------------------------------------------------------- Grenzen
async def test_oversized_body(env):
    _e, device, app, client, _ = env
    resp = await app.post(client, b"ITP/1\n" + b"x" * 5000)
    assert resp.status == 413
    assert device.last_seq == 0


async def test_payload_over_2048_is_413_and_consumes_seq(env):
    _e, device, app, client, _ = env
    big = json.dumps({"v": 1, "type": "heartbeat", "pad": "x" * 2100}).encode()
    resp = await app.post(client, app.body(5, big))
    assert resp.status == 413 and (await resp.json())["error"] == "payload_too_large"
    assert device.last_seq == 5


@pytest.mark.parametrize(
    "payload",
    [
        b'{"v":1,"type":"heartbeat","app_version":"0.3.0","platform":"tizen","state_rev":1,'
        b'"state_rev":2}',
        b"NaN", b'{"v":1,"type":"state","rev":NaN,"status":"idle"}', b"[1,2]", b"null",
        b'{"v":1.0,"type":"unpair"}', b'{"v":true,"type":"unpair"}',
        b'{"v":1,"type":"state","rev":1.0,"status":"idle"}',
        b'{"v":1,"type":"state","rev":1e2,"status":"idle"}',
        b'{"v":1,"type":"state","rev":1,"status":"playing","media":{"kind":"movie","title":"' +
        b"a" * 121 + b'"}}',
        b'{"v":1,"type":"state","rev":1,"status":"idle","media":{"kind":"movie"}}',
        b'{"v":1,"type":"heartbeat","app_version":"0.3.0\\n","platform":"tizen","state_rev":0}',
        b'{"v":1,"type":"event","name":"channel_changed\\n"}',
        b'{"v":1,"type":"state","rev":1,"status":"playing","media":{"kind":"movie",'
        b'"title":"a\\u0000b"}}',
        b'{"v":1,"type":"state","rev":1,"status":"playing","media":{"kind":"movie",'
        b'"title":"\\ud800"}}',
        b"\xff\xfe",
    ],
)
async def test_bad_payloads_get_422_and_consume_seq(env, payload):
    _e, device, app, client, _ = env
    resp = await app.post(client, app.body(3, payload))
    assert resp.status == 422
    assert (await resp.json())["error"] == "bad_payload"
    assert device.last_seq == 3
    assert device.state.available is False  # kein Zustand uebernommen


async def test_title_limits_in_codepoints(env):
    _e, _d, app, client, _ = env
    ok = {"v": 1, "type": "state", "rev": 1, "status": "playing",
          "media": {"kind": "movie", "title": "😀" * 120}}
    assert (await app.post(client, app.body(1, ok))).status == 200
    ok["media"]["title"] = "😀" * 121
    assert (await app.post(client, app.body(2, ok))).status == 422


async def test_max_seq_accepted_and_beyond_rejected(env):
    _e, device, app, client, _ = env
    resp = await app.post(client, app.body(2**53 - 1, HB))
    assert resp.status == 200
    assert device.last_seq == 2**53 - 1
    assert (await app.post(client, app.body(2**53, HB))).status == 400


# ------------------------------------------------------------------ Sequenz
async def test_replay_returns_409_with_proof_and_does_not_change_state(env):
    _e, device, app, client, _ = env
    body = app.body(10, IDLE)
    assert (await app.post(client, body)).status == 200
    resp = await app.post(client, body)
    assert resp.status == 409
    data = await resp.json()
    assert data["error"] == "seq_too_low" and data["last_seq"] == 10
    assert data["proof"] == app.proof(10, body, "seq_too_low", 10, False)
    lower = app.body(9, IDLE)
    resp = await app.post(client, lower)
    assert resp.status == 409
    assert (await resp.json())["proof"] == app.proof(9, lower, "seq_too_low", 10, False)
    assert device.last_seq == 10


async def test_gap_is_allowed_and_resync_flow(env):
    _e, device, app, client, _ = env
    body = app.body(1, HB)
    resp = await app.post(client, body)
    data = await resp.json()
    assert data["resync"] is True  # HA kennt noch keinen state (state_rev passt nicht)
    assert data["proof"] == app.proof(1, body, "ok", 0, True)
    st = app.body(2, {"v": 1, "type": "state", "rev": 7, "status": "idle"})
    assert (await app.post(client, st)).status == 200
    resp = await app.post(client, app.body(500, HB))
    assert (await resp.json())["resync"] is False
    assert device.last_seq == 500


async def test_parallel_requests_with_same_seq_one_wins(env):
    _e, device, app, client, _ = env
    body = app.body(7, IDLE)
    responses = await asyncio.gather(*(app.post(client, body) for _ in range(5)))
    statuses = sorted(r.status for r in responses)
    assert statuses == [200, 409, 409, 409, 409]
    assert device.last_seq == 7


async def test_parallel_requests_different_seq_ordered_under_lock(env):
    _e, device, app, client, _ = env
    bodies = [app.body(s, IDLE) for s in (4, 3, 2, 1)]
    responses = await asyncio.gather(*(app.post(client, b) for b in bodies))
    assert all(r.status in (200, 409) for r in responses)
    assert device.last_seq == max(
        int(b.split(b"\n")[2]) for b, r in zip(bodies, responses, strict=True) if r.status == 200)


async def test_reservation_is_saved_before_accept_and_survives_restart(hass, env):
    entry, device, app, client, _ = env
    assert (await app.post(client, app.body(5, IDLE))).status == 200
    assert device.reserved == 104
    assert (await app.post(client, app.body(6, IDLE))).status == 200
    assert device.reserved == 104  # innerhalb der Reservierung kein neues Speichern
    stored = await device._store.async_load()
    assert stored == {"reserved": 104}
    # Neustart: last_seq = reserved -> alte Meldungen bleiben abgelehnt
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    device2 = entry.runtime_data
    assert device2 is not device and device2.last_seq == 104
    resp = await app.post(client, app.body(50, IDLE))
    assert resp.status == 409 and (await resp.json())["last_seq"] == 104
    assert (await app.post(client, app.body(105, IDLE))).status == 200
    assert device2.reserved == 204


async def test_failed_save_rejects_message(hass, env, monkeypatch):
    _e, device, app, client, _ = env

    async def boom(data):
        raise OSError("disk full")

    monkeypatch.setattr(device._store, "async_save", boom)
    resp = await app.post(client, app.body(1, IDLE))
    assert resp.status == 500 and (await resp.json())["error"] == "internal"
    assert device.last_seq == 0


async def test_unhandled_error_gives_json_500(env, monkeypatch):
    _e, device, app, client, _ = env
    monkeypatch.setattr(device, "_apply", lambda obj: 1 / 0)
    resp = await app.post(client, app.body(1, IDLE))
    assert resp.status == 500 and (await resp.json()) == {"ok": False, "error": "internal"}
    assert resp.headers["Access-Control-Allow-Origin"] == "*"


# ------------------------------------------------------------- Rate-Limits
async def test_per_device_rate_limit(env):
    _e, device, app, client, clock = env
    statuses = []
    for seq in range(1, 13):
        statuses.append((await app.post(client, app.body(seq, IDLE))).status)
    assert statuses[:10] == [200] * 10
    assert statuses[10:] == [429, 429]
    assert device.last_seq == 10  # abgelehnte Meldungen verbrauchen keine Sequenz
    clock.advance(11)
    assert (await app.post(client, app.body(11, IDLE))).status == 200


async def test_replays_do_not_consume_device_limit(env):
    _e, _d, app, client, _ = env
    body = app.body(1, IDLE)
    await app.post(client, body)
    for _ in range(15):
        assert (await app.post(client, body)).status in (409, 429)
    # Angreifer ohne Schluessel / mit Replays darf die echte Meldung nicht aussperren,
    # solange die Quelladresse nicht gesperrt ist.
    assert (await app.post(client, app.body(2, IDLE))).status in (200, 429)


async def test_bad_signature_rate_limit_per_source(env):
    _e, device, app, client, clock = env
    good = app.body(1, IDLE)
    bad = good.replace(good.split(b"\n")[3], b"A" * 43, 1)
    statuses = [(await app.post(client, bad)).status for _ in range(32)]
    assert statuses[:30] == [401] * 30
    assert statuses[30:] == [429, 429]
    # ohne weitere Pruefung: auch ein gueltiger Body bekommt 429
    resp = await app.post(client, good)
    assert resp.status == 429 and int(resp.headers["Retry-After"]) >= 1
    clock.advance(61)
    assert (await app.post(client, good)).status == 200


# ---------------------------------------------------- geklonter Schluessel
async def test_cloned_key_detection_by_repeated_stale_messages(hass, env):
    entry, _d, app, client, clock = env
    await app.post(client, app.body(10, IDLE))
    issue_id = ISSUE_KEY_COPIED.format(entry_id=entry.entry_id)
    registry = ir.async_get(hass)
    old = app.body(5, IDLE)
    for _ in range(4):  # ein einzelner 409 ist normal
        assert (await app.post(client, old)).status == 409
        clock.advance(1)
    assert registry.async_get_issue(DOMAIN, issue_id) is None
    assert (await app.post(client, old)).status == 409
    issue = registry.async_get_issue(DOMAIN, issue_id)
    assert issue is not None and issue.translation_key == "key_possibly_copied"
    assert issue.is_fixable is False


async def test_stale_messages_outside_window_do_not_count(hass, env):
    entry, _d, app, client, clock = env
    await app.post(client, app.body(10, IDLE))
    old = app.body(5, IDLE)
    for _ in range(8):
        await app.post(client, old)
        clock.advance(200)
    assert ir.async_get(hass).async_get_issue(
        DOMAIN, ISSUE_KEY_COPIED.format(entry_id=entry.entry_id)) is None


async def test_sequence_jump_over_1000_flags_issue(hass, env):
    entry, _d, app, client, _ = env
    await app.post(client, app.body(10, IDLE))
    issue_id = ISSUE_KEY_COPIED.format(entry_id=entry.entry_id)
    assert (await app.post(client, app.body(1010, IDLE))).status == 200  # genau 1000: ok
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is None
    assert (await app.post(client, app.body(2011, IDLE))).status == 200
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None


# ------------------------------------------------------------------ Logs
async def test_logs_contain_no_secrets_or_content(hass, env, caplog, vectors):
    _e, _d, app, client, _ = env
    caplog.set_level("DEBUG")
    pay = {"v": 1, "type": "state", "rev": 1, "status": "playing",
           "media": {"kind": "movie", "title": "Geheimer Titel XYZ"}}
    good = app.body(1, pay)
    await app.post(client, good)
    await app.post(client, good)  # 409
    await app.post(client, good.replace(good.split(b"\n")[3], b"A" * 43, 1))  # 401
    await app.post(client, app.body(2, b"not json"))  # 422
    await app.post(client, app.body(3, b'{"v":1,"type":"state","rev":1,"status":"idle","x":1,'
                                    b'"x":2}'))
    w = vectors["webhook"]
    # HA Core protokolliert die webhook_id selbst; die Geheimnisse duerfen nirgends stehen.
    text = caplog.text
    sig = app.sig_of(good)
    for secret in (w["K_a2h_hex"], w["K_h2a_hex"], proto.b64u(app.k_a2h), proto.b64u(app.k_h2a),
                   "Geheimer Titel XYZ", sig, app.proof(1, good)):
        assert secret not in text
    # Logs der Integration: hoechstens 4 Zeichen der webhook_id. (Die Logs von HA Core
    # und aiohttp liegen ausserhalb unserer Wirkung, PROTOCOL.md 8.5.)
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if r.name.startswith("custom_components.itrend_player"))
    assert app.webhook_id not in ours


async def test_aiohttp_not_our_logs_leak_webhook_id(hass, env, caplog):
    """Die Integration selbst nennt hoechstens 4 Zeichen der webhook_id."""
    _e, _d, app, client, _ = env
    caplog.set_level("DEBUG", logger="custom_components.itrend_player")
    await app.post(client, app.body(1, IDLE))
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if r.name.startswith("custom_components.itrend_player"))
    assert app.webhook_id not in ours
