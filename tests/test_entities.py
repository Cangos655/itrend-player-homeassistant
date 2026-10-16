"""Entitaeten, Verfuegbarkeit, Trennen, Loeschen."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from pathlib import Path

import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.helpers import (
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_capture_events, async_fire_time_changed

from custom_components.itrend_player import (
    async_remove_config_entry_device,
    protocol as proto,
)
from custom_components.itrend_player.const import (
    CONF_K_A2H,
    CONF_K_H2A,
    CONF_UNPAIRED,
    DOMAIN,
    ISSUE_UNPAIRED,
)

from .helpers import FakeClock, VectorApp, entry_from_vectors

EPISODE = {"v": 1, "type": "state", "rev": 7, "status": "playing",
           "media": {"kind": "episode", "title": "Pilot", "series": "Beispielserie",
                     "season": 1, "episode": 2, "duration_ms": 2700000, "position_ms": 125000}}
HB_SUB = {"v": 1, "type": "heartbeat", "app_version": "0.3.5", "platform": "android",
          "state_rev": 7, "ws": False,
          "sub": {"expires": "2027-03-31", "connections_active": 1, "connections_max": 2}}


@pytest.fixture
async def env(hass, hass_client_no_auth, hass_storage, vectors):
    from homeassistant.setup import async_setup_component
    assert await async_setup_component(hass, "media_player", {})
    entry = entry_from_vectors(vectors)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    client = await hass_client_no_auth()
    device = entry.runtime_data
    clock = FakeClock()
    device._clock = clock
    ents = er.async_get(hass)

    def eid(domain, key):
        return ents.async_get_entity_id(domain, DOMAIN, f"{entry.entry_id}_{key}")

    ids = {
        "mp": eid("media_player", "media_player"),
        "version": eid("sensor", "app_version"),
        "sub": eid("sensor", "subscription_expires"),
        "conn": eid("sensor", "connections"),
        "max": eid("sensor", "connections_max"),
        "active": eid("binary_sensor", "app_active"),
    }
    assert all(ids.values()), ids
    return entry, device, VectorApp(vectors), client, ids, hass_storage


async def send(hass, app, client, seq, payload):
    resp = await app.post(client, app.body(seq, payload))
    assert resp.status == 200, await resp.text()
    await hass.async_block_till_done()
    return resp


async def test_initial_states(hass, env):
    _e, _d, _a, _c, ids, _s = env
    assert hass.states.get(ids["mp"]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["version"]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["sub"]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["conn"]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["active"]).state == STATE_OFF


async def test_entity_names_and_categories(hass, env):
    _e, _d, _a, _c, ids, _s = env
    ents = er.async_get(hass)
    assert ids["mp"] == "media_player.itrend_player_wohnzimmer_tv"
    assert ids["version"].endswith("_app_version")
    assert ents.async_get(ids["version"]).entity_category == "diagnostic"
    assert hass.states.get(ids["active"]).name == "iTrend Player (Wohnzimmer TV) App active"


async def test_playing_episode(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, EPISODE)
    st = hass.states.get(ids["mp"])
    assert st.state == "playing"
    a = st.attributes
    assert a["media_title"] == "Pilot"
    assert a["media_series_title"] == "Beispielserie"
    assert a["media_season"] == "1" and a["media_episode"] == "2"
    assert a["media_content_type"] == "episode"
    assert a["media_duration"] == 2700 and a["media_position"] == 125
    assert a["media_kind"] == "episode"
    assert a["supported_features"] == 0
    assert "media_position_updated_at" in a
    assert hass.states.get(ids["active"]).state == STATE_ON


async def test_live_channel_and_other_statuses(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, {"v": 1, "type": "state", "rev": 1, "status": "buffering",
                                      "media": {"kind": "live", "channel": "Beispielsender 1",
                                                "title": "Nachrichten"}})
    st = hass.states.get(ids["mp"])
    assert st.state == "buffering"
    assert st.attributes["media_channel"] == "Beispielsender 1"
    assert st.attributes["media_content_type"] == "channel"
    assert "media_position" not in st.attributes
    await send(hass, app, client, 2, {"v": 1, "type": "state", "rev": 2, "status": "paused",
                                      "media": {"kind": "movie", "title": "Film"}})
    assert hass.states.get(ids["mp"]).state == "paused"
    assert hass.states.get(ids["mp"]).attributes["media_content_type"] == "movie"
    await send(hass, app, client, 3, {"v": 1, "type": "state", "rev": 3, "status": "idle"})
    st = hass.states.get(ids["mp"])
    assert st.state == "idle"
    assert "media_title" not in st.attributes  # alter Titel ist weg


async def test_heartbeat_fills_sensors(hass, env):
    _e, device, app, client, ids, _s = env
    await send(hass, app, client, 1, HB_SUB)
    assert hass.states.get(ids["version"]).state == "0.3.5"
    expires = hass.states.get(ids["sub"]).state
    assert dt_util.parse_datetime(expires) == dt_util.start_of_local_day(
        datetime(2027, 3, 31).date())
    conn = hass.states.get(ids["conn"])
    assert conn.state == "1" and conn.attributes["connections_max"] == 2
    assert hass.states.get(ids["active"]).state == STATE_ON
    # Geraeteeintrag zeigt die gemeldete App-Version
    dev = dr.async_get(hass).async_get(device.registry_device_id)
    assert dev.sw_version == "0.3.5" and dev.model == "Android TV / Fire TV"
    # Ohne Abo-Einwilligung: Werte werden leer, nicht veraltet
    await send(hass, app, client, 2, {k: v for k, v in HB_SUB.items() if k != "sub"})
    assert hass.states.get(ids["sub"]).state == STATE_UNKNOWN
    assert hass.states.get(ids["conn"]).state == STATE_UNKNOWN


async def test_sub_expires_null(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, dict(HB_SUB, sub={"expires": None}))
    assert hass.states.get(ids["sub"]).state == STATE_UNKNOWN


async def test_availability_after_three_missed_heartbeats(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, EPISODE)
    now = dt_util.utcnow()
    async_fire_time_changed(hass, now + timedelta(seconds=89))
    await hass.async_block_till_done()
    assert hass.states.get(ids["mp"]).state == "playing"
    async_fire_time_changed(hass, now + timedelta(seconds=91))
    await hass.async_block_till_done()
    for key in ("mp", "version", "conn", "sub"):
        assert hass.states.get(ids[key]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["active"]).state == STATE_OFF
    # Titel werden nicht ueber den Ausfall hinaus gehalten
    await send(hass, app, client, 2, HB_SUB)
    assert hass.states.get(ids["mp"]).state == "idle"
    assert "media_title" not in hass.states.get(ids["mp"]).attributes
    assert hass.states.get(ids["active"]).state == STATE_ON


async def test_heartbeats_keep_it_available(hass, env, freezer):
    _e, _d, app, client, ids, _s = env
    for i in range(1, 6):
        await send(hass, app, client, i, HB_SUB)
        freezer.tick(timedelta(seconds=30))
        async_fire_time_changed(hass)
        await hass.async_block_till_done()
    assert hass.states.get(ids["mp"]).state != STATE_UNAVAILABLE


async def test_closed_sets_idle_off_immediately(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, EPISODE)
    await send(hass, app, client, 2, {"v": 1, "type": "state", "rev": 8, "status": "closed"})
    st = hass.states.get(ids["mp"])
    assert st.state == STATE_OFF and "media_title" not in st.attributes
    assert hass.states.get(ids["active"]).state == STATE_OFF
    # bleibt "aus", wird nicht nach 90 s "nicht verfuegbar"
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=300))
    await hass.async_block_till_done()
    assert hass.states.get(ids["mp"]).state == STATE_OFF
    # App startet wieder: Herzschlag -> aktiv, State folgt
    await send(hass, app, client, 3, HB_SUB)
    assert hass.states.get(ids["active"]).state == STATE_ON
    assert hass.states.get(ids["mp"]).state == "idle"


async def test_media_not_in_recorder_attributes(hass, env):
    _e, _d, _a, _c, ids, _s = env
    entity = hass.data["entity_components"]["media_player"].get_entity(ids["mp"])
    unrecorded = entity._Entity__combined_unrecorded_attributes
    for attr in ("media_title", "media_channel", "media_series_title"):
        assert attr in unrecorded


async def test_resync_requested_after_ha_restart(hass, env):
    entry, device, app, client, ids, _s = env
    await send(hass, app, client, 1, EPISODE)
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    resp = await app.post(client, app.body(200, dict(HB_SUB)))
    assert (await resp.json())["resync"] is True


# -------------------------------------------------------- Trennen / Loeschen
async def test_delete_removes_webhook_secret_and_storage(hass, env):
    entry, _d, app, client, ids, storage = env
    await send(hass, app, client, 1, EPISODE)
    key = f"{DOMAIN}.{entry.entry_id}"
    assert key in storage
    assert await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert app.webhook_id not in hass.data.get("webhook", {})
    assert key not in storage
    assert hass.config_entries.async_get_entry(entry.entry_id) is None
    resp = await app.post(client, app.body(2, EPISODE))
    assert resp.status == 200 and await resp.read() == b""  # HA-Verhalten, nicht beeinflussbar
    assert hass.states.get(ids["mp"]) is None


async def test_delete_device_in_ui_removes_entry(hass, env):
    entry, device, _a, _c, _i, _s = env
    dev = dr.async_get(hass).async_get(device.registry_device_id)
    assert await async_remove_config_entry_device(hass, entry, dev) is True
    await hass.async_block_till_done()
    assert hass.config_entries.async_get_entry(entry.entry_id) is None


async def test_unload_unregisters_webhook(hass, env):
    entry, _d, app, _c, _i, _s = env
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert app.webhook_id not in hass.data.get("webhook", {})
    assert entry.state is ConfigEntryState.NOT_LOADED


async def test_unpair_by_app(hass, env):
    entry, device, app, client, ids, _s = env
    await send(hass, app, client, 1, EPISODE)
    resp = await send(hass, app, client, 2, {"v": 1, "type": "unpair"})
    body = await resp.json()
    assert body["ok"] is True and body["proof"]
    assert app.webhook_id not in hass.data["webhook"]
    assert entry.data[CONF_UNPAIRED] is True
    assert entry.data[CONF_K_A2H] == "" and entry.data[CONF_K_H2A] == ""
    assert device.paired is False and device._k_a2h == b""
    for key in ("mp", "version", "conn", "sub"):
        assert hass.states.get(ids[key]).state == STATE_UNAVAILABLE
    assert hass.states.get(ids["active"]).state == STATE_OFF
    issue = ir.async_get(hass).async_get_issue(
        DOMAIN, ISSUE_UNPAIRED.format(entry_id=entry.entry_id))
    assert issue is not None and issue.translation_key == "unpaired_by_app"
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert any(f["context"]["source"] == "reauth" for f in flows)
    # Nach Neustart bleibt der Zustand: kein Webhook
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert app.webhook_id not in hass.data["webhook"]
    assert hass.states.get(ids["mp"]).state == STATE_UNAVAILABLE


async def test_corrupt_key_in_entry_fails_setup(hass, vectors):
    entry = entry_from_vectors(vectors, **{CONF_K_A2H: "***"})
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR


# ---------------------------------------------------- Paket-Konsistenz
PKG = Path(__file__).resolve().parent.parent / "custom_components" / "itrend_player"


def _paths(d, prefix=""):
    out = set()
    for k, v in d.items():
        if isinstance(v, dict):
            out |= _paths(v, f"{prefix}{k}.")
        else:
            out.add(f"{prefix}{k}")
    return out


def _walk(d, prefix=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _walk(v, f"{prefix}{k}.")
        else:
            yield f"{prefix}{k}", v


def test_translations_complete_and_consistent():
    import re
    strings = json.loads((PKG / "strings.json").read_text(encoding="utf-8"))
    en = json.loads((PKG / "translations/en.json").read_text(encoding="utf-8"))
    assert strings == en
    keys = _paths(en)
    ph = lambda t: set(re.findall(r"\{(\w+)\}", t))  # noqa: E731
    for lang in ("de", "tr"):
        tr = json.loads((PKG / f"translations/{lang}.json").read_text(encoding="utf-8"))
        assert _paths(tr) == keys, lang
        eng = dict(_walk(en))
        for path, text in _walk(tr):
            assert text.strip(), (lang, path)
            assert ph(text) == ph(eng[path]), (lang, path)
    # Platzhalter, die der Code liefert
    assert ph(en["config"]["progress"]["wait_for_app"]) == {"code", "address"}


def test_manifest():
    m = json.loads((PKG / "manifest.json").read_text(encoding="utf-8"))
    assert m["domain"] == "itrend_player" and m["version"] == "0.3.0"
    assert m["config_flow"] is True and m["integration_type"] == "device"
    assert m["iot_class"] == "local_push" and m["requirements"] == []
    assert m["dependencies"] == ["webhook", "http"]
    assert m["codeowners"] == ["@Cangos655"]
    assert m["documentation"].startswith("https://github.com/Cangos655/")
    assert m["issue_tracker"].startswith("https://github.com/Cangos655/")


def test_no_forbidden_logging_or_urls_in_source():
    """Quellcode-Wache: keine Print-/Log-Aufrufe mit Geheimnissen, keine fremden Adressen."""
    import re
    for path in PKG.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "print(" not in text, path.name
        for m in re.finditer(r"_LOGGER\.\w+\((.*)", text):
            line = m.group(1)
            for bad in ("k_a2h", "k_h2a", "payload", "body", "obj", "sig", "code", "media"):
                assert not re.search(rf"[,(\s]{bad}\b[^\"']*$", line), (path.name, line)
    assert proto.N  # Modul importierbar


async def test_unpaired_device_never_checks_with_empty_key(hass, env):
    """Eine Anfrage, die waehrend `unpair` noch laeuft, wird nicht mit leerem Schluessel geprueft."""
    import hmac
    import hashlib
    _e, device, app, _c, _i, _s = env
    device.paired = False
    device._k_a2h = b""

    class Req:
        remote = "127.0.0.1"
        content_length = 10
        headers = {"Content-Type": "text/plain"}

    resp = await device._handle(Req())
    assert resp.status == 401
    assert hmac.new(b"", b"x", hashlib.sha256)  # (leerer Schluessel waere rechnerisch moeglich)


async def test_allow_remote_option_reregisters_webhook(hass, env):
    from homeassistant.data_entry_flow import FlowResultType
    entry, _d, app, _c, _i, _s = env
    assert hass.data["webhook"][app.webhook_id]["local_only"] is True
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"allow_remote": True})
    assert result["type"] == FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.allow_remote is True
    assert hass.data["webhook"][app.webhook_id]["local_only"] is False
    result = await hass.config_entries.options.async_init(entry.entry_id)
    await hass.config_entries.options.async_configure(result["flow_id"], {"allow_remote": False})
    await hass.async_block_till_done()
    assert hass.data["webhook"][app.webhook_id]["local_only"] is True


async def test_nonlocal_sender_gets_empty_200_unless_allowed(hass, hass_client_no_auth, vectors):
    """HA Core verwirft nicht-lokale Absender bei local_only mit leerem 200 (Hairpin-NAT)."""
    from unittest.mock import patch
    from homeassistant.setup import async_setup_component
    assert await async_setup_component(hass, "media_player", {})
    entry = entry_from_vectors(vectors)
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    client = await hass_client_no_auth()
    app = VectorApp(vectors)
    body = app.body(1, {"v": 1, "type": "state", "rev": 1, "status": "idle"})
    with patch("homeassistant.util.network.is_local", return_value=False):
        resp = await app.post(client, body)
        assert resp.status == 200 and await resp.read() == b""
        assert entry.runtime_data.last_seq == 0
        await _set_remote(hass, entry, True)
        resp = await app.post(client, body)
        assert (await resp.json())["ok"] is True


async def test_remote_pairing_creates_hint_and_option_clears_it(hass, vectors):
    entry = entry_from_vectors(vectors, paired_from_remote=True)
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    issue_id = f"remote_source_{entry.entry_id}"
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None
    await _set_remote(hass, entry, True)
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is None


async def _set_remote(hass, entry, value):
    result = await hass.config_entries.options.async_init(entry.entry_id)
    await hass.config_entries.options.async_configure(result["flow_id"], {"allow_remote": value})
    await hass.async_block_till_done()


async def test_max_connections_sensor_works_with_max_only(hass, env):
    _e, _d, app, client, ids, _s = env
    assert hass.states.get(ids["max"]).state == STATE_UNAVAILABLE
    await send(hass, app, client, 1, dict(HB_SUB, sub={"connections_max": 3}))
    assert hass.states.get(ids["max"]).state == "3"
    assert hass.states.get(ids["conn"]).state == STATE_UNKNOWN


# ------------------------------------------------ Cover und Playlist-Status
PIC = "https://img.example.com/covers/123.jpg"
PL_HB = {"v": 1, "type": "heartbeat", "app_version": "0.4.0", "platform": "android", "state_rev": 7,
         "playlist": {"updated": "2026-10-15T08:30:00Z", "live": 1200, "movies": 3400,
                      "series": 560, "error": "none"}}


async def test_picture_becomes_remote_entity_picture_only(hass, env):
    _e, _d, app, client, ids, _s = env
    st = dict(EPISODE, picture=PIC)
    await send(hass, app, client, 1, st)
    state = hass.states.get(ids["mp"])
    assert state.attributes["entity_picture"] == PIC  # Client laedt selbst, kein HA-Proxy
    assert "entity_picture_local" not in state.attributes or state.attributes["entity_picture_local"] is None
    entity = hass.data["entity_components"]["media_player"].get_entity(ids["mp"])
    assert entity.media_image_hash is None
    assert await entity.async_get_media_image() == (None, None)
    await send(hass, app, client, 2, dict(EPISODE, rev=8))  # ohne picture: weg
    assert "entity_picture" not in hass.states.get(ids["mp"]).attributes \
        or not hass.states.get(ids["mp"]).attributes["entity_picture"]


async def test_picture_gone_when_idle_or_closed(hass, env):
    _e, _d, app, client, ids, _s = env
    await send(hass, app, client, 1, dict(EPISODE, picture=PIC))
    await send(hass, app, client, 2, {"v": 1, "type": "state", "rev": 8, "status": "idle"})
    assert not hass.states.get(ids["mp"]).attributes.get("entity_picture")


@pytest.mark.parametrize(
    "bad",
    ["http://127.0.0.1/a.jpg", "https://u:p@img.example.com/a.jpg", "https://img.example.com/movie/a/b/1.mp4",
     "https://img.example.com/a.jpg?token=x", "javascript:alert(1)", "https://[::ffff:8.8.8.8]/a.jpg"],
)
async def test_bad_picture_is_422(hass, env, bad):
    _e, device, app, client, ids, _s = env
    resp = await app.post(client, app.body(1, dict(EPISODE, picture=bad)))
    assert resp.status == 422
    assert device.state.picture is None and device.state.available is False


async def test_picture_without_media_is_422(env):
    _e, _d, app, client, _i, _s = env
    resp = await app.post(client, app.body(1, {"v": 1, "type": "state", "rev": 1, "status": "idle",
                                               "picture": PIC}))
    assert resp.status == 422


async def test_playlist_sensors(hass, env):
    _e, _d, app, client, ids, _s = env
    ents = er.async_get(hass)
    entry = env[0]

    def eid(key):
        return ents.async_get_entity_id("sensor", DOMAIN, f"{entry.entry_id}_{key}")

    await send(hass, app, client, 1, PL_HB)
    assert dt_util.parse_datetime(hass.states.get(eid("playlist_updated")).state) == datetime(
        2026, 10, 15, 8, 30, tzinfo=dt_util.UTC)
    assert hass.states.get(eid("playlist_live")).state == "1200"
    assert hass.states.get(eid("playlist_movies")).state == "3400"
    assert hass.states.get(eid("playlist_series")).state == "560"
    assert hass.states.get(eid("playlist_error")).state == "none"
    for key in ("playlist_live", "playlist_movies", "playlist_series"):
        assert ents.async_get(eid(key)).entity_category == "diagnostic"
    await send(hass, app, client, 2, dict(PL_HB, playlist={"error": "unauthorized", "updated": None}))
    assert hass.states.get(eid("playlist_error")).state == "unauthorized"
    assert hass.states.get(eid("playlist_updated")).state == STATE_UNKNOWN
    assert hass.states.get(eid("playlist_live")).state == STATE_UNKNOWN
    # Ohne Einwilligung (kein playlist-Objekt): Werte leer
    await send(hass, app, client, 3, {k: v for k, v in PL_HB.items() if k != "playlist"})
    assert hass.states.get(eid("playlist_error")).state == STATE_UNKNOWN


@pytest.mark.parametrize(
    "playlist",
    [{"updated": "2026-10-15T08:30:00+00:00"}, {"updated": "2026-10-15 08:30:00Z"},
     {"updated": "2026-02-30T08:30:00Z"}, {"updated": "2026-10-15T24:00:00Z"},
     {"updated": "2026-10-15T08:30:60Z"}, {"updated": "2026-10-15T08:30:00.5Z"},
     {"live": -1}, {"movies": 1000000}, {"series": 1.0}, {"live": True}, {"error": "boom"}, {"error": None},
     "x", [1]],
)
async def test_bad_playlist_is_422(env, playlist):
    _e, _d, app, client, _i, _s = env
    resp = await app.post(client, app.body(1, dict(PL_HB, playlist=playlist)))
    assert resp.status == 422


async def test_playlist_events(hass, env):
    _e, _d, app, client, _i, _s = env
    events = async_capture_events(hass, "itrend_player_event")
    await send(hass, app, client, 1, {"v": 1, "type": "event", "name": "playlist_refreshed", "x": 1})
    await send(hass, app, client, 2, {"v": 1, "type": "event", "name": "playlist_failed",
                                      "error": "no_network", "url": "http://secret"})
    await hass.async_block_till_done()
    assert [e.data["type"] for e in events] == ["playlist_refreshed", "playlist_failed"]
    assert "error" not in events[0].data and events[1].data["error"] == "no_network"
    assert "url" not in events[1].data and "x" not in events[0].data
    for bad in ({"name": "playlist_failed"}, {"name": "playlist_failed", "error": "none"},
                {"name": "playlist_refreshed", "error": "other"}):
        resp = await app.post(client, app.body(10 + len(str(bad)), {"v": 1, "type": "event", **bad}))
        assert resp.status == 422


async def test_unknown_fields_and_types_are_dropped(hass, env, caplog):
    _e, device, app, client, ids, _s = env
    caplog.set_level("DEBUG")
    events = async_capture_events(hass, "itrend_player_event")
    st = dict(EPISODE, picture=PIC, secret_url="http://provider.example/xtream", extra={"a": 1})
    st["media"] = dict(EPISODE["media"], stream_url="http://provider.example/live/u/p/1.ts")
    await send(hass, app, client, 1, st)
    attrs = str(hass.states.get(ids["mp"]).attributes)
    assert "provider.example" not in attrs
    assert "provider.example" not in " ".join(r.getMessage() for r in caplog.records
                                                if r.name.startswith("custom_components"))
    assert "stream_url" not in device.state.media
    # unbekannter Typ: 200 ignored, nichts gespeichert, kein Ereignis
    resp = await app.post(client, app.body(2, {"v": 1, "type": "future", "title": "Geheim"}))
    data = await resp.json()
    assert resp.status == 200 and data["ignored"] is True
    resp = await app.post(client, app.body(3, {"v": 1, "type": "event", "name": "new_thing", "q": 1}))
    assert (await resp.json())["ignored"] is True
    await hass.async_block_till_done()
    assert events == []
    assert "Geheim" not in caplog.text


def test_brand_images_exist_with_expected_sizes():
    import struct
    brand = PKG / "brand"

    def size(path):
        head = path.read_bytes()[:24]
        assert head[:8] == b"\x89PNG\r\n\x1a\n", path.name
        return struct.unpack(">II", head[16:24])

    for prefix in ("", "dark_"):
        assert size(brand / f"{prefix}icon.png") == (256, 256)
        assert size(brand / f"{prefix}icon@2x.png") == (512, 512)
        w1, h1 = size(brand / f"{prefix}logo.png")
        w2, h2 = size(brand / f"{prefix}logo@2x.png")
        assert 128 <= h1 <= 256 and w1 > h1
        assert (w2, h2) == (w1 * 2, h1 * 2) and 256 <= h2 <= 512
    for path in brand.glob("*.png"):
        assert path.stat().st_size < 60_000, path.name


async def _now_playing(hass, env):
    entry = env[0]
    return er.async_get(hass).async_get_entity_id(
        "sensor", DOMAIN, f"{entry.entry_id}_now_playing")


async def test_now_playing_sensor(hass, env):
    _e, _d, app, client, ids, _s = env
    eid = await _now_playing(hass, env)
    assert eid and hass.states.get(eid).state == STATE_UNAVAILABLE
    # Titelfreigabe aus: Zustand ohne media
    await send(hass, app, client, 1, {"v": 1, "type": "state", "rev": 1, "status": "playing"})
    assert hass.states.get(eid).state == "\u2013"
    assert hass.states.get(eid).attributes["icon"] == "mdi:play-circle-outline"
    await send(hass, app, client, 2, {"v": 1, "type": "state", "rev": 2, "status": "playing",
                                      "media": {"kind": "movie", "title": "Film X"}})
    assert hass.states.get(eid).state == "Film X"
    await send(hass, app, client, 3, EPISODE)
    assert hass.states.get(eid).state == "Beispielserie, Season 1, Episode 2"
    hass.config.language = "de"
    await send(hass, app, client, 4, dict(EPISODE, rev=9))
    assert hass.states.get(eid).state == "Beispielserie, Staffel 1, Folge 2"
    hass.config.language = "tr"
    await send(hass, app, client, 5, dict(EPISODE, rev=10))
    assert hass.states.get(eid).state == "Beispielserie, Sezon 1, B\u00f6l\u00fcm 2"
    await send(hass, app, client, 6, {"v": 1, "type": "state", "rev": 11, "status": "playing",
                                      "media": {"kind": "live", "channel": "Sender 1", "title": "Nachrichten"}})
    assert hass.states.get(eid).state == "Sender 1"
    await send(hass, app, client, 7, {"v": 1, "type": "state", "rev": 12, "status": "playing",
                                      "media": {"kind": "live", "title": "Nur Titel"}})
    assert hass.states.get(eid).state == "Nur Titel"
    await send(hass, app, client, 8, {"v": 1, "type": "state", "rev": 13, "status": "idle"})
    assert hass.states.get(eid).state == "\u2013"
    await send(hass, app, client, 9, dict(EPISODE, rev=14))
    await send(hass, app, client, 10, {"v": 1, "type": "state", "rev": 15, "status": "closed"})
    assert hass.states.get(eid).state == "\u2013"
    assert hass.states.get(eid).attributes.get("entity_category") is None


async def test_now_playing_episode_without_numbers(hass, env):
    _e, _d, app, client, _i, _s = env
    eid = await _now_playing(hass, env)
    await send(hass, app, client, 1, {"v": 1, "type": "state", "rev": 1, "status": "playing",
                                      "media": {"kind": "episode", "series": "Serie", "episode": 4}})
    assert hass.states.get(eid).state == "Serie, Episode 4"
    await send(hass, app, client, 2, {"v": 1, "type": "state", "rev": 2, "status": "playing",
                                      "media": {"kind": "episode", "title": "Nur Titel"}})
    assert hass.states.get(eid).state == "Nur Titel"
