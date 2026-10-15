"""Einrichtungsdialog und Kopplung erneuern."""

from __future__ import annotations

from datetime import timedelta

import pytest

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

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
    ISSUE_UNPAIRED,
)
from custom_components.itrend_player.pairing import PairingBlocked

from .helpers import AppSim, FakeClock, entry_from_vectors


@pytest.fixture
async def env(hass, hass_client_no_auth):
    assert await async_setup_component(hass, DOMAIN, {})
    # media_player registriert eigene Views: vor dem Einfrieren des Routers laden.
    assert await async_setup_component(hass, "media_player", {})
    manager = hass.data[DOMAIN]["pairing"]
    manager._clock = FakeClock()
    client = await hass_client_no_auth()
    return manager, client


async def _finish(hass, result):
    """Nach Ende der Wartephase bis zum Ergebnis weiterschalten."""
    for _ in range(3):
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
        if result["type"] != FlowResultType.SHOW_PROGRESS_DONE:
            return result
    raise AssertionError(result)


async def _start(hass):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] == FlowResultType.SHOW_PROGRESS
    assert result["step_id"] == "pair"
    assert result["progress_action"] == "wait_for_app"
    return result


async def test_flow_shows_code_and_address(hass, env):
    manager, _ = env
    result = await _start(hass)
    ph = result["description_placeholders"]
    assert manager.active is not None
    assert ph["code"] == manager.active.display_code
    assert len(ph["code"].replace(" ", "")) == 6 and ph["code"][3] == " "
    assert ph["address"].startswith("http")


async def test_full_flow_creates_entry_and_device(hass, env):
    manager, client = env
    result = await _start(hass)
    code = manager.active.code
    out = await AppSim(code=code, name="Wohnzimmer TV", platform="android",
                       app_version="0.3.1").pair(client)
    assert out["status"] == 200
    await hass.async_block_till_done()
    result = await _finish(hass, result)
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["title"] == "Wohnzimmer TV"
    data = result["data"]
    assert data[CONF_NAME] == "Wohnzimmer TV" and data[CONF_PLATFORM] == "android"
    assert data[CONF_APP_VERSION] == "0.3.1" and data[CONF_UNPAIRED] is False
    assert data[CONF_DEVICE_ID] == out["json"]["device_id"]
    assert data[CONF_WEBHOOK_ID] == out["json"]["webhook_id"]
    # Schluessel stimmen mit denen der App ueberein und werden nie uebertragen
    assert proto.b64u_dec(data[CONF_K_A2H]) == out["keys"]["K_a2h"]
    assert proto.b64u_dec(data[CONF_K_H2A]) == out["keys"]["K_h2a"]
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert entry.state is config_entries.ConfigEntryState.LOADED
    from homeassistant.helpers import device_registry as dr
    dev = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, entry.entry_id)})
    assert dev.name == "iTrend Player (Wohnzimmer TV)"
    assert dev.manufacturer == "iTrend24" and dev.sw_version == "0.3.1"
    # Webhook ist registriert
    assert data[CONF_WEBHOOK_ID] in hass.data["webhook"]
    assert hass.data["webhook"][data[CONF_WEBHOOK_ID]]["local_only"] is True


async def test_flow_wrong_code_locks_and_offers_retry(hass, env):
    manager, client = env
    result = await _start(hass)
    code = manager.active.code
    bad = "000000" if code != "000000" else "111111"
    for _ in range(3):
        assert (await AppSim(code=bad).pair(client))["status"] == 403
    await hass.async_block_till_done()
    result = await _finish(hass, result)
    assert result["type"] == FlowResultType.FORM and result["step_id"] == "retry"
    assert result["errors"] == {"base": "code_locked"}
    # neuer Code
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.SHOW_PROGRESS
    assert manager.active is not None and manager.active.code != ""


async def test_flow_code_expires(hass, env):
    manager, _ = env
    result = await _start(hass)
    manager._clock.advance(301)
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=301))
    await hass.async_block_till_done()
    result = await _finish(hass, result)
    assert result["errors"] == {"base": "code_expired"}


async def test_closing_the_dialog_deletes_the_code(hass, env):
    manager, client = env
    result = await _start(hass)
    assert manager.active is not None
    hass.config_entries.flow.async_abort(result["flow_id"])
    await hass.async_block_till_done()
    assert manager.active is None
    resp = await client.post("/api/itrend_player/pair/start", data='{"v":1}',
                             headers={"Content-Type": "text/plain"})
    assert resp.status == 404


async def test_second_flow_replaces_code(hass, env):
    manager, _ = env
    first = await _start(hass)
    code1 = manager.active.code
    second = await _start(hass)
    assert manager.active is not None
    await hass.async_block_till_done()
    result = await _finish(hass, first)
    assert result["errors"] == {"base": "code_replaced"}
    assert second["flow_id"] != first["flow_id"] and code1


async def test_blocked_pairing_shows_error(hass, env):
    manager, _ = env

    async def blocked():
        raise PairingBlocked(125)

    manager.async_open_code = blocked
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "pairing_blocked"}
    assert result["description_placeholders"]["minutes"] == "3"


async def test_two_devices_can_be_added(hass, env):
    manager, client = env
    names = []
    for name in ("TV 1", "TV 2"):
        result = await _start(hass)
        out = await AppSim(code=manager.active.code, name=name).pair(client)
        assert out["status"] == 200
        await hass.async_block_till_done()
        result = await _finish(hass, result)
        assert result["type"] == FlowResultType.CREATE_ENTRY
        names.append(result["title"])
    assert names == ["TV 1", "TV 2"]
    assert len(hass.config_entries.async_entries(DOMAIN)) == 2


async def test_reauth_renews_pairing_and_keeps_entities(hass, env, vectors):
    manager, client = env
    entry = entry_from_vectors(vectors)
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    old_entities = {e.entity_id for e in
                    __import__("homeassistant.helpers.entity_registry", fromlist=["x"])
                    .async_entries_for_config_entry(
                        __import__("homeassistant.helpers.entity_registry",
                                   fromlist=["x"]).async_get(hass), entry.entry_id)}
    assert len(old_entities) == 6  # Media-Player, 4 Sensoren, Binaer-Sensor
    ir.async_create_issue(hass, DOMAIN, ISSUE_UNPAIRED.format(entry_id=entry.entry_id),
                          is_fixable=False, severity=ir.IssueSeverity.WARNING,
                          translation_key="unpaired_by_app")

    result = await entry.start_reauth_flow(hass)
    assert result["type"] == FlowResultType.FORM and result["step_id"] == "reauth_confirm"
    assert result["description_placeholders"]["name"] == "Wohnzimmer TV"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.SHOW_PROGRESS
    out = await AppSim(code=manager.active.code, name="Wohnzimmer TV (neu)").pair(client)
    assert out["status"] == 200
    await hass.async_block_till_done()
    result = await _finish(hass, result)
    assert result["type"] == FlowResultType.ABORT and result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert entry.data[CONF_DEVICE_ID] == out["json"]["device_id"]
    assert entry.data[CONF_DEVICE_ID] != vectors["webhook"]["device_id"]
    assert entry.unique_id == out["json"]["device_id"]
    assert entry.title == "Wohnzimmer TV (neu)"
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert vectors["webhook"]["webhook_id"] not in hass.data["webhook"]
    assert entry.data[CONF_WEBHOOK_ID] in hass.data["webhook"]
    assert ir.async_get(hass).async_get_issue(
        DOMAIN, ISSUE_UNPAIRED.format(entry_id=entry.entry_id)) is None
    from homeassistant.helpers import entity_registry as er
    new_entities = {e.entity_id for e in er.async_entries_for_config_entry(
        er.async_get(hass), entry.entry_id)}
    assert new_entities == old_entities


async def test_reauth_resets_sequence_state(hass, env, vectors):
    """Nach neuer Kopplung beginnt die App wieder bei seq 1; alte Reservierung ist weg."""
    from .helpers import TEXT, VectorApp
    manager, client = env
    entry = entry_from_vectors(vectors)
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    old = VectorApp(vectors)
    resp = await old.post(client, old.body(5, {"v": 1, "type": "heartbeat",
                                               "app_version": "0.3.0", "platform": "tizen",
                                               "state_rev": 0}))
    assert resp.status == 200 and entry.runtime_data.reserved == 104
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    out = await AppSim(code=manager.active.code).pair(client)
    await hass.async_block_till_done()
    result = await _finish(hass, result)
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    device = entry.runtime_data
    assert device.reserved == 0 and device.last_seq == 0
    keys = out["keys"]
    body = ref_build(keys["K_a2h"], out["json"], 1)
    resp = await client.post("/api/webhook/" + out["json"]["webhook_id"], data=body, headers=TEXT)
    assert resp.status == 200
    # der alte Webhook ist weg: HA antwortet selbst mit 200 und leerem Body
    resp = await old.post(client, old.body(6, {"v": 1, "type": "unpair"}))
    assert resp.status == 200 and await resp.read() == b""
    assert entry.state is config_entries.ConfigEntryState.LOADED


def ref_build(key, fin, seq):
    import reference as ref
    payload = b'{"v":1,"type":"state","rev":0,"status":"idle"}'
    return ref.build_body(key, "/api/webhook/" + fin["webhook_id"], fin["device_id"], seq, payload)
