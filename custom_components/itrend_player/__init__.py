"""iTrend Player: Zustand des Players in Home Assistant (Stufe 1)."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN, ISSUE_KEY_COPIED, ISSUE_REMOTE_HINT, ISSUE_UNPAIRED, STORAGE_VERSION
from .device import ITrendDevice, RateLimiters
from .pairing import PairingManager
from .views import async_register_views

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS = [Platform.MEDIA_PLAYER, Platform.SENSOR, Platform.BINARY_SENSOR]

type ITrendConfigEntry = ConfigEntry[ITrendDevice]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Pairing-Endpunkte einmal je HA-Instanz anlegen."""
    manager = PairingManager(hass)
    hass.data[DOMAIN] = {
        "pairing": manager,
        "limiters": RateLimiters(lambda: manager._clock()),  # noqa: SLF001
    }
    async_register_views(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ITrendConfigEntry) -> bool:
    device = ITrendDevice(hass, entry, hass.data[DOMAIN]["limiters"])
    try:
        await device.async_setup()
    except ValueError as err:  # defektes Geheimnis im Eintrag
        raise ConfigEntryError("Stored pairing data is invalid; pairing must be renewed") from err
    entry.runtime_data = device
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ITrendConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        entry.runtime_data.async_shutdown()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ITrendConfigEntry) -> None:
    """Eintrag geloescht: Geheimnis (Config-Entry) und Sequenzspeicher entfernen."""
    await Store(hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}").async_remove()
    for template in (ISSUE_UNPAIRED, ISSUE_KEY_COPIED, ISSUE_REMOTE_HINT):
        ir.async_delete_issue(hass, DOMAIN, template.format(entry_id=entry.entry_id))


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: ITrendConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """"Geraet loeschen" in der Oberflaeche entfernt die ganze Kopplung."""
    hass.async_create_task(hass.config_entries.async_remove(entry.entry_id))
    return True
