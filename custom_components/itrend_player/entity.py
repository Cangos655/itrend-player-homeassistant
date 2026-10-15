"""Basisklasse der Entitaeten."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import DOMAIN
from .device import ITrendDevice


class ITrendEntity(Entity):
    """Entitaet, die auf Aenderungen des ITrendDevice hoert."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, device: ITrendDevice, key: str) -> None:
        self._device = device
        self._attr_unique_id = f"{device.entry.entry_id}_{key}"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, device.entry.entry_id)})

    @property
    def available(self) -> bool:
        return self._device.paired and self._device.state.available

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._device.async_add_listener(self.async_write_ha_state))
