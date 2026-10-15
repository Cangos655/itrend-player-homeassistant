"""Binaer-Sensor "App aktiv"."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import ITrendConfigEntry
from .entity import ITrendEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ITrendConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([ITrendAppActiveSensor(entry.runtime_data)])


class ITrendAppActiveSensor(ITrendEntity, BinarySensorEntity):
    """An, solange die App sendet; aus, wenn sie beendet ist oder schweigt."""

    _attr_translation_key = "app_active"

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "app_active")

    @property
    def available(self) -> bool:
        # Immer verfuegbar: "aus" ist hier die Aussage (Fernseher aus / App beendet).
        return True

    @property
    def is_on(self) -> bool:
        return self._device.paired and self._device.state.app_active
