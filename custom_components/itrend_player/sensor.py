"""Sensoren: App-Version, Abo-Ablauf, Verbindungen."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from . import ITrendConfigEntry
from .entity import ITrendEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ITrendConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    device = entry.runtime_data
    async_add_entities(
        [
            ITrendAppVersionSensor(device),
            ITrendSubscriptionSensor(device),
            ITrendConnectionsSensor(device),
            ITrendMaxConnectionsSensor(device),
        ]
    )


class ITrendAppVersionSensor(ITrendEntity, SensorEntity):
    _attr_translation_key = "app_version"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "app_version")

    @property
    def native_value(self) -> str | None:
        return self._device.state.app_version


class ITrendSubscriptionSensor(ITrendEntity, SensorEntity):
    _attr_translation_key = "subscription_expires"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "subscription_expires")

    @property
    def native_value(self) -> datetime | None:
        expires = self._device.state.sub_expires
        # Das Protokoll liefert nur ein Datum: Beginn dieses Tages (HA-Zeitzone).
        return None if expires is None else dt_util.start_of_local_day(expires)


class ITrendConnectionsSensor(ITrendEntity, SensorEntity):
    _attr_translation_key = "connections"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "connections")

    @property
    def native_value(self) -> int | None:
        return self._device.state.connections_active

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        maximum = self._device.state.connections_max
        return None if maximum is None else {"connections_max": maximum}


class ITrendMaxConnectionsSensor(ITrendEntity, SensorEntity):
    """Erlaubte Verbindungen laut Anbieter."""

    _attr_translation_key = "connections_max"

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "connections_max")

    @property
    def native_value(self) -> int | None:
        return self._device.state.connections_max
