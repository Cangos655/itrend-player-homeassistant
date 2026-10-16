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
from .protocol import PLAYLIST_ERRORS


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
            ITrendNowPlayingSensor(device),
            ITrendPlaylistUpdatedSensor(device),
            ITrendPlaylistCountSensor(device, "live", "playlist_live"),
            ITrendPlaylistCountSensor(device, "movies", "playlist_movies"),
            ITrendPlaylistCountSensor(device, "series", "playlist_series"),
            ITrendPlaylistErrorSensor(device),
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


class ITrendPlaylistUpdatedSensor(ITrendEntity, SensorEntity):
    _attr_translation_key = "playlist_updated"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "playlist_updated")

    @property
    def native_value(self) -> datetime | None:
        return self._device.state.playlist_updated


class ITrendPlaylistCountSensor(ITrendEntity, SensorEntity):
    """Anzahl Sender, Filme oder Serien der geladenen Playlist."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, device, key: str, field: str) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, f"playlist_{key}")
        self._attr_translation_key = f"playlist_{key}"
        self._field = field

    @property
    def native_value(self) -> int | None:
        return getattr(self._device.state, self._field)


class ITrendPlaylistErrorSensor(ITrendEntity, SensorEntity):
    _attr_translation_key = "playlist_error"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(PLAYLIST_ERRORS)

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "playlist_error")

    @property
    def native_value(self) -> str | None:
        return self._device.state.playlist_error


_EPISODE_WORDS = {"de": ("Staffel", "Folge"), "tr": ("Sezon", "Bölüm"), "en": ("Season", "Episode")}
NOTHING_PLAYING = "–"


class ITrendNowPlayingSensor(ITrendEntity, SensorEntity):
    """Titel des laufenden Inhalts als Text (sichtbar in der Sensorenliste der Geraeteseite).

    Hinweis: HA speichert den Zustand eines Sensors im Recorder-Verlauf; ein Ausschluss je
    Entitaet ist nur ueber die Recorder-Konfiguration (exclude) moeglich, siehe README.
    """

    _attr_translation_key = "now_playing"
    _attr_icon = "mdi:play-circle-outline"

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "now_playing")

    @property
    def native_value(self) -> str:
        media = self._device.state.media
        if not media:
            return NOTHING_PLAYING
        kind = media.get("kind")
        if kind == "live":
            return media.get("channel") or media.get("title") or NOTHING_PLAYING
        if kind == "episode" and media.get("series"):
            lang = (self.hass.config.language or "en").split("-")[0].lower()
            season_word, episode_word = _EPISODE_WORDS.get(lang, _EPISODE_WORDS["en"])
            parts = [media["series"]]
            if "season" in media:
                parts.append(f"{season_word} {media['season']}")
            if "episode" in media:
                parts.append(f"{episode_word} {media['episode']}")
            return ", ".join(parts)
        return media.get("title") or NOTHING_PLAYING
