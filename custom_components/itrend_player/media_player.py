"""Media-Player: zeigt, was die App spielt. Stufe 1: keine Steuerfunktionen."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.media_player import (
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
    MediaType,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import ITrendConfigEntry
from .entity import ITrendEntity

_STATE_MAP = {
    "idle": MediaPlayerState.IDLE,
    "buffering": MediaPlayerState.BUFFERING,
    "playing": MediaPlayerState.PLAYING,
    "paused": MediaPlayerState.PAUSED,
    "closed": MediaPlayerState.OFF,
}

_TYPE_MAP = {
    "live": MediaType.CHANNEL,
    "movie": MediaType.MOVIE,
    "episode": MediaType.EPISODE,
    "trailer": MediaType.VIDEO,
    "other": MediaType.VIDEO,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ITrendConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([ITrendMediaPlayer(entry.runtime_data)])


class ITrendMediaPlayer(ITrendEntity, MediaPlayerEntity):
    """Media-Player eines Fernsehers."""

    _attr_name = None
    _attr_supported_features = MediaPlayerEntityFeature(0)
    # Titel & Co. sollen nicht im Recorder-Verlauf landen (PROTOCOL.md 8.3, 8.4).
    _unrecorded_attributes = frozenset(
        {
            "media_title",
            "media_channel",
            "media_series_title",
            "media_season",
            "media_episode",
            "media_content_type",
            "media_duration",
            "media_position",
            "media_position_updated_at",
            "media_kind",
        }
    )

    def __init__(self, device) -> None:  # type: ignore[no-untyped-def]
        super().__init__(device, "media_player")

    @property
    def _media(self) -> dict[str, Any]:
        return self._device.state.media or {}

    @property
    def state(self) -> MediaPlayerState | None:
        status = self._device.state.status
        if status is None:
            return MediaPlayerState.IDLE
        return _STATE_MAP.get(status, MediaPlayerState.IDLE)

    @property
    def media_content_type(self) -> str | None:
        kind = self._media.get("kind")
        return _TYPE_MAP.get(kind) if kind else None

    @property
    def media_title(self) -> str | None:
        return self._media.get("title")

    @property
    def media_channel(self) -> str | None:
        return self._media.get("channel")

    @property
    def media_series_title(self) -> str | None:
        return self._media.get("series")

    @property
    def media_season(self) -> str | None:
        season = self._media.get("season")
        return None if season is None else str(season)

    @property
    def media_episode(self) -> str | None:
        episode = self._media.get("episode")
        return None if episode is None else str(episode)

    @property
    def media_duration(self) -> int | None:
        ms = self._media.get("duration_ms")
        return None if ms is None else ms // 1000

    @property
    def media_position(self) -> int | None:
        ms = self._media.get("position_ms")
        return None if ms is None else ms // 1000

    @property
    def media_position_updated_at(self) -> datetime | None:
        if self._media.get("position_ms") is None:
            return None
        return self._device.state.media_updated_at

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        kind = self._media.get("kind")
        return {"media_kind": kind} if kind else None
