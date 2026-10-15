"""Einrichtungsdialog: Code anzeigen, auf die App warten, Eintrag anlegen."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlowWithReload
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.helpers.storage import Store
from homeassistant.setup import async_setup_component

from . import protocol as proto
from .const import (
    CONF_APP_VERSION,
    CONF_DEVICE_ID,
    CONF_K_A2H,
    CONF_K_H2A,
    CONF_NAME,
    CONF_PLATFORM,
    CONF_REMOTE_PAIRED,
    CONF_UNPAIRED,
    CONF_WEBHOOK_ID,
    DOMAIN,
    ISSUE_KEY_COPIED,
    ISSUE_REMOTE_HINT,
    ISSUE_UNPAIRED,
    OPT_ALLOW_REMOTE,
    STORAGE_VERSION,
)
from .pairing import ActiveCode, FailureReason, PairingBlocked, PairingManager, PairingResult

_LOGGER = logging.getLogger(__name__)


def _ha_address(hass: HomeAssistant) -> str:
    """Adresse, die der Nutzer in der App eintippt (Basisadresse von HA)."""
    for kwargs in (
        {"require_current_request": True, "allow_external": False},
        {"allow_external": False},
        {"prefer_external": False},
    ):
        try:
            return get_url(hass, allow_cloud=False, **kwargs)  # type: ignore[arg-type]
        except NoURLAvailableError:
            continue
        except Exception:  # noqa: BLE001
            continue
    return "http://<HA-Adresse>:8123"


class ITrendPlayerConfigFlow(ConfigFlow, domain=DOMAIN):
    """Kopplung neuer Fernseher und Erneuerung bestehender Kopplungen."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> ITrendOptionsFlow:
        return ITrendOptionsFlow()

    def __init__(self) -> None:
        self._active: ActiveCode | None = None
        self._task: asyncio.Task[Any] | None = None
        self._outcome: PairingResult | FailureReason | None = None
        self._blocked_minutes = 0

    @property
    def _manager(self) -> PairingManager:
        return self.hass.data[DOMAIN]["pairing"]

    # ------------------------------------------------------------- Einstieg
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self.async_step_pair()

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                description_placeholders={"name": self._get_reauth_entry().data[CONF_NAME]},
            )
        return await self.async_step_pair()

    # --------------------------------------------------------- Kopplung
    async def async_step_pair(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._active is None:
            # Pairing-Endpunkte muessen stehen, bevor ein Code angezeigt wird.
            if not await async_setup_component(self.hass, DOMAIN, {}):
                return self.async_abort(reason="setup_failed")
            try:
                self._active = await self._manager.async_open_code()
            except PairingBlocked as err:
                self._blocked_minutes = max(1, -(-err.retry_in // 60))
                return self.async_show_form(
                    step_id="retry",
                    errors={"base": "pairing_blocked"},
                    description_placeholders={"minutes": str(self._blocked_minutes)},
                )
            self._task = self.hass.async_create_background_task(
                self._wait_for_app(self._active), name="itrend_player pairing wait"
            )
        assert self._task is not None
        if not self._task.done():
            return self.async_show_progress(
                step_id="pair",
                progress_action="wait_for_app",
                description_placeholders={
                    "code": self._active.display_code,
                    "address": _ha_address(self.hass),
                },
                progress_task=self._task,
            )
        return self.async_show_progress_done(next_step_id="finish")

    async def _wait_for_app(self, active: ActiveCode) -> None:
        self._outcome = await active.future

    async def async_step_finish(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        outcome = self._outcome
        self._active = None
        self._task = None
        if isinstance(outcome, PairingResult):
            return await self._async_store(outcome)
        reason = outcome.value if isinstance(outcome, FailureReason) else "expired"
        return self.async_show_form(step_id="retry", errors={"base": f"code_{reason}"},
                                    description_placeholders={"minutes": "10"})

    async def async_step_retry(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(step_id="retry", description_placeholders={"minutes": "10"})
        self._outcome = None
        return await self.async_step_pair()

    async def _async_store(self, result: PairingResult) -> ConfigFlowResult:
        data = {
            CONF_DEVICE_ID: result.device_id,
            CONF_WEBHOOK_ID: result.webhook_id,
            CONF_K_A2H: proto.b64u(result.k_a2h),
            CONF_K_H2A: proto.b64u(result.k_h2a),
            CONF_NAME: result.name,
            CONF_PLATFORM: result.platform,
            CONF_APP_VERSION: result.app_version,
            CONF_UNPAIRED: False,
            CONF_REMOTE_PAIRED: result.remote,
        }
        if self.source == "reauth":
            entry = self._get_reauth_entry()
            for template in (ISSUE_UNPAIRED, ISSUE_KEY_COPIED, ISSUE_REMOTE_HINT):
                ir.async_delete_issue(self.hass, DOMAIN, template.format(entry_id=entry.entry_id))
            # Neue Kopplung = neue Sequenz ab 1: alte Reservierung verwerfen.
            await Store(self.hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}").async_remove()
            return self.async_update_reload_and_abort(
                entry, unique_id=result.device_id, title=result.name, data=data
            )
        await self.async_set_unique_id(result.device_id)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=result.name, data=data)

    @callback
    def async_remove(self) -> None:
        """Dialog geschlossen: Code sofort loeschen."""
        if self._active is not None:
            self._manager.async_close_code(self._active)
        if self._task is not None and not self._task.done():
            self._task.cancel()


class ITrendOptionsFlow(OptionsFlowWithReload):
    """Option: Meldungen auch von ausserhalb des Heimnetzes annehmen (laedt den Eintrag neu)."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data={OPT_ALLOW_REMOTE: bool(user_input[OPT_ALLOW_REMOTE])})
        current = self.config_entry.options.get(OPT_ALLOW_REMOTE, False)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required(OPT_ALLOW_REMOTE, default=current): bool}),
        )
