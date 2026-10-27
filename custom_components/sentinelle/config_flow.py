"""Config flow Sentinelle : une seule instance, réglages identiques à la création et en options."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_GEOIP,
    CONF_NOTIFY,
    CONF_NOTIFY_HA_LOGIN,
    CONF_THRESHOLD,
    CONF_WINDOW,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW,
    DOMAIN,
)

# Services notify qui ne visent pas un appareil précis.
_GENERIC_NOTIFY = {"notify", "send_message", "persistent_notification"}


def _schema(hass: HomeAssistant, current: dict[str, Any]) -> vol.Schema:
    targets = sorted(
        s for s in hass.services.async_services_for_domain("notify") if s not in _GENERIC_NOTIFY
    )
    return vol.Schema(
        {
            vol.Optional(
                CONF_NOTIFY,
                default=[t for t in current.get(CONF_NOTIFY, []) if t in targets],
            ): SelectSelector(
                SelectSelectorConfig(options=targets, multiple=True, mode=SelectSelectorMode.LIST)
            ),
            vol.Optional(
                CONF_THRESHOLD, default=current.get(CONF_THRESHOLD, DEFAULT_THRESHOLD)
            ): NumberSelector(NumberSelectorConfig(min=2, max=100, step=1, mode=NumberSelectorMode.BOX)),
            vol.Optional(
                CONF_WINDOW, default=current.get(CONF_WINDOW, DEFAULT_WINDOW)
            ): NumberSelector(
                NumberSelectorConfig(
                    min=1, max=120, step=1, unit_of_measurement="min", mode=NumberSelectorMode.BOX
                )
            ),
            vol.Optional(
                CONF_NOTIFY_HA_LOGIN, default=current.get(CONF_NOTIFY_HA_LOGIN, True)
            ): BooleanSelector(),
            vol.Optional(CONF_GEOIP, default=current.get(CONF_GEOIP, True)): BooleanSelector(),
        }
    )


class SentinelleConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is not None:
            return self.async_create_entry(title="Sentinelle", data={}, options=user_input)
        return self.async_show_form(step_id="user", data_schema=_schema(self.hass, {}))

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return SentinelleOptionsFlow()


class SentinelleOptionsFlow(OptionsFlow):
    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(
            step_id="init", data_schema=_schema(self.hass, dict(self.config_entry.options))
        )
