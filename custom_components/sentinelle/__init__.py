"""Sentinelle integration: monitors rejected logins (Home Assistant + SSH)."""
from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN, VERSION
from .monitor import SentinelleMonitor

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR]
CARD_URL = f"/{DOMAIN}/sentinelle-card.js"


async def _register_card(hass: HomeAssistant) -> None:
    """Serve the Lovelace card and load it automatically (available in the visual editor)."""
    if hass.data.get(f"{DOMAIN}_card"):
        return
    card = Path(__file__).parent / "sentinelle-card.js"
    try:
        from homeassistant.components.http import StaticPathConfig

        await hass.http.async_register_static_paths(
            [StaticPathConfig(CARD_URL, str(card), False)]
        )
        from homeassistant.components.frontend import add_extra_js_url

        # ?v= forces browsers (and the mobile app) to reload the card after an update.
        add_extra_js_url(hass, f"{CARD_URL}?v={VERSION}")
        hass.data[f"{DOMAIN}_card"] = True
    except Exception as err:  # noqa: BLE001 - non-blocking: the integration works without the card
        _LOGGER.warning("Cannot auto-load the card (%s). "
                        "Add %s as a Lovelace resource manually if needed.", err, CARD_URL)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    await _register_card(hass)
    monitor = SentinelleMonitor(hass, entry)
    await monitor.async_start()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = monitor
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def _async_reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await hass.data[DOMAIN].pop(entry.entry_id).async_stop()
    return unload_ok
