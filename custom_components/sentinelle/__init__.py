"""Sentinelle integration: monitors rejected logins (Home Assistant + SSH)."""
from __future__ import annotations

import hashlib
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


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:8]


async def _upsert_lovelace_resource(hass: HomeAssistant, url: str) -> None:
    """Declare the card as a dashboard resource too (storage mode), updated in place on each version.

    Dashboards load their resources themselves, which the mobile app does more reliably than the
    extra JS URLs (a phone kept showing "configuration error" with only the latter).
    """
    lovelace = hass.data.get("lovelace")
    resources = getattr(lovelace, "resources", None)
    if resources is None and isinstance(lovelace, dict):
        resources = lovelace.get("resources")
    if resources is None or not hasattr(resources, "async_create_item"):
        return  # YAML mode: resources are managed by the user
    if not getattr(resources, "loaded", True):
        await resources.async_load()
        resources.loaded = True
    base = url.split("?")[0]
    for item in resources.async_items():
        if item.get("url", "").split("?")[0] == base:
            if item["url"] != url:
                await resources.async_update_item(item["id"], {"res_type": "module", "url": url})
            return
    await resources.async_create_item({"res_type": "module", "url": url})


async def _register_card(hass: HomeAssistant) -> None:
    """Serve the Lovelace card and load it automatically (available in the visual editor)."""
    if hass.data.get(f"{DOMAIN}_card"):
        return
    card = Path(__file__).parent / "sentinelle-card.js"
    try:
        from homeassistant.components.http import StaticPathConfig

        # Cached like the HACS cards: the URL carries a hash of the file, so any change gives a new
        # URL and no browser (nor the mobile app, which keeps stale copies for days) runs an old card.
        await hass.http.async_register_static_paths(
            [StaticPathConfig(CARD_URL, str(card), True)]
        )
        url = f"{CARD_URL}?v={VERSION}-{await hass.async_add_executor_job(_file_hash, card)}"
        from homeassistant.components.frontend import add_extra_js_url

        add_extra_js_url(hass, url)
        try:
            await _upsert_lovelace_resource(hass, url)
        except Exception as err:  # noqa: BLE001 - the extra JS URL above still loads the card
            _LOGGER.debug("Card not declared as a dashboard resource: %s", err)
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
