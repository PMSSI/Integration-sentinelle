"""Intégration Sentinelle : surveille les connexions refusées (Home Assistant + SSH)."""
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
    """Sert la carte Lovelace et la charge automatiquement (dispo dans l'éditeur graphique)."""
    if hass.data.get(f"{DOMAIN}_card"):
        return
    card = Path(__file__).parent / "sentinelle-card.js"
    try:
        from homeassistant.components.http import StaticPathConfig

        await hass.http.async_register_static_paths(
            [StaticPathConfig(CARD_URL, str(card), False)]
        )
        from homeassistant.components.frontend import add_extra_js_url

        # ?v= : force le navigateur à recharger la carte après une mise à jour.
        add_extra_js_url(hass, f"{CARD_URL}?v={VERSION}")
        hass.data[f"{DOMAIN}_card"] = True
    except Exception as err:  # noqa: BLE001 - non bloquant : l'intégration marche sans la carte
        _LOGGER.warning("Chargement auto de la carte impossible (%s). "
                        "Ajoutez %s en ressource manuellement si besoin.", err, CARD_URL)


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
