"""Entité de base Sentinelle (un seul appareil « Sentinelle »)."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity

from .const import DOMAIN, SIGNAL_UPDATE, VERSION
from .monitor import SentinelleMonitor


class SentinelleEntity(Entity):
    """Rafraîchie par le moniteur (dispatcher), jamais interrogée."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, monitor: SentinelleMonitor, key: str) -> None:
        self.monitor = monitor
        self._attr_unique_id = f"{monitor.entry.entry_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, monitor.entry.entry_id)},
            name="Sentinelle",
            manufacturer="Sentinelle",
            model="Détection d'intrusion",
            sw_version=VERSION,
            entry_type=DeviceEntryType.SERVICE,
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{SIGNAL_UPDATE}_{self.monitor.entry.entry_id}",
                self.async_write_ha_state,
            )
        )
