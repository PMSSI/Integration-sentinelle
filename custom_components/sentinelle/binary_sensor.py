"""Binary sensor Sentinelle : « Attaque en cours »."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import SentinelleEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([SentinelleAttackBinarySensor(hass.data[DOMAIN][entry.entry_id])])


class SentinelleAttackBinarySensor(SentinelleEntity, BinarySensorEntity):
    """ON (= dangereux) dès que le seuil de tentatives est atteint dans la fenêtre glissante."""

    _attr_device_class = BinarySensorDeviceClass.SAFETY
    _attr_name = "Attaque en cours"

    def __init__(self, monitor) -> None:
        super().__init__(monitor, "attack")

    @property
    def is_on(self) -> bool:
        return bool(self.monitor.data.get("attack"))

    @property
    def icon(self) -> str:
        return "mdi:shield-alert" if self.is_on else "mdi:shield-check"

    @property
    def extra_state_attributes(self) -> dict:
        data = self.monitor.data
        return {
            "sentinelle_kind": "attack",
            "depuis": data.get("attack_since"),
            "tentatives_fenetre": data.get("count_window"),
            "ip_fenetre": data.get("ips_window"),
            "fenetre_min": data.get("window"),
            "seuil": data.get("threshold"),
        }
