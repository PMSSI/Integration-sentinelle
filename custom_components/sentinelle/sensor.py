"""Capteurs Sentinelle : compteurs de tentatives et dernière tentative."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .entity import SentinelleEntity


@dataclass(frozen=True, kw_only=True)
class SentinelleSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict], Any]


COUNTERS = (
    SentinelleSensorDescription(
        key="attempts_ha_24h",
        name="Tentatives HA 24 h",
        icon="mdi:home-lock",
        native_unit_of_measurement="tentatives",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_ha_24h"),
    ),
    SentinelleSensorDescription(
        key="attempts_ssh_24h",
        name="Tentatives SSH 24 h",
        icon="mdi:console-network",
        native_unit_of_measurement="tentatives",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_ssh_24h"),
    ),
    SentinelleSensorDescription(
        key="ips_24h",
        name="IP distinctes 24 h",
        icon="mdi:ip-network",
        native_unit_of_measurement="IP",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("ips_24h"),
    ),
    SentinelleSensorDescription(
        key="attempts_7d",
        name="Tentatives 7 jours",
        icon="mdi:calendar-week",
        native_unit_of_measurement="tentatives",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_7d"),
    ),
)

SUMMARY = SentinelleSensorDescription(
    key="attempts_24h",
    name="Tentatives 24 h",
    icon="mdi:shield-search",
    native_unit_of_measurement="tentatives",
    state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("count_24h"),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    monitor = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            SentinelleSummarySensor(monitor, SUMMARY),
            *(SentinelleCounterSensor(monitor, desc) for desc in COUNTERS),
            SentinelleLastAttemptSensor(monitor),
        ]
    )


class SentinelleCounterSensor(SentinelleEntity, SensorEntity):
    entity_description: SentinelleSensorDescription

    def __init__(self, monitor, description: SentinelleSensorDescription) -> None:
        super().__init__(monitor, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.monitor.data)


class SentinelleSummarySensor(SentinelleCounterSensor):
    """Total 24 h ; porte aussi tout ce qu'affiche la carte (attributs non enregistrés)."""

    _unrecorded_attributes = frozenset(
        {"recent", "top_ips", "ssh_slugs", "ssh_error", "ha_monitored", "window", "threshold"}
    )

    @property
    def extra_state_attributes(self) -> dict:
        data = self.monitor.data
        return {
            "sentinelle_kind": "summary",
            "ha": data.get("count_ha_24h"),
            "ssh": data.get("count_ssh_24h"),
            "ips": data.get("ips_24h"),
            "week": data.get("count_7d"),
            "count_window": data.get("count_window"),
            "window": data.get("window"),
            "threshold": data.get("threshold"),
            "attack": data.get("attack"),
            "attack_since": data.get("attack_since"),
            "ha_monitored": data.get("ha_monitored"),
            "ssh_slugs": data.get("ssh_slugs"),
            "ssh_error": data.get("ssh_error"),
            "top_ips": data.get("top_ips"),
            "recent": data.get("recent"),
        }


class SentinelleLastAttemptSensor(SentinelleEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_name = "Dernière tentative"
    _attr_icon = "mdi:clock-alert-outline"

    def __init__(self, monitor) -> None:
        super().__init__(monitor, "last_attempt")

    @property
    def native_value(self) -> datetime | None:
        last = self.monitor.data.get("last")
        return dt_util.parse_datetime(last["t"]) if last else None

    @property
    def extra_state_attributes(self) -> dict:
        last = self.monitor.data.get("last") or {}
        return {
            "ip": last.get("ip"),
            "source": last.get("src"),
            "utilisateur": last.get("user"),
            "pays": last.get("country"),
            "fai": last.get("isp"),
        }
