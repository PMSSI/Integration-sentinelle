"""Sentinelle sensors: attempt counters and last attempt."""
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


# Names and units ("attempts" / "tentatives") come from the translations (translation_key).
COUNTERS = (
    SentinelleSensorDescription(
        key="attempts_ha_24h",
        translation_key="attempts_ha_24h",
        icon="mdi:home-lock",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_ha_24h"),
    ),
    SentinelleSensorDescription(
        key="attempts_ssh_24h",
        translation_key="attempts_ssh_24h",
        icon="mdi:console-network",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_ssh_24h"),
    ),
    SentinelleSensorDescription(
        key="ips_24h",
        translation_key="ips_24h",
        icon="mdi:ip-network",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("ips_24h"),
    ),
    SentinelleSensorDescription(
        key="attempts_7d",
        translation_key="attempts_7d",
        icon="mdi:calendar-week",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.get("count_7d"),
    ),
)

SUMMARY = SentinelleSensorDescription(
    key="attempts_24h",
    translation_key="attempts_24h",
    icon="mdi:shield-search",
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
    """24 h total; also carries everything the card displays (unrecorded attributes)."""

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
    _attr_translation_key = "last_attempt"
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
            "user": last.get("user"),
            "country": last.get("country"),
            "isp": last.get("isp"),
        }
