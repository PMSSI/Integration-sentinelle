"""Sentinelle core: collects rejected logins (HA + SSH add-ons), detects attacks, notifies.

Monitoring only: nothing is ever blocked.
"""
from __future__ import annotations

import asyncio
import bisect
from collections import Counter
from collections.abc import Coroutine
from datetime import datetime, timedelta
import ipaddress
import logging
import os
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    BAN_LOGGER,
    CONF_GEOIP,
    CONF_NOTIFY,
    CONF_NOTIFY_HA_LOGIN,
    CONF_THRESHOLD,
    CONF_WINDOW,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW,
    DOMAIN,
    GEOIP_BATCH,
    GEOIP_PAUSE,
    GEOIP_URL,
    HISTORY_DAYS,
    LOGIN_NOTIFY_COOLDOWN,
    MAX_ATTEMPTS,
    RECENT_ATTEMPTS,
    RENOTIFY_MINUTES,
    SAVE_DELAY,
    SIGNAL_UPDATE,
    SOURCE_LABELS,
    SRC_HA,
    SRC_SSH,
    SSH_LOG_LINES,
    SSH_LOG_LINES_MAX,
    SSH_POLL_SECONDS,
    STORAGE_VERSION,
    TOP_IPS,
    UPDATE_DEBOUNCE,
)
from .parsing import iso_utc, new_ssh_attempts, parse_ha_failure

_LOGGER = logging.getLogger(__name__)

# Notification texts: French when Home Assistant runs in French, English otherwise.
_TEXT = {
    "fr": {
        "lan": "réseau local",
        "lan_country": "Réseau local",
        "describe": "{n} tentatives ({sources}) depuis {ips} IP. Principale : {top}{where} ({top_n}).",
        "start_title": "🚨 Sentinelle : attaque en cours",
        "start": "En {window} min : {summary}",
        "ongoing_title": "🚨 Sentinelle : attaque toujours en cours",
        "ongoing": "Depuis {start} : {summary}",
        "end_title": "✅ Sentinelle : attaque terminée",
        "end": "De {start} à {end} : {summary}",
        "login_title": "🔐 Connexion Home Assistant refusée",
        "login": "Mot de passe refusé depuis {ip}{where}.",
    },
    "en": {
        "lan": "local network",
        "lan_country": "Local network",
        "describe": "{n} attempts ({sources}) from {ips} IPs. Top: {top}{where} ({top_n}).",
        "start_title": "🚨 Sentinelle: attack in progress",
        "start": "In {window} min: {summary}",
        "ongoing_title": "🚨 Sentinelle: attack still in progress",
        "ongoing": "Since {start}: {summary}",
        "end_title": "✅ Sentinelle: attack over",
        "end": "From {start} to {end}: {summary}",
        "login_title": "🔐 Home Assistant login rejected",
        "login": "Password rejected from {ip}{where}.",
    },
}


def _ts(attempt: dict) -> str:
    return attempt["t"]


def _flag(cc: str | None) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


class _BanLogHandler(logging.Handler):
    """Catches the "Login attempt …" warning written by HA's http.ban module."""

    def __init__(self, hass: HomeAssistant, on_message) -> None:
        super().__init__(logging.WARNING)
        self._hass = hass
        self._on_message = on_message

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a log handler must never raise
            return
        if message.startswith("Login attempt"):
            self._hass.loop.call_soon_threadsafe(self._on_message, message)


class SentinelleMonitor:
    """Attempt history (7 days, persisted), attack detection, notifications."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self.attempts: list[dict] = []  # sorted by "t" (ISO UTC)
        self.geo: dict[str, dict] = {}
        self.ssh_cursors: dict[str, dict] = {}
        self.ssh_slugs: list[str] = []
        self.ssh_error: str | None = None
        self.ha_monitored = False
        self.data: dict[str, Any] = {}
        self._attack_since: str | None = None  # first attempt of the ongoing attack
        self._attack_announced = False
        self._last_attack_notify: datetime | None = None
        self._last_login_notify: dict[str, datetime] = {}
        self._geo_pending: set[str] = set()
        self._geo_task: asyncio.Task | None = None
        self._handler: _BanLogHandler | None = None
        self._unsubs: list = []
        self._update_unsub = None

    @property
    def threshold(self) -> int:
        return int(self.entry.options.get(CONF_THRESHOLD, DEFAULT_THRESHOLD))

    @property
    def window(self) -> int:
        return int(self.entry.options.get(CONF_WINDOW, DEFAULT_WINDOW))

    @property
    def _lang(self) -> str:
        return "fr" if (self.hass.config.language or "").lower().startswith("fr") else "en"

    def _t(self, key: str, **kwargs: Any) -> str:
        return _TEXT[self._lang][key].format(**kwargs)

    # ------------------------------------------------------------------ lifecycle

    async def async_start(self) -> None:
        stored = await self._store.async_load() or {}
        cutoff = iso_utc(dt_util.utcnow() - timedelta(days=HISTORY_DAYS))
        self.attempts = sorted(
            (a for a in stored.get("attempts", []) if a.get("t", "") >= cutoff), key=_ts
        )[-MAX_ATTEMPTS:]
        self.geo = stored.get("geo", {})
        self.ssh_cursors = stored.get("ssh_cursors", {})

        self._handler = _BanLogHandler(self.hass, self._on_ha_log)
        ban_logger = logging.getLogger(BAN_LOGGER)
        ban_logger.addHandler(self._handler)
        self.ha_monitored = ban_logger.isEnabledFor(logging.WARNING)
        if not self.ha_monitored:
            _LOGGER.warning(
                "The log level of %s is above WARNING: "
                "rejected HA logins will not be detected",
                BAN_LOGGER,
            )

        self._queue_geo({a["ip"] for a in self.attempts})
        self._evaluate(notify=False)
        self.data = self._compute()
        self._unsubs.append(
            async_track_time_interval(
                self.hass, self._async_tick, timedelta(seconds=SSH_POLL_SECONDS)
            )
        )
        self._spawn(self._async_tick(), "first_poll")

    async def async_stop(self) -> None:
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        if self._update_unsub is not None:
            self._update_unsub()
            self._update_unsub = None
        if self._handler is not None:
            logging.getLogger(BAN_LOGGER).removeHandler(self._handler)
            self._handler = None
        await self._store.async_save(self._to_store())

    @callback
    def _spawn(self, coro: Coroutine, name: str) -> None:
        # Task bound to the entry: cancelled automatically on unload.
        self.entry.async_create_background_task(self.hass, coro, f"{DOMAIN}_{name}")

    @callback
    def _to_store(self) -> dict[str, Any]:
        # Copies: the Store serialises off the event loop while new attempts keep arriving.
        ips = {a["ip"] for a in self.attempts}
        return {
            "attempts": list(self.attempts),
            "geo": {ip: g for ip, g in self.geo.items() if ip in ips},
            "ssh_cursors": dict(self.ssh_cursors),
        }

    # ------------------------------------------------------------------ collection

    @callback
    def _on_ha_log(self, message: str) -> None:
        attempt = parse_ha_failure(message)
        if attempt is None:
            return
        now = dt_util.utcnow()
        attempt["t"] = iso_utc(now)
        self._add([attempt], notify=True)
        if attempt["kind"] != "login" or not self.entry.options.get(CONF_NOTIFY_HA_LOGIN, True):
            return
        last = self._last_login_notify.get(attempt["ip"])
        if last is None or now - last >= timedelta(minutes=LOGIN_NOTIFY_COOLDOWN):
            self._last_login_notify[attempt["ip"]] = now
            self._spawn(self._async_notify_login(attempt), "notify")

    async def _async_tick(self, _now: datetime | None = None) -> None:
        await self._async_poll_ssh()
        self._prune()
        self._queue_geo(set())  # retry geolocations that failed earlier
        self._evaluate(notify=True)
        self._schedule_update()

    async def _async_poll_ssh(self) -> None:
        token = os.environ.get("SUPERVISOR_TOKEN")
        if not token:
            self.ssh_error = "No Supervisor: SSH monitoring unavailable"
            return
        base = f"http://{os.environ.get('SUPERVISOR', 'supervisor')}"
        headers = {"Authorization": f"Bearer {token}"}
        session = async_get_clientsession(self.hass)
        try:
            async with asyncio.timeout(15):
                resp = await session.get(f"{base}/addons", headers=headers)
                resp.raise_for_status()
                addons = (await resp.json())["data"]["addons"]
            self.ssh_slugs = sorted(a["slug"] for a in addons if "ssh" in a["slug"])
            for slug in self.ssh_slugs:
                await self._async_poll_addon(session, base, headers, slug)
        except (aiohttp.ClientError, TimeoutError, KeyError, TypeError, ValueError) as err:
            self.ssh_error = f"{type(err).__name__}: {err}"[:200]
            _LOGGER.debug("Cannot read SSH logs: %s", self.ssh_error)
        else:
            self.ssh_error = None

    async def _async_poll_addon(
        self, session: aiohttp.ClientSession, base: str, headers: dict, slug: str
    ) -> None:
        cursor = self.ssh_cursors.get(slug)
        tz = dt_util.get_default_time_zone()
        lines = await self._async_fetch_logs(
            session, base, headers, slug, SSH_LOG_LINES if cursor else SSH_LOG_LINES_MAX
        )
        attempts, new_cursor, gap = new_ssh_attempts(lines, cursor, tz)
        if gap:
            lines = await self._async_fetch_logs(session, base, headers, slug, SSH_LOG_LINES_MAX)
            attempts, new_cursor, _ = new_ssh_attempts(lines, cursor, tz)
        if new_cursor != cursor:
            self.ssh_cursors[slug] = new_cursor
            self._store.async_delay_save(self._to_store, SAVE_DELAY)
        # First poll = backfilling history: no alert for past attempts.
        self._add(attempts, notify=cursor is not None)

    @staticmethod
    async def _async_fetch_logs(
        session: aiohttp.ClientSession, base: str, headers: dict, slug: str, lines: int
    ) -> list[str]:
        async with asyncio.timeout(30):
            resp = await session.get(
                f"{base}/addons/{slug}/logs",
                headers={**headers, "Accept": "text/x-log", "Range": f"entries=:-{lines}:"},
            )
            resp.raise_for_status()
            return (await resp.text()).splitlines()

    @callback
    def _add(self, new: list[dict], notify: bool) -> None:
        if not new:
            return
        for attempt in new:
            bisect.insort(self.attempts, attempt, key=_ts)
        if len(self.attempts) > MAX_ATTEMPTS:
            del self.attempts[: len(self.attempts) - MAX_ATTEMPTS]
        self._queue_geo({a["ip"] for a in new})
        self._store.async_delay_save(self._to_store, SAVE_DELAY)
        self._evaluate(notify)
        self._schedule_update()

    @callback
    def _prune(self) -> None:
        now = dt_util.utcnow()
        self._last_login_notify = {
            ip: ts
            for ip, ts in self._last_login_notify.items()
            if now - ts < timedelta(minutes=LOGIN_NOTIFY_COOLDOWN)
        }
        cutoff = iso_utc(now - timedelta(days=HISTORY_DAYS))
        if idx := bisect.bisect_left(self.attempts, cutoff, key=_ts):
            del self.attempts[:idx]
            self._store.async_delay_save(self._to_store, SAVE_DELAY)

    def _since(self, delta: timedelta) -> list[dict]:
        cutoff = iso_utc(dt_util.utcnow() - delta)
        return self.attempts[bisect.bisect_left(self.attempts, cutoff, key=_ts) :]

    # ------------------------------------------------------------------ geolocation

    @callback
    def _queue_geo(self, ips: set[str]) -> None:
        for ip in ips:
            if ip in self.geo or ip in self._geo_pending:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not addr.is_global:
                self.geo[ip] = {"cc": "LAN", "country": self._t("lan_country")}
            elif self.entry.options.get(CONF_GEOIP, True):
                self._geo_pending.add(ip)
        if self._geo_pending and (self._geo_task is None or self._geo_task.done()):
            self._geo_task = self.entry.async_create_background_task(
                self.hass, self._async_geo_worker(), f"{DOMAIN}_geoip"
            )

    async def _async_geo_worker(self) -> None:
        session = async_get_clientsession(self.hass)
        while self._geo_pending:
            batch = sorted(self._geo_pending)[:GEOIP_BATCH]
            try:
                async with asyncio.timeout(15):
                    resp = await session.post(GEOIP_URL.format(lang=self._lang), json=batch)
                    resp.raise_for_status()
                    results = await resp.json(content_type=None)
            except (aiohttp.ClientError, TimeoutError, ValueError) as err:
                _LOGGER.debug("Geolocation unavailable: %s", err)
                return  # retried on the next poll
            for res in results if isinstance(results, list) else []:
                if not isinstance(res, dict) or res.get("query") not in self._geo_pending:
                    continue
                ok = res.get("status") == "success"
                self.geo[res["query"]] = {
                    "cc": res.get("countryCode") if ok else None,
                    "country": res.get("country") if ok else None,
                    "city": res.get("city") if ok else None,
                    "isp": res.get("isp") if ok else None,
                }
            self._geo_pending.difference_update(batch)
            self._store.async_delay_save(self._to_store, SAVE_DELAY)
            self._schedule_update()
            if self._geo_pending:
                await asyncio.sleep(GEOIP_PAUSE)

    async def _async_wait_geo(self, ip: str) -> None:
        for _ in range(20):
            if ip in self.geo or ip not in self._geo_pending:
                return
            await asyncio.sleep(0.5)

    def _geo_short(self, ip: str) -> dict:
        geo = self.geo.get(ip) or {}
        return {"cc": geo.get("cc"), "country": geo.get("country"), "isp": geo.get("isp")}

    def _where(self, ip: str) -> str:
        geo = self.geo.get(ip) or {}
        if geo.get("cc") == "LAN":
            return self._t("lan")
        place = ", ".join(p for p in (geo.get("country"), geo.get("city")) if p)
        return f"{_flag(geo.get('cc'))} {place}".strip()

    # ------------------------------------------------------------------ detection / alerts

    @callback
    def _evaluate(self, notify: bool) -> None:
        recent = self._since(timedelta(minutes=self.window))
        now = dt_util.utcnow()
        if len(recent) >= self.threshold:
            if self._attack_since is None:
                self._attack_since = recent[0]["t"]
            if notify and not self._attack_announced:
                self._attack_announced = True
                self._last_attack_notify = now
                self._spawn(self._async_notify_attack("start", self._attack_since), "notify")
            elif (
                self._attack_announced
                and self._last_attack_notify is not None
                and now - self._last_attack_notify >= timedelta(minutes=RENOTIFY_MINUTES)
            ):
                self._last_attack_notify = now
                self._spawn(self._async_notify_attack("ongoing", self._attack_since), "notify")
        elif self._attack_since is not None:
            if self._attack_announced:
                self._spawn(self._async_notify_attack("end", self._attack_since), "notify")
            self._attack_since = None
            self._attack_announced = False

    def _describe(self, attempts: list[dict]) -> str:
        by_src = Counter(a["src"] for a in attempts)
        by_ip = Counter(a["ip"] for a in attempts)
        sources = ", ".join(f"{SOURCE_LABELS.get(s, s)} {n}" for s, n in by_src.most_common())
        top_ip, top_n = by_ip.most_common(1)[0]
        where = self._where(top_ip)
        return self._t(
            "describe",
            n=len(attempts),
            sources=sources,
            ips=len(by_ip),
            top=top_ip,
            where=f" {where}" if where else "",
            top_n=top_n,
        )

    async def _async_notify_attack(self, kind: str, since: str) -> None:
        attempts = [a for a in self.attempts if a["t"] >= since]
        if not attempts:
            return
        await self._async_wait_geo(Counter(a["ip"] for a in attempts).most_common(1)[0][0])
        start = dt_util.as_local(dt_util.parse_datetime(since)).strftime("%H:%M")
        if kind == "start":
            recent = self._since(timedelta(minutes=self.window)) or attempts
            message = self._t("start", window=self.window, summary=self._describe(recent))
        elif kind == "ongoing":
            message = self._t("ongoing", start=start, summary=self._describe(attempts))
        else:
            end = dt_util.as_local(dt_util.parse_datetime(attempts[-1]["t"])).strftime("%H:%M")
            message = self._t("end", start=start, end=end, summary=self._describe(attempts))
        await self._async_notify(self._t(f"{kind}_title"), message, f"{DOMAIN}_attack")

    async def _async_notify_login(self, attempt: dict) -> None:
        await self._async_wait_geo(attempt["ip"])
        where = self._where(attempt["ip"])
        await self._async_notify(
            self._t("login_title"),
            self._t("login", ip=attempt["ip"], where=f" ({where})" if where else ""),
            f"{DOMAIN}_login_{attempt['ip']}",
        )

    async def _async_notify(self, title: str, message: str, tag: str) -> None:
        for target in self.entry.options.get(CONF_NOTIFY, []):
            try:
                await self.hass.services.async_call(
                    "notify",
                    target,
                    {
                        "title": title,
                        "message": message,
                        "data": {
                            "tag": tag,
                            "channel": "Sentinelle",
                            "importance": "high",
                            "priority": "high",
                            "ttl": 0,
                        },
                    },
                    blocking=True,
                )
            except HomeAssistantError as err:
                _LOGGER.warning("Cannot notify via notify.%s: %s", target, err)

    # ------------------------------------------------------------------ publishing

    @callback
    def _schedule_update(self) -> None:
        if self._update_unsub is None:
            self._update_unsub = async_call_later(self.hass, UPDATE_DEBOUNCE, self._async_publish)

    @callback
    def _async_publish(self, _now: datetime) -> None:
        self._update_unsub = None
        self.data = self._compute()
        async_dispatcher_send(self.hass, f"{SIGNAL_UPDATE}_{self.entry.entry_id}")

    @callback
    def _compute(self) -> dict[str, Any]:
        day = self._since(timedelta(hours=24))
        window = self._since(timedelta(minutes=self.window))
        by_src = Counter(a["src"] for a in day)
        by_ip = Counter(a["ip"] for a in day)
        last = self.attempts[-1] if self.attempts else None
        return {
            "count_24h": len(day),
            "count_ha_24h": by_src.get(SRC_HA, 0),
            "count_ssh_24h": by_src.get(SRC_SSH, 0),
            "ips_24h": len(by_ip),
            "count_7d": len(self._since(timedelta(days=HISTORY_DAYS))),
            "count_window": len(window),
            "ips_window": len({a["ip"] for a in window}),
            "attack": self._attack_since is not None,
            "attack_since": self._attack_since,
            "last": {**last, **self._geo_short(last["ip"])} if last else None,
            "top_ips": [
                {"ip": ip, "n": n, **self._geo_short(ip)} for ip, n in by_ip.most_common(TOP_IPS)
            ],
            "recent": [
                {**a, **self._geo_short(a["ip"])}
                for a in reversed(self.attempts[-RECENT_ATTEMPTS:])
            ],
            "ha_monitored": self.ha_monitored,
            "ssh_slugs": self.ssh_slugs,
            "ssh_error": self.ssh_error,
            "window": self.window,
            "threshold": self.threshold,
        }
