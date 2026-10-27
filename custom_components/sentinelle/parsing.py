"""Analyse des logs, sans dépendance à Home Assistant (testable seule)."""
from __future__ import annotations

from datetime import datetime, timezone, tzinfo
import re

# Avertissement émis par homeassistant.components.http.ban.process_wrong_login().
# Hôte non gourmand : l'URL et le user-agent qui suivent sont fournis par le client.
HA_FAIL_RE = re.compile(
    r"^Login attempt or request with invalid authentication from (?P<host>.*?) "
    r"\((?P<ip>[0-9A-Fa-f:.]+)\)\. Requested URL: '(?P<url>.*?)'\. \(",
    re.S,
)
# Ligne journald renvoyée par le Supervisor avec « Accept: text/x-log » :
#   2026-01-01 03:41:16.776+01:00 homeassistant app_core_ssh[42]: <message>
LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r" \S+ \S+: (?P<msg>.*)$"
)
# sshd écrit une ligne par mot de passe / clé refusé(e).
SSH_FAIL_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def iso_utc(ts: datetime) -> str:
    """Horodatage normalisé (UTC, millisecondes) : se trie correctement comme une chaîne."""
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_ha_failure(message: str) -> dict | None:
    """Connexion HA refusée → tentative (sans horodatage), ou None."""
    match = HA_FAIL_RE.match(message)
    if match is None:
        return None
    # La query string peut contenir un jeton : on ne garde que le chemin.
    path = match["url"].split("?", 1)[0]
    return {
        "src": "ha",
        "ip": match["ip"],
        "user": None,
        "detail": path[:120],
        "kind": "login" if path.startswith("/auth/login_flow") else "token",
    }


def parse_log_line(line: str, default_tz: tzinfo) -> tuple[str, str] | None:
    """Ligne x-log → (horodatage ISO UTC, message), ou None si illisible."""
    match = LOG_LINE_RE.match(ANSI_RE.sub("", line).rstrip("\r"))
    if match is None:
        return None
    try:
        ts = datetime.fromisoformat(match["ts"])
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=default_tz)
    return iso_utc(ts), match["msg"]


def parse_ssh_failure(message: str) -> dict | None:
    """Message sshd « Failed … » → tentative (sans horodatage), ou None."""
    match = SSH_FAIL_RE.match(message)
    if match is None:
        return None
    return {
        "src": "ssh",
        "ip": match["ip"],
        "user": match["user"][:64],
        "detail": match["method"],
        "kind": match["method"],
    }


def new_ssh_attempts(
    lines: list[str], cursor: dict | None, default_tz: tzinfo
) -> tuple[list[dict], dict, bool]:
    """Extrait les tentatives SSH postérieures au curseur.

    Le curseur mémorise le dernier horodatage traité et les messages déjà vus à cet
    horodatage (sshd écrit plusieurs lignes à la même milliseconde).
    Retourne (tentatives, nouveau curseur, trou) ; trou = la première ligne reçue est
    déjà plus récente que le curseur, des lignes ont pu être manquées.
    """
    last_ts = cursor["ts"] if cursor else ""
    seen = set(cursor["seen"]) if cursor else set()
    max_ts, seen_at_max = last_ts, set(seen)
    first_ts: str | None = None
    attempts: list[dict] = []
    for raw in lines:
        parsed = parse_log_line(raw, default_tz)
        if parsed is None:
            continue
        ts, msg = parsed
        if first_ts is None:
            first_ts = ts
        if ts < last_ts or (ts == last_ts and msg in seen):
            continue
        if ts > max_ts:
            max_ts, seen_at_max = ts, {msg}
        else:
            seen_at_max.add(msg)
        attempt = parse_ssh_failure(msg)
        if attempt is not None:
            attempts.append({"t": ts, **attempt})
    gap = bool(cursor and cursor["ts"]) and first_ts is not None and first_ts > last_ts
    return attempts, {"ts": max_ts, "seen": sorted(seen_at_max)[:200]}, gap
