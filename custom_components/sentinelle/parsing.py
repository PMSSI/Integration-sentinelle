"""Log parsing, without any Home Assistant dependency (testable on its own)."""
from __future__ import annotations

from datetime import datetime, timezone, tzinfo
import re

# Warning emitted by homeassistant.components.http.ban.process_wrong_login().
# Non-greedy host: the URL and user agent that follow are client-controlled.
HA_FAIL_RE = re.compile(
    r"^Login attempt or request with invalid authentication from (?P<host>.*?) "
    r"\((?P<ip>[0-9A-Fa-f:.]+)\)\. Requested URL: '(?P<url>.*?)'\. \(",
    re.S,
)
# journald line returned by the Supervisor with "Accept: text/x-log":
#   2026-01-01 03:41:16.776+01:00 homeassistant app_core_ssh[42]: <message>
LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r" \S+ \S+: (?P<msg>.*)$"
)
# sshd writes one line per rejected password / key.
SSH_FAIL_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def iso_utc(ts: datetime) -> str:
    """Normalised timestamp (UTC, milliseconds): sorts correctly as a string."""
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_ha_failure(message: str) -> dict | None:
    """Rejected HA login → attempt (without timestamp), or None."""
    match = HA_FAIL_RE.match(message)
    if match is None:
        return None
    # The query string may carry a token: keep the path only.
    path = match["url"].split("?", 1)[0]
    return {
        "src": "ha",
        "ip": match["ip"],
        "user": None,
        "detail": path[:120],
        "kind": "login" if path.startswith("/auth/login_flow") else "token",
    }


def parse_log_line(line: str, default_tz: tzinfo) -> tuple[str, str] | None:
    """x-log line → (ISO UTC timestamp, message), or None if unreadable."""
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
    """sshd "Failed …" message → attempt (without timestamp), or None."""
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
    """Extract the SSH attempts newer than the cursor.

    The cursor stores the last processed timestamp and the messages already seen at
    that timestamp (sshd writes several lines within the same millisecond).
    Returns (attempts, new cursor, gap); gap = the first line received is already
    newer than the cursor, so lines may have been missed.
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
