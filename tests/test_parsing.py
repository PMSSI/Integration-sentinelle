"""Tests de parsing.py (sans Home Assistant) : python tests/test_parsing.py

Adresses de documentation uniquement (RFC 5737 / 3849) : aucune donnée réelle.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "parsing", ROOT / "custom_components" / "sentinelle" / "parsing.py"
)
parsing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parsing)
TZ = timezone.utc
PARIS = timezone(timedelta(hours=1))


def _line(ts: datetime, msg: str) -> str:
    """Ligne au format journald x-log renvoyé par le Supervisor."""
    return f"{ts.isoformat(sep=' ', timespec='milliseconds')} homeassistant app_core_ssh[42]: {msg}"


def _synthetic_log(n: int = 300) -> list[str]:
    """Journal sshd réaliste : connexions, refus (plusieurs à la même milliseconde), succès."""
    start = datetime(2026, 1, 1, 3, 0, tzinfo=PARIS)
    lines = []
    for i in range(n):
        ts = start + timedelta(seconds=7 * i)
        ip = f"203.0.113.{i % 40}"
        lines.append(_line(ts, f"Connection from {ip} port {40000 + i} on 192.0.2.10 port 22"))
        lines.append(_line(ts, f"Failed password for invalid user root from {ip} port {40000 + i} ssh2"))
        lines.append(_line(ts, f"Failed password for invalid user admin from {ip} port {40000 + i} ssh2"))
        if i % 25 == 0:
            lines.append(_line(ts, "Accepted password for alice from 192.0.2.50 port 5000 ssh2"))
    return lines


def test_ha_failure():
    msg = ("Login attempt or request with invalid authentication from scan.example.net (203.0.113.7). "
           "Requested URL: '/auth/login_flow/abc?x=1'. (Mozilla/5.0 (X11) '. (fake 198.51.100.9))")
    a = parsing.parse_ha_failure(msg)
    assert a == {"src": "ha", "ip": "203.0.113.7", "user": None,
                 "detail": "/auth/login_flow/abc", "kind": "login"}, a
    tok = parsing.parse_ha_failure(
        "Login attempt or request with invalid authentication from 192.0.2.50 (192.0.2.50). "
        "Requested URL: '/api/states?token=secret'. (curl/8)")
    assert tok["kind"] == "token" and tok["detail"] == "/api/states", tok
    v6 = parsing.parse_ha_failure(
        "Login attempt or request with invalid authentication from 2001:db8::1 (2001:db8::1). "
        "Requested URL: '/auth/login_flow'. (None)")
    assert v6["ip"] == "2001:db8::1", v6
    assert parsing.parse_ha_failure("Banned IP 203.0.113.7 for too many login attempts") is None


def test_ssh_failure():
    a = parsing.parse_ssh_failure("Failed password for invalid user root from 203.0.113.20 port 60972 ssh2")
    assert a == {"src": "ssh", "ip": "203.0.113.20", "user": "root", "detail": "password", "kind": "password"}, a
    b = parsing.parse_ssh_failure("Failed password for alice from 192.0.2.50 port 5000 ssh2")
    assert b["user"] == "alice", b
    c = parsing.parse_ssh_failure("Failed password for invalid user  from 198.51.100.4 port 1 ssh2")
    assert c["user"] == "" and c["ip"] == "198.51.100.4", c
    assert parsing.parse_ssh_failure("Accepted password for alice from 192.0.2.50 port 5 ssh2") is None


def test_log_line_timezone():
    ts, msg = parsing.parse_log_line(
        "2026-10-27 03:41:16.776+01:00 homeassistant app_core_ssh[42]: Failed password", TZ)
    assert ts == "2026-10-27T02:41:16.776+00:00" and msg == "Failed password", (ts, msg)
    naive, _ = parsing.parse_log_line("2026-10-27 03:41:16.776 h app_core_ssh[42]: x", PARIS)
    assert naive == "2026-10-27T02:41:16.776+00:00", naive
    assert parsing.parse_log_line("garbage", TZ) is None


def test_cursor():
    lines = _synthetic_log()
    expected = sum(1 for l in lines if ": Failed " in l)
    first, cur, gap = parsing.new_ssh_attempts(lines, None, TZ)
    assert len(first) == expected and not gap, (len(first), expected)
    assert [a["t"] for a in first] == sorted(a["t"] for a in first)
    # Relecture identique : rien de neuf.
    again, cur2, gap2 = parsing.new_ssh_attempts(lines, cur, TZ)
    assert again == [] and cur2 == cur and not gap2, (len(again), gap2)
    # Fenêtre glissante : les 500 dernières lignes + nouvelles lignes, dont plusieurs à la même milliseconde.
    later = datetime(2099, 1, 1, tzinfo=PARIS)
    new = [
        _line(later, "Failed password for invalid user admin from 198.51.100.8 port 1 ssh2"),
        _line(later, "Connection reset by 198.51.100.8 port 1"),
        _line(later, "Failed password for invalid user test from 198.51.100.8 port 1 ssh2"),
    ]
    nxt, cur3, gap3 = parsing.new_ssh_attempts(lines[-500:] + new, cur, TZ)
    assert [a["user"] for a in nxt] == ["admin", "test"] and not gap3, nxt
    # Même milliseconde relue + une ligne de plus à cette milliseconde : seule la nouvelle compte.
    more = new + [_line(later, "Failed password for invalid user oracle from 198.51.100.8 port 1 ssh2")]
    last, _, _ = parsing.new_ssh_attempts(more, cur3, TZ)
    assert [a["user"] for a in last] == ["oracle"], last
    # Trou : la 1re ligne reçue est déjà postérieure au curseur.
    _, _, gap4 = parsing.new_ssh_attempts(more, {"ts": "2026-01-01T00:00:00.000+00:00", "seen": []}, TZ)
    assert gap4


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
