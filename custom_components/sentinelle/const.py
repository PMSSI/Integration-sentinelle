"""Constants for the Sentinelle integration."""
from __future__ import annotations

DOMAIN = "sentinelle"
VERSION = "0.2.0"

CONF_NOTIFY = "notify_targets"
CONF_THRESHOLD = "threshold"
CONF_WINDOW = "window_minutes"
CONF_NOTIFY_HA_LOGIN = "notify_ha_login"
CONF_GEOIP = "geoip"

DEFAULT_THRESHOLD = 5  # attempts…
DEFAULT_WINDOW = 10  # …within this many minutes ⇒ "attack in progress"

SRC_HA = "ha"
SRC_SSH = "ssh"
SOURCE_LABELS = {SRC_HA: "HA", SRC_SSH: "SSH"}

BAN_LOGGER = "homeassistant.components.http.ban"

SSH_POLL_SECONDS = 60
SSH_LOG_LINES = 500  # lines re-read on every poll
SSH_LOG_LINES_MAX = 5000  # first poll, or after a gap was detected

HISTORY_DAYS = 7
MAX_ATTEMPTS = 5000
RENOTIFY_MINUTES = 30  # reminder while the attack lasts
LOGIN_NOTIFY_COOLDOWN = 10  # minutes between two "HA login rejected" alerts for the same IP
SAVE_DELAY = 30  # seconds
UPDATE_DEBOUNCE = 2  # seconds
TOP_IPS = 8
RECENT_ATTEMPTS = 60

# ip-api.com: free, no key, 15 "batch" requests (100 IPs each) per minute.
GEOIP_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp&lang={lang}"
GEOIP_BATCH = 100
GEOIP_PAUSE = 5  # seconds between two batches

STORAGE_VERSION = 1
SIGNAL_UPDATE = f"{DOMAIN}_update"
