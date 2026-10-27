"""Constantes de l'intégration Sentinelle."""
from __future__ import annotations

DOMAIN = "sentinelle"
VERSION = "0.1.0"

CONF_NOTIFY = "notify_targets"
CONF_THRESHOLD = "threshold"
CONF_WINDOW = "window_minutes"
CONF_NOTIFY_HA_LOGIN = "notify_ha_login"
CONF_GEOIP = "geoip"

DEFAULT_THRESHOLD = 5  # tentatives…
DEFAULT_WINDOW = 10  # …en minutes ⇒ « attaque en cours »

SRC_HA = "ha"
SRC_SSH = "ssh"
SOURCE_LABELS = {SRC_HA: "HA", SRC_SSH: "SSH"}

BAN_LOGGER = "homeassistant.components.http.ban"

SSH_POLL_SECONDS = 60
SSH_LOG_LINES = 500  # lignes relues à chaque passage
SSH_LOG_LINES_MAX = 5000  # premier passage, ou trou détecté

HISTORY_DAYS = 7
MAX_ATTEMPTS = 5000
RENOTIFY_MINUTES = 30  # rappel tant que l'attaque dure
LOGIN_NOTIFY_COOLDOWN = 10  # minutes entre deux alertes « connexion HA refusée » pour une même IP
SAVE_DELAY = 30  # secondes
UPDATE_DEBOUNCE = 2  # secondes
TOP_IPS = 8
RECENT_ATTEMPTS = 60

# ip-api.com : gratuit, sans clé, 15 requêtes « batch » (100 IP chacune) par minute.
GEOIP_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp&lang=fr"
GEOIP_BATCH = 100
GEOIP_PAUSE = 5  # secondes entre deux lots

STORAGE_VERSION = 1
SIGNAL_UPDATE = f"{DOMAIN}_update"
