# Sentinelle

Home Assistant integration that **monitors rejected logins** to Home Assistant and to SSH add-ons, with a Lovelace card and phone notifications. **Nothing is blocked**: Sentinelle watches and tells you.

## What it detects

- **Home Assistant**: every password rejected on the login page, and every request with an invalid token (read from the `homeassistant.components.http.ban` log).
- **SSH**: every password or key rejected by an SSH add-on (`core_ssh`, "Advanced SSH & Web Terminal"…), read from its logs through the Supervisor every minute.
- **Attack in progress**: at least *N* attempts within *X* minutes, all sources and IPs combined (5 in 10 min by default).

Each public IP is located (country, city, ISP) with [ip-api.com](https://ip-api.com). Private IPs are labelled "Local network" and are **never sent** anywhere. Geolocation can be turned off.

## Notifications

- Attack started, a reminder every 30 min while it lasts, then attack over with a summary.
- Optional: an alert for every rejected Home Assistant password (at most one every 10 min per IP).

Targets are the `notify.*` services of your installation (mobile app…), picked during setup.

## Entities

| Entity | Purpose |
|---|---|
| Attack in progress (`binary_sensor`) | `on` during an attack (*safety* device class) |
| Attempts 24 h (`sensor`) | 24 h total; its attributes feed the card |
| HA attempts 24 h, SSH attempts 24 h | Split by source |
| Distinct IPs 24 h, Attempts 7 days | Different IPs, 7-day total |
| Last attempt (`sensor`, timestamp) | Time, IP, source, country of the latest attempt |

The history (7 days) survives restarts. Counters have a state class, so they get long-term statistics.

## Installation (HACS)

1. HACS → ⋮ menu → **Custom repositories** → `https://github.com/PMSSI/Integration-sentinelle`, category **Integration**.
2. Download **Sentinelle**, then restart Home Assistant.
3. **Settings → Devices & services → Add integration → Sentinelle**: choose the phones, the threshold and the window.

SSH monitoring needs Home Assistant OS or Supervised (Supervisor access). Without a Supervisor, only the Home Assistant part works.

## Card

The card is loaded automatically: add **Sentinelle** from the card picker, or in YAML:

```yaml
type: custom:sentinelle-card
top: 5        # IPs shown (default 5)
max_rows: 8   # latest attempts (default 8)
```

It shows the status (quiet / attempts / attack), the counters, the top IPs over 24 h and the latest attempts (grouped), in light and dark themes.

## Language

Entity names, the setup dialog, notifications and the card follow the Home Assistant language. English and French are included.

**Français** : l'interface (entités, configuration, notifications, carte) est traduite en français et suit la langue de Home Assistant.

## Tests

```bash
python tests/test_parsing.py   # log parsing, no Home Assistant needed
node tests/card_smoke.js       # card rendering with a fake hass (FR + EN)
```

## License

MIT
