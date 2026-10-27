# Sentinelle

Intégration Home Assistant qui **surveille les connexions refusées** à Home Assistant et aux add-ons SSH, avec une carte Lovelace et des notifications. **Rien n'est bloqué** : Sentinelle observe et prévient.

## Ce qu'elle détecte

- **Home Assistant** : chaque mot de passe refusé sur la page de connexion, et chaque requête avec un jeton invalide (lus dans le journal `homeassistant.components.http.ban`).
- **SSH** : chaque mot de passe ou clé refusé par un add-on SSH (`core_ssh`, « Advanced SSH & Web Terminal »…), lu toutes les minutes dans ses logs via le Supervisor.
- **Attaque en cours** : au moins *N* tentatives en *X* minutes, toutes sources et toutes IP confondues (5 en 10 min par défaut).

Chaque IP est localisée (pays, ville, FAI) via [ip-api.com](https://ip-api.com). Les IP privées sont marquées « Réseau local » et ne sont jamais envoyées. La localisation peut être désactivée.

## Notifications

- Début d'attaque, rappel toutes les 30 min tant qu'elle dure, puis fin d'attaque avec le bilan.
- Option : une alerte à chaque mot de passe Home Assistant refusé (au plus une toutes les 10 min par IP).

Les cibles sont les services `notify.*` de votre installation (application mobile…), à choisir lors de la configuration.

## Entités

| Entité | Rôle |
|---|---|
| `binary_sensor.sentinelle_attaque_en_cours` | `on` pendant une attaque (classe *safety*) |
| `sensor.sentinelle_tentatives_24_h` | Total sur 24 h ; ses attributs alimentent la carte |
| `sensor.sentinelle_tentatives_ha_24_h`, `…_ssh_24_h` | Détail par source |
| `sensor.sentinelle_ip_distinctes_24_h`, `sensor.sentinelle_tentatives_7_jours` | IP différentes, total 7 jours |
| `sensor.sentinelle_derniere_tentative` | Horodatage, IP, source, pays de la dernière tentative |

L'historique (7 jours) est conservé entre les redémarrages.

## Installation (HACS)

1. HACS → menu ⋮ → **Dépôts personnalisés** → `https://github.com/PMSSI/Integration-sentinelle`, catégorie **Intégration**.
2. Télécharger **Sentinelle**, redémarrer Home Assistant.
3. **Paramètres → Appareils et services → Ajouter une intégration → Sentinelle** : choisir les téléphones, le seuil et la fenêtre.

La surveillance SSH nécessite Home Assistant OS ou Supervised (accès au Supervisor). Sans Supervisor, seule la partie Home Assistant fonctionne.

## Carte

La carte est chargée automatiquement : ajoutez **Sentinelle** depuis le sélecteur de cartes, ou en YAML :

```yaml
type: custom:sentinelle-card
top: 5        # IP affichées (défaut 5)
max_rows: 8   # dernières tentatives (défaut 8)
```

Elle affiche l'état (calme / tentatives / attaque), les compteurs, les principales IP sur 24 h et les dernières tentatives (regroupées), en thème clair comme sombre.

## Tests

```bash
python tests/test_parsing.py   # analyse des logs, sans Home Assistant
node tests/card_smoke.js       # rendu de la carte avec un faux hass
```

## Licence

MIT
