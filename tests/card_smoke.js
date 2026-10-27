// Rendu de la carte avec un DOM minimal et un faux hass : node tests/card_smoke.js
const fs = require("fs");
const path = require("path");
class FakeRoot { constructor() { this.innerHTML = ""; } querySelector() { return { addEventListener() {} }; } }
global.HTMLElement = class { attachShadow() { return new FakeRoot(); } dispatchEvent() {} };
const registry = {};
global.customElements = { get: (n) => registry[n], define: (n, c) => { registry[n] = c; } };
global.window = {};
global.CustomEvent = class {};
eval(fs.readFileSync(path.join(__dirname, "../custom_components/sentinelle/sentinelle-card.js"), "utf8"));
const Card = registry["sentinelle-card"];
const now = new Date().toISOString();
const mk = (attack, recent) => ({
  states: {
    "sensor.sentinelle_tentatives_24_h": { entity_id: "sensor.sentinelle_tentatives_24_h", state: String(recent.length), last_updated: now + attack,
      attributes: { sentinelle_kind: "summary", ha: 1, ssh: recent.length - 1, ips: 2, week: 900, count_window: attack ? 7 : 0, window: 10, threshold: 5,
        attack, attack_since: attack ? now : null, ha_monitored: true, ssh_slugs: ["core_ssh"], ssh_error: null,
        top_ips: [{ ip: "203.0.113.7", n: 5, cc: "NL", country: "Pays-Bas", isp: "Hosting <b>SRV</b>" }],
        recent } },
    "binary_sensor.sentinelle_attaque_en_cours": { entity_id: "binary_sensor.sentinelle_attaque_en_cours", state: attack ? "on" : "off", last_updated: now, attributes: { sentinelle_kind: "attack" } },
  },
  entities: { "sensor.sentinelle_tentatives_24_h": { platform: "sentinelle" }, "binary_sensor.sentinelle_attaque_en_cours": { platform: "sentinelle" } },
});
const ssh = (u) => ({ t: now, src: "ssh", ip: "203.0.113.7", user: u, detail: "password", kind: "password", cc: "NL", country: "Pays-Bas" });
const cases = [
  ["calme", mk(false, [])],
  ["tentatives", mk(false, [ssh("root"), ssh("root"), ssh("<img src=x onerror=alert(1)>"), { t: now, src: "ha", ip: "192.0.2.50", user: null, detail: "/auth/login_flow", kind: "login", cc: "LAN", country: "Réseau local" }])],
  ["attaque", mk(true, [ssh("root"), ssh("admin")])],
  ["sans entité", { states: {}, entities: {} }],
];
for (const [name, hass] of cases) {
  const c = new Card(); c.setConfig({}); c.hass = hass;
  const html = c._root.innerHTML;
  if (html.includes("affichage impossible")) throw new Error(name + " : erreur de rendu");
  if (html.includes("<img src=x") || html.includes("<b>SRV")) throw new Error(name + " : texte non échappé");
  console.log("ok", name.padEnd(12), (html.match(/class="row"/g) || []).length, "lignes,",
    html.includes("Attaque en cours") ? "ATTAQUE" : html.includes("aucune entité") ? "vide" : "calme",
    html.includes("×2") ? "(regroupé ×2)" : "");
}
