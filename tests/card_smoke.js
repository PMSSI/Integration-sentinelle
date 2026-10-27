// Renders the card with a minimal DOM and a fake hass: node tests/card_smoke.js
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
const mk = (attack, recent, language) => ({
  language,
  states: {
    "sensor.sentinelle_attempts_24_h": { entity_id: "sensor.sentinelle_attempts_24_h", state: String(recent.length), last_updated: now + attack,
      attributes: { sentinelle_kind: "summary", ha: 1, ssh: recent.length - 1, ips: 2, week: 900, count_window: attack ? 7 : 0, window: 10, threshold: 5,
        attack, attack_since: attack ? now : null, ha_monitored: true, ssh_slugs: ["core_ssh"], ssh_error: null,
        top_ips: [{ ip: "203.0.113.7", n: 5, cc: "NL", country: "Netherlands", isp: "Hosting <b>SRV</b>" }],
        recent } },
    "binary_sensor.sentinelle_attack_in_progress": { entity_id: "binary_sensor.sentinelle_attack_in_progress", state: attack ? "on" : "off", last_updated: now, attributes: { sentinelle_kind: "attack" } },
  },
  entities: { "sensor.sentinelle_attempts_24_h": { platform: "sentinelle" }, "binary_sensor.sentinelle_attack_in_progress": { platform: "sentinelle" } },
});
const ssh = (u) => ({ t: now, src: "ssh", ip: "203.0.113.7", user: u, detail: "password", kind: "password", cc: "NL", country: "Netherlands" });
const lanLogin = { t: now, src: "ha", ip: "192.0.2.50", user: null, detail: "/auth/login_flow", kind: "login", cc: "LAN", country: "Local network" };
const cases = [
  // [name, hass, text that must appear]
  ["calm fr", mk(false, [], "fr"), "Aucune tentative"],
  ["attempts fr", mk(false, [ssh("root"), ssh("root"), ssh("<img src=x onerror=alert(1)>"), lanLogin], "fr"), "mot de passe refusé"],
  ["attack fr", mk(true, [ssh("root"), ssh("admin")], "fr"), "Attaque en cours"],
  ["no entity fr", { language: "fr", states: {}, entities: {} }, "aucune entité"],
  ["attack en", mk(true, [ssh("root"), ssh("root"), lanLogin], "en"), "Attack in progress"],
  ["calm en", mk(false, [], "en"), "No attempt"],
  ["default lang", mk(false, [ssh("root")], undefined), "Latest attempts"],
];
for (const [name, hass, expected] of cases) {
  const c = new Card(); c.setConfig({}); c.hass = hass;
  const html = c._root.innerHTML;
  if (html.includes("affichage impossible") || html.includes("cannot render")) throw new Error(name + ": render error");
  if (html.includes("<img src=x") || html.includes("<b>SRV")) throw new Error(name + ": unescaped text");
  if (!html.includes(expected)) throw new Error(name + ": missing \"" + expected + "\"");
  console.log("ok", name.padEnd(13), (html.match(/class="row"/g) || []).length, "rows", html.includes("×2") ? "(grouped ×2)" : "");
}
