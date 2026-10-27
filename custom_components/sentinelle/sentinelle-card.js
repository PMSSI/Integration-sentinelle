/**
 * Lovelace card for the Sentinelle integration (rejected HA + SSH logins).
 * Loaded automatically by the integration:  type: custom:sentinelle-card
 * Options: top (IPs shown, default 5), max_rows (latest attempts, default 8).
 *
 * Styled like Mushroom + card_mod tiles: coloured glow behind the icon,
 * 4 px glowing bar at the bottom, dark value pill in the top-right corner.
 * Text follows the Home Assistant language (French or English).
 */
const SENTINELLE_CARD_VERSION = "0.2.0";

const RGB = {
  ok: "0, 230, 180",
  warn: "255, 152, 0",
  alert: "239, 68, 68",
  ha: "56, 189, 248",
  ssh: "224, 64, 251",
};
const SRC_LABEL = { ha: "HA", ssh: "SSH" };

const STRINGS = {
  en: {
    error: "Sentinelle: cannot render.",
    noEntity: "Sentinelle: no entity found. Is the integration set up?",
    attackSince: "Attack in progress since {time} · {n} attempts in {w} min",
    calmLast: "No attack · last attempt {ago}",
    calm: "No attempt · all quiet",
    topIps: "Top IPs",
    recent: "Latest attempts",
    week: "{n} over 7 days",
    empty: "No attempt recorded in 7 days 👌",
    haLogins: "HA logins",
    sshDown: "SSH unavailable",
    alert: "Alert: {n} in {w} min",
    kpiIps: "IPs",
    kpiWeek: "7 days",
    now: "just now",
    minAgo: "{n} min ago",
    hAgo: "{n} h ago",
    dAgo: "{n} d ago",
    lan: "Local network",
    sshUser: "user \u201c{u}\u201d",
    sshEmpty: "empty user",
    password: "password rejected",
    token: "invalid token · {d}",
  },
  fr: {
    error: "Sentinelle : affichage impossible.",
    noEntity: "Sentinelle : aucune entité trouvée. L'intégration est-elle configurée ?",
    attackSince: "Attaque en cours depuis {time} · {n} tentatives en {w} min",
    calmLast: "Aucune attaque · dernière tentative {ago}",
    calm: "Aucune tentative · tout est calme",
    topIps: "Principales IP",
    recent: "Dernières tentatives",
    week: "{n} sur 7 jours",
    empty: "Aucune tentative enregistrée sur 7 jours 👌",
    haLogins: "Connexions HA",
    sshDown: "SSH indisponible",
    alert: "Alerte : {n} en {w} min",
    kpiIps: "IP",
    kpiWeek: "7 jours",
    now: "à l'instant",
    minAgo: "il y a {n} min",
    hAgo: "il y a {n} h",
    dAgo: "il y a {n} j",
    lan: "Réseau local",
    sshUser: "utilisateur « {u} »",
    sshEmpty: "utilisateur vide",
    password: "mot de passe refusé",
    token: "jeton invalide · {d}",
  },
};

const LANG = (hass) => {
  const l = (hass && (hass.language || (hass.locale && hass.locale.language))) || "en";
  return String(l).toLowerCase().indexOf("fr") === 0 ? "fr" : "en";
};

// Fills {placeholders}; the result is plain text, to be passed through ESC().
const FMT = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => (v && v[k] != null ? String(v[k]) : m));

const STYLE = `
:host{
 --ink:var(--primary-text-color,#141821);
 --muted:var(--secondary-text-color,#8a909c);
 --plane:var(--secondary-background-color,rgba(128,128,128,.08));
}
ha-card{position:relative;overflow:hidden;padding:12px 12px 16px;
 background-image:radial-gradient(circle at 40px 40px,rgba(var(--c),.15) 0%,transparent 60%)}
ha-card::after{content:'';position:absolute;bottom:0;left:0;height:4px;width:var(--lvl,0%);
 background:linear-gradient(90deg,transparent,rgb(var(--c)));box-shadow:0 0 10px rgba(var(--c),.5);
 transition:width .5s ease;pointer-events:none}
.hero{display:flex;align-items:center;gap:14px;cursor:pointer;padding-right:96px;min-height:65px}
.shape{width:65px;height:65px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;
 background:rgba(var(--c),.2);box-shadow:0 2px 12px rgba(var(--c),.4)}
.shape ha-icon{--mdc-icon-size:34px;color:rgb(var(--c))}
.attack .shape{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{50%{box-shadow:0 0 22px rgba(var(--c),.8)}}
.primary{font-size:15px;font-weight:bold;color:var(--ink)}
.secondary{font-size:12px;color:var(--muted);margin-top:2px;line-height:1.35}
.badge{position:absolute;top:12px;right:12px;z-index:4;font-size:1rem;font-weight:700;padding:2px 6px;border-radius:4px;
 background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1);backdrop-filter:blur(4px);
 text-shadow:0 1px 3px rgba(0,0,0,.8);box-shadow:0 2px 6px rgba(0,0,0,.15);color:rgb(var(--c));white-space:nowrap}
.badge small{font-size:11px;font-weight:600;opacity:.85}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}
.kpi{position:relative;overflow:hidden;border-radius:10px;padding:8px 10px 10px;background-color:var(--plane);
 background-image:radial-gradient(circle at 14px 14px,rgba(var(--k),.20) 0%,transparent 70%)}
.kpi::after{content:'';position:absolute;bottom:0;left:0;height:3px;width:var(--l,0%);
 background:linear-gradient(90deg,transparent,rgb(var(--k)));box-shadow:0 0 8px rgba(var(--k),.5)}
.kpi .l{font-size:11px;color:var(--muted);font-weight:600;white-space:nowrap}
.kpi .v{font-size:19px;font-weight:700;color:var(--ink);margin-top:2px;font-variant-numeric:tabular-nums}
.sec{display:flex;justify-content:space-between;align-items:baseline;margin:14px 2px 6px;
 font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.sec span{text-transform:none;letter-spacing:0;font-weight:500}
.row{position:relative;overflow:hidden;display:flex;align-items:center;gap:8px;padding:7px 10px;margin-bottom:5px;
 border-radius:10px;background:var(--plane);font-size:13px;color:var(--ink)}
.row .fill{position:absolute;top:0;bottom:0;left:0;width:var(--w,0%);
 background:linear-gradient(90deg,rgba(var(--k),.04),rgba(var(--k),.22));pointer-events:none}
.row > :not(.fill){position:relative}
.ip{font-weight:650;font-variant-numeric:tabular-nums;white-space:nowrap}
.flag{font-size:15px;line-height:1}
.where{flex:1;min-width:0;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.n{font-weight:700;color:rgb(var(--k));font-variant-numeric:tabular-nums}
.t{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap;min-width:38px}
.src{font-size:10.5px;font-weight:700;padding:1px 6px;border-radius:6px;background:rgba(var(--k),.18);color:rgb(var(--k))}
.empty{padding:14px;text-align:center;color:var(--muted);font-size:13px;background:var(--plane);border-radius:10px;margin-top:12px}
.foot{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;font-size:11.5px;color:var(--muted)}
.foot i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:1px;background:rgb(${RGB.ok})}
.foot i.ko{background:rgb(${RGB.alert})}
`;

const ESC = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const FLAG = (cc) => {
  if (cc === "LAN") return "🏠";
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "🌐";
  return String.fromCodePoint.apply(null, cc.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
};

const TIME = (iso, lang) => {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const locale = lang === "fr" ? "fr-FR" : undefined;
  const hm = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === new Date().toDateString()) return hm;
  return d.toLocaleDateString(locale, { day: "2-digit", month: "2-digit" }) + " " + hm;
};

const AGO = (iso, T) => {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!(s >= 0)) return "";
  if (s < 60) return T.now;
  if (s < 3600) return FMT(T.minAgo, { n: Math.floor(s / 60) });
  if (s < 86400) return FMT(T.hAgo, { n: Math.floor(s / 3600) });
  return FMT(T.dAgo, { n: Math.floor(s / 86400) });
};

const PLACE = (a, T) => {
  if (a.cc === "LAN") return T.lan;
  return [a.country, a.isp].filter((x) => x).join(" · ");
};

const DETAIL = (a, T) => {
  if (a.src === "ssh") return a.user ? FMT(T.sshUser, { u: a.user }) : T.sshEmpty;
  return a.kind === "login" ? T.password : FMT(T.token, { d: a.detail || "" });
};

class SentinelleCard extends HTMLElement {
  setConfig(config) {
    this._config = Object.assign({ top: 5, max_rows: 8 }, config || {});
    this._sig = null;
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._root) this._root = this.attachShadow({ mode: "open" });
    try {
      this._render();
    } catch (err) {
      console.error("[sentinelle-card]", err);
      this._sig = null;
      this._root.innerHTML = `<style>${STYLE}</style><ha-card style="--c:${RGB.warn}"><div class="empty">${ESC(STRINGS[LANG(hass)].error)}</div></ha-card>`;
    }
  }

  _find() {
    const hass = this._hass;
    const reg = hass.entities || {};
    let summary = null;
    let attack = null;
    Object.keys(hass.states).forEach((id) => {
      const st = hass.states[id];
      const kind = st.attributes && st.attributes.sentinelle_kind;
      if (!kind || (reg[id] && reg[id].platform !== "sentinelle")) return;
      if (kind === "summary") summary = st;
      if (kind === "attack") attack = st;
    });
    return { summary, attack };
  }

  _render() {
    const found = this._find();
    const S = found.summary;
    const A = found.attack;
    const lang = LANG(this._hass);
    const T = STRINGS[lang];
    // Re-render only when the entities (or the language) change, or every minute for "… ago".
    const sig = [S && S.last_updated, A && A.last_updated, lang, Math.floor(Date.now() / 60000)].join("|");
    if (sig === this._sig) return;
    this._sig = sig;

    if (!S) {
      this._root.innerHTML = `<style>${STYLE}</style><ha-card style="--c:${RGB.warn}"><div class="empty">${ESC(T.noEntity)}</div></ha-card>`;
      return;
    }
    const at = S.attributes;
    const total = Number(S.state) || 0;
    const attackOn = A ? A.state === "on" : !!at.attack;
    const color = attackOn ? RGB.alert : total > 0 ? RGB.warn : RGB.ok;
    const threshold = Number(at.threshold) || 5;
    const level = attackOn ? 100 : Math.min(100, Math.round(((Number(at.count_window) || 0) / threshold) * 100));
    const recent = at.recent || [];
    const top = (at.top_ips || []).slice(0, this._config.top);

    let secondary;
    if (attackOn) {
      secondary = FMT(T.attackSince, { time: TIME(at.attack_since, lang), n: at.count_window, w: at.window });
    } else if (recent.length) {
      secondary = FMT(T.calmLast, { ago: AGO(recent[0].t, T) });
    } else {
      secondary = T.calm;
    }

    const ha = Number(at.ha) || 0;
    const ssh = Number(at.ssh) || 0;
    const share = (n) => (total ? Math.round((n / total) * 100) : 0);
    const kpi = (label, value, rgb, lvl) =>
      `<div class="kpi" style="--k:${rgb};--l:${lvl}%"><div class="l">${ESC(label)}</div><div class="v">${ESC(value)}</div></div>`;

    const topHtml = top.length
      ? `<div class="sec">${ESC(T.topIps)} <span>24 h</span></div>` +
        top.map((r) => {
          const w = Math.max(6, Math.round((r.n / top[0].n) * 100));
          return `<div class="row" style="--k:${color};--w:${w}%"><div class="fill"></div>` +
            `<span class="flag">${FLAG(r.cc)}</span><span class="ip">${ESC(r.ip)}</span>` +
            `<span class="where">${ESC(PLACE(r, T))}</span><span class="n">${ESC(r.n)}</span></div>`;
        }).join("")
      : "";

    // Group identical consecutive attempts (sshd writes one line per password).
    const groups = [];
    recent.forEach((a) => {
      const g = groups[groups.length - 1];
      if (g && g.src === a.src && g.ip === a.ip && g.user === a.user && g.detail === a.detail &&
          new Date(g.first).getTime() - new Date(a.t).getTime() < 5 * 60 * 1000) {
        g.n += 1;
        g.first = a.t;
      } else {
        groups.push(Object.assign({}, a, { n: 1, first: a.t }));
      }
    });
    const recentHtml = groups.length
      ? `<div class="sec">${ESC(T.recent)} <span>${ESC(FMT(T.week, { n: at.week }))}</span></div>` +
        groups.slice(0, this._config.max_rows).map((g) => {
          const k = RGB[g.src] || RGB.warn;
          return `<div class="row" style="--k:${k}"><span class="t">${ESC(TIME(g.t, lang))}</span>` +
            `<span class="src">${ESC(SRC_LABEL[g.src] || g.src)}</span>` +
            `<span class="flag">${FLAG(g.cc)}</span><span class="ip">${ESC(g.ip)}</span>` +
            `<span class="where">${ESC(DETAIL(g, T))}</span>` +
            `${g.n > 1 ? `<span class="n">×${g.n}</span>` : ""}</div>`;
        }).join("")
      : `<div class="empty">${ESC(T.empty)}</div>`;

    const slugs = at.ssh_slugs || [];
    const sshOk = !at.ssh_error && slugs.length > 0;
    const foot = `<div class="foot">` +
      `<span><i class="${at.ha_monitored ? "" : "ko"}"></i>${ESC(T.haLogins)}</span>` +
      `<span title="${ESC(at.ssh_error || slugs.join(", "))}"><i class="${sshOk ? "" : "ko"}"></i>${sshOk ? "SSH" : ESC(T.sshDown)}</span>` +
      `<span>${ESC(FMT(T.alert, { n: threshold, w: at.window }))}</span></div>`;

    this._root.innerHTML = `<style>${STYLE}</style>
      <ha-card class="${attackOn ? "attack" : ""}" style="--c:${color};--lvl:${level}%">
        <div class="badge">${ESC(total)} <small>/ 24 h</small></div>
        <div class="hero">
          <div class="shape"><ha-icon icon="${attackOn ? "mdi:shield-alert" : total ? "mdi:shield-half-full" : "mdi:shield-check"}"></ha-icon></div>
          <div><div class="primary">Sentinelle</div><div class="secondary">${ESC(secondary)}</div></div>
        </div>
        <div class="kpis">
          ${kpi("HA", ha, RGB.ha, share(ha))}
          ${kpi("SSH", ssh, RGB.ssh, share(ssh))}
          ${kpi(T.kpiIps, at.ips || 0, color, 0)}
          ${kpi(T.kpiWeek, at.week || 0, color, 0)}
        </div>
        ${topHtml}
        ${recentHtml}
        ${foot}
      </ha-card>`;

    const hero = this._root.querySelector(".hero");
    const target = A ? A.entity_id : S.entity_id;
    hero.addEventListener("click", () => {
      this.dispatchEvent(new CustomEvent("hass-more-info", { detail: { entityId: target }, bubbles: true, composed: true }));
    });
  }

  getCardSize() { return 7; }
  getGridOptions() { return { columns: 12, min_columns: 6, rows: "auto" }; }
  static getStubConfig() { return {}; }
}

// IDEMPOTENT registration (the file can be loaded twice: by the integration AND through a
// manual Lovelace resource) — otherwise "already defined" breaks the mobile frontend.
if (customElements.get("sentinelle-card")) {
  console.warn(`[sentinelle-card] v${SENTINELLE_CARD_VERSION} skipped: "sentinelle-card" is already defined by another file.`);
} else {
  customElements.define("sentinelle-card", SentinelleCard);
  window.customCards = window.customCards || [];
  if (!window.customCards.some((c) => c && c.type === "sentinelle-card")) {
    window.customCards.push({
      type: "sentinelle-card",
      name: "Sentinelle",
      description: "Rejected logins (Home Assistant + SSH): status, top IPs, latest attempts.",
      preview: true,
    });
  }
  console.info(`%c SENTINELLE-CARD %c v${SENTINELLE_CARD_VERSION} `, "background:#ef4444;color:#fff;border-radius:4px 0 0 4px;padding:2px 6px", "background:#17181c;color:#fff;border-radius:0 4px 4px 0;padding:2px 6px");
}
