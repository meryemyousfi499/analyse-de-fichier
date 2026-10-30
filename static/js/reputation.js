// Réputation intégrée aux Indicateurs de compromission : chaque IP / domaine / URL
// affiche son score, son niveau et le résultat de chaque source, de façon visuelle.
// Quand une source a détecté quelque chose, sa pastille ouvre la fiche de l'indicateur.
(function () {
  let _ti = null, _sha = "";
  const FLAG = 25;  // à partir de ce score, l'indicateur est « signalé »
  const NAMES = { abuseipdb: "AbuseIPDB", otx: "OTX", urlhaus: "URLhaus", malwarebazaar: "MalwareBazaar" };
  const band = (s) => s === null ? ["Non vérifié", "#7A705C"] : s === 0 ? ["Non signalé", "#5FA37F"]
    : s < 25 ? ["Faible", "#C9A24C"] : s < 50 ? ["Moyen", "#D98A3D"] : s < 75 ? ["Élevé", "#D9534F"] : ["Critique", "#E0463E"];

  // Score 0-100 d'une source (null = source indisponible : jamais interprété comme « sain »).
  // Un seul ou deux pulses OTX restent faibles : beaucoup de sites légitimes y figurent.
  function sourceScore(src, res, type) {
    if (!res || !res.disponible) return null;
    if (src === "abuseipdb") return res.score_abus || 0;
    if (src === "otx") { const n = res.nombre_pulses || 0; return n === 0 ? 0 : n < 3 ? 12 * n : Math.min(80, 40 + 10 * n); }
    if (src === "urlhaus") return res.signale ? (type === "url" ? 100 : 80) : 0;
    if (src === "malwarebazaar") return res.signale ? 100 : 0;
    return res.signale ? 80 : 0;
  }

  // Fiche publique de l'indicateur chez la source (OTX : liste des pulses).
  function link(src, type, ind) {
    if (!ind) return null;
    const e = encodeURIComponent;
    if (src === "otx") {
      const t = type === "IP" ? "ip" : type === "domaine" ? (ind.split(".").length > 2 ? "hostname" : "domain")
        : type === "url" ? "url" : type === "hash" ? "file" : null;
      return t ? `https://otx.alienvault.com/indicator/${t}/${e(ind)}` : null;
    }
    if (src === "abuseipdb") return type === "IP" ? `https://www.abuseipdb.com/check/${e(ind)}` : null;
    if (src === "urlhaus") return type === "url" ? `https://urlhaus.abuse.ch/browse.php?search=${e(ind)}`
      : type === "domaine" ? `https://urlhaus.abuse.ch/host/${e(ind)}/` : null;
    if (src === "malwarebazaar") return type === "hash" ? `https://bazaar.abuse.ch/sample/${e(ind)}/` : null;
    return null;
  }

  function chip(src, res, type, ind) {
    const name = NAMES[src] || src, s = sourceScore(src, res, type);
    if (s === null) return { cls: "", text: `${name} · indisponible` };
    let t = "non signalé", seen = false;
    if (src === "abuseipdb") { t = `${res.score_abus}/100`; seen = res.score_abus > 0 || res.nombre_signalements > 0; }
    else if (src === "otx") { t = `${res.nombre_pulses} pulse(s)`; seen = res.nombre_pulses > 0; }
    else if (res.signale) { t = src === "malwarebazaar" ? "malware connu" : "signalé"; seen = true; }
    return {
      cls: s >= FLAG ? "bad" : "ok", text: `${name} · ${t}`,
      href: seen ? link(src, type, ind) : null,
      title: src === "otx" ? "Voir les pulses sur AlienVault OTX" : `Ouvrir la fiche sur ${name}`,
    };
  }
  function evaluate(type, sources, ind) {
    const scores = Object.entries(sources).map(([s, r]) => sourceScore(s, r, type)).filter((x) => x !== null);
    return {
      score: scores.length ? Math.max(...scores) : null,
      chips: Object.entries(sources).map(([s, r]) => chip(s, r, type, ind)),
    };
  }
  const TYPE = { ips: "IP", domaines: "domaine", urls: "url" };

  function allRows(ti, sha) {
    const out = [];
    if (ti.hash_fichier_analyse) out.push({ type: "hash", ...evaluate("hash", ti.hash_fichier_analyse, sha) });
    Object.keys(TYPE).forEach((g) => Object.entries(ti[g] || {}).forEach(([ind, src]) => out.push({ type: TYPE[g], ind, ...evaluate(TYPE[g], src, ind) })));
    return out;
  }
  window.cnRepFlagged = (r) => (r.threat_intelligence
    ? allRows(r.threat_intelligence, (r.empreintes || {}).sha256).filter((x) => x.score !== null && x.score >= FLAG).length : 0);

  function rowHtml(ind, ev, note, sub) {
    const [label, color] = note ? ["Non interrogé", "#7A705C"] : band(ev.score);
    const pct = ev.score === null ? 0 : ev.score;
    const chips = (ev.chips || []).map((c) => c.href
      ? `<a class="chip ${c.cls} link" href="${esc(c.href)}" target="_blank" rel="noopener noreferrer" title="${esc(c.title)}"><i></i>${esc(c.text)} ↗</a>`
      : `<span class="chip ${c.cls}"><i></i>${esc(c.text)}</span>`).join("")
      || `<span class="chip"><i></i>${esc(note || "aucune source")}</span>`;
    return `<div class="rep-row"><div class="rep-ind">${esc(ind)}${sub ? `<div class="rep-host">${sub}</div>` : ""}</div>
      <div class="rep-meter"><div class="rep-score"><b style="color:${color}">${label}</b><span>${ev.score === null ? "—" : ev.score + " / 100"}</span></div>
      <div class="rep-bar"><span style="width:${pct}%;background:${color}"></span></div></div>
      <div class="rep-chips">${chips}</div></div>`;
  }
  window.cnRep = { evaluate, rowHtml, FLAG };

  // Hôtes des URLs signalées (score le plus élevé par hôte)
  function flaggedUrlHosts() {
    const out = {};
    Object.entries((_ti && _ti.urls) || {}).forEach(([u, src]) => {
      const sc = evaluate("url", src, u).score;
      if (sc === null || sc < FLAG) return;
      let host = ""; try { host = new URL(u).hostname.toLowerCase(); } catch (e) { return; }
      if (host && (!out[host] || out[host] < sc)) out[host] = sc;
    });
    return out;
  }
  const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return ""; } };

  // Onglets IP / Domaines / URLs
  const _showIOC = showIOCTab;
  showIOCTab = function (iocs, key) {
    const type = TYPE[key];
    if (!type) return _showIOC(iocs, key);
    const rows = (iocs[key] || []).map((ind) => {
      const src = _ti && _ti[key] && _ti[key][ind];
      const sub = key === "urls" && hostOf(ind) ? "hôte : " + esc(hostOf(ind)) : "";
      return src ? { ind, sub, ev: evaluate(type, src, ind) }
        : { ind, sub, ev: { score: null, chips: [] }, note: _ti ? "limite TI_MAX_LOOKUPS" : "réputation non exécutée" };
    });
    if (key === "domaines") {   // l'hôte d'une URL signalée est signalé lui aussi
      Object.entries(flaggedUrlHosts()).forEach(([host, sc]) => {
        const via = { cls: "bad", text: "hôte d'une URL signalée" };
        const row = rows.find((x) => x.ind.toLowerCase() === host);
        if (row) row.ev = { score: Math.max(row.ev.score ?? 0, sc), chips: [...row.ev.chips, via] };
        else rows.push({ ind: host, sub: "", ev: { score: sc, chips: [via] } });
      });
    }
    if (!rows.length) return _showIOC(iocs, key);
    rows.sort((a, b) => (b.ev.score ?? -1) - (a.ev.score ?? -1));
    const ok = rows.filter((x) => x.ev.score !== null), bad = ok.filter((x) => x.ev.score >= FLAG);
    const h = _ti && _ti.hash_fichier_analyse ? evaluate("hash", _ti.hash_fichier_analyse, _sha) : null;
    let html = `<div class="rep-summary">
      <span class="pill ${bad.length ? "bad" : "ok"}">${bad.length} signalé(s)</span>
      <span class="pill">${ok.length} vérifié(s)</span>
      ${rows.length - ok.length ? `<span class="pill off">${rows.length - ok.length} non vérifié(s)</span>` : ""}
      ${h ? `<span class="pill ${h.score === null ? "off" : h.score >= FLAG ? "bad" : "ok"}">Hash du fichier : ${h.score === null ? "non vérifié" : h.score >= FLAG ? "signalé" : "non signalé"}</span>` : ""}</div>`;
    if (!_ti || !_ti.au_moins_une_source_disponible)
      html += `<div class="rep-warn">Aucune source de réputation n'est joignable (clés API manquantes ou réseau) : ces éléments ne sont pas vérifiés, ce qui ne veut pas dire qu'ils sont sains. Voir « État des moteurs ».</div>`;
    document.getElementById("ioc-content").innerHTML = html + rows.map((x) => rowHtml(x.ind, x.ev, x.note, x.sub)).join("");
  };

  const _render = renderReport;
  renderReport = function (r) {
    _ti = r.threat_intelligence || null;   // avant le rendu : les onglets IOC en ont besoin
    _sha = (r.empreintes || {}).sha256 || "";
    _render(r);
    try {  // onglet rouge quand il contient un indicateur signalé
      const btns = document.querySelectorAll("#ioc-tabs .ioc-tab");
      ["ips", "domaines", "urls"].forEach((k, i) => {
        let bad = (r.iocs[k] || []).some((ind) => { const s = _ti && _ti[k] && _ti[k][ind]; const v = s && evaluate(TYPE[k], s, ind).score; return v !== null && v >= FLAG; });
        if (k === "domaines" && Object.keys(flaggedUrlHosts()).length) bad = true;
        btns[i]?.classList.toggle("is-flagged", !!bad);
      });
    } catch (e) { console.error(e); }
  };
})();