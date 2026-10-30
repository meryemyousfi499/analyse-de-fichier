// Réputation automatique des indicateurs (IP, domaines, URLs, hash) extraits du fichier.
// Les données viennent de r.threat_intelligence, déjà calculé par l'agent à chaque analyse.
(function () {
  const LEVELS = [[75, "critique"], [50, "eleve"], [25, "moyen"], [0, "faible"]];
  const level = (s) => LEVELS.find(([min]) => s >= min)[1];
  let _ti = null;

  // Score 0-100 d'une source (null = source non disponible : jamais "sain")
  function sourceScore(src, res, type) {
    if (!res || !res.disponible) return null;
    if (src === "abuseipdb") return res.score_abus || 0;
    if (src === "otx") return res.nombre_pulses > 0 ? Math.min(90, 30 + 15 * res.nombre_pulses) : 0;
    if (src === "urlhaus") return res.signale ? (type === "url" ? 100 : 80) : 0;
    if (src === "malwarebazaar") return res.signale ? 100 : 0;
    return res.signale ? 80 : 0;
  }
  function sourceLabel(src, res) {
    if (!res || !res.disponible) return `${src} : indisponible`;
    if (src === "abuseipdb") return `${src} : ${res.score_abus}/100 (${res.nombre_signalements || 0} signalement(s))`;
    if (src === "otx") return `${src} : ${res.nombre_pulses} pulse(s)`;
    if (src === "malwarebazaar") return `${src} : ${res.signale ? "malware connu" + (res.signature ? " (" + res.signature + ")" : "") : "inconnu"}`;
    return `${src} : ${res.signale ? "signalé" : "non signalé"}`;
  }
  function evaluate(type, sources) {
    const scores = Object.entries(sources).map(([s, r]) => sourceScore(s, r, type)).filter((x) => x !== null);
    return {
      score: scores.length ? Math.max(...scores) : null,
      detail: Object.entries(sources).map(([s, r]) => sourceLabel(s, r)).join(" · "),
    };
  }
  const scoreHtml = (s) => s === null
    ? `<span style="color:#A79A82">non vérifié</span>`
    : `<span style="color:${STATUS_COLORS[level(s)]}">${s} / 100</span>`;

  function rows(ti) {
    const out = [];
    const add = (type, ind, sources) => out.push({ type, ind, ...evaluate(type, sources) });
    if (ti.hash_fichier_analyse) add("hash du fichier", "SHA-256 du fichier analysé", ti.hash_fichier_analyse);
    [["ips", "IP"], ["domaines", "domaine"], ["urls", "url"], ["hashs", "hash intégré"]].forEach(([g, label]) =>
      Object.entries(ti[g] || {}).forEach(([ind, src]) => add(label, ind, src)));
    return out.sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  }

  function renderReputation(r) {
    const el = document.getElementById("panel-reputation");
    if (!el) return;
    const ti = r.threat_intelligence;
    if (!ti) { el.innerHTML = `<p class="empty-note">Vérification de réputation non exécutée pour ce fichier.</p>`; return; }
    const list = rows(ti);
    const verifies = list.filter((x) => x.score !== null);
    const signales = verifies.filter((x) => x.score >= 25);
    const nonVerifies = list.length - verifies.length;
    const iocs = r.iocs || {};
    const extraits = ["ips", "domaines", "urls"].reduce((n, k) => n + (iocs[k] || []).length, 0);
    const controles = ["ips", "domaines", "urls"].reduce((n, k) => n + Object.keys(ti[k] || {}).length, 0);
    let html = `<p class="empty-note" style="margin-bottom:10px">${verifies.length} élément(s) vérifié(s), ${signales.length} signalé(s)` +
      (nonVerifies ? `, ${nonVerifies} non vérifié(s) (source indisponible : clé API manquante ou réseau)` : "") + `.</p>`;
    if (!ti.au_moins_une_source_disponible)
      html += `<p class="empty-note">Aucune source de réputation n'est joignable : vérifiez les clés dans le fichier .env (voir « État des moteurs »). Un élément non vérifié n'est pas un élément sain.</p>`;
    if (extraits > controles) html += `<p class="empty-note">${extraits - controles} indicateur(s) extrait(s) non interrogé(s) (limite TI_MAX_LOOKUPS).</p>`;
    html += list.length
      ? `<table class="history-table"><thead><tr><th>Type</th><th>Indicateur</th><th>Score</th><th>Sources</th></tr></thead><tbody>` +
        list.map((x) => `<tr><td>${esc(x.type)}</td><td style="word-break:break-all">${esc(x.ind)}</td><td>${scoreHtml(x.score)}</td>
          <td style="font-size:11.5px">${esc(x.detail)}</td></tr>`).join("") + `</tbody></table>`
      : `<p class="empty-note">Aucun indicateur à vérifier dans ce fichier.</p>`;
    el.innerHTML = html;
  }

  // Onglets IP / Domaines / URLs : chaque élément affiche directement son score.
  const _showIOC = showIOCTab;
  showIOCTab = function (iocs, key) {
    const group = { ips: "ips", domaines: "domaines", urls: "urls" }[key];
    const items = iocs[key] || [];
    if (!group || !items.length) return _showIOC(iocs, key);
    const type = key === "urls" ? "url" : key === "ips" ? "IP" : "domaine";
    const lines = items.map((ind) => {
      const src = _ti && _ti[group] && _ti[group][ind];
      let txt;
      if (!_ti) txt = `<span style="color:#A79A82">non vérifié (réputation non exécutée)</span>`;
      else if (!src) txt = `<span style="color:#A79A82">non interrogé (limite TI_MAX_LOOKUPS)</span>`;
      else { const e = evaluate(type, src); txt = `${scoreHtml(e.score)} — ${esc(e.detail)}`; }
      return `${esc(ind)}  →  ${txt}`;
    });
    document.getElementById("ioc-content").innerHTML = `<div class="mono-block">${lines.join("\n")}</div>`;
  };

  const _render = renderReport;
  renderReport = function (r) {
    _ti = r.threat_intelligence || null;   // avant le rendu : les onglets IOC en ont besoin
    _render(r);
    try { renderReputation(r); } catch (e) { console.error(e); }
  };
})();