// Rendu visuel des panneaux du rapport : empreintes, YARA, ClamAV, analyse statique,
// métadonnées, cohérence du type, entropie. Même style que les Indicateurs de compromission.
(function () {
  const $ = (id) => document.getElementById(id);
  const pill = (t, c = "") => `<span class="pill ${c}">${esc(t)}</span>`;
  const warn = (html) => `<div class="rep-warn">${html}</div>`;
  const note = (t) => `<p class="empty-note">${t}</p>`;
  // on = la propriété est présente ; bad = sa présence est un signal négatif
  const flag = (label, on, bad = true) => `<div class="flag-row"><span>${esc(label)}</span>${pill(on ? "oui" : "non", on ? (bad ? "bad" : "ok") : (bad ? "ok" : "off"))}</div>`;
  const tile = (l, v) => `<div class="tile"><span>${esc(l)}</span><b>${esc(v ?? "—")}</b></div>`;
  const show = (id, html) => { const el = $(id); if (el) { el.className = "vis"; el.innerHTML = html; } };

  // ---------- Empreintes ----------
  function hashes(r) {
    const e = r.empreintes || {}, ti = r.threat_intelligence, R = window.cnRep;
    const rep = ti && ti.hash_fichier_analyse ? R.evaluate("hash", ti.hash_fichier_analyse, e.sha256) : null;
    const repPill = !rep ? pill("Réputation : non exécutée", "off")
      : rep.score === null ? pill("Réputation : non vérifiée", "off")
      : rep.score >= R.FLAG ? pill("Réputation : signalé", "bad") : pill("Réputation : non signalé", "ok");
    const rows = [["SHA-256", e.sha256], ["SHA-1", e.sha1], ["MD5", e.md5]].map(([l, v]) =>
      `<div class="hash-row"><span class="hash-label">${l}</span><code class="hash-val">${esc(v)}</code><button class="copy-btn" data-copy="${esc(v)}">Copier</button></div>`).join("");
    show("panel-hashes",
      `<div class="rep-summary">${pill(e.connu_malveillant ? "Base locale : hash malveillant connu" : "Base locale : hash non connu", e.connu_malveillant ? "bad" : "ok")}${repPill}</div>` +
      rows + `<h4 class="vis-title">Vérification du SHA-256 auprès des sources de réputation</h4>` +
      (rep ? R.rowHtml("SHA-256 du fichier", rep) : note("Aucune vérification externe pour ce fichier.")) +
      note("Seul le SHA-256 est interrogé ; SHA-1 et MD5 sont affichés pour information."));
    $("panel-hashes").querySelectorAll(".copy-btn").forEach((b) => b.addEventListener("click", () => {
      navigator.clipboard?.writeText(b.dataset.copy); b.textContent = "Copié ✓"; setTimeout(() => (b.textContent = "Copier"), 1500);
    }));
  }

  // ---------- YARA ----------
  const SEV = { critique: [100, "#E0463E", "Critique"], eleve: [75, "#D9534F", "Élevée"], moyen: [45, "#D98A3D", "Moyenne"] };
  function yara(r) {
    const y = r.yara || {};
    if (!y.disponible) return show("panel-yara", warn(`<b>Les règles YARA n'ont pas été appliquées.</b><br>${esc(y.raison || "raison inconnue")}<br>
      Le point vert du menu indique seulement que le module est installé. Corrigez <code>rules/generic_rules.yar</code> : la page « État des moteurs » indique si les règles se compilent. Relancez ensuite l'analyse : un rapport garde le résultat de son époque.`));
    const m = y.matches || [];
    show("panel-yara", `<div class="rep-summary">${pill("Règles chargées", "ok")}${pill(m.length + " déclenchée(s)", m.length ? "bad" : "ok")}${y.version_regles ? pill("version " + y.version_regles) : ""}</div>` +
      (m.length ? m.map((x) => { const [w, c, l] = SEV[x.severite] || [25, "#C9A24C", x.severite || "?"];
        return `<div class="rep-row"><div class="rep-ind">${esc(x.regle)}</div>
          <div class="rep-meter"><div class="rep-score"><b style="color:${c}">${esc(l)}</b></div><div class="rep-bar"><span style="width:${w}%;background:${c}"></span></div></div>
          <div class="rep-desc">${esc(x.description)}</div></div>`; }).join("")
        : `<div class="status-card ok"><span class="status-ico">✓</span><div><b>Aucune règle déclenchée</b><span>Le fichier ne correspond à aucune règle YARA chargée</span></div></div>`));
  }

  // ---------- ClamAV ----------
  function clam(r) {
    const a = r.antivirus || {};
    if (!a.disponible) return show("panel-clamav", warn(`<b>ClamAV n'a pas analysé ce fichier.</b><br>${esc(a.raison || "")}<br>
      Installez le module (<code>pip install clamd</code>) et lancez le service ClamAV (Docker, port 3310). Sans lui l'analyse reste incomplète.`));
    show("panel-clamav", `<div class="status-card ${a.infecte ? "bad" : "ok"}"><span class="status-ico">${a.infecte ? "✕" : "✓"}</span>
      <div><b>${a.infecte ? "Signature détectée" : "Aucune signature détectée"}</b><span>${a.infecte ? esc(a.signature) : "Analyse ClamAV terminée"}</span></div></div>` +
      (a.statut_brut ? `<div class="flag-row"><span>Statut ClamAV</span>${pill(a.statut_brut)}</div>` : ""));
  }

  // ---------- Analyse statique ----------
  function statique(r) {
    const sa = r.analyse_statique || {};
    let h = sa.type_analyse ? `<div class="rep-summary">${pill("Type analysé : " + sa.type_analyse)}</div>` : "";
    const chips = (list, bad) => list && list.length ? `<div class="rep-chips">${list.map((x) => `<span class="chip ${bad ? "bad" : ""}"><i></i>${esc(x)}</span>`).join("")}</div>` : "";
    if (sa.pdf) { const p = sa.pdf;
      h += p.disponible ? `<div class="flag-grid">${flag("JavaScript embarqué", p.javascript_embarque)}${flag("Action d'ouverture automatique", p.action_ouverture)}
        ${flag("Fichiers embarqués", p.fichiers_embarques)}${flag("Action /Launch", p.action_launch)}</div>${p.nombre_pages != null ? `<div class="rep-summary">${pill(p.nombre_pages + " page(s)")}</div>` : ""}`
        : warn(esc(p.raison)); }
    if (sa.office) { const o = sa.office;
      h += o.disponible ? `<div class="flag-grid">${flag("Macros présentes", o.macros_presentes)}${flag("Exécution automatique", (o.auto_execution || []).length > 0)}</div>` +
        (o.macros_presentes ? `<h4 class="vis-title">Exécution automatique</h4>${chips(o.auto_execution, true) || note("aucune")}<h4 class="vis-title">Indicateurs dans les macros</h4>${chips(o.iocs_macro, true) || note("aucun")}` : "")
        : warn(esc(o.raison)); }
    if (sa.pe) { const p = sa.pe;
      h += p.disponible ? `<div class="rep-summary">${pill(p.type)}${pill("architecture " + p.architecture)}${pill("entrée " + p.point_entree)}</div>
        <div class="flag-grid">${flag("Packer suspecté", p.packer_suspecte)}${flag("Signature numérique présente", p.signature_presente, false)}</div>
        <h4 class="vis-title">Imports dangereux</h4>${chips(p.imports_dangereux_detectes, true) || note("aucun")}
        <h4 class="vis-title">Sections</h4>${(p.sections || []).map((s) => { const c = s.entropie >= 7 ? "#D98A3D" : "#5FA37F";
          return `<div class="rep-row"><div class="rep-ind">${esc(s.nom)}</div><div class="rep-meter"><div class="rep-score"><span>entropie</span><b style="color:${c}">${esc(s.entropie)} / 8</b></div>
          <div class="rep-bar"><span style="width:${(s.entropie / 8) * 100}%;background:${c}"></span></div></div><div class="rep-chips">${s.executable ? '<span class="chip">exécutable</span>' : ""}${s.ecriture ? '<span class="chip">écriture</span>' : ""}</div></div>`; }).join("")}`
        : warn(esc(p.raison)); }
    if (sa.elf) h += `<div class="rep-summary">${pill(sa.elf.classe || "")}${pill(sa.elf.endianness || "")}</div>${note(esc(sa.elf.note || ""))}`;
    if (sa.image) { const i = sa.image;
      h += `<div class="rep-summary">${i.dimensions ? pill(i.dimensions + " px") : ""}</div><div class="flag-grid">${flag("Données cachées après la fin de l'image", i.donnees_ajoutees_apres_fin)}</div>` +
        (i.donnees_ajoutees_apres_fin ? warn(`${esc(i.taille_donnees_ajoutees_octets)} octets ajoutés après la fin officielle du fichier.`) : ""); }
    if (sa.note) h += note(esc(sa.note));
    show("panel-static", h || note("Aucune analyse structurelle pour ce type de fichier."));
  }

  // ---------- Métadonnées, type, entropie ----------
  const ZONES = ["Ordinateur local", "Intranet local", "Sites de confiance", "Internet", "Sites sensibles"];
  function metadata(r) {
    const m = r.metadonnees || {}; let zone = "non applicable";
    if (m.zone_origine) { const z = /ZoneId=(\d)/.exec(m.zone_origine); zone = z ? ZONES[+z[1]] || "Zone " + z[1] : "présente"; const u = /HostUrl=(\S+)/.exec(m.zone_origine); if (u) zone += " · " + u[1].slice(0, 40); }
    show("panel-metadata", `<div class="tiles">${tile("Nom", m.nom)}${tile("Extension", m.extension)}${tile("Taille", m.taille_lisible)}${tile("Type MIME réel", m.mime_reel)}
      ${tile("Propriétaire", m.proprietaire)}${tile("Permissions", m.permissions)}${tile("Modifié le", m.date_modification)}${tile("Origine", zone)}</div>`);
  }
  function type(r) {
    const c = r.coherence_type || {};
    const st = c.coherent === null ? ["Indéterminé", "off"] : c.coherent ? ["Cohérent", "ok"] : ["Incohérent", "bad"];
    show("panel-type", `<div class="rep-summary">${pill(st[0], st[1])}</div><div class="tiles">${tile("Extension déclarée", c.extension_declaree)}${tile("Type réel détecté", c.type_reel_detecte)}</div>` +
      (c.alerte ? warn(esc(c.commentaire)) : note(esc(c.commentaire || ""))));
  }
  function entropie(r) {
    const e = r.entropie_obfuscation || {}, v = e.entropie_globale || 0, nat = e.format_naturellement_compresse;
    const [lab, col] = nat ? [v >= 7.2 ? "Élevée, normale pour ce format compressé" : "Normale", "#C9A24C"]
      : v >= 7.2 ? ["Très élevée : chiffrement ou packer possible", "#D9534F"] : v >= 6.5 ? ["Élevée", "#D98A3D"] : ["Normale", "#5FA37F"];
    const b64 = (e.base64 || {}).nombre_blobs_base64, xor = e.xor || {};
    show("panel-entropy", `<div class="rep-meter"><div class="rep-score"><b style="color:${col}">${lab}</b><span>${v} / 8</span></div>
      <div class="rep-bar"><span style="width:${(v / 8) * 100}%;background:${col}"></span></div></div>
      <div class="flag-grid" style="margin-top:12px"><div class="flag-row"><span>Blobs Base64</span>${pill(String(b64 ?? "—"), b64 >= 3 ? "bad" : "ok")}</div>
      <div class="flag-row"><span>XOR simple</span>${xor.xor_simple_suspecte ? pill("indice faible · clé " + xor.cle_probable, "warn") : pill("non", "ok")}</div></div>`);
  }

  const _render = renderReport;
  renderReport = function (r) {
    _render(r);
    try { hashes(r); yara(r); clam(r); statique(r); metadata(r); type(r); entropie(r); } catch (e) { console.error(e); }
  };
})();