// ---------------------------------------------------------------
// Rapport en "pages" : une vue d'ensemble (verdict + boutons) et une
// page dédiée par section, avec un bouton Retour.
// Ne modifie pas renderReport : on l'enveloppe simplement.
// ---------------------------------------------------------------
(function () {
  // id de l'élément contenu dans chaque panneau -> indice affiché sur le bouton
  const HINTS = {
    "panel-metadata": (r) => (r.metadonnees && r.metadonnees.taille_lisible) || "",
    "panel-type": (r) => (r.coherence_type.coherent === false ? "extension incohérente"
      : r.coherence_type.coherent ? "cohérent" : "indéterminé"),
    "panel-hashes": (r) => (r.empreintes.sha256 || "").slice(0, 12) + "…",
    "panel-entropy": (r) => r.entropie_obfuscation.entropie_globale + " / 8",
    "panel-static": (r) => (r.analyse_statique && r.analyse_statique.type_analyse) || "",
    "ioc-content": (r) => {
      const k = ["ips", "domaines", "urls", "emails", "chemins_windows", "chemins_unix", "cles_registre", "chaines_suspectes"];
      const f = window.cnRepFlagged ? window.cnRepFlagged(r) : 0;
      return k.reduce((n, x) => n + ((r.iocs && r.iocs[x]) || []).length, 0) + " indicateur(s)" + (f ? " · " + f + " signalé(s)" : "");
    },
    "panel-yara": (r) => (r.yara.disponible ? r.yara.matches.length + " règle(s)" : "indisponible"),
    "panel-clamav": (r) => (r.antivirus.disponible ? (r.antivirus.infecte ? "infecté" : "aucune détection") : "indisponible"),
    "panel-ml": (r) => (r.scoring_ml.probabilite_risque * 100).toFixed(1) + " %",
  };
  const ALERT_IF = {
    "panel-type": (r) => r.coherence_type.coherent === false,
    "panel-yara": (r) => !r.yara.disponible || r.yara.matches.length > 0,
    "panel-clamav": (r) => !r.antivirus.disponible || r.antivirus.infecte,
    "panel-hashes": (r) => r.empreintes.connu_malveillant,
    "ioc-content": (r) => (window.cnRepFlagged ? window.cnRepFlagged(r) : 0) > 0,
  };

  function panels() {
    return [...document.querySelectorAll("#report-grid > .panel:not(.panel-verdict)")];
  }
  function keyOf(panel) {
    return Object.keys(HINTS).find((id) => panel.querySelector("#" + id)) || null;
  }

  function showOverview() {
    const grid = document.getElementById("report-grid");
    grid.classList.remove("is-section-open");
    panels().forEach((p) => p.classList.remove("is-open"));
    document.getElementById("section-nav").hidden = false;
    document.getElementById("section-back").hidden = true;
    document.querySelector(".panel-verdict").hidden = false;
  }

  function showSection(panel) {
    const grid = document.getElementById("report-grid");
    grid.classList.add("is-section-open");
    panels().forEach((p) => p.classList.toggle("is-open", p === panel));
    document.getElementById("section-nav").hidden = true;
    document.querySelector(".panel-verdict").hidden = true;
    const back = document.getElementById("section-back");
    back.hidden = false;
    back.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setupSectionPages(r) {
    const grid = document.getElementById("report-grid");
    if (!grid.querySelector("#section-nav")) {
      const back = document.createElement("button");
      back.id = "section-back";
      back.className = "section-back";
      back.hidden = true;
      back.textContent = "← Retour au résumé";
      back.addEventListener("click", showOverview);
      const nav = document.createElement("div");
      nav.id = "section-nav";
      nav.className = "section-nav";
      const verdict = grid.querySelector(".panel-verdict");
      verdict.after(nav);
      grid.prepend(back);
    }
    const nav = document.getElementById("section-nav");
    nav.innerHTML = "";
    panels().forEach((p) => {
      p.classList.add("panel-section");
      const key = keyOf(p);
      const btn = document.createElement("button");
      btn.className = "stat-card section-btn" + (key && ALERT_IF[key] && ALERT_IF[key](r) ? " is-alert" : "");
      const title = p.querySelector("h3").textContent;
      let hint = "";
      try { hint = key ? HINTS[key](r) : ""; } catch (e) { /* indice facultatif */ }
      btn.innerHTML = `<span class="stat-label"></span><span class="stat-sub"></span>`;
      btn.children[0].textContent = title;
      btn.children[1].textContent = hint;
      btn.addEventListener("click", () => showSection(p));
      nav.appendChild(btn);
    });
    showOverview();
  }

  const original = renderReport;
  renderReport = function (r) {
    original(r);
    try { setupSectionPages(r); } catch (e) { console.error(e); }
  };
})();