// Vue d'ensemble du parc, page d'une machine, alertes, état des moteurs.
// Les cartes de chiffres sont cliquables : elles ouvrent la liste correspondante
// (tout le parc sur l'accueil, une seule machine sur la page d'une machine).
(function () {
  const $ = (id) => document.getElementById(id);
  const getJSON = async (u) => (await fetch(u)).json();
  const date = (t) => {
    if (!t) return "—";
    const d = typeof t === "number" ? new Date(t * 1000) : new Date(t);
    return isNaN(d) ? "—" : d.toLocaleString("fr-FR");
  };
  const name = (h) => (h === "local" ? "Cet agent (local)" : h);
  const badge = (v) => v ? `<span style="color:${VERDICT_COLORS[v] || "#A79A82"}">${esc(VERDICT_LABELS[v] || v)}</span>` : "—";
  const TITLES = {
    fichiers: "Fichiers analysés", suspects: "Fichiers suspects", malveillants: "Fichiers malveillants",
    quarantaine: "Fichiers en quarantaine", sandbox: "Sandbox à traiter", a_revoir: "Analyses incomplètes (à revoir)",
    alertes: "Alertes à traiter",
  };
  const state = { host: null, back: "machines", days: 7, sel: { home: null, machine: "fichiers" }, det: { k: "", n: "" }, topAt: 0 };

  // ---------- Cartes cliquables ----------
  function cards(el, c, scope) {
    const list = [["fichiers", c.fichiers], ["suspects", c.suspects], ["malveillants", c.malveillants],
      ["quarantaine", c.quarantaine], ["sandbox", c.sandbox_a_traiter], ["a_revoir", c.non_concluants]];
    const alert = { suspects: 1, malveillants: 1, sandbox: 1, a_revoir: 1 };
    el.innerHTML = (scope === "home"
      ? `<div class="stat-card is-static"><span class="stat-label">Machines</span><span class="stat-value">${c.machines}</span></div>` : "") +
      list.map(([k, n]) => `<button class="stat-card${state.sel[scope] === k ? " is-selected" : ""}${alert[k] && n > 0 ? " is-alert" : ""}" data-kind="${k}">
        <span class="stat-label">${esc(TITLES[k])}</span><span class="stat-value">${n}</span></button>`).join("");
    el.querySelectorAll("[data-kind]").forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.kind;
      state.sel[scope] = scope === "home" && state.sel.home === k ? null : k;
      cards(el, c, scope);
      loadItems(scope);
    }));
  }

  // ---------- Listes ----------
  async function loadItems(scope) {
    const box = $("items-" + scope);
    const kind = (scope === "alertes" || scope === "recent") ? "alertes" : state.sel[scope];
    if (!kind) { box.hidden = true; return; }
    const host = scope === "machine" ? state.host : "";
    const days = scope === "alertes" ? 0 : state.days;
    const extra = scope === "recent" ? "&limit=8"
      : kind === "detection" ? `&dkind=${state.det.k}&name=${encodeURIComponent(state.det.n)}` : "";
    const title = scope === "recent" ? "Dernières alertes"
      : kind === "detection" ? "Fichiers concernés : " + state.det.n : TITLES[kind];
    let d;
    try { d = await getJSON(`/api/items?kind=${kind}&host=${encodeURIComponent(host)}&days=${days}${extra}`); }
    catch (e) { box.hidden = false; box.innerHTML = `<p class="empty-note">Erreur de chargement : ${esc(e.message)}</p>`; return; }
    const showHost = scope !== "machine";
    const H = showHost ? "<th>Machine</th>" : "";
    const hostTd = (r) => (showHost ? `<td>${esc(name(r.host))}</td>` : "");
    let head, rows;
    if (kind === "sandbox") {
      head = `<tr>${H}<th>Fichier</th><th>Statut</th><th>Verdict comportemental</th><th>Menaces</th><th>Date</th></tr>`;
      rows = d.rows.map((e) => `<tr class="history-row" data-report="${esc(e.report_id)}">${hostTd(e)}<td>${esc(e.nom_original)}</td>
        <td>${esc(SANDBOX_STATUS_LABELS[e.statut] || e.statut)}</td><td>${esc(e.verdict || "—")}</td>
        <td>${esc((e.menaces_detectees || []).join(", ") || "—")}</td><td>${date(e.created_at)}</td></tr>`);
    } else if (kind === "quarantaine") {
      head = `<tr>${H}<th>Fichier</th><th>Niveau</th><th>Action</th><th>Date</th><th>Emplacement</th></tr>`;
      rows = d.rows.map((r) => `<tr class="history-row" data-report="${esc(r.id)}">${hostTd(r)}<td>${esc(r.nom)}</td>
        <td style="color:${STATUS_COLORS[r.niveau] || "inherit"}">${esc(r.niveau)} (${esc(r.score)})</td>
        <td>${esc(ACTION_LABELS[r.action] || r.action)}</td><td>${date(r.created_at)}</td><td>${esc(r.chemin || "—")}</td></tr>`);
    } else {
      head = `<tr>${H}<th>Fichier</th><th>Verdict</th><th>Score</th><th>Action</th><th>Date</th></tr>`;
      rows = d.rows.map((r) => `<tr class="history-row" data-report="${esc(r.id)}">${hostTd(r)}<td>${esc(r.nom)}</td><td>${badge(r.verdict)}</td>
        <td style="color:${STATUS_COLORS[r.niveau] || "inherit"}">${esc(r.score)}</td><td>${esc(ACTION_LABELS[r.action] || r.action)}</td><td>${date(r.created_at)}</td></tr>`);
    }
    box.hidden = false;
    box.innerHTML = `<div class="items-head"><h3>${esc(title)} <span>${d.rows.length}</span></h3>
      ${scope === "home" ? '<button class="mini-btn" data-close>✕ fermer</button>' : ""}</div>
      <table class="history-table"><thead>${head}</thead><tbody>${rows.join("") ||
      `<tr><td colspan="6">Rien à afficher ici.</td></tr>`}</tbody></table>`;
    box.querySelectorAll("tr[data-report]").forEach((tr) => tr.addEventListener("click", () => viewReportById(tr.dataset.report)));
    box.querySelector("[data-close]")?.addEventListener("click", () => { state.sel.home = null; loadHome(); });
  }

  // ---------- Accueil ----------
  function charts(d) {
    const cv = d.totaux.couverture;
    $("chart-coverage").innerHTML = cv === null ? `<p class="empty-note">Aucune analyse sur la période.</p>`
      : `<p class="big">${cv} %</p><div class="stack"><span style="width:${cv}%;background:#3C6E52"></span></div>
         <p class="empty-note" style="margin-top:12px">Part des analyses où tous les contrôles requis (ClamAV, YARA, analyse statique) ont tourné. Le reste est « non concluant » : ouvrez « Analyses incomplètes ».</p>`;
    const order = [["malicious", "Malveillant"], ["suspect", "Suspect"], ["inconclusive", "Non concluant"], ["clean", "Sain"]];
    const total = Object.values(d.verdicts).reduce((a, b) => a + b, 0) || 1;
    $("chart-verdicts").innerHTML =
      `<div class="stack">${order.map(([k]) => `<span style="width:${((d.verdicts[k] || 0) / total) * 100}%;background:${VERDICT_COLORS[k]}"></span>`).join("")}</div>
       <ul class="legend">${order.map(([k, l]) => `<li><i style="background:${VERDICT_COLORS[k]}"></i>${l} <b>${d.verdicts[k] || 0}</b></li>`).join("")}</ul>`;
    const max = Math.max(1, ...d.par_jour.map((j) => j.total));
    $("chart-days").innerHTML = d.par_jour.length
      ? `<div class="daybars">${d.par_jour.map((j) => `<div class="col" title="${esc(j.d)} : ${j.total} fichier(s), ${j.risque} à risque">
          <span class="t" style="height:${(j.total / max) * 100}%"><i class="r" style="height:${j.total ? (j.risque / j.total) * 100 : 0}%"></i></span></div>`).join("")}</div>
         <p class="empty-note">Barre = fichiers analysés ; partie orange = suspects ou malveillants.</p>`
      : `<p class="empty-note">Aucune analyse sur la période.</p>`;
  }

  async function loadHome() {
    const d = await getJSON(`/api/overview?days=${state.days}`);
    cards($("machines-stats"), d.totaux, "home");
    charts(d);
    $("machines-body").innerHTML = d.machines.length ? d.machines.map((m) => `
      <tr class="history-row" data-host="${esc(m.host)}">
        <td>${esc(name(m.host))}</td><td>${m.fichiers}</td>
        <td style="color:${m.suspects ? "#B5652E" : "inherit"}">${m.suspects}</td>
        <td style="color:${m.malveillants ? "#C0504D" : "inherit"}">${m.malveillants}</td>
        <td>${m.quarantaine}</td><td>${m.sandbox_a_traiter}</td><td>${date(m.derniere_activite)}</td></tr>`).join("")
      : `<tr><td colspan="7">Aucune machine sur cette période : les fichiers arrivent automatiquement depuis SecAgent.</td></tr>`;
    document.querySelectorAll("#machines-body tr[data-host]").forEach((tr) =>
      tr.addEventListener("click", () => openMachine(tr.dataset.host)));
    state.machines = d.machines;
    loadItems("home");
    loadItems("recent");
    loadTop();
  }

  // ---------- Détections les plus fréquentes ----------
  async function loadTop(force) {
    if (!force && Date.now() - state.topAt < 30000) return;
    state.topAt = Date.now();
    let t;
    try { t = await getJSON(`/api/top?days=${state.days}`); } catch (e) { return; }
    const wait = t.indexation_restante
      ? `<p class="empty-note">Indexation en cours : ${t.indexation_restante} rapport(s) restant(s) à résumer.</p>` : "";
    const list = (id, rows, dk, empty) => {
      $(id).innerHTML = (rows.length
        ? `<table class="history-table"><tbody>${rows.map((r) => `<tr class="history-row" data-dk="${dk}" data-name="${esc(r.name)}">
            <td style="word-break:break-all">${esc(r.name)}</td><td style="text-align:right">${r.n}</td></tr>`).join("")}</tbody></table>`
        : `<p class="empty-note">${empty}</p>`) + wait;
      $(id).querySelectorAll("tr[data-dk]").forEach((tr) => tr.addEventListener("click", () => {
        state.det = { k: tr.dataset.dk, n: tr.dataset.name };
        state.sel.home = "detection";
        loadItems("home").then(() => $("items-home").scrollIntoView({ behavior: "smooth", block: "nearest" }));
      }));
    };
    list("top-clamav", t.clamav, "clamav", "Aucune signature ClamAV détectée sur la période.");
    list("top-yara", t.yara, "yara", "Aucune règle YARA déclenchée sur la période.");
    list("top-ioc", t.ioc, "ioc", "Aucun indicateur signalé par les sources de réputation.");
    const max = Math.max(1, ...t.extensions.map((x) => x.n));
    $("top-ext").innerHTML = t.extensions.length ? `<div class="feature-bars">${t.extensions.map((x) => `<div class="feature-row">
      <span class="label">${esc(x.name)}</span><span class="track"><span class="fill" style="width:${(x.n / max) * 100}%"></span></span>
      <span class="value">${x.n}</span></div>`).join("")}</div>` : `<p class="empty-note">Aucun fichier sur la période.</p>`;
  }

  // ---------- Page d'une machine ----------
  function openMachine(host) {
    state.host = host; state.sel.machine = "fichiers";
    switchView("machine");
    $("machine-title").textContent = name(host);
    refreshMachine();
  }
  async function refreshMachine() {
    if (!state.host) return;
    const d = await getJSON(`/api/overview?days=${state.days}`);
    const m = d.machines.find((x) => x.host === state.host) ||
      { fichiers: 0, suspects: 0, malveillants: 0, quarantaine: 0, sandbox_a_traiter: 0, non_concluants: 0 };
    cards($("machine-stats"), m, "machine");
    loadItems("machine");
  }

  // ---------- État des moteurs ----------
  async function loadEngines() {
    const s = await getJSON("/api/status");
    const ti = s.threat_intelligence || {}, ar = s.archives_protegees || {};
    const sb = s.sandbox || {}, w = s.surveillance_automatique || {};
    const rows = [
      ["YARA", s.yara, "Règles de détection (module yara-python et fichier rules/generic_rules.yar)."],
      ["ClamAV", s.clamav, "Antivirus : module clamd installé ; le service clamd doit aussi tourner (Docker, port 3310)."],
      ["AbuseIPDB", ti.abuseipdb, "Réputation des adresses IP (ABUSEIPDB_API_KEY)."],
      ["AlienVault OTX", ti.otx, "Réputation des domaines, URLs et hashs (OTX_API_KEY)."],
      ["MalwareBazaar + URLhaus", ti.abusech_malwarebazaar_urlhaus, "Hashs et URLs de malwares connus (ABUSECH_AUTH_KEY)."],
      ["Archives .7z", ar["7z"], "Module py7zr."], ["Archives .rar", ar.rar, "Modules rarfile et unrar."],
      ["Sandbox Hybrid Analysis", sb.cle_api_configuree, "Test comportemental (HYBRID_ANALYSIS_API_KEY)."],
      ["Surveillance automatique", w.actif, `${w.fichiers_traites || 0} fichier(s) traité(s), ${(w.en_attente_nouveaux || 0) + (w.en_attente_arriere_plan || 0)} en file.`],
    ];
    $("engines-body").innerHTML = rows.map(([n, ok, note]) => `<tr><td>${esc(n)}</td>
      <td style="color:${ok ? "#3C6E52" : "#C0504D"}">${ok ? "actif" : "indisponible"}</td><td>${esc(note)}</td></tr>`).join("");
  }

  // ---------- Branchements ----------
  $("machine-back").addEventListener("click", () => switchView("machines"));
  $("report-back").addEventListener("click", () => switchView(state.back));
  $("period").addEventListener("change", (e) => { state.days = +e.target.value; state.topAt = 0; loadHome(); });

  const _switch = switchView;
  switchView = function (v) {
    _switch(v);
    if (v === "machine" || v === "analyse")
      document.querySelector(`.rail-link[data-view="${state.back === "alertes" ? "alertes" : "machines"}"]`)?.classList.add("is-active");
    if (v === "machines") loadHome();
    if (v === "alertes") loadItems("alertes");
    if (v === "moteurs") loadEngines();
  };
  const _view = viewReportById;
  viewReportById = function (id) {
    const cur = (document.querySelector(".view.is-active") || {}).id;
    if (cur && cur !== "view-analyse") state.back = cur.replace("view-", "");
    return _view(id);
  };

  loadHome();
  setInterval(() => {   // l'agent est automatique : l'écran se met à jour tout seul
    const cur = (document.querySelector(".view.is-active") || {}).id;
    if (cur === "view-machines") loadHome();
    else if (cur === "view-machine") refreshMachine();
    else if (cur === "view-alertes") loadItems("alertes");
    else if (cur === "view-moteurs") loadEngines();
  }, 5000);
})();