const STATUS_COLORS = {
  faible: "#3C6E52",
  moyen: "#B8863B",
  eleve: "#B5652E",
  critique: "#7A2A2A",
};

const ACTION_LABELS = {
  allow: "Autoriser",
  monitor: "Surveiller",
  quarantine: "Mettre en quarantaine",
  block: "Bloquer",
  alert: "Alerter un analyste",
  human_review: "Revue humaine requise",
};

// ---------------- Utilitaires ----------------
// Les noms de fichiers, IOC et noms de sections viennent du fichier analysé
// (donc d'un attaquant potentiel) : toujours échapper avant innerHTML.
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

// Une "menace" peut être une chaîne (ancien format) ou un objet MITRE
// ATT&CK {tactic, technique, attck_id, ...} : jamais afficher [object Object].
function threatLabel(t) {
  if (t == null) return "";
  if (typeof t === "string") return t;
  const base = [t.attck_id, t.technique].filter(Boolean).join(" ") || "technique inconnue";
  return t.tactic ? `${base} (${t.tactic})` : base;
}

// Sépare menaces réelles (identifiants malveillants/suspects) et comportements
// simplement informatifs. Gère les anciennes entrées (objets MITRE dans
// menaces_detectees) et le nouveau format (menaces_detectees = menaces réelles,
// comportements_informatifs = le reste).
function splitThreats(e) {
  const real = [];
  const info = (e.comportements_informatifs || []).map(threatLabel);
  (e.menaces_detectees || []).forEach((t) => {
    if (t && typeof t === "object") {
      const mal = (t.malicious_identifiers_count || 0) + (t.suspicious_identifiers_count || 0);
      (mal > 0 ? real : info).push(threatLabel(t));
    } else if (t) {
      real.push(String(t));
    }
  });
  return { real, info };
}

function parseTs(v) {
  if (!v) return null;
  const d = typeof v === "number" ? new Date(v * 1000) : new Date(v);
  return isNaN(d) ? null : d;
}

const VERDICT_LABELS = {
  clean: "Sain (analyse complète)",
  suspect: "Suspect",
  malicious: "Malveillant (preuve forte)",
  inconclusive: "Non concluant (analyse incomplète)",
};
const VERDICT_COLORS = {
  clean: "#3C6E52", suspect: "#B5652E", malicious: "#7A2A2A", inconclusive: "#B8863B",
};
const TOOL_STATUS_LABELS = {
  ok: "ok", detected: "détection", error: "erreur", unavailable: "indisponible",
  not_applicable: "non applicable", skipped: "non lancé", pending: "en attente",
};

// ---------------- Statut des moteurs ----------------
async function loadEngineStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    setDot("yara", data.yara);
    setDot("clamav", data.clamav);

    const ti = data.threat_intelligence || {};
    setDot("ti", Object.values(ti).some(Boolean));

    const archives = data.archives_protegees || {};
    setDot("archives", Object.values(archives).some(Boolean));
  } catch (err) { /* silencieux : le dashboard reste utilisable */ }
}
function setDot(key, isOn) {
  const li = document.querySelector(`#engine-status li[data-engine="${key}"] .dot`);
  if (li) li.className = "dot " + (isOn ? "dot-on" : "dot-off");
}
loadEngineStatus();

// ---------------- Navigation ----------------
function switchView(viewName) {
  const railBtn = document.querySelector(`.rail-link[data-view="${viewName}"]`);
  document.querySelectorAll(".rail-link").forEach((b) => b.classList.remove("is-active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("is-active"));
  if (railBtn) railBtn.classList.add("is-active");
  const viewEl = document.getElementById("view-" + viewName);
  if (viewEl) viewEl.classList.add("is-active");
  if (viewName === "historique") loadHistory();
  if (viewName === "sandbox") loadSandbox();
  if (viewName === "watch-current" || viewName === "watch-queue") {
    loadWatchDetail();
  }
}

document.querySelectorAll(".rail-link").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

document.querySelectorAll(".stat-card[data-nav]").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.nav));
});

document.getElementById("stat-last-report")?.addEventListener("click", () => {
  if (_lastReportId) viewReportById(_lastReportId);
});

// ---------------- Vérification manuelle d'un indicateur ----------------
const indicatorForm = document.getElementById("indicator-form");
if (indicatorForm) {
  indicatorForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const type = document.getElementById("indicator-type").value;
    const indicateur = document.getElementById("indicator-value").value.trim();
    const out = document.getElementById("indicator-result");
    if (!indicateur) return;
    out.textContent = "Vérification en cours...";
    try {
      const res = await fetch("/api/check-indicator", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicateur, type }),
      });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      out.textContent = "Erreur reseau : " + err.message;
    }
  });
}

// ---------------- Surveillance automatique : 3 pages dédiées ----------------
// Entièrement automatique (démarre avec le serveur) : ces pages sont en
// lecture seule, aucun bouton suspendre/reprendre. Chaque bouton du
// tableau de bord ouvre la page dédiée à SA statistique, et cette page
// se rafraîchit toute seule tant qu'elle reste affichée.
let _watchPollTimer = null;

function _activeWatchView() {
  return ["watch-current", "watch-queue"].find(
    (v) => document.getElementById("view-" + v)?.classList.contains("is-active")
  );
}

function fillKVList(id, rows) {
  const dl = document.getElementById(id);
  if (!dl) return;
  dl.innerHTML = "";
  rows.forEach(([k, v]) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd");
    if (v instanceof Node) dd.appendChild(v); else dd.textContent = v;
    dl.appendChild(dt); dl.appendChild(dd);
  });
}

let _watchLastReportId = null;

function renderWatchCurrent(state) {
  const dot = document.getElementById("watch-current-dot");
  const label = document.getElementById("watch-current-label");
  const sub = document.getElementById("watch-current-sub");
  if (state.fichier_en_cours) {
    dot?.classList.add("is-active");
    if (label) label.textContent = state.fichier_en_cours.split(/[\\/]/).pop();
    if (sub) sub.textContent = "analyse en cours…";
  } else {
    dot?.classList.remove("is-active");
    if (label) label.textContent = "Aucun fichier en cours";
    if (sub) sub.textContent = "La file d'attente est vide pour l'instant.";
  }

  const btn = document.getElementById("watch-lastfile-btn");
  const nameEl = document.getElementById("watch-lastfile-name");
  const subEl = document.getElementById("watch-lastfile-sub");
  _watchLastReportId = state.dernier_rapport_id || null;
  if (btn) {
    if (state.dernier_fichier) {
      btn.hidden = false;
      if (nameEl) nameEl.textContent = state.dernier_fichier.split(/[\\/]/).pop();
      if (subEl) subEl.textContent = _watchLastReportId ? `rapport ${_watchLastReportId} — voir le détail` : "voir le détail";
    } else {
      btn.hidden = true;
    }
  }
}

document.getElementById("watch-lastfile-btn")?.addEventListener("click", () => {
  if (_watchLastReportId) viewReportById(_watchLastReportId);
});

const PRIORITY_LABELS = { nouveau: "Nouveau téléchargement", arriere_plan: "Arrière-plan" };

function renderWatchQueueTable(items) {
  const tbody = document.getElementById("watch-queue-body");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="3">File d'attente vide pour l'instant.</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map((it) => `
    <tr>
      <td>${it.nom}</td>
      <td>${it.dossier || "—"}</td>
      <td>${PRIORITY_LABELS[it.priorite] || it.priorite}</td>
    </tr>`).join("");
}

async function loadWatchDetail() {
  clearTimeout(_watchPollTimer);
  try {
    const res = await fetch("/api/watch/status");
    renderWatchCurrent(await res.json());
  } catch (err) { /* silencieux */ }

  if (document.getElementById("view-watch-queue")?.classList.contains("is-active")) {
    try {
      const res = await fetch("/api/watch/queue");
      renderWatchQueueTable(await res.json());
    } catch (err) { /* silencieux */ }
  }

  // Tant qu'une de ces pages est affichée, on la rafraîchit toute seule
  // pour suivre en direct l'arrivée d'un nouveau téléchargement.
  if (_activeWatchView()) {
    _watchPollTimer = setTimeout(loadWatchDetail, 2000);
  }
}

// ---------------- Tableau de bord global : stats-bar + indicateurs du rail ----------------
// Contrairement au rafraichissement de la vue "Surveillance" (qui ne tourne
// que si cette vue est ouverte), ce polling tourne en continu quelle que
// soit la vue affichee, pour que la barre de statistiques et les puces du
// rail refletent toujours l'etat reel sans action de l'utilisateur.
let _lastReportId = null;
let _lastReportName = null;

async function refreshGlobalStats() {
  try {
    const [watchRes, sandboxRes] = await Promise.all([
      fetch("/api/watch/status"),
      fetch("/api/sandbox/status"),
    ]);
    const watch = await watchRes.json();
    const sandbox = await sandboxRes.json();

    // Rail
    const railSandboxCount = document.getElementById("rail-sandbox-count");
    const enAttenteSandbox = (sandbox.en_attente || 0) + (sandbox.en_cours || 0);
    if (railSandboxCount) railSandboxCount.textContent = enAttenteSandbox > 0 ? enAttenteSandbox : "";

    // Stats-bar : fichier en cours d'analyse
    const statCurrent = document.getElementById("stat-watch-current");
    const statCurrentSub = document.getElementById("stat-watch-current-sub");
    if (statCurrent) {
      statCurrent.textContent = watch.fichier_en_cours
        ? watch.fichier_en_cours.split(/[\\/]/).pop()
        : "—";
    }
    if (statCurrentSub) {
      statCurrentSub.textContent = watch.fichier_en_cours ? "analyse en cours…" : "aucun fichier en cours";
    }

    // Stats-bar : fichiers traités / file d'attente
    const statTotal = document.getElementById("stat-files-total");
    if (statTotal) statTotal.textContent = watch.fichiers_traites ?? 0;
    const statQueue = document.getElementById("stat-files-queue");
    if (statQueue) statQueue.textContent = (watch.en_attente_nouveaux || 0) + (watch.en_attente_arriere_plan || 0);

    // Stats-bar : sandbox
    const statSandboxTotal = document.getElementById("stat-sandbox-total");
    if (statSandboxTotal) statSandboxTotal.textContent = sandbox.total ?? 0;
    const statSandboxSub = document.getElementById("stat-sandbox-sub");
    const sandboxCard = statSandboxTotal ? statSandboxTotal.closest(".stat-card") : null;
    if (statSandboxSub) {
      if (!sandbox.cle_api_configuree) {
        statSandboxSub.textContent = "clé API absente — voir Sandbox";
        if (sandboxCard) sandboxCard.classList.add("is-alert");
      } else {
        statSandboxSub.textContent = `${sandbox.en_attente || 0} en attente, ${sandbox.en_cours || 0} en cours`;
        if (sandboxCard) sandboxCard.classList.remove("is-alert");
      }
    }

    // Stats-bar : dernier rapport
    if (watch.dernier_rapport_id) {
      _lastReportId = watch.dernier_rapport_id;
      _lastReportName = watch.dernier_fichier || null;
      const idEl = document.getElementById("stat-last-report-id");
      const nameEl = document.getElementById("stat-last-report-name");
      if (idEl) idEl.textContent = _lastReportId;
      if (nameEl) nameEl.textContent = _lastReportName ? _lastReportName.split(/[\\/]/).pop() : "voir le rapport";
    }
  } catch (err) { /* silencieux : le dashboard reste utilisable hors-ligne */ }
}
refreshGlobalStats();
setInterval(refreshGlobalStats, 4000);

// ---------------- Vue Sandbox ----------------
const SANDBOX_STATUS_LABELS = {
  en_attente: "En attente",
  en_attente_validation: "À valider",
  cle_api_absente: "Clé API absente",
  en_cours: "Test en cours",
  termine: "Terminé",
  echec: "Échec",
};

let _sandboxEntries = [];

async function loadSandbox() {
  const tbody = document.getElementById("sandbox-body");
  const warning = document.getElementById("sandbox-key-warning");
  tbody.innerHTML = `<tr><td colspan="6">Chargement...</td></tr>`;
  closeSandboxDetail();
  try {
    const [listRes, statusRes] = await Promise.all([
      fetch("/api/sandbox/list"),
      fetch("/api/sandbox/status"),
    ]);
    const entries = await listRes.json();
    const status = await statusRes.json();
    _sandboxEntries = entries;

    warning.hidden = !!status.cle_api_configuree;

    if (!entries.length) {
      tbody.innerHTML = `<tr><td colspan="6">Aucun fichier suspect pour l'instant — tout ce qui est passé par l'analyse était en dessous du seuil "élevé".</td></tr>`;
      return;
    }

    tbody.innerHTML = entries.map((e) => {
      const t = splitThreats(e);
      const menaces = t.real.length
        ? esc(t.real.join(", "))
        : (t.info.length ? `aucune menace · ${t.info.length} comportement(s) informatif(s)` : "—");
      return `
      <tr class="sandbox-row" data-entry-id="${esc(e.id)}">
        <td>${esc(e.nom_original)}</td>
        <td style="color:${STATUS_COLORS[e.niveau_statique] || "#EDE6D5"}">${esc(e.niveau_statique)} (${esc(e.score_statique)})</td>
        <td><span class="badge badge-${esc(e.statut)}">${esc(SANDBOX_STATUS_LABELS[e.statut] || e.statut)}</span></td>
        <td>${esc(e.verdict || "—")}</td>
        <td>${menaces}</td>
        <td>${sandboxActionCell(e)}</td>
      </tr>`;
    }).join("");

    // Clic sur une ligne (hors boutons/liens) -> ouvre le rapport sandbox
    // récupéré, directement dans le panneau de détail du dashboard.
    tbody.querySelectorAll(".sandbox-row").forEach((row) => {
      row.addEventListener("click", (evt) => {
        if (evt.target.closest("button, a")) return; // ne pas intercepter les actions
        openSandboxDetail(row.dataset.entryId);
      });
    });

    tbody.querySelectorAll("button[data-submit-id]").forEach((btn) => {
      btn.addEventListener("click", async (evt) => {
        evt.stopPropagation();
        btn.disabled = true;
        btn.textContent = "Envoi...";
        try {
          const res = await fetch(`/api/sandbox/submit/${btn.dataset.submitId}`, { method: "POST" });
          if (!res.ok) { const d = await res.json(); alert(d.erreur || "échec de la soumission"); }
        } finally {
          loadSandbox();
        }
      });
    });
    tbody.querySelectorAll("a[data-report-link]").forEach((a) => {
      a.addEventListener("click", (evt) => {
        evt.stopPropagation();
        evt.preventDefault();
        viewReportById(a.dataset.reportLink);
      });
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6">Erreur de chargement : ${err.message}</td></tr>`;
  }
}

function sandboxActionCell(e) {
  const reportLink = `<a href="#" data-report-link="${esc(e.report_id)}">analyse statique</a>`;
  if (e.statut === "cle_api_absente" || e.statut === "echec" || e.statut === "en_attente_validation") {
    return `<button class="mini-btn" data-submit-id="${esc(e.id)}">Soumettre</button> · ${reportLink}`;
  }
  return `${reportLink}`;
}

// ---------------- Détail sandbox : affiché dans le dashboard, sans lien sortant ----------------
function closeSandboxDetail() {
  const panel = document.getElementById("sandbox-detail");
  if (panel) panel.hidden = true;
  document.querySelectorAll(".sandbox-row.is-selected").forEach((r) => r.classList.remove("is-selected"));
}

function openSandboxDetail(entryId) {
  const e = _sandboxEntries.find((x) => x.id === entryId);
  if (!e) return;

  document.querySelectorAll(".sandbox-row").forEach((r) => r.classList.toggle("is-selected", r.dataset.entryId === entryId));

  const panel = document.getElementById("sandbox-detail");
  const title = document.getElementById("sandbox-detail-title");
  const kv = document.getElementById("sandbox-detail-kv");

  title.textContent = `Rapport sandbox — ${e.nom_original}`;

  const created = parseTs(e.created_at || e.horodatage_ajout);
  const updated = parseTs(e.updated_at || e.horodatage_maj);
  const rows = [
    ["Statut", SANDBOX_STATUS_LABELS[e.statut] || e.statut],
    ["Niveau statique (analyse pré-sandbox)", `${e.niveau_statique} (score ${e.score_statique})`],
    ["Ajouté à la file le", created ? created.toLocaleString("fr-FR") : "—"],
    ["Dernière mise à jour", updated ? updated.toLocaleString("fr-FR") : "—"],
  ];

  if (e.statut === "en_attente_validation") {
    rows.push(["Détail", "Ce fichier justifie un test comportemental, mais il n'a PAS été envoyé : la sandbox est un service externe (Hybrid Analysis) et l'envoi automatique est désactivé. Cliquez sur \"Soumettre\" pour autoriser le partage de ce fichier."]);
  } else if (e.statut === "cle_api_absente") {
    rows.push(["Détail", "Ce fichier a été identifié comme suspect mais n'a pas encore été envoyé au sandbox (clé API Hybrid Analysis absente). Configurez HYBRID_ANALYSIS_API_KEY puis cliquez sur \"Soumettre\"."]);
  } else if (e.statut === "en_attente") {
    rows.push(["Détail", "En file d'attente, sera soumis au sandbox sous peu."]);
  } else if (e.statut === "en_cours") {
    rows.push(["Détail", "Fichier en cours d'exécution dans la machine virtuelle jetable. Le rapport apparaîtra ici automatiquement une fois terminé (quelques minutes)."]);
    if (e.ha_job_id) rows.push(["Identifiant de soumission", e.ha_job_id]);
  } else if (e.statut === "echec" || e.statut === "non_applicable") {
    rows.push(["Détail", e.erreur || "erreur inconnue"]);
  } else if (e.statut === "termine") {
    const t = splitThreats(e);
    rows.push(["Verdict comportemental", e.verdict || "—"]);
    rows.push(["Score de menace (sandbox)", e.score_menace_sandbox != null ? e.score_menace_sandbox : "—"]);
    rows.push(["Menaces (identifiants malveillants/suspects)", t.real.length ? t.real.join(", ") : "aucune"]);
    rows.push(["Comportements informatifs (non malveillants)", t.info.length ? t.info.join(", ") : "aucun"]);
    if (e.ha_job_id) rows.push(["Identifiant de soumission", e.ha_job_id]);
    if (e.url_rapport_public && /^https?:\/\//i.test(e.url_rapport_public)) {
      rows.push(["Rapport complet (détail processus/réseau)", { href: e.url_rapport_public, text: "ouvrir sur Hybrid Analysis ↗" }]);
    }
  }
  if (e.copie_purgee) rows.push(["Copie de l'échantillon", e.copie_purgee]);

  kv.innerHTML = "";
  rows.forEach(([k, v]) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd");
    if (v && typeof v === "object" && v.href) {
      const a = document.createElement("a");
      a.href = v.href; a.target = "_blank"; a.rel = "noopener"; a.textContent = v.text;
      dd.appendChild(a);
    } else {
      dd.textContent = v;
    }
    kv.appendChild(dt); kv.appendChild(dd);
  });
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

document.getElementById("sandbox-detail-close")?.addEventListener("click", closeSandboxDetail);

// ---------------- Upload / Dropzone ----------------
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");

dropzone?.addEventListener("click", () => fileInput.click());
dropzone?.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("is-dragover"); });
dropzone?.addEventListener("dragleave", () => dropzone.classList.remove("is-dragover"));
dropzone?.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("is-dragover");
  if (e.dataTransfer.files.length) analyzeFile(e.dataTransfer.files[0]);
});
fileInput?.addEventListener("change", () => {
  if (fileInput.files.length) analyzeFile(fileInput.files[0]);
});

async function analyzeFile(file) {
  document.getElementById("dropzone-filename").textContent = file.name;
  document.getElementById("verdict-line").textContent = "Analyse en cours...";
  resetPipelineTrack();
  document.getElementById("report-grid").hidden = true;

  const formData = new FormData();
  formData.append("fichier", file);
  const pwdInput = document.getElementById("archive-password");
  if (pwdInput && pwdInput.value) formData.append("mot_de_passe", pwdInput.value);

  animatePipelineSteps();

  try {
    const res = await fetch("/api/analyze", { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) {
      document.getElementById("verdict-line").textContent = "Erreur : " + (data.erreur || "inconnue");
      return;
    }
    renderReport(data);
  } catch (err) {
    document.getElementById("verdict-line").textContent = "Erreur reseau : " + err.message;
  }
}

function resetPipelineTrack() {
  document.querySelectorAll("#pipeline-track li").forEach((li) => li.classList.remove("is-done"));
}

function animatePipelineSteps() {
  const items = document.querySelectorAll("#pipeline-track li");
  items.forEach((li, i) => setTimeout(() => li.classList.add("is-done"), i * 90));
}

// ---------------- Voir le détail d'un rapport (depuis Historique ou Surveillance) ----------------
async function viewReportById(reportId) {
  if (!reportId) return;
  // Bascule sur la vue Analyse et y affiche le rapport demande
  document.querySelectorAll(".rail-link").forEach((b) => b.classList.remove("is-active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("is-active"));
  document.querySelector('.rail-link[data-view="analyse"]')?.classList.add("is-active");
  document.getElementById("view-analyse").classList.add("is-active");

  document.getElementById("verdict-line").textContent = "Chargement du rapport...";
  document.getElementById("report-grid").hidden = true;
  try {
    const res = await fetch(`/api/report/${reportId}`);
    if (!res.ok) {
      document.getElementById("verdict-line").textContent = "Rapport introuvable.";
      return;
    }
    const data = await res.json();
    (document.getElementById("dropzone-filename") || {}).textContent =
      (data.metadonnees && data.metadonnees.nom) || reportId;
    resetPipelineTrack();
    animatePipelineSteps();
    renderReport(data);
  } catch (err) {
    document.getElementById("verdict-line").textContent = "Erreur reseau : " + err.message;
  }
}

// ---------------- Rendu du rapport ----------------
function renderReport(r) {
  const score = r.score_final.score;
  const niveau = r.score_final.niveau;
  const color = STATUS_COLORS[niveau] || "#A79A82";

  const circumference = 578;
  const offset = circumference - (score / 100) * circumference;
  const arc = document.getElementById("gauge-arc");
  arc.style.stroke = color;
  requestAnimationFrame(() => { arc.style.strokeDashoffset = offset; });

  document.getElementById("gauge-score").textContent = score;
  document.getElementById("gauge-label").textContent = "niveau " + niveau;

  const v = r.verdict || null;
  const vText = v ? ` · verdict : <strong style="color:${VERDICT_COLORS[v.verdict] || color}">${esc(VERDICT_LABELS[v.verdict] || v.verdict)}</strong> (confiance ${esc(v.confiance)})` : "";
  document.getElementById("verdict-line").innerHTML =
    `<strong style="color:${color}">Niveau ${esc(niveau)}</strong>${vText} — action recommandee : ${esc(ACTION_LABELS[r.action.action] || r.action.action)}`;

  // Explications + actions
  const expl = document.getElementById("panel-explications");
  expl.innerHTML = "";
  r.score_final.explications.forEach((e) => {
    const li = document.createElement("li");
    li.textContent = e;
    expl.appendChild(li);
  });
  appendOrchestration(expl, r);
  if (r.cache && r.cache.reutilise) {
    const li = document.createElement("li");
    li.textContent = `Résultat réutilisé du rapport ${r.cache.rapport_source} (${r.cache.raison}).`;
    expl.appendChild(li);
  }
  if (r.sandbox && r.sandbox.recommande) {
    const li = document.createElement("li");
    const attente = r.sandbox.soumission_automatique_autorisee === false;
    li.innerHTML = r.sandbox.id_soumission
      ? (attente
          ? `Un <a href="#" id="goto-sandbox-link">test sandbox</a> est justifié mais attend votre validation : le fichier n'est pas partagé avec le service externe sans accord.`
          : `Ce fichier a été mis en file pour un <a href="#" id="goto-sandbox-link">test sandbox</a> (comportement réel, en plus de l'analyse statique ci-dessus).`)
      : `Ce fichier mériterait un test sandbox, mais la mise en file a échoué${r.sandbox.erreur ? " (" + esc(r.sandbox.erreur) + ")" : ""}.`;
    expl.appendChild(li);
    const link = document.getElementById("goto-sandbox-link");
    if (link) link.addEventListener("click", (e2) => { e2.preventDefault(); switchView("sandbox"); });
  }

  const actionBar = document.getElementById("action-bar");
  actionBar.innerHTML = "";
  Object.entries(ACTION_LABELS).forEach(([key, label]) => {
    const pill = document.createElement("span");
    pill.className = "action-pill" + (key === r.action.action ? " is-taken" : "");
    pill.textContent = label;
    actionBar.appendChild(pill);
  });

  // Métadonnées
  fillKV("panel-metadata", {
    "Nom": r.metadonnees.nom,
    "Extension": r.metadonnees.extension,
    "Taille": r.metadonnees.taille_lisible,
    "MIME reel": r.metadonnees.mime_reel,
    "Proprietaire": r.metadonnees.proprietaire,
    "Permissions": r.metadonnees.permissions,
    "Modifie le": r.metadonnees.date_modification,
    "Zone d'origine": r.metadonnees.zone_origine || "non applicable",
  });

  // Cohérence type
  fillKV("panel-type", {
    "Extension declaree": r.coherence_type.extension_declaree,
    "Type reel detecte": r.coherence_type.type_reel_detecte,
    "Coherent": r.coherence_type.coherent === null ? "indetermine" : (r.coherence_type.coherent ? "oui" : "NON"),
    "Commentaire": r.coherence_type.commentaire,
  });

  // Empreintes
  fillKV("panel-hashes", {
    "SHA-256": r.empreintes.sha256,
    "SHA-1": r.empreintes.sha1,
    "MD5": r.empreintes.md5,
    "Connu malveillant": r.empreintes.connu_malveillant ? "OUI" : "non",
  });

  // Entropie
  const bars = document.getElementById("panel-entropy-bars");
  bars.innerHTML = "";
  (r.entropie_obfuscation.entropie_par_bloc || []).forEach((v) => {
    const bar = document.createElement("span");
    bar.style.height = Math.max(4, (v / 8) * 100) + "%";
    bars.appendChild(bar);
  });
  fillKV("panel-entropy", {
    "Entropie globale": r.entropie_obfuscation.entropie_globale + " / 8",
    "Verdict": r.entropie_obfuscation.verdict_entropie,
    "Blobs Base64": r.entropie_obfuscation.base64.nombre_blobs_base64,
    "XOR simple suspecte": r.entropie_obfuscation.xor.xor_simple_suspecte ? "oui (" + r.entropie_obfuscation.xor.cle_probable + ")" : "non",
  });

  renderStaticAnalysis(r.analyse_statique);
  renderIOCs(r.iocs);
  renderYara(r.yara);
  renderClamav(r.antivirus);
  renderMLFeatures(r.scoring_ml);

  document.getElementById("report-grid").hidden = false;
  document.getElementById("report-grid").style.animation = "none";
  void document.getElementById("report-grid").offsetWidth;
  document.getElementById("report-grid").style.animation = "reveal .5s ease forwards";
}

// Trace de l'orchestrateur : verdict, outils lancés / non lancés et pourquoi,
// analyses manquantes. C'est ce qui distingue « fichier sain » de « analyse incomplète ».
function appendOrchestration(listEl, r) {
  const add = (text) => { const li = document.createElement("li"); li.textContent = text; listEl.appendChild(li); };
  if (r.verdict) {
    (r.verdict.raisons || []).forEach((t) => add("Verdict — " + t));
    const manquants = (r.verdict.couverture && r.verdict.couverture.manquants) || [];
    manquants.forEach((m) => add(`Analyse manquante : ${m.outil} (${TOOL_STATUS_LABELS[m.statut] || m.statut})${m.raison ? " — " + m.raison : ""}`));
  }
  const outils = r.orchestration && r.orchestration.outils;
  if (outils) {
    const parts = Object.entries(outils).map(([n, t]) =>
      `${n}: ${TOOL_STATUS_LABELS[t.status] || t.status}${t.duration_s ? " (" + t.duration_s + " s)" : ""}`);
    add("Outils — " + parts.join(" · "));
  }
  ((r.orchestration && r.orchestration.plan) || []).filter((p) => !p.lance).forEach((p) =>
    add(`Non lancé : ${p.outil} — ${p.raison}`));
  const enfants = r.sous_rapports_archive || [];
  if (enfants.length) {
    add(`Contenu d'archive : ${enfants.length} fichier(s) analysé(s) — ` +
        enfants.slice(0, 8).map((c) => `${c.nom} (${c.verdict || c.score})`).join(", ") + (enfants.length > 8 ? "…" : ""));
  }
}

function fillKV(id, obj) {
  const dl = document.getElementById(id);
  dl.innerHTML = "";
  Object.entries(obj).forEach(([k, v]) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v === null || v === undefined ? "—" : v;
    dl.appendChild(dt); dl.appendChild(dd);
  });
}

function renderStaticAnalysis(sa) {
  const el = document.getElementById("panel-static");
  el.innerHTML = "";
  if (sa.pe) {
    const pe = sa.pe;
    el.innerHTML += pe.disponible ? `
      <div class="block">
        <h4>Executable PE — ${pe.type}</h4>
        <div class="mono-block">Architecture: ${pe.architecture}
Point d'entree: ${pe.point_entree}
Imports dangereux: ${pe.imports_dangereux_detectes.map(esc).join(", ") || "aucun"}
Packer suspecte: ${pe.packer_suspecte ? "oui" : "non"}
Signature presente: ${pe.signature_presente ? "oui" : "non"}
Sections: ${pe.sections.map(s => esc(s.nom) + " (entropie " + esc(s.entropie) + ")").join(" | ")}</div>
      </div>` : `<p class="empty-note">${pe.raison}</p>`;
  }
  if (sa.office) {
    const o = sa.office;
    el.innerHTML += o.disponible ? `
      <div class="block">
        <h4>Document Office</h4>
        <div class="mono-block">Macros presentes: ${o.macros_presentes ? "oui" : "non"}
${o.macros_presentes ? "Auto-execution: " + (o.auto_execution || []).map(esc).join(", ") + "\nIOC macro: " + (o.iocs_macro || []).map(esc).join(", ") : ""}</div>
      </div>` : `<p class="empty-note">${o.raison}</p>`;
  }
  if (sa.pdf) {
    const p = sa.pdf;
    el.innerHTML += p.disponible ? `
      <div class="block">
        <h4>Document PDF</h4>
        <div class="mono-block">Pages: ${p.nombre_pages ?? "?"}
JavaScript embarque: ${p.javascript_embarque ? "oui" : "non"}
Action d'ouverture automatique: ${p.action_ouverture ? "oui" : "non"}
Fichiers embarques: ${p.fichiers_embarques ? "oui" : "non"}
Action /Launch: ${p.action_launch ? "oui" : "non"}</div>
      </div>` : `<p class="empty-note">${p.raison}</p>`;
  }
  if (sa.elf) {
    const e = sa.elf;
    el.innerHTML += `<div class="block"><h4>Executable ELF</h4><div class="mono-block">${e.classe || ""} ${e.endianness || ""}\n${e.note || ""}</div></div>`;
  }
  if (sa.note) {
    el.innerHTML += `<p class="empty-note">${esc(sa.note)}</p>`;
  }
}

const IOC_TABS = [
  ["ips", "Adresses IP"], ["domaines", "Domaines"], ["urls", "URLs"],
  ["emails", "Emails"], ["chemins_windows", "Chemins Windows"],
  ["chemins_unix", "Chemins Unix"], ["cles_registre", "Cles de registre"],
  ["chaines_suspectes", "Chaines suspectes"],
];

function renderIOCs(iocs) {
  const tabsEl = document.getElementById("ioc-tabs");
  const contentEl = document.getElementById("ioc-content");
  tabsEl.innerHTML = "";

  IOC_TABS.forEach(([key, label], i) => {
    const btn = document.createElement("button");
    btn.className = "ioc-tab" + (i === 0 ? " is-active" : "");
    btn.textContent = `${label} (${Array.isArray(iocs[key]) ? iocs[key].length : 0})`;
    btn.addEventListener("click", () => {
      document.querySelectorAll(".ioc-tab").forEach((t) => t.classList.remove("is-active"));
      btn.classList.add("is-active");
      showIOCTab(iocs, key);
    });
    tabsEl.appendChild(btn);
  });

  showIOCTab(iocs, IOC_TABS[0][0]);
}

function showIOCTab(iocs, key) {
  const contentEl = document.getElementById("ioc-content");
  const items = iocs[key] || [];
  if (!items.length) {
    contentEl.innerHTML = `<p class="empty-note">Aucun element detecte dans cette categorie.</p>`;
    return;
  }
  if (key === "chaines_suspectes") {
    contentEl.innerHTML = `<div class="mono-block">${items.map(x => `${esc(x.chaine)} — ${esc(x.occurrences)} occurrence(s)`).join("\n")}</div>`;
  } else {
    contentEl.innerHTML = `<div class="mono-block">${items.map(esc).join("\n")}</div>`;
  }
}

function renderYara(yara) {
  const el = document.getElementById("panel-yara");
  el.innerHTML = "";
  if (!yara.disponible) {
    el.innerHTML = `<p class="empty-note">${yara.raison}</p>`;
    return;
  }
  if (!yara.matches.length) {
    el.innerHTML = `<p class="empty-note">Aucune regle declenchee.</p>`;
    return;
  }
  yara.matches.forEach((m) => {
    const div = document.createElement("div");
    div.className = `yara-badge sev-${m.severite}`;
    div.innerHTML = `<b>${esc(m.regle)}</b><span>${esc(m.description)} — severite ${esc(m.severite)}</span>`;
    el.appendChild(div);
  });
}

function renderClamav(av) {
  fillKV("panel-clamav", av.disponible ? {
    "Infecte": av.infecte ? "OUI" : "non",
    "Signature": av.signature || "—",
    "Statut brut": av.statut_brut,
  } : { "Statut": av.raison });
}

function renderMLFeatures(ml) {
  const el = document.getElementById("panel-ml");
  if (!el) return;
  el.innerHTML = `<p class="empty-note" style="margin-bottom:10px">Methode : ${ml.methode} — probabilite globale : ${(ml.probabilite_risque * 100).toFixed(1)}%</p>`;
  Object.entries(ml.features).forEach(([k, v]) => {
    const pct = Math.min(100, Math.abs(v) * (v <= 1 ? 100 : 20));
    const row = document.createElement("div");
    row.className = "feature-row";
    row.innerHTML = `<span class="label">${k}</span><span class="track"><span class="fill" style="width:${pct}%"></span></span><span class="value">${typeof v === "number" ? v.toFixed(2) : v}</span>`;
    el.appendChild(row);
  });
}

// ---------------- Historique ----------------
async function loadHistory() {
  const tbody = document.getElementById("history-body");
  tbody.innerHTML = `<tr><td colspan="5">Chargement...</td></tr>`;
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="5">Aucune analyse effectuee pour le moment.</td></tr>`;
      return;
    }
    tbody.innerHTML = data.map((r) => `
      <tr class="history-row" data-report-id="${esc(r.id_rapport)}" style="cursor:pointer">
        <td>${esc(r.nom)}</td>
        <td style="color:${STATUS_COLORS[r.niveau] || "#EDE6D5"}">${esc(r.score)}</td>
        <td>${esc(r.niveau)}${r.verdict ? " · " + esc(VERDICT_LABELS[r.verdict] || r.verdict) : ""}</td>
        <td>${esc(ACTION_LABELS[r.action] || r.action)}</td>
        <td>${esc((r.sha256 || "").slice(0, 16)) || "—"}...</td>
      </tr>`).join("");
    tbody.querySelectorAll("tr.history-row").forEach((tr) => {
      tr.addEventListener("click", () => viewReportById(tr.dataset.reportId));
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5">Erreur de chargement : ${err.message}</td></tr>`;
  }
}