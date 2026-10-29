"""
Orchestrateur de Cabinet Noir : le cœur « agent » du projet.

Là où l'ancien pipeline enchaînait des fonctions dans un ordre fixe, ce
module DÉCIDE, à partir de ce qu'il observe :

  1. identifie le fichier (type réel, hash) et regarde s'il est déjà connu ;
  2. lance en parallèle les contrôles locaux (ClamAV, YARA, analyse statique,
     entropie, IOC) avec durée, statut et erreur normalisés (ToolResult) ;
  3. choisit les outils spécialisés adaptés (Office, PDF, PE, script) ;
  4. corrèle les preuves (score + verdict + couverture) ;
  5. décide si la sandbox est justifiée, éligible et autorisée, et
     enregistre POURQUOI chaque outil a été lancé ou non ;
  6. produit un rapport unique avec cette trace.

Les décisions de sécurité restent déterministes (règles explicites dans
config.py) : aucune IA ne peut déclarer un fichier sain ou lancer un outil
librement.
"""
import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor

from config import (
    ARCHIVE_MAX_DEPTH, CACHE_TTL_HOURS, REPORTS_DIR,
    SANDBOX_ALLOW_EXTERNAL_SUBMISSION, SANDBOX_MAX_FILE_MB, SANDBOX_MIN_SCORE,
    SANDBOX_NEVER_STANDALONE_EXTENSIONS,
)

from . import archive_handler
from . import clamav_scan
from . import decision_engine
from . import entropy_tools
from . import hashing
from . import ioc_extraction
from . import metadata as metadata_mod
from . import ml_scoring
from . import quarantine
from . import report_store
from . import scoring_engine
from . import signatures
from . import specialized_analysis
from . import static_analysis
from . import type_check as type_check_mod
from . import verdict as verdict_mod
from . import yara_scan
from .tool_result import (
    ToolResult, STATUS_ERROR, STATUS_PENDING, STATUS_SKIPPED, STATUS_NOT_APPLICABLE,
    from_clamav, from_specialized, from_static, from_yara,
)

# Correspondance type_check (français) -> vocabulaire de decision_engine.
_DECISION_TYPES = {
    "pe_executable": "PE/EXE",
    "pdf": "PDF",
    "zip_or_office_ooxml": "ZIP/OOXML",
    "elf_executable": "ELF",
}


def _timed(tool, fn, *args, **kwargs):
    """Exécute un outil, mesure sa durée et ne laisse JAMAIS remonter
    d'exception : un outil qui plante devient un ToolResult « error »."""
    t0 = time.time()
    try:
        return fn(*args, **kwargs), round(time.time() - t0, 3), None
    except Exception as e:  # noqa: BLE001 - frontière d'isolation volontaire
        return None, round(time.time() - t0, 3), f"{type(e).__name__}: {e}"


def _empty_entropy():
    return {
        "entropie_globale": 0, "verdict_entropie": None,
        "format_naturellement_compresse": False, "entropie_par_bloc": [],
        "base64": {"nombre_blobs_base64": None}, "xor": {"xor_simple_suspecte": None, "cle_probable": None},
    }


def _empty_iocs():
    return {
        "ips": [], "domaines": [], "urls": [], "emails": [], "chemins_windows": [],
        "chemins_unix": [], "cles_registre": [], "processus_mentionnes": [],
        "hashs_embarques": {"md5": [], "sha1": [], "sha256": []},
        "chaines_suspectes": [], "score_indicateurs": 0,
    }


# ---------------------------------------------------------------------------
# Politique sandbox
# ---------------------------------------------------------------------------

def decide_sandbox(*, filename, size_bytes, score_report,
                   clamav_detected, hash_connu, yara_severe, decision_hint):
    """Décide si la sandbox est (a) justifiée, (b) éligible, (c) autorisée à
    partir automatiquement. Retourne un dict avec toutes les raisons.

    justifiee  : un signal justifie un test comportemental
    eligible   : le fichier PEUT être soumis (type/taille/politique)
    """
    ext = os.path.splitext(filename or "")[1].lower()
    declencheurs, bloquants = [], []

    if clamav_detected:
        declencheurs.append("l'antivirus a détecté une signature")
    if hash_connu:
        declencheurs.append("le hash est déjà connu comme malveillant")
    if yara_severe:
        declencheurs.append("une règle YARA critique/élevée a été déclenchée")
    if score_report["score"] >= SANDBOX_MIN_SCORE:
        declencheurs.append(f"le score statique ({score_report['score']}) atteint le seuil {SANDBOX_MIN_SCORE}")

    if ext in SANDBOX_NEVER_STANDALONE_EXTENSIONS:
        bloquants.append(
            f"l'extension '{ext}' n'est jamais soumise seule (composant interne ou média) ; "
            "analyser le document complet"
        )
    if size_bytes and size_bytes > SANDBOX_MAX_FILE_MB * 1024 * 1024:
        bloquants.append(f"fichier > {SANDBOX_MAX_FILE_MB} Mo")
    if decision_hint.get("sandbox_status") in ("non_applicable", "desactive"):
        # decision_engine : extensions sensibles (.key, .pem, .env, .kdbx...), .rels, taille
        bloquants.append("politique decision_engine : " + decision_hint["reasons"][-1])

    justifiee = bool(declencheurs)
    eligible = not bloquants
    return {
        "justifiee": justifiee,
        "eligible": eligible,
        "recommande": justifiee and eligible,
        "declencheurs": declencheurs,
        "bloquants": bloquants,
        "soumission_automatique_autorisee": SANDBOX_ALLOW_EXTERNAL_SUBMISSION,
    }


# ---------------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------------

def analyze(filepath, report_id, started, known_malicious_hashes=None,
            enable_threat_intel=True, origine="manuel", archive_password=None,
            parent_id=None, depth=0, run_child=None):
    """Analyse complète d'un fichier. `run_child(path, **kw)` est la fonction
    utilisée pour ré-analyser les fichiers extraits d'une archive (injectée
    par pipeline.run_pipeline pour garder une seule porte d'entrée)."""
    plan_log = []   # trace « outil lancé / pas lancé / pourquoi »
    tools = {}      # nom -> ToolResult

    # --- 1. Identification ------------------------------------------------
    meta = metadata_mod.collect_metadata(filepath)
    type_res = type_check_mod.check_type_consistency(filepath, meta["extension"])
    hashes = hashing.compute_hashes(filepath)
    hash_check = hashing.check_known_hash(hashes, known_malicious_hashes)
    rules_version = yara_scan.rules_version()

    # Cache : réservé à la surveillance automatique d'un fichier de premier niveau.
    if origine == "auto_watch" and depth == 0 and not hash_check.get("connu_malveillant"):
        cached_id = report_store.find_cached(hashes["sha256"], rules_version, CACHE_TTL_HOURS)
        if cached_id:
            cached = _load_report(cached_id)
            if cached:
                cached = dict(cached)
                cached["cache"] = {
                    "reutilise": True, "rapport_source": cached_id,
                    "raison": f"même SHA-256 et mêmes règles YARA, analysé il y a moins de {CACHE_TTL_HOURS:g} h",
                }
                return cached

    # --- 2. Conteneur / archive -------------------------------------------
    container = archive_handler.container_kind(filepath)
    if container:
        archive_res = {"est_archive": False, "conteneur": container}
        plan_log.append({
            "outil": "extraction_archive", "lance": False,
            "raison": f"document/paquet ({container}) : analysé comme un tout, jamais extrait en fichiers indépendants",
        })
    elif depth >= ARCHIVE_MAX_DEPTH and archive_handler._is_archive(filepath):
        archive_res = {
            "est_archive": True, "extraction_reussie": False, "extraction_refusee": True,
            "erreur": f"profondeur maximale d'archives imbriquées atteinte ({ARCHIVE_MAX_DEPTH})",
        }
        plan_log.append({"outil": "extraction_archive", "lance": False, "raison": archive_res["erreur"]})
    else:
        archive_res = archive_handler.handle_if_archive(filepath, password=archive_password)
        if archive_res.get("est_archive"):
            plan_log.append({"outil": "extraction_archive", "lance": True,
                             "raison": "archive détectée ; contenu ré-analysé fichier par fichier"})

    detected_type = type_res["type_reel_detecte"]

    # --- 3. Contrôles locaux en parallèle ---------------------------------
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="cn-local") as pool:
        f_static = pool.submit(_timed, "static", static_analysis.run_static_analysis, filepath, detected_type)
        f_entropy = pool.submit(_timed, "entropy", entropy_tools.analyze_entropy_and_obfuscation, filepath, detected_type)
        f_ioc = pool.submit(_timed, "ioc", ioc_extraction.extract_iocs, filepath)
        f_yara = pool.submit(_timed, "yara", yara_scan.scan_file, filepath, meta["nom"])
        f_clam = pool.submit(_timed, "clamav", clamav_scan.scan_with_clamav, filepath)
        static_res, d_static, e_static = f_static.result()
        entropy_res, d_entropy, e_entropy = f_entropy.result()
        iocs, d_ioc, e_ioc = f_ioc.result()
        yara_res, d_yara, e_yara = f_yara.result()
        clamav_res, d_clam, e_clam = f_clam.result()

    if e_clam:
        clamav_res = {"disponible": False, "raison": f"Erreur pendant l'analyse ClamAV : {e_clam}"}
    if e_yara:
        yara_res = {"disponible": False, "raison": f"erreur de scan: {e_yara}", "matches": []}
    static_res = static_res if static_res is not None else {"note": f"Analyse statique en erreur : {e_static}"}
    entropy_res = entropy_res if entropy_res is not None else _empty_entropy()
    iocs = iocs if iocs is not None else _empty_iocs()

    tools["clamav"] = from_clamav(clamav_res, d_clam)
    tools["yara"] = from_yara(yara_res, d_yara)
    tools["analyse_statique"] = from_static(static_res, d_static, e_static)
    for name, err, dur in (("entropie_obfuscation", e_entropy, d_entropy), ("extraction_ioc", e_ioc, d_ioc)):
        tools[name] = ToolResult(name, STATUS_ERROR if err else "ok", dur,
                                 err or "terminé", error=err)
    plan_log.append({"outil": "controles_locaux", "lance": True,
                     "raison": "ClamAV, YARA, analyse statique, entropie et IOC lancés en parallèle pour tout fichier"})

    sig_res = signatures.check_pe_signature(filepath, static_res.get("pe") if isinstance(static_res, dict) else None)
    ml_res = ml_scoring.run_ml_scoring(meta, type_res, entropy_res, static_res, iocs)

    # --- 4. Décision : outils spécialisés ---------------------------------
    clam_pos = tools["clamav"].status == "detected"
    file_info = {
        "file_name": meta["nom"], "file_path": filepath, "extension": ("." + meta["extension"].lstrip(".")) if meta["extension"] else "",
        "size_bytes": meta["taille_octets"],
        "detected_type": _DECISION_TYPES.get(detected_type, "INCONNU"),
        "extension_mismatch": bool(type_res.get("alerte")),
    }
    decision = decision_engine.decide_analysis(
        file_info,
        clamav_result={"detected": clam_pos, "signature": clamav_res.get("signature") if clam_pos else None},
        yara_result={"detected": tools["yara"].status == "detected"},
        max_sandbox_size=SANDBOX_MAX_FILE_MB * 1024 * 1024,
    )

    spec_res = None
    if archive_res.get("est_archive"):
        tools["analyse_specialisee"] = ToolResult(
            "analyse_specialisee", STATUS_NOT_APPLICABLE, 0.0, "archive : le contenu extrait est analysé fichier par fichier")
        plan_log.append({"outil": "analyse_specialisee", "lance": False, "raison": "archive : analyse du contenu extrait"})
    elif decision["run_specialized_analysis"]:
        spec_res, d_spec, e_spec = _timed("specialisee", specialized_analysis.analyze_specialized_file,
                                          filepath, file_info["detected_type"])
        if e_spec:
            tools["analyse_specialisee"] = ToolResult("analyse_specialisee", STATUS_ERROR, d_spec, e_spec, error=e_spec)
        else:
            tools["analyse_specialisee"] = from_specialized(spec_res, d_spec)
        plan_log.append({"outil": "analyse_specialisee", "lance": True,
                         "raison": f"type '{file_info['detected_type']}' / extension '{file_info['extension']}' : analyseur dédié applicable"})
    else:
        tools["analyse_specialisee"] = ToolResult(
            "analyse_specialisee", STATUS_NOT_APPLICABLE, 0.0, "aucun analyseur dédié pour ce type")
        plan_log.append({"outil": "analyse_specialisee", "lance": False, "raison": "aucun analyseur dédié pour ce type"})

    # --- 5. Threat intelligence -------------------------------------------
    ti_res = None
    if enable_threat_intel:
        from . import threat_intel
        ti_res, d_ti, e_ti = _timed("ti", threat_intel.run_threat_intel, iocs)
        if ti_res is not None:
            ti_res["hash_fichier_analyse"] = {
                "otx": threat_intel.check_hash_otx(hashes["sha256"]),
                "malwarebazaar": threat_intel.check_hash_malwarebazaar(hashes["sha256"]),
            }
        else:
            plan_log.append({"outil": "threat_intelligence", "lance": True, "raison": f"échec : {e_ti}"})

    # --- 6. Contenu d'archive : ré-analyse récursive ----------------------
    sous_rapports = []
    if archive_res.get("est_archive") and archive_res.get("extraction_reussie") and run_child:
        for extrait_path in archive_res.get("fichiers_extraits", []):
            try:
                sous_rapports.append(run_child(
                    extrait_path, known_malicious_hashes=known_malicious_hashes,
                    enable_threat_intel=enable_threat_intel, origine="extrait_archive",
                    parent_id=report_id, depth=depth + 1,
                ))
            except Exception as e:  # noqa: BLE001
                sous_rapports.append({"erreur": f"echec analyse fichier extrait {extrait_path}: {e}"})
        tmp_dir = archive_res.pop("_dest_dir_temporaire", None)
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # --- 7. Score + verdict -----------------------------------------------
    score_report = scoring_engine.compute_score(
        hash_check, type_res, entropy_res, static_res, yara_res, clamav_res,
        iocs, ml_res, ti_res, specialized_result=spec_res,
    )

    if archive_res.get("est_archive") and not archive_res.get("extraction_reussie"):
        if archive_res.get("extraction_refusee"):
            score_report["explications"].append(
                "Archive NON extraite par mesure de securite (" + str(archive_res.get("erreur")) +
                ") : contenu non inspecte."
            )
        else:
            score_report["explications"].append(
                "Archive protegee par mot de passe : contenu NON inspecte "
                "(aucun mot de passe valide fourni ou trouve parmi les mots de passe courants). "
                "Fournissez le mot de passe partage pour une analyse complete."
            )
        if score_report["niveau"] == "faible":
            score_report["niveau"] = "moyen"
            score_report["action_recommandee"] = "human_review"

    for sr in sous_rapports:
        sous_score = sr.get("score_final", {}).get("score", 0)
        if sous_score > score_report["score"]:
            score_report["score"] = sous_score
            score_report["niveau"] = sr["score_final"]["niveau"]
            score_report["action_recommandee"] = sr["score_final"]["action_recommandee"]
            score_report["explications"].append(
                f"Score releve par le contenu extrait de l'archive : {sr['metadonnees']['nom']} "
                f"(score {sous_score}, rapport {sr['id_rapport']})."
            )

    ti_hash_mal = bool(ti_res and any(
        r.get("disponible") and r.get("signale")
        for r in (ti_res.get("hash_fichier_analyse") or {}).values()))
    extra_required = ("analyse_specialisee",) if tools["analyse_specialisee"].status not in (
        STATUS_NOT_APPLICABLE, STATUS_SKIPPED) else ()
    verdict = verdict_mod.compute_verdict(
        score_report, tools,
        hash_connu_malveillant=bool(hash_check.get("connu_malveillant")),
        ti_hash_malveillant=ti_hash_mal, extra_required=extra_required,
    )
    # Un enfant plus grave que son archive fait remonter le verdict.
    for sr in sous_rapports:
        sv = (sr.get("verdict") or {}).get("verdict")
        if sv in (verdict_mod.VERDICT_MALICIOUS, verdict_mod.VERDICT_SUSPECT) and verdict["verdict"] in (
                verdict_mod.VERDICT_CLEAN, verdict_mod.VERDICT_INCONCLUSIVE):
            verdict["verdict"] = sv
            verdict["libelle"] = verdict_mod.VERDICT_LABELS[sv]
            verdict["raisons"].append(f"Contenu extrait '{sr['metadonnees']['nom']}' : verdict {sv}")

    score_report["action_recommandee"] = verdict_mod.adjust_action(
        score_report["action_recommandee"], verdict["verdict"])

    action_result = quarantine.apply_action(score_report["action_recommandee"], filepath, score_report)

    # --- 8. Sandbox : justifiée ? éligible ? autorisée ? ------------------
    yara_severe = any(m.get("severite") in ("critique", "eleve") for m in yara_res.get("matches", []))
    sb_decision = decide_sandbox(
        filename=meta["nom"], size_bytes=meta["taille_octets"],
        score_report=score_report, clamav_detected=clam_pos,
        hash_connu=bool(hash_check.get("connu_malveillant")), yara_severe=yara_severe,
        decision_hint=decision,
    )

    sandbox_entry_id, sandbox_error = None, None
    if sb_decision["recommande"]:
        from . import sandbox as sandbox_mod
        source = action_result.get("chemin_quarantaine") or (filepath if os.path.exists(filepath) else None)
        # Isolé : une erreur d'enqueue ne doit JAMAIS transformer un fichier
        # analysé normalement en faux « neutralisé / critique ».
        try:
            sandbox_entry_id = sandbox_mod.enqueue(
                source, meta["nom"], report_id, score_report["score"], score_report["niveau"],
                auto_submit=SANDBOX_ALLOW_EXTERNAL_SUBMISSION,
                parent_report_id=parent_id,
            )
        except Exception as e:  # noqa: BLE001
            sandbox_error = f"{type(e).__name__}: {e}"
        if sandbox_entry_id:
            if SANDBOX_ALLOW_EXTERNAL_SUBMISSION:
                summary = "mis en file pour soumission automatique"
            else:
                summary = "mis en file, en attente de validation manuelle (le fichier n'est pas partagé sans accord)"
            tools["sandbox"] = ToolResult("sandbox", STATUS_PENDING, 0.0, summary)
        else:
            tools["sandbox"] = ToolResult("sandbox", STATUS_ERROR, 0.0,
                                          "mise en file impossible", error=sandbox_error)
        plan_log.append({"outil": "sandbox", "lance": bool(sandbox_entry_id),
                         "raison": "; ".join(sb_decision["declencheurs"]) + (f" | erreur : {sandbox_error}" if sandbox_error else "")})
    else:
        why = sb_decision["bloquants"] or ["aucun signal ne justifie un test comportemental"]
        tools["sandbox"] = ToolResult("sandbox", STATUS_SKIPPED, 0.0, "; ".join(why))
        plan_log.append({"outil": "sandbox", "lance": False, "raison": "; ".join(why)})

    if sb_decision["recommande"] and score_report["niveau"] not in ("eleve", "critique") and sb_decision["declencheurs"]:
        score_report["explications"].append(
            "Mis en file sandbox malgre un niveau de risque global '" + score_report["niveau"] +
            "' : " + ", ".join(sb_decision["declencheurs"]) + "."
        )

    report = {
        "id_rapport": report_id,
        "id_parent": parent_id,
        "profondeur": depth,
        "origine": origine,
        "duree_analyse_s": round(time.time() - started, 3),
        "metadonnees": meta,
        "coherence_type": type_res,
        "empreintes": {**hashes, **hash_check},
        "analyse_statique": static_res,
        "entropie_obfuscation": entropy_res,
        "iocs": iocs,
        "signature_numerique": sig_res,
        "yara": yara_res,
        "antivirus": clamav_res,
        "analyse_specialisee": spec_res,
        "threat_intelligence": ti_res,
        "scoring_ml": ml_res,
        "archive": archive_res,
        "conteneur": container,
        "sous_rapports_archive": [
            {"id_rapport": sr.get("id_rapport"), "nom": sr.get("metadonnees", {}).get("nom"),
             "score": sr.get("score_final", {}).get("score"),
             "verdict": (sr.get("verdict") or {}).get("verdict")}
            for sr in sous_rapports
        ],
        "score_final": score_report,
        "verdict": verdict,
        "action": action_result,
        "orchestration": {
            "outils": {name: t.to_dict() for name, t in tools.items()},
            "plan": plan_log,
            "decision_engine": decision,
            "extra_requis": list(extra_required),
        },
        "version_regles": rules_version,
        "sandbox": {
            "recommande": sb_decision["recommande"],
            "justifiee": sb_decision["justifiee"],
            "eligible": sb_decision["eligible"],
            "declencheurs": sb_decision["declencheurs"],
            "bloquants": sb_decision["bloquants"],
            "soumission_automatique_autorisee": sb_decision["soumission_automatique_autorisee"],
            "id_soumission": sandbox_entry_id,
            "erreur": sandbox_error,
        },
    }
    save_report(report)
    return report


def save_report(report):
    path = os.path.join(REPORTS_DIR, f"{report['id_rapport']}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)
    report_store.index_report(report)
    return path


def _load_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{os.path.basename(str(report_id))}.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
