"""Orchestre l'ensemble des étapes d'analyse sur un fichier donné."""
import json
import os
import shutil
import time
import uuid

from config import REPORTS_DIR, SANDBOX_AUTO_LEVELS

from . import metadata as metadata_mod
from . import hashing
from . import type_check as type_check_mod
from . import entropy_tools
from . import ioc_extraction
from . import static_analysis
from . import signatures
from . import yara_scan
from . import clamav_scan
from . import ml_scoring
from . import scoring_engine
from . import quarantine
from . import archive_handler

PIPELINE_STEPS = [
    "metadonnees", "coherence_type", "empreintes", "analyse_statique",
    "entropie_obfuscation", "extraction_ioc", "signature", "yara",
    "antivirus", "scoring_ml", "fusion_score", "action_reponse",
]


def run_pipeline(filepath, known_malicious_hashes=None, enable_threat_intel=True,
                  origine="manuel", archive_password=None):
    """Analyse un fichier.

    origine : d'ou vient l'analyse — "manuel" (depot dashboard/API),
              "auto_watch" (dossier surveille automatiquement),
              "extrait_archive" (fichier issu d'une archive protegee).
    archive_password : mot de passe fourni par l'utilisateur si le fichier
              est une archive chiffree partagee "avec une cle". Si aucun
              mot de passe n'est fourni, l'agent essaie une petite liste
              de mots de passe courants avant de renoncer proprement.

    Ne leve jamais d'exception pour un probleme de disparition/illisibilite
    du fichier en cours d'analyse (voir _build_neutralized_report) : ce cas
    tres concret survient quand l'antivirus temps reel DU SYSTEME (ex.
    Windows Defender) detecte le fichier de son cote et le supprime/met en
    quarantaine avant que ce pipeline ait fini de le lire.
    """
    report_id = str(uuid.uuid4())[:8]
    started = time.time()

    try:
        return _run_pipeline_core(
            filepath, report_id, started, known_malicious_hashes,
            enable_threat_intel, origine, archive_password,
        )
    except (FileNotFoundError, PermissionError, OSError) as e:
        return _build_neutralized_report(filepath, report_id, started, origine, e)


def _run_pipeline_core(filepath, report_id, started, known_malicious_hashes,
                        enable_threat_intel, origine, archive_password):
    # --- Archive potentiellement protegee par mot de passe ("fichier partage avec une cle") ---
    archive_res = archive_handler.handle_if_archive(filepath, password=archive_password)

    meta = metadata_mod.collect_metadata(filepath)
    type_res = type_check_mod.check_type_consistency(filepath, meta["extension"])
    hashes = hashing.compute_hashes(filepath)
    hash_check = hashing.check_known_hash(hashes, known_malicious_hashes)
    static_res = static_analysis.run_static_analysis(filepath, type_res["type_reel_detecte"])
    entropy_res = entropy_tools.analyze_entropy_and_obfuscation(filepath, type_res["type_reel_detecte"])
    iocs = ioc_extraction.extract_iocs(filepath)
    sig_res = signatures.check_pe_signature(filepath, static_res.get("pe"))
    yara_res = yara_scan.scan_file(filepath)
    clamav_res = clamav_scan.scan_with_clamav(filepath)
    ml_res = ml_scoring.run_ml_scoring(meta, type_res, entropy_res, static_res, iocs)

    ti_res = None
    if enable_threat_intel:
        from . import threat_intel
        ti_res = threat_intel.run_threat_intel(iocs)
        # Le hash SHA-256 du fichier lui-meme est aussi verifie contre les
        # bases externes (MalwareBazaar / OTX), independamment des hashs
        # embarques trouves dans son contenu.
        ti_res["hash_fichier_analyse"] = {
            "otx": threat_intel.check_hash_otx(hashes["sha256"]),
            "malwarebazaar": threat_intel.check_hash_malwarebazaar(hashes["sha256"]),
        }

    # --- Analyse recursive du contenu d'une archive extraite avec succes ---
    sous_rapports = []
    if archive_res.get("est_archive") and archive_res.get("extraction_reussie"):
        for extrait_path in archive_res.get("fichiers_extraits", []):
            try:
                sous_rapports.append(run_pipeline(
                    extrait_path, known_malicious_hashes=known_malicious_hashes,
                    enable_threat_intel=enable_threat_intel, origine="extrait_archive",
                ))
            except Exception as e:
                sous_rapports.append({"erreur": f"echec analyse fichier extrait {extrait_path}: {e}"})

        # Nettoyage du dossier temporaire d'extraction (les fichiers dangereux ont deja
        # ete deplaces en quarantaine par leurs propres run_pipeline() si necessaire).
        tmp_dir = archive_res.pop("_dest_dir_temporaire", None)
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    score_report = scoring_engine.compute_score(
        hash_check, type_res, entropy_res, static_res,
        yara_res, clamav_res, iocs, ml_res, ti_res,
    )

    # Une archive protegee non ouverte (aucun mot de passe valide) ne peut
    # pas etre inspectee en profondeur : on le signale clairement plutot
    # que de rendre un score faussement rassurant.
    if archive_res.get("est_archive") and not archive_res.get("extraction_reussie"):
        score_report["explications"].append(
            "Archive protegee par mot de passe : contenu NON inspecte "
            "(aucun mot de passe valide fourni ou trouve parmi les mots de passe courants). "
            "Fournissez le mot de passe partage pour une analyse complete."
        )
        if score_report["niveau"] == "faible":
            score_report["niveau"] = "moyen"
            score_report["action_recommandee"] = "human_review"

    # Si un sous-fichier extrait est plus risque que l'archive elle-meme,
    # le score et l'action remontent au niveau de l'archive.
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

    action_result = quarantine.apply_action(
        score_report["action_recommandee"], filepath, score_report
    )

    # --- Sandbox dynamique : fichiers juges suspects par l'analyse STATIQUE ---
    # ci-dessus (score_report) sont mis en file pour un test comportemental
    # reel (execution en VM jetable), en plus/complement de l'analyse
    # statique qui ne fait que lire le fichier. Non bloquant : le pipeline
    # rend son rapport sans attendre l'issue du test sandbox.
    #
    # Le passage en sandbox ne depend PAS uniquement du niveau de risque
    # global (score_report["niveau"]) : un signal de detection fort et
    # independant (l'antivirus qui reconnait une signature, une regle YARA
    # critique/elevee, un hash deja connu comme malveillant, ou une action
    # de reponse "quarantine"/"block") doit a lui seul declencher la
    # sandbox, meme si les autres signaux (entropie, IOC, ML...) restent
    # faibles et font redescendre le score fusionne dans la bande "moyen".
    # Sans ca, un fichier detecte/bloque par l'antivirus mais avec un score
    # global insuffisant n'etait jamais envoye au sandbox.
    clamav_infecte = bool(clamav_res.get("disponible") and clamav_res.get("infecte"))
    hash_deja_connu_malveillant = bool(hash_check.get("connu_malveillant"))
    yara_severe = any(
        m.get("severite") in ("critique", "eleve") for m in yara_res.get("matches", [])
    )
    action_bloquante = score_report["action_recommandee"] in ("quarantine", "block")

    sandbox_recommande = (
        score_report["niveau"] in SANDBOX_AUTO_LEVELS
        or clamav_infecte
        or hash_deja_connu_malveillant
        or yara_severe
        or action_bloquante
    )

    if sandbox_recommande and score_report["niveau"] not in SANDBOX_AUTO_LEVELS:
        raisons = []
        if clamav_infecte:
            raisons.append("l'antivirus a detecte une signature")
        if hash_deja_connu_malveillant:
            raisons.append("le hash est deja connu comme malveillant")
        if yara_severe:
            raisons.append("une regle YARA critique/elevee a ete declenchee")
        if action_bloquante:
            raisons.append(f"l'action recommandee est '{score_report['action_recommandee']}'")
        score_report["explications"].append(
            "Mis en file sandbox malgre un niveau de risque global '"
            f"{score_report['niveau']}' : " + ", ".join(raisons) + "."
        )

    sandbox_entry_id = None
    if sandbox_recommande:
        from . import sandbox as sandbox_mod
        source_pour_sandbox = action_result.get("chemin_quarantaine") or (
            filepath if os.path.exists(filepath) else None
        )
        sandbox_entry_id = sandbox_mod.enqueue(
            source_pour_sandbox, meta["nom"], report_id,
            score_report["score"], score_report["niveau"],
        )

    duration = round(time.time() - started, 3)

    report = {
        "id_rapport": report_id,
        "origine": origine,
        "duree_analyse_s": duration,
        "metadonnees": meta,
        "coherence_type": type_res,
        "empreintes": {**hashes, **hash_check},
        "analyse_statique": static_res,
        "entropie_obfuscation": entropy_res,
        "iocs": iocs,
        "signature_numerique": sig_res,
        "yara": yara_res,
        "antivirus": clamav_res,
        "threat_intelligence": ti_res,
        "scoring_ml": ml_res,
        "archive": archive_res,
        "sous_rapports_archive": [
            {"id_rapport": sr.get("id_rapport"), "nom": sr.get("metadonnees", {}).get("nom"),
             "score": sr.get("score_final", {}).get("score")}
            for sr in sous_rapports
        ],
        "score_final": score_report,
        "action": action_result,
        "sandbox": {
            "recommande": sandbox_recommande,
            "id_soumission": sandbox_entry_id,
        },
    }

    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    return report


def _build_neutralized_report(filepath, report_id, started, origine, error):
    """Rapport de repli lorsque le fichier devient introuvable/illisible EN
    PLEIN MILIEU de l'analyse (FileNotFoundError, PermissionError, ou toute
    autre OSError). Cas concret le plus frequent : l'antivirus temps reel
    du systeme d'exploitation (Windows Defender ou equivalent) detecte le
    fichier de son cote et le supprime/neutralise avant que ce pipeline ait
    fini de le lire — souvent en quelques millisecondes pour une signature
    connue (ex. fichier de test EICAR).

    C'est en soi un signal de detection tres fort (un antivirus tiers a
    juge le fichier assez dangereux pour intervenir immediatement) : ce
    rapport le traite comme "critique"/"block" plutot que comme un simple
    echec technique invisible pour l'utilisateur. Aucune soumission au
    sandbox n'est tentee : il n'y a plus rien a copier."""
    nom = os.path.basename(filepath)
    existe_encore = os.path.exists(filepath)
    duration = round(time.time() - started, 3)

    explication = (
        f"Le fichier est devenu inaccessible en cours d'analyse ({error}). "
        "Cela survient typiquement quand l'antivirus temps reel du systeme "
        "d'exploitation (ex. Windows Defender) detecte le fichier de son "
        "cote et le neutralise (suppression ou mise en quarantaine) avant "
        "que ce pipeline ait fini de le lire. Traite comme une detection "
        "positive forte : niveau 'critique', meme si l'analyse interne de "
        "cet agent n'a pas pu aller a son terme."
    )

    score_report = {
        "score": 100,
        "niveau": "critique",
        "action_recommandee": "block",
        "explications": [explication],
    }

    if existe_encore:
        note_action = (
            "Fichier encore present sur le disque mais illisible (permissions "
            "ou verrou pose par un autre processus, ex. l'antivirus du systeme "
            "en cours de scan) : aucune quarantaine interne tentee pour eviter "
            "de corrompre un fichier deja verrouille."
        )
        raison_sandbox = "fichier illisible : impossible de le copier vers le sandbox"
    else:
        note_action = (
            "Fichier deja supprime ou mis en quarantaine par l'antivirus du "
            "systeme : aucune action de quarantaine interne necessaire ni "
            "possible, le fichier n'existe plus a cet emplacement."
        )
        raison_sandbox = "fichier deja supprime par l'antivirus du systeme : rien a soumettre au sandbox"

    score_report["explications"].append(f"Sandbox non soumis : {raison_sandbox}.")

    ext = os.path.splitext(nom)[1].lstrip(".") or "(aucune)"

    report = {
        "id_rapport": report_id,
        "origine": origine,
        "duree_analyse_s": duration,
        "metadonnees": {
            "nom": nom,
            "extension": ext,
            "taille_octets": None,
            "taille_lisible": "inconnue (analyse interrompue)",
            "mime_reel": "inconnu",
            "chemin": filepath,
            "proprietaire": "inconnu",
            "permissions": "inconnu",
            "date_creation": None,
            "date_modification": None,
            "date_acces": None,
            "zone_origine": None,
        },
        "coherence_type": {
            "extension_declaree": "." + ext if ext != "(aucune)" else ext,
            "type_reel_detecte": None,
            "coherent": None,
            "alerte": False,
            "commentaire": "Analyse interrompue avant la verification de coherence.",
        },
        "empreintes": {"sha256": "", "sha1": "", "md5": "", "connu_malveillant": False},
        "analyse_statique": {
            "note": "Analyse statique interrompue : le fichier est devenu inaccessible avant cette etape."
        },
        "entropie_obfuscation": {
            "entropie_globale": 0,
            "verdict_entropie": None,
            "format_naturellement_compresse": False,
            "entropie_par_bloc": [],
            "base64": {"nombre_blobs_base64": None},
            "xor": {"xor_simple_suspecte": None, "cle_probable": None},
        },
        "iocs": {
            "ips": [], "domaines": [], "urls": [], "emails": [],
            "chemins_windows": [], "chemins_unix": [], "cles_registre": [],
            "chaines_suspectes": [], "score_indicateurs": 0,
        },
        "signature_numerique": None,
        "yara": {"disponible": False, "raison": "analyse interrompue avant ce stade", "matches": []},
        "antivirus": {"disponible": False, "raison": "analyse interrompue avant ce stade"},
        "threat_intelligence": None,
        "scoring_ml": {"features": {}, "probabilite_risque": 0, "methode": "non_execute"},
        "archive": None,
        "sous_rapports_archive": [],
        "score_final": score_report,
        "action": {
            "succes": True,
            "action": "block",
            "libelle": quarantine.ACTION_LABELS.get("block", "Bloquer"),
            "note": note_action,
        },
        "sandbox": {
            "recommande": False,
            "id_soumission": None,
            "raison_non_soumis": raison_sandbox,
        },
        "erreur_pipeline": str(error),
    }

    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    return report


def list_reports(limit=50):
    reports = []
    if not os.path.isdir(REPORTS_DIR):
        return reports
    files = sorted(
        (f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")),
        key=lambda f: os.path.getmtime(os.path.join(REPORTS_DIR, f)),
        reverse=True,
    )
    for f in files[:limit]:
        with open(os.path.join(REPORTS_DIR, f), encoding="utf-8") as fh:
            try:
                data = json.load(fh)
                reports.append({
                    "id_rapport": data["id_rapport"],
                    "nom": data["metadonnees"]["nom"],
                    "score": data["score_final"]["score"],
                    "niveau": data["score_final"]["niveau"],
                    "action": data["action"]["action"],
                    "sha256": data["empreintes"]["sha256"],
                    "host": data.get("host", ""),
                })
            except Exception:
                continue
    return reports


def get_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)