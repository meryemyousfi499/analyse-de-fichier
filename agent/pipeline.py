"""Point d'entree de l'analyse d'un fichier.

La logique de decision (quels outils lancer, quand soumettre a la sandbox,
verdict) vit dans agent/orchestrator.py ; ce module garde l'API publique
historique (run_pipeline, list_reports, get_report) et le rapport de repli
quand le fichier disparait en cours d'analyse.
"""
import json
import os
import time
import uuid

from config import REPORTS_DIR

from . import orchestrator
from . import quarantine
from . import report_store

PIPELINE_STEPS = [
    "metadonnees", "coherence_type", "empreintes", "analyse_statique",
    "entropie_obfuscation", "extraction_ioc", "signature", "yara",
    "antivirus", "scoring_ml", "fusion_score", "action_reponse",
]


def run_pipeline(filepath, known_malicious_hashes=None, enable_threat_intel=True,
                  origine="manuel", archive_password=None, parent_id=None, depth=0):
    """Analyse un fichier.

    origine : "manuel" (depot dashboard/API), "auto_watch" (dossier surveille),
              "extrait_archive" (fichier issu d'une archive), "agent_distant".
    archive_password : mot de passe fourni si le fichier est une archive chiffree.
    parent_id / depth : lien enfant -> parent pour les fichiers extraits d'une
              archive (le rapport parent reference ses enfants).

    Le rapport "neutralise" (score 100 / critique) n'est produit QUE si le
    fichier a reellement disparu ou est devenu illisible en cours d'analyse
    (typiquement : l'antivirus temps reel du systeme l'a supprime). Toute
    autre erreur d'E/S (disque plein, rapport non ecrit...) est une vraie
    erreur technique et remonte a l'appelant au lieu de se faire passer pour
    une detection.
    """
    report_id = str(uuid.uuid4())[:8]
    started = time.time()

    try:
        return orchestrator.analyze(
            filepath, report_id, started, known_malicious_hashes, enable_threat_intel,
            origine, archive_password, parent_id=parent_id, depth=depth, run_child=run_pipeline,
        )
    except (FileNotFoundError, PermissionError) as e:
        return _build_neutralized_report(filepath, report_id, started, origine, e,
                                         parent_id=parent_id, depth=depth)
    except OSError as e:
        if not os.path.exists(filepath):
            return _build_neutralized_report(filepath, report_id, started, origine, e,
                                             parent_id=parent_id, depth=depth)
        raise


def _build_neutralized_report(filepath, report_id, started, origine, error, parent_id=None, depth=0):
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
        "id_parent": parent_id,
        "profondeur": depth,
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
        "verdict": {
            "verdict": "malicious",
            "libelle": "Fichier neutralise par un antivirus tiers en cours d'analyse",
            "confiance": "moyenne",
            "couverture": {"requis": [], "couverts": [], "ratio": 0.0, "manquants": []},
            "preuves_fortes": ["Fichier supprime/verrouille pendant l'analyse (antivirus du systeme probable)"],
            "raisons": [explication],
        },
        "erreur_pipeline": str(error),
    }

    orchestrator.save_report(report)
    return report


def list_reports(limit=50):
    """Historique (plus recents d'abord), via l'index SQLite ; retombe sur la
    lecture des JSON si la base est inutilisable."""
    rows = report_store.list_recent(limit)
    if rows is not None:
        return [{
            "id_rapport": r["id"], "nom": r["nom"], "score": r["score"], "niveau": r["niveau"],
            "verdict": r["verdict"], "action": r["action"], "sha256": r["sha256"], "host": r["host"] or "",
        } for r in rows]
    return _list_reports_from_json(limit)


def _list_reports_from_json(limit=50):
    reports = []
    if not os.path.isdir(REPORTS_DIR):
        return reports
    files = sorted(
        (f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")),
        key=lambda f: os.path.getmtime(os.path.join(REPORTS_DIR, f)),
        reverse=True,
    )
    for f in files:
        if len(reports) >= limit:
            break
        try:
            with open(os.path.join(REPORTS_DIR, f), encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("id_parent"):
                continue
            reports.append({
                "id_rapport": data["id_rapport"],
                "nom": data["metadonnees"]["nom"],
                "score": data["score_final"]["score"],
                "niveau": data["score_final"]["niveau"],
                "verdict": (data.get("verdict") or {}).get("verdict"),
                "action": data["action"]["action"],
                "sha256": data["empreintes"]["sha256"],
                "host": data.get("host", ""),
            })
        except Exception:
            continue
    return reports


def get_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{os.path.basename(str(report_id))}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)