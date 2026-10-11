"""
Actions de réponse selon le score : autoriser, surveiller, mettre en
quarantaine, bloquer, alerter, ou demander une revue humaine.

Principe de sécurité : l'agent ne supprime JAMAIS automatiquement un
fichier, quel que soit le score. La quarantaine neutralise (renommage,
permissions retirées, déplacement hors zone d'exécution) sans détruire
la preuve, afin de permettre une revue humaine ou une investigation.
"""
import json
import os
import shutil
import stat
import time

from config import QUARANTINE_DIR

ACTION_LABELS = {
    "allow": "Autoriser",
    "monitor": "Surveiller",
    "quarantine": "Mettre en quarantaine",
    "block": "Bloquer",
    "alert": "Alerter un analyste",
    "human_review": "Revue humaine requise",
}


def _log_action(entry):
    log_path = os.path.join(QUARANTINE_DIR, "journal_quarantaine.jsonl")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def quarantine_file(path, reason=""):
    if not os.path.exists(path):
        return {"succes": False, "raison": "fichier introuvable"}

    name = os.path.basename(path)
    timestamp = int(time.time())
    dest_name = f"{timestamp}_{name}.quarantine"
    dest_path = os.path.join(QUARANTINE_DIR, dest_name)

    shutil.move(path, dest_path)
    try:
        os.chmod(dest_path, stat.S_IREAD)  # lecture seule, non executable
    except Exception:
        pass

    entry = {
        "horodatage": timestamp,
        "fichier_original": name,
        "chemin_quarantaine": dest_path,
        "raison": reason,
    }
    _log_action(entry)
    return {"succes": True, **entry}


def apply_action(action, path, score_report):
    """Applique l'action recommandee par le moteur de scoring.
    Ne supprime jamais le fichier ; la quarantaine deplace + neutralise."""
    reason = "; ".join(score_report.get("explications", []))

    if action in ("quarantine", "block"):
        result = quarantine_file(path, reason=reason)
        result["action"] = action
        result["libelle"] = ACTION_LABELS.get(action, action)
        return result

    if action in ("allow", "monitor", "alert", "human_review"):
        return {
            "succes": True,
            "action": action,
            "libelle": ACTION_LABELS.get(action, action),
            "fichier_conserve_a": path,
            "note": "Aucun deplacement effectue pour cette action.",
        }

    return {"succes": False, "raison": f"action inconnue: {action}"}
