"""
Sandbox dynamique (exécution contrôlée en environnement jetable).

Le reste du pipeline (agent/static_analysis.py, agent/yara_scan.py, etc.)
n'analyse un fichier QUE de façon statique — il le lit, mais ne l'exécute
et ne l'ouvre jamais. Ce module fait l'inverse pour les fichiers jugés
suspects (niveau "élevé" ou "critique") : il les soumet réellement à une
machine virtuelle jetable distante, via l'API gratuite Hybrid Analysis
(hybrid-analysis.com), qui les ouvre/exécute et observe leur comportement
(processus lancés, connexions réseau, fichiers créés, clés de registre
modifiées...).

Fonctionnement :
  - `enqueue(...)` est appelé par agent/pipeline.py juste après le scoring
    statique. Il copie le fichier dans un coffre dédié (SANDBOX_DIR) — pour
    qu'il survive même si l'original est ensuite supprimé/déplacé — et
    l'ajoute à une file d'attente. Cet appel est NON BLOQUANT : le pipeline
    principal continue et rend son rapport sans attendre le résultat de la
    sandbox, qui peut prendre plusieurs minutes.
  - Un thread d'arrière-plan dépile la file, soumet chaque fichier à
    Hybrid Analysis, patiente puis récupère le verdict comportemental.
  - Chaque entrée est persistée en JSON dans SANDBOX_REPORTS_DIR, consultable
    à tout moment via list_entries() / get_status() (exposés par app.py sous
    /api/sandbox/...).

Dégradation propre : si HYBRID_ANALYSIS_API_KEY n'est pas configurée, les
fichiers suspects sont quand même répertoriés (statut "cle_api_absente")
pour signaler qu'ils MÉRITERAIENT un test sandbox, sans qu'aucune requête
réseau ne soit tentée.
"""
import json
import os
import queue
import shutil
import threading
import time
import uuid

import requests

from config import (
    SANDBOX_DIR, SANDBOX_REPORTS_DIR, HYBRID_ANALYSIS_API_KEY,
    SANDBOX_ENVIRONMENT_ID, SANDBOX_POLL_INTERVAL_S, SANDBOX_MAX_WAIT_S,
)

API_BASE = "https://www.hybrid-analysis.com/api/v2"
USER_AGENT = "Falcon Sandbox"

_lock = threading.Lock()
_queue = queue.Queue()
_worker_thread = None
_stop_event = threading.Event()


# --------------------------------------------------------------------------
# Persistance (un fichier JSON par entrée, même logique que agent/pipeline.py)
# --------------------------------------------------------------------------
def _entry_path(entry_id):
    return os.path.join(SANDBOX_REPORTS_DIR, f"{entry_id}.json")


def _save_entry(entry):
    with open(_entry_path(entry["id"]), "w", encoding="utf-8") as f:
        json.dump(entry, f, ensure_ascii=False, indent=2, default=str)


def _load_entry(entry_id):
    path = _entry_path(entry_id)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_entries(limit=200):
    if not os.path.isdir(SANDBOX_REPORTS_DIR):
        return []
    files = sorted(
        (f for f in os.listdir(SANDBOX_REPORTS_DIR) if f.endswith(".json")),
        key=lambda f: os.path.getmtime(os.path.join(SANDBOX_REPORTS_DIR, f)),
        reverse=True,
    )
    out = []
    for f in files[:limit]:
        try:
            with open(os.path.join(SANDBOX_REPORTS_DIR, f), encoding="utf-8") as fh:
                out.append(json.load(fh))
        except Exception:
            continue
    return out


def get_status():
    entries = list_entries(limit=2000)
    return {
        "cle_api_configuree": bool(HYBRID_ANALYSIS_API_KEY),
        "en_attente": sum(1 for e in entries if e["statut"] in ("en_attente", "cle_api_absente")),
        "en_cours": sum(1 for e in entries if e["statut"] == "en_cours"),
        "termines": sum(1 for e in entries if e["statut"] == "termine"),
        "echecs": sum(1 for e in entries if e["statut"] == "echec"),
        "total": len(entries),
    }


# --------------------------------------------------------------------------
# Mise en file (appelé par agent/pipeline.py)
# --------------------------------------------------------------------------
def enqueue(source_path, nom_original, report_id, score, niveau):
    """Copie le fichier suspect dans le coffre sandbox et le met en file
    d'attente pour un test comportemental. Non bloquant. Retourne
    l'identifiant de l'entrée, ou None si la copie a échoué."""
    if not source_path or not os.path.exists(source_path):
        return None

    entry_id = uuid.uuid4().hex[:10]
    dest_path = os.path.join(SANDBOX_DIR, f"{entry_id}_{os.path.basename(nom_original)}")
    try:
        shutil.copy2(source_path, dest_path)
    except Exception:
        return None

    entry = {
        "id": entry_id,
        "report_id": report_id,
        "nom_original": nom_original,
        "score_statique": score,
        "niveau_statique": niveau,
        "statut": "en_attente" if HYBRID_ANALYSIS_API_KEY else "cle_api_absente",
        "horodatage_ajout": time.time(),
        "horodatage_maj": time.time(),
        "chemin_sandbox": dest_path,
        "ha_job_id": None,
        "verdict": None,
        "score_menace_sandbox": None,
        "menaces_detectees": [],
        "url_rapport_public": None,
        "erreur": None,
    }
    _save_entry(entry)

    if HYBRID_ANALYSIS_API_KEY:
        _queue.put(entry_id)
        _ensure_worker()

    return entry_id


def submit_now(entry_id):
    """Permet de soumettre manuellement une entrée en attente (par ex. si
    la clé API vient d'être configurée après coup)."""
    entry = _load_entry(entry_id)
    if entry is None or not HYBRID_ANALYSIS_API_KEY:
        return False
    if entry["statut"] not in ("en_attente", "cle_api_absente", "echec"):
        return False
    entry["statut"] = "en_attente"
    _save_entry(entry)
    _queue.put(entry_id)
    _ensure_worker()
    return True


# --------------------------------------------------------------------------
# Appels API Hybrid Analysis
# --------------------------------------------------------------------------
def _submit_to_hybrid_analysis(filepath, filename):
    with open(filepath, "rb") as f:
        r = requests.post(
            f"{API_BASE}/submit/file",
            headers={"api-key": HYBRID_ANALYSIS_API_KEY, "User-Agent": USER_AGENT},
            data={"environment_id": SANDBOX_ENVIRONMENT_ID},
            files={"file": (filename, f)},
            timeout=60,
        )
    r.raise_for_status()
    data = r.json()
    return data.get("job_id") or data.get("sha256")


def _fetch_summary(job_id):
    r = requests.get(
        f"{API_BASE}/report/{job_id}/summary",
        headers={"api-key": HYBRID_ANALYSIS_API_KEY, "User-Agent": USER_AGENT},
        timeout=30,
    )
    if r.status_code == 404:
        return None  # rapport pas encore pret
    r.raise_for_status()
    return r.json()


def _process_entry(entry_id):
    entry = _load_entry(entry_id)
    if entry is None:
        return
    entry["statut"] = "en_cours"
    entry["horodatage_maj"] = time.time()
    _save_entry(entry)

    try:
        job_id = _submit_to_hybrid_analysis(entry["chemin_sandbox"], entry["nom_original"])
        entry["ha_job_id"] = job_id
        _save_entry(entry)

        waited, summary = 0.0, None
        while waited < SANDBOX_MAX_WAIT_S:
            time.sleep(SANDBOX_POLL_INTERVAL_S)
            waited += SANDBOX_POLL_INTERVAL_S
            summary = _fetch_summary(job_id)
            if summary and summary.get("state") in ("SUCCESS", "ERROR"):
                break

        if summary is None:
            entry["statut"] = "echec"
            entry["erreur"] = "delai d'attente depasse sans reponse de la sandbox"
        elif summary.get("state") == "ERROR":
            entry["statut"] = "echec"
            entry["erreur"] = summary.get("error_type") or "erreur sandbox"
        else:
            entry["statut"] = "termine"
            entry["verdict"] = summary.get("verdict") or "inconnu"
            entry["score_menace_sandbox"] = summary.get("threat_score")
            entry["menaces_detectees"] = [
                t.get("name") for t in (summary.get("classification_tags") or []) if t.get("name")
            ] or (summary.get("threat_level_readable_tags") or [])
            sha256 = summary.get("sha256")
            entry["url_rapport_public"] = (
                f"https://www.hybrid-analysis.com/sample/{sha256}" if sha256 else None
            )
    except Exception as e:
        entry["statut"] = "echec"
        entry["erreur"] = str(e)

    entry["horodatage_maj"] = time.time()
    _save_entry(entry)


def _worker_loop():
    while not _stop_event.is_set():
        try:
            entry_id = _queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            _process_entry(entry_id)
        except Exception:
            pass
        finally:
            _queue.task_done()


def _ensure_worker():
    global _worker_thread
    with _lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _stop_event.clear()
            _worker_thread = threading.Thread(target=_worker_loop, daemon=True)
            _worker_thread.start()


def resume_pending_on_startup():
    """À appeler au démarrage de app.py : remet en file les entrées encore
    'en_attente' issues d'une précédente session (ex: après un redémarrage
    du serveur alors que des fichiers attendaient d'être soumis)."""
    if not HYBRID_ANALYSIS_API_KEY:
        return
    pending = [e["id"] for e in list_entries(limit=2000) if e["statut"] == "en_attente"]
    for entry_id in pending:
        _queue.put(entry_id)
    if pending:
        _ensure_worker()
