
"""
Gestion de la sandbox Hybrid Analysis pour Cabinet Noir.

- Les fichiers sont copiés dans SANDBOX_DIR.
- Les soumissions et les rapports sont gérés en arrière-plan.
- Les fichiers .rels sont marqués non_applicable : ils doivent être
  analysés dans le contexte de leur document Office d'origine.
- Une erreur de sandbox ne modifie pas le résultat de l'analyse statique.
"""

import json
import os
import queue
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from config import (
    SANDBOX_DIR,
    SANDBOX_REPORTS_DIR,
    HYBRID_ANALYSIS_API_KEY,
    SANDBOX_ENVIRONMENT_ID,
    SANDBOX_POLL_INTERVAL_S,
    SANDBOX_MAX_WAIT_S,
)


API_BASE = "https://hybrid-analysis.com/api/v2"
USER_AGENT = "Falcon Sandbox"

_UNSUITABLE_STANDALONE_EXTENSIONS = {".rels"}

_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
}

if HYBRID_ANALYSIS_API_KEY:
    _REQUEST_HEADERS["api-key"] = HYBRID_ANALYSIS_API_KEY

_queue = queue.Queue()
_worker_lock = threading.Lock()
_worker_started = False


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def _now():
    """Retourne la date actuelle au format ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_directories():
    """Crée les dossiers nécessaires s'ils n'existent pas."""
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    os.makedirs(SANDBOX_REPORTS_DIR, exist_ok=True)


def _report_path(entry_id):
    """Retourne le chemin JSON d'un rapport."""
    safe_id = os.path.basename(str(entry_id))
    return os.path.join(SANDBOX_REPORTS_DIR, f"{safe_id}.json")


def _save_entry(entry):
    """Enregistre un rapport JSON de manière atomique."""
    _ensure_directories()

    path = _report_path(entry["id"])
    temp_path = path + ".tmp"

    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(entry, file, ensure_ascii=False, indent=2)

    os.replace(temp_path, path)


def _load_entry(entry_id):
    """Charge un rapport à partir de son identifiant."""
    path = _report_path(entry_id)

    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            entry = json.load(file)

        if not isinstance(entry, dict):
            return None

        return entry

    except (OSError, json.JSONDecodeError):
        return None


def get_entry(entry_id):
    """Retourne un rapport précis, ou None s'il n'existe pas."""
    return _load_entry(entry_id)


def list_entries(limit=None):
    """
    Retourne les rapports sandbox du plus récent au plus ancien.

    Exemple :
        list_entries(10)
    """
    _ensure_directories()
    entries = []

    try:
        filenames = os.listdir(SANDBOX_REPORTS_DIR)
    except OSError:
        return entries

    for filename in filenames:
        if not filename.endswith(".json"):
            continue

        entry_id = filename[:-5]
        entry = _load_entry(entry_id)

        if entry is not None:
            entries.append(entry)

    entries.sort(
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )

    if limit is not None:
        try:
            limit = max(0, int(limit))
            entries = entries[:limit]
        except (TypeError, ValueError):
            pass

    return entries


def get_status():
    """Retourne les compteurs utilisés par le tableau de bord."""
    entries = list_entries()

    counts = {
        "cle_api_configuree": bool(HYBRID_ANALYSIS_API_KEY),
        "en_attente": 0,
        "en_cours": 0,
        "termines": 0,
        "echecs": 0,
        "non_applicables": 0,
        "total": len(entries),
    }

    for entry in entries:
        status = entry.get("statut", "")

        if status in ("en_attente", "cle_api_absente"):
            counts["en_attente"] += 1
        elif status == "en_cours":
            counts["en_cours"] += 1
        elif status == "termine":
            counts["termines"] += 1
        elif status == "echec":
            counts["echecs"] += 1
        elif status == "non_applicable":
            counts["non_applicables"] += 1

    return counts


def _is_unsuitable_file(filename):
    """Indique si l'extension ne convient pas à une soumission autonome."""
    extension = os.path.splitext(filename or "")[1].lower()
    return extension in _UNSUITABLE_STANDALONE_EXTENSIONS


def _safe_filename(filename):
    """Nettoie le nom de fichier sans modifier son extension."""
    filename = os.path.basename(str(filename or "fichier_inconnu"))
    filename = filename.replace("\x00", "")
    filename = filename.strip()

    if not filename or filename in (".", ".."):
        filename = "fichier_inconnu"

    return filename


def _response_error(response):
    """Construit un message d'erreur détaillé pour une réponse HTTP."""
    parts = [
        f"Erreur HTTP {response.status_code}",
        f"URL : {response.url}",
    ]

    location = response.headers.get("Location")
    if location:
        parts.append(f"Redirection : {location}")

    try:
        body = response.json()
        body_text = json.dumps(body, ensure_ascii=False)
    except (ValueError, json.JSONDecodeError):
        body_text = response.text or ""

    body_text = body_text.strip()

    if body_text:
        # Évite d'enregistrer une réponse d'erreur démesurée.
        parts.append(f"Réponse : {body_text[:2000]}")

    return " | ".join(parts)


def _update_entry(entry_id, **changes):
    """Met à jour un rapport et l'enregistre."""
    entry = _load_entry(entry_id)

    if entry is None:
        return None

    entry.update(changes)
    entry["updated_at"] = _now()
    _save_entry(entry)

    return entry


# ---------------------------------------------------------------------------
# Enregistrement d'une demande d'analyse
# ---------------------------------------------------------------------------

def enqueue(source_path, nom_original, report_id, score, niveau):
    """
    Ajoute un fichier à la file d'attente sandbox.

    Retourne l'identifiant de la demande créée.
    L'analyse statique existante n'est pas modifiée.
    """
    _ensure_directories()

    if not source_path or not os.path.isfile(source_path):
        raise FileNotFoundError(
            f"Fichier introuvable pour la sandbox : {source_path}"
        )

    original_name = _safe_filename(
        nom_original or os.path.basename(source_path)
    )

    entry_id = uuid.uuid4().hex
    destination_name = f"{entry_id}_{original_name}"
    destination_path = os.path.join(SANDBOX_DIR, destination_name)

    shutil.copy2(source_path, destination_path)

    if _is_unsuitable_file(original_name):
        status = "non_applicable"
        error = (
            "Analyse dynamique non applicable : le fichier .rels est un "
            "composant XML interne à un document Office OOXML, et non un "
            "échantillon autonome. L'analyse statique est conservée. "
            "Si nécessaire, analyser le document Office complet après "
            "vérification de la politique de partage des données."
        )
    elif not HYBRID_ANALYSIS_API_KEY:
        status = "cle_api_absente"
        error = (
            "Clé API Hybrid Analysis absente. Configurez "
            "HYBRID_ANALYSIS_API_KEY pour activer la soumission."
        )
    else:
        status = "en_attente"
        error = None

    entry = {
        "id": entry_id,
        "report_id": report_id,
        "nom_original": original_name,
        "score_statique": score,
        "niveau_statique": niveau,
        "statut": status,
        "created_at": _now(),
        "updated_at": _now(),
        "chemin_sandbox": destination_path,
        "ha_job_id": None,
        "verdict": None,
        "score_menace_sandbox": None,
        "menaces_detectees": [],
        "url_rapport_public": None,
        "erreur": error,
    }

    _save_entry(entry)

    if status == "en_attente":
        _queue.put(entry_id)
        start_worker()

    return entry_id


# ---------------------------------------------------------------------------
# Soumission manuelle
# ---------------------------------------------------------------------------

def submit_now(entry_id):
    """
    Place une demande existante dans la file d'attente.

    Retourne True si la demande a été ajoutée à la file,
    False si elle ne peut pas être soumise.
    """
    entry = _load_entry(entry_id)

    if entry is None:
        return False

    if _is_unsuitable_file(entry.get("nom_original", "")):
        _update_entry(
            entry_id,
            statut="non_applicable",
            erreur=(
                "Soumission ignorée : un fichier .rels est un composant "
                "interne d'un document Office OOXML. Analysez le document "
                "Office complet si une analyse dynamique est nécessaire."
            ),
        )
        return False

    if not HYBRID_ANALYSIS_API_KEY:
        _update_entry(
            entry_id,
            statut="cle_api_absente",
            erreur="Clé API Hybrid Analysis absente.",
        )
        return False

    if entry.get("statut") == "en_cours":
        return False

    if entry.get("statut") == "termine":
        return False

    _update_entry(
        entry_id,
        statut="en_attente",
        erreur=None,
    )

    _queue.put(entry_id)
    start_worker()
    return True


# ---------------------------------------------------------------------------
# API Hybrid Analysis
# ---------------------------------------------------------------------------

def _submit_to_hybrid_analysis(file_path, original_name):
    """Soumet un fichier à Hybrid Analysis et retourne les données du job."""
    if not HYBRID_ANALYSIS_API_KEY:
        raise RuntimeError("Clé API Hybrid Analysis absente.")

    if _is_unsuitable_file(original_name):
        raise ValueError(
            "Le fichier .rels n'est pas soumis individuellement à la sandbox."
        )

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"Fichier sandbox introuvable : {file_path}"
        )

    headers = dict(_REQUEST_HEADERS)
    data = {}

    if SANDBOX_ENVIRONMENT_ID:
        data["environment_id"] = str(SANDBOX_ENVIRONMENT_ID)

    with open(file_path, "rb") as file:
        files = {
            "file": (
                original_name,
                file,
                "application/octet-stream",
            )
        }

        response = requests.post(
            f"{API_BASE}/submit/file",
            headers=headers,
            data=data,
            files=files,
            timeout=(15, 120),
            allow_redirects=False,
        )

    if 300 <= response.status_code < 400:
        raise RuntimeError(
            "Hybrid Analysis a renvoyé une redirection inattendue. "
            + _response_error(response)
        )

    if not response.ok:
        raise RuntimeError(_response_error(response))

    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "Réponse JSON invalide de Hybrid Analysis : "
            + (response.text or "")[:1000]
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError(
            "Réponse inattendue de Hybrid Analysis : objet JSON attendu."
        )

    job_id = (
        result.get("job_id")
        or result.get("id")
        or result.get("submission_id")
    )

    if not job_id:
        raise RuntimeError(
            "Hybrid Analysis n'a pas retourné d'identifiant de tâche. "
            f"Réponse reçue : {json.dumps(result, ensure_ascii=False)[:1500]}"
        )

    return {
        "job_id": str(job_id),
        "response": result,
    }


def _fetch_summary(job_id):
    """Récupère le résumé d'un rapport Hybrid Analysis."""
    encoded_job_id = quote(str(job_id), safe="")
    response = requests.get(
        f"{API_BASE}/report/{encoded_job_id}/summary",
        headers=_REQUEST_HEADERS,
        timeout=(15, 45),
        allow_redirects=False,
    )

    if response.status_code == 404:
        return None

    if 300 <= response.status_code < 400:
        raise RuntimeError(
            "Redirection inattendue lors de la récupération du rapport. "
            + _response_error(response)
        )

    if not response.ok:
        raise RuntimeError(_response_error(response))

    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "Résumé sandbox JSON invalide : "
            + (response.text or "")[:1000]
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError("Format inattendu du résumé Hybrid Analysis.")

    return result


# ---------------------------------------------------------------------------
# Traitement d'une tâche
# ---------------------------------------------------------------------------

def _get_summary_state(summary):
    """Normalise le statut du résumé fourni par l'API."""
    if not isinstance(summary, dict):
        return ""

    state = (
        summary.get("state")
        or summary.get("status")
        or summary.get("verdict")
        or ""
    )

    return str(state).strip().upper()


def _extract_tags(summary):
    """Extrait une liste de menaces/tags sans supposer un format unique."""
    if not isinstance(summary, dict):
        return []

    tags = (
        summary.get("threat_level_human")
        or summary.get("tags")
        or summary.get("mitre_attcks")
        or summary.get("threats")
        or []
    )

    if isinstance(tags, str):
        return [tags]

    if isinstance(tags, list):
        return tags

    return []


def _process_entry(entry_id):
    """Soumet une demande, puis attend son résumé."""
    entry = _load_entry(entry_id)

    if entry is None:
        return

    original_name = entry.get("nom_original", "")

    # Garde-fou : ne jamais soumettre un .rels seul.
    if _is_unsuitable_file(original_name):
        _update_entry(
            entry_id,
            statut="non_applicable",
            erreur=(
                "Soumission ignorée : le fichier .rels est un composant "
                "interne à un document Office OOXML, pas un échantillon "
                "autonome. L'analyse statique est conservée."
            ),
        )
        return

    if not HYBRID_ANALYSIS_API_KEY:
        _update_entry(
            entry_id,
            statut="cle_api_absente",
            erreur="Clé API Hybrid Analysis absente.",
        )
        return

    file_path = entry.get("chemin_sandbox")

    if not file_path or not os.path.isfile(file_path):
        _update_entry(
            entry_id,
            statut="echec",
            erreur="Le fichier copié dans le dossier sandbox est introuvable.",
        )
        return

    _update_entry(
        entry_id,
        statut="en_cours",
        erreur=None,
    )

    try:
        submission = _submit_to_hybrid_analysis(
            file_path,
            original_name,
        )

        job_id = submission["job_id"]

        _update_entry(
            entry_id,
            ha_job_id=job_id,
            erreur=None,
        )

        start_time = time.monotonic()
        max_wait = max(0, int(SANDBOX_MAX_WAIT_S))
        poll_interval = max(1, int(SANDBOX_POLL_INTERVAL_S))
        last_poll_error = None

        while time.monotonic() - start_time < max_wait:
            try:
                summary = _fetch_summary(job_id)
                last_poll_error = None
            except (requests.RequestException, RuntimeError) as exc:
                last_poll_error = str(exc)
                time.sleep(poll_interval)
                continue

            if summary is None:
                # Le rapport peut ne pas être disponible immédiatement.
                time.sleep(poll_interval)
                continue

            state = _get_summary_state(summary)

            if state in ("SUCCESS", "SUCCEEDED", "COMPLETED", "FINISHED"):
                verdict = (
                    summary.get("verdict")
                    or summary.get("threat_level_human")
                    or summary.get("threat_level")
                )

                threat_score = (
                    summary.get("threat_score")
                    if summary.get("threat_score") is not None
                    else summary.get("score")
                )

                report_url = (
                    summary.get("report_url")
                    or summary.get("url")
                    or summary.get("permalink")
                )

                _update_entry(
                    entry_id,
                    statut="termine",
                    verdict=verdict,
                    score_menace_sandbox=threat_score,
                    menaces_detectees=_extract_tags(summary),
                    url_rapport_public=report_url,
                    erreur=None,
                )
                return

            if state in ("ERROR", "FAILED", "FAILURE"):
                error_message = (
                    summary.get("error_message")
                    or summary.get("error")
                    or summary.get("message")
                    or "Hybrid Analysis a signalé un échec de traitement."
                )

                _update_entry(
                    entry_id,
                    statut="echec",
                    erreur=f"Échec du traitement sandbox : {error_message}",
                )
                return

            time.sleep(poll_interval)

        timeout_message = (
            f"Délai d'attente dépassé après {max_wait} secondes. "
            f"Identifiant Hybrid Analysis : {job_id}."
        )

        if last_poll_error:
            timeout_message += f" Dernière erreur API : {last_poll_error}"

        _update_entry(
            entry_id,
            statut="echec",
            erreur=timeout_message,
        )

    except (
        requests.RequestException,
        RuntimeError,
        OSError,
        ValueError,
    ) as exc:
        _update_entry(
            entry_id,
            statut="echec",
            erreur=f"{type(exc).__name__} : {exc}",
        )

    except Exception as exc:
        # Empêche une erreur inattendue de bloquer le worker.
        _update_entry(
            entry_id,
            statut="echec",
            erreur=f"Erreur inattendue : {type(exc).__name__} : {exc}",
        )


# ---------------------------------------------------------------------------
# Worker en arrière-plan
# ---------------------------------------------------------------------------

def _worker_loop():
    """Traite les demandes jusqu'à l'arrêt du processus."""
    while True:
        entry_id = _queue.get()

        try:
            if entry_id is None:
                return

            _process_entry(entry_id)

        finally:
            _queue.task_done()


def start_worker():
    """Démarre le worker s'il n'est pas déjà actif."""
    global _worker_started

    with _worker_lock:
        if _worker_started:
            return

        thread = threading.Thread(
            target=_worker_loop,
            name="cabinet-noir-sandbox-worker",
            daemon=True,
        )
        thread.start()
        _worker_started = True


def resume_pending_on_startup():
    """
    Réinscrit les demandes en attente au démarrage de l'application.

    Les fichiers .rels ne sont pas remis dans la file d'attente.
    """
    entries = list_entries()
    resumed = 0

    for entry in entries:
        status = entry.get("statut")
        entry_id = entry.get("id")
        filename = entry.get("nom_original", "")

        if not entry_id:
            continue

        if _is_unsuitable_file(filename):
            if status != "non_applicable":
                _update_entry(
                    entry_id,
                    statut="non_applicable",
                    erreur=(
                        "Analyse dynamique non applicable : fichier .rels "
                        "interne à un document Office OOXML."
                    ),
                )
            continue

        if status == "en_attente":
            _queue.put(entry_id)
            resumed += 1

        elif status == "en_cours":
            # La tâche précédente a pu être interrompue lors d'un redémarrage.
            _update_entry(
                entry_id,
                statut="en_attente",
                erreur=(
                    "Traitement interrompu par un redémarrage. "
                    "La demande est remise en attente."
                ),
            )
            _queue.put(entry_id)
            resumed += 1

        elif status == "cle_api_absente" and HYBRID_ANALYSIS_API_KEY:
            _update_entry(
                entry_id,
                statut="en_attente",
                erreur=None,
            )
            _queue.put(entry_id)
            resumed += 1

    if resumed:
        start_worker()

    return resumed
