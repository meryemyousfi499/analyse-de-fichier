"""
Surveillance automatique de dossiers (ex : ~/Downloads / ~/Téléchargements).

Objectif : l'agent n'attend pas qu'on lui dépose un fichier sur le
dashboard — chaque nouveau fichier qui apparaît dans un dossier surveillé
est automatiquement envoyé dans le pipeline d'analyse.

Architecture à deux vitesses (détection / traitement séparés) :
  - Un thread de DÉTECTION scanne les dossiers en continu, de façon non
    bloquante (jamais de pause active dans la boucle), et se contente
    d'empiler les fichiers stabilisés dans une file d'attente à priorité.
  - Un thread de TRAITEMENT dépile cette file et lance le pipeline
    d'analyse, un fichier à la fois.

Priorité — LE POINT IMPORTANT :
  - Au tout premier instant du démarrage, l'agent prend un "instantané"
    immédiat (sans délai) de ce qui existe déjà dans les dossiers
    surveillés : c'est l'inventaire de départ.
  - Tout fichier de cet inventaire de départ est analysé, mais en
    ARRIÈRE-PLAN (priorité basse) : il ne bloque jamais rien d'autre.
  - Tout fichier qui n'était PAS dans cet instantané — donc un nouveau
    téléchargement qui arrive après coup, même pendant que l'arrière-plan
    tourne encore — passe en priorité HAUTE et double la file d'attente.
  - Cette distinction est faite une fois pour toutes à l'instantané de
    départ, indépendamment du temps que prend ensuite la détection ou
    l'analyse : un gros arrière-plan qui met du temps à se traiter ne
    fait jamais passer un nouveau téléchargement pour un "ancien" fichier.

Détection de stabilité NON BLOQUANTE :
  - un fichier encore en cours de téléchargement (.crdownload, .part, ...)
    est ignoré jusqu'à son renommage final ;
  - la taille de chaque fichier candidat est comparée entre deux passages
    successifs du scanner (pas d'attente active) ; un fichier est
    considéré stable quand sa taille n'a pas changé depuis au moins
    WATCH_STABILIZE_S secondes ;
  - un fichier déjà mis en file (même chemin + même mtime) n'est pas
    remis en file ;
  - toute erreur sur un fichier ne bloque jamais la surveillance des autres.
"""
import itertools
import os
import queue
import threading
import time
import traceback

from config import (
    WATCH_DIRS, WATCH_POLL_INTERVAL_S, WATCH_STABILIZE_S,
    INCOMPLETE_DOWNLOAD_SUFFIXES, QUARANTINE_DIR, REPORTS_DIR,
    WATCH_RECENT_FILE_WINDOW_S,
)

PRIORITE_NOUVEAU = 0       # nouveau telechargement, arrive apres l'instantane de depart
PRIORITE_ARRIERE_PLAN = 1  # fichier deja present sur la machine au demarrage

_lock = threading.Lock()
_scanner_thread = None
_worker_thread = None
_stop_event = threading.Event()
_queue = queue.PriorityQueue()
_counter = itertools.count()  # tie-breaker pour garder l'ordre d'arrivee

_state = {
    "actif": False,
    "dossiers_surveilles": [],
    "fichiers_traites": 0,
    "dernier_fichier": None,
    "dernier_rapport_id": None,
    "fichier_en_cours": None,
    "en_attente_nouveaux": 0,
    "en_attente_arriere_plan": 0,
    "erreurs": [],
    "demarre_le": None,
}

_seen = set()            # chemins deja mis en file (avec quel mtime), evite les doublons
_seen_mtimes = {}        # chemin -> mtime au moment de la mise en file
_size_tracker = {}       # chemin -> (taille, horodatage_dernier_changement) : detection non bloquante
_baseline_paths = set()  # instantane immediat pris au demarrage : fichiers deja presents
_baseline_time = 0.0     # horodatage de cet instantane, pour la fenetre "recent"


def _is_incomplete(path):
    return path.lower().endswith(INCOMPLETE_DOWNLOAD_SUFFIXES)


def _already_under_agent_dirs(path):
    # Evite d'auto-analyser les fichiers deja geres par l'agent lui-meme
    # (quarantaine, rapports), pour ne pas boucler sur ses propres artefacts.
    abspath = os.path.abspath(path)
    for d in (QUARANTINE_DIR, REPORTS_DIR):
        if abspath.startswith(os.path.abspath(d) + os.sep):
            return True
    return False


def _list_candidate_files():
    found = []
    for folder in WATCH_DIRS:
        if not os.path.isdir(folder):
            continue
        try:
            entries = os.listdir(folder)
        except OSError:
            continue
        for name in entries:
            path = os.path.join(folder, name)
            if not os.path.isfile(path):
                continue
            if _is_incomplete(path):
                continue
            if _already_under_agent_dirs(path):
                continue
            found.append(path)
    return found


def _snapshot_baseline():
    """Instantané immédiat (aucune attente) de ce qui existe déjà dans les
    dossiers surveillés au moment précis du démarrage. Sert uniquement à
    décider la priorité plus tard — un fichier de cet instantané reste
    "arrière-plan" SAUF s'il est très récent (voir WATCH_RECENT_FILE_WINDOW_S) :
    un fichier téléchargé juste avant de lancer la surveillance est encore
    traité comme un nouveau téléchargement prioritaire, pas enterré derrière
    des centaines d'anciens fichiers."""
    global _baseline_time
    _baseline_paths.clear()
    _baseline_time = time.time()
    _baseline_paths.update(_list_candidate_files())


def _enqueue(path, priority, mtime):
    # Cle de tri secondaire : les nouveaux telechargements gardent l'ordre
    # d'arrivee (FIFO) ; l'arriere-plan est traite du plus recent au plus
    # ancien (-mtime), pour que le fichier le plus susceptible d'interesser
    # l'utilisateur "maintenant" sorte en tete de son propre lot, meme s'il
    # a ete classe arriere-plan.
    sort_key = next(_counter) if priority == PRIORITE_NOUVEAU else -mtime
    _queue.put((priority, sort_key, path))
    if priority == PRIORITE_NOUVEAU:
        _state["en_attente_nouveaux"] += 1
    else:
        _state["en_attente_arriere_plan"] += 1


def _scan_once():
    """Thread de detection : repere les fichiers dont la taille est stable
    depuis au moins WATCH_STABILIZE_S secondes (comparaison entre passages
    successifs, sans jamais bloquer/dormir a l'interieur de cette fonction)
    et les met en file. Ne lance jamais l'analyse lui-meme."""
    now = time.time()
    candidats = _list_candidate_files()
    candidats_set = set(candidats)

    # Nettoyage : un fichier qui a disparu (deplace/supprime) ne doit plus
    # etre suivi pour la stabilisation.
    for path in list(_size_tracker.keys()):
        if path not in candidats_set:
            _size_tracker.pop(path, None)

    for path in candidats:
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except OSError:
            continue

        if _seen_mtimes.get(path) == mtime:
            continue  # deja mis en file pour cette version du fichier

        last = _size_tracker.get(path)
        if last is None or last[0] != size:
            # Taille jamais vue, ou changee depuis le dernier passage :
            # le fichier est encore en train d'etre ecrit -> pas stable.
            _size_tracker[path] = (size, now)
            continue

        stable_depuis = now - last[1]
        if size <= 0 or stable_depuis < WATCH_STABILIZE_S:
            continue  # pas encore assez stable, on repassera au prochain scan

        # Fichier stable : direction de la file d'attente.
        _size_tracker.pop(path, None)
        _seen_mtimes[path] = mtime

        # Priorite : absent de l'instantane de depart -> nouveau telechargement
        # -> priorite haute. Present des le depart mais modifie tres
        # recemment (proche de l'instant de demarrage) -> traite pareil,
        # car c'est tres probablement un fichier que l'utilisateur venait
        # de telecharger juste avant de lancer/relancer la surveillance,
        # pas un vieux fichier a rattraper.
        est_nouveau = path not in _baseline_paths
        est_tres_recent = (_baseline_time - mtime) <= WATCH_RECENT_FILE_WINDOW_S
        priority = PRIORITE_NOUVEAU if (est_nouveau or est_tres_recent) else PRIORITE_ARRIERE_PLAN
        _enqueue(path, priority, mtime)


def _scanner_loop():
    while not _stop_event.is_set():
        _scan_once()
        _stop_event.wait(WATCH_POLL_INTERVAL_S)


def _worker_loop(on_new_file):
    """Thread de traitement : depile la file (priorite haute = nouveaux
    telechargements d'abord) et lance le pipeline d'analyse un fichier a
    la fois, sans jamais retarder la detection de nouveaux fichiers."""
    while not _stop_event.is_set():
        try:
            priority, _, path = _queue.get(timeout=0.5)
        except queue.Empty:
            continue

        _state["fichier_en_cours"] = path
        try:
            on_new_file(path)
        except Exception as e:
            _state["erreurs"].append(f"{path}: {e}")
            _state["erreurs"] = _state["erreurs"][-20:]  # borne la liste
            traceback.print_exc()
        finally:
            _state["fichier_en_cours"] = None
            if priority == PRIORITE_NOUVEAU:
                _state["en_attente_nouveaux"] = max(0, _state["en_attente_nouveaux"] - 1)
            else:
                _state["en_attente_arriere_plan"] = max(0, _state["en_attente_arriere_plan"] - 1)
            _queue.task_done()


def start(on_new_file):
    """Démarre la surveillance en tâche de fond. `on_new_file(path)` est
    appelé pour chaque fichier stabilisé détecté ; l'appelant y branche
    typiquement `agent.pipeline.run_pipeline(path, origine="auto_watch")`.

    Les fichiers déjà présents sur la machine (instantané pris tout de
    suite au démarrage) sont analysés en arrière-plan ; tout fichier qui
    apparaît ensuite — un nouveau téléchargement en temps réel — passe
    devant dans la file de traitement, même si l'arrière-plan est encore
    en cours."""
    global _scanner_thread, _worker_thread
    with _lock:
        if _state["actif"]:
            return _state
        _stop_event.clear()
        _seen_mtimes.clear()
        _size_tracker.clear()
        _snapshot_baseline()  # instantane immediat, avant tout delai de traitement
        _state["actif"] = True
        _state["dossiers_surveilles"] = list(WATCH_DIRS)
        _scanner_thread = threading.Thread(target=_scanner_loop, daemon=True)
        _worker_thread = threading.Thread(target=_worker_loop, args=(on_new_file,), daemon=True)
        _state["demarre_le"] = time.time()
        _scanner_thread.start()
        _worker_thread.start()
    return _state


def stop():
    with _lock:
        _stop_event.set()
        _state["actif"] = False
    return _state


def record_result(path, report):
    _state["fichiers_traites"] += 1
    _state["dernier_fichier"] = path
    _state["dernier_rapport_id"] = report.get("id_rapport")


def get_status():
    return dict(_state)


def list_queue():
    """Liste (sans dépiler) les fichiers actuellement en file d'attente,
    dans leur ordre de traitement (priorité haute — nouveaux téléchargements
    — en premier). Ne modifie jamais la file, sert uniquement à l'affichage."""
    with _queue.mutex:
        items = list(_queue.queue)
    items.sort(key=lambda item: (item[0], item[1]))
    out = []
    for priority, _, path in items:
        out.append({
            "chemin": path,
            "nom": os.path.basename(path),
            "dossier": os.path.dirname(path),
            "priorite": "nouveau" if priority == PRIORITE_NOUVEAU else "arriere_plan",
        })
    return out