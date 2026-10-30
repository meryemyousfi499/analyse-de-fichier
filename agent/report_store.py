"""
Index SQLite des rapports d'analyse.

Les rapports complets restent des fichiers JSON (reports/<id>.json) : ils
sont lisibles et déjà utilisés par le dashboard. SQLite sert d'INDEX :
  - historique rapide sans relire des centaines de JSON à chaque requête ;
  - cache par SHA-256 + version des règles YARA, pour ne pas ré-analyser
    à chaque redémarrage les mêmes fichiers d'un dossier surveillé.

Si la base est inutilisable, tout retombe sur les fichiers JSON.
"""
import contextlib
import json
import os
import sqlite3
import threading
import time

from config import DB_PATH, REPORTS_DIR

_init_lock = threading.Lock()
_initialized = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    sha256 TEXT,
    nom TEXT,
    score INTEGER,
    niveau TEXT,
    verdict TEXT,
    action TEXT,
    host TEXT,
    parent_id TEXT,
    depth INTEGER DEFAULT 0,
    rules_version TEXT,
    complete INTEGER DEFAULT 0,
    created_at REAL
);
CREATE INDEX IF NOT EXISTS idx_reports_sha ON reports (sha256, rules_version);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_parent ON reports (parent_id);
"""


@contextlib.contextmanager
def _connect():
    """Connexion qui valide (commit) puis FERME : le `with sqlite3.connect()`
    standard ne ferme pas la connexion, ce qui laisse le fichier verrouille
    (notamment sous Windows)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _ensure():
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        with _connect() as c:
            c.executescript(_SCHEMA)
            first_run = c.execute("PRAGMA user_version").fetchone()[0] == 0
        _initialized = True
        if first_run:
            # Premier lancement avec cet index : importe les rapports JSON existants
            # (sinon l'historique ne montrerait que les nouvelles analyses).
            rebuild_from_json()
            with _connect() as c:
                c.execute("PRAGMA user_version = 1")


def _row_from_report(report, created_at=None):
    verdict = (report.get("verdict") or {}).get("verdict")
    couverture = (report.get("verdict") or {}).get("couverture") or {}
    return (
        report.get("id_rapport"),
        (report.get("empreintes") or {}).get("sha256", ""),
        (report.get("metadonnees") or {}).get("nom", ""),
        (report.get("score_final") or {}).get("score"),
        (report.get("score_final") or {}).get("niveau"),
        verdict,
        (report.get("action") or {}).get("action"),
        report.get("host", ""),
        report.get("id_parent"),
        report.get("profondeur", 0),
        report.get("version_regles"),
        1 if (couverture.get("ratio") == 1.0 and not report.get("erreur_pipeline")) else 0,
        created_at if created_at is not None else time.time(),
    )


def index_report(report, created_at=None):
    """Ajoute ou met à jour un rapport dans l'index. Ne lève jamais."""
    try:
        _ensure()
        row = _row_from_report(report, created_at)
        if not row[0]:
            return
        with _connect() as c:
            old = c.execute("SELECT created_at FROM reports WHERE id=?", (row[0],)).fetchone()
            if old:
                row = row[:-1] + (old["created_at"],)
            c.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
    except Exception as e:  # l'index est secondaire : jamais bloquant
        print(f"[cabinet-noir] avertissement: indexation du rapport impossible: {e}")


def rebuild_from_json():
    """Reconstruit l'index depuis les JSON existants (premier lancement)."""
    n = 0
    if not os.path.isdir(REPORTS_DIR):
        return n
    for f in os.listdir(REPORTS_DIR):
        if not f.endswith(".json"):
            continue
        try:
            full = os.path.join(REPORTS_DIR, f)
            with open(full, encoding="utf-8") as fh:
                rep = json.load(fh)
            index_report(rep, created_at=os.path.getmtime(full))
            n += 1
        except Exception:
            continue
    return n


def list_recent(limit=50, include_children=False):
    """Historique : les plus récents d'abord. Les rapports enfants (fichiers
    extraits d'une archive) sont masqués par défaut : ils sont rattachés à
    leur archive via `sous_rapports_archive`."""
    try:
        _ensure()
        where = "" if include_children else "WHERE parent_id IS NULL"
        with _connect() as c:
            rows = c.execute(
                f"SELECT * FROM reports {where} ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return None  # l'appelant retombe sur les JSON


def find_cached(sha256, rules_version, ttl_hours):
    """Retourne l'id d'un rapport récent, COMPLET et sain pour ce hash et ces
    règles, sinon None. Seuls les verdicts « clean » sont réutilisables : un
    fichier suspect doit toujours repasser par les actions de réponse."""
    if not sha256 or not ttl_hours:
        return None
    try:
        _ensure()
        limit = time.time() - ttl_hours * 3600
        with _connect() as c:
            row = c.execute(
                "SELECT id FROM reports WHERE sha256=? AND rules_version=? AND complete=1 "
                "AND verdict='clean' AND created_at>=? ORDER BY created_at DESC LIMIT 1",
                (sha256, rules_version, limit),
            ).fetchone()
        return row["id"] if row else None
    except Exception:
        return None