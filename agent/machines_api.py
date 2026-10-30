"""API du dashboard : vue d'ensemble du parc, listes filtrables (par machine ou globales).
Les machines viennent du champ `host` des rapports (agents SecAgent via /api/ingest-remote).
Les rapports sans host (surveillance locale) sont regroupés sous "local"."""
import os
import threading
import time

from flask import Blueprint, jsonify, request

from . import report_store, sandbox
from .pipeline import get_report

bp = Blueprint("machines", __name__)
_HOST = "COALESCE(NULLIF(host,''),'local')"
_PENDING = ("en_attente", "en_attente_validation", "cle_api_absente", "en_cours")
_KINDS = {  # filtre SQL de chaque liste (liste blanche : jamais construit depuis l'URL)
    "fichiers": "1=1",
    "suspects": "verdict='suspect'",
    "malveillants": "verdict='malicious'",
    "quarantaine": "action IN ('quarantine','block')",
    "a_revoir": "verdict='inconclusive'",
    "alertes": "verdict IN ('malicious','suspect','inconclusive')",
}


def _rows(sql, args=()):
    report_store._ensure()
    with report_store._connect() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def _since():
    days = request.args.get("days", 0, type=int)
    return time.time() - days * 86400 if days > 0 else 0


def _host_index():
    """id de rapport -> machine (un fichier extrait d'une archive hérite de son parent)."""
    rows = _rows(f"SELECT id, parent_id, {_HOST} AS h FROM reports")
    by_id = {r["id"]: r for r in rows}
    idx = {}
    for r in rows:
        cur, depth = r, 0
        while cur.get("parent_id") in by_id and depth < 5:
            cur, depth = by_id[cur["parent_id"]], depth + 1
        idx[r["id"]] = cur["h"]
    return idx


def _sandbox_by_host():
    idx, out = _host_index(), {}
    for e in sandbox.list_entries():
        h = idx.get(e.get("report_id")) or idx.get(e.get("report_parent_id"))
        if h:
            out.setdefault(h, []).append(e)
    return out


@bp.route("/api/overview")
def overview():
    since = _since()
    base = "parent_id IS NULL AND created_at>=?"
    machines = _rows(f"""
        SELECT {_HOST} AS host, COUNT(*) AS fichiers,
               SUM(verdict='malicious') AS malveillants, SUM(verdict='suspect') AS suspects,
               SUM(verdict='inconclusive') AS non_concluants,
               SUM(action IN ('quarantine','block')) AS quarantaine,
               MAX(created_at) AS derniere_activite
        FROM reports WHERE {base} GROUP BY 1
        ORDER BY malveillants DESC, suspects DESC, derniere_activite DESC""", (since,))
    sb = _sandbox_by_host()
    keys = ("malveillants", "suspects", "non_concluants", "quarantaine")
    for m in machines:
        for k in keys:
            m[k] = m[k] or 0
        m["sandbox_a_traiter"] = sum(1 for e in sb.get(m["host"], []) if e.get("statut") in _PENDING)
    totaux = {k: sum(m[k] for m in machines) for k in keys + ("fichiers", "sandbox_a_traiter")}
    totaux["machines"] = len(machines)
    cov = _rows(f"SELECT COUNT(*) AS n, SUM(complete) AS c FROM reports WHERE {base}", (since,))[0]
    totaux["couverture"] = round(100 * (cov["c"] or 0) / cov["n"]) if cov["n"] else None
    verdicts = {r["v"]: r["n"] for r in _rows(
        f"SELECT COALESCE(verdict,'inconnu') AS v, COUNT(*) AS n FROM reports WHERE {base} GROUP BY v", (since,))}
    par_jour = _rows(f"""
        SELECT date(created_at,'unixepoch','localtime') AS d, COUNT(*) AS total,
               SUM(verdict IN ('malicious','suspect')) AS risque
        FROM reports WHERE {base} GROUP BY d ORDER BY d DESC LIMIT 30""", (since,))[::-1]
    for j in par_jour:
        j["risque"] = j["risque"] or 0
    return jsonify({"totaux": totaux, "machines": machines, "verdicts": verdicts, "par_jour": par_jour})


@bp.route("/api/items")
def items():
    kind = request.args.get("kind", "fichiers")
    host = request.args.get("host", "").strip()
    limit = max(1, min(request.args.get("limit", 300, type=int), 300))
    since = _since()
    if kind == "sandbox":
        out = []
        for h, ents in _sandbox_by_host().items():
            if host and h != host:
                continue
            out += [{**e, "host": h} for e in ents if e.get("statut") in _PENDING]
        out.sort(key=lambda e: e.get("created_at", ""), reverse=True)
        return jsonify({"kind": kind, "rows": out[:limit]})
    args = [since]
    if kind == "detection":   # fichiers ayant déclenché une signature / règle / indicateur précis
        where = "created_at>=? AND id IN (SELECT report_id FROM detections WHERE kind=? AND name=?)"
        args += [request.args.get("dkind", ""), request.args.get("name", "")]
    elif kind in _KINDS:
        where = f"parent_id IS NULL AND created_at>=? AND {_KINDS[kind]}"
    else:
        return jsonify({"erreur": "liste inconnue"}), 400
    if host:
        where += f" AND {_HOST}=?"
        args.append(host)
    rows = _rows(
        f"SELECT id, nom, score, niveau, verdict, action, sha256, created_at, {_HOST} AS host "
        f"FROM reports WHERE {where} ORDER BY "
        f"CASE verdict WHEN 'malicious' THEN 0 WHEN 'suspect' THEN 1 WHEN 'inconclusive' THEN 2 ELSE 3 END, "
        f"created_at DESC LIMIT {limit}", tuple(args))
    if kind == "quarantaine":
        for r in rows[:100]:
            r["chemin"] = ((get_report(r["id"]) or {}).get("action") or {}).get("chemin_quarantaine")
    return jsonify({"kind": kind, "rows": rows})


# ---------------------------------------------------------------------------
# Détections les plus fréquentes (signatures ClamAV, règles YARA, indicateurs signalés).
# Chaque rapport est lu UNE seule fois, en arrière-plan, puis résumé dans la table
# `detections` : l'affichage reste instantané même avec des milliers de rapports.
# ---------------------------------------------------------------------------
_tables_ready = False
_sync = {"running": False}
_sync_lock = threading.Lock()
_TODO = ("FROM reports r LEFT JOIN detections_done d ON d.report_id=r.id "
         "WHERE d.report_id IS NULL AND (r.score>0 OR r.verdict IS NULL OR r.verdict!='clean')")


def _ensure_tables():
    global _tables_ready
    if _tables_ready:
        return
    report_store._ensure()
    with report_store._connect() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS detections (report_id TEXT, kind TEXT, name TEXT, severity TEXT);
            CREATE INDEX IF NOT EXISTS idx_det_kn ON detections (kind, name);
            CREATE INDEX IF NOT EXISTS idx_det_r ON detections (report_id);
            CREATE TABLE IF NOT EXISTS detections_done (report_id TEXT PRIMARY KEY);""")
    _tables_ready = True


def _extract(rep):
    out = []
    av = rep.get("antivirus") or {}
    if av.get("disponible") and av.get("infecte") and av.get("signature"):
        out.append(("clamav", av["signature"], "critique"))
    for m in (rep.get("yara") or {}).get("matches", []):
        out.append(("yara", m.get("regle"), m.get("severite")))
    for s in (rep.get("threat_intelligence") or {}).get("indicateurs_signales") or []:
        out.append(("ioc", s.get("indicateur"), s.get("type")))
    return [o for o in out if o[1]]


def _sync_worker():
    try:
        while True:
            ids = [r["id"] for r in _rows(f"SELECT r.id {_TODO} LIMIT 200")]
            if not ids:
                break
            with report_store._connect() as c:
                for rid in ids:
                    for k, n, s in _extract(get_report(rid) or {}):
                        c.execute("INSERT INTO detections VALUES (?,?,?,?)", (rid, k, n, s))
                    c.execute("INSERT OR IGNORE INTO detections_done VALUES (?)", (rid,))
    except Exception as e:  # jamais bloquant pour le reste du dashboard
        print(f"[cabinet-noir] avertissement: indexation des détections: {e}")
    finally:
        _sync["running"] = False


def _start_sync():
    _ensure_tables()
    with _sync_lock:
        if _sync["running"]:
            return
        _sync["running"] = True
    threading.Thread(target=_sync_worker, daemon=True, name="cn-detections").start()


@bp.route("/api/top")
def top():
    _start_sync()
    since = _since()

    def q(kind):
        return _rows(
            "SELECT d.name AS name, COUNT(DISTINCT d.report_id) AS n FROM detections d "
            "JOIN reports r ON r.id=d.report_id WHERE d.kind=? AND r.created_at>=? "
            "GROUP BY d.name ORDER BY n DESC LIMIT 8", (kind, since))

    exts = {}
    for r in _rows("SELECT nom FROM reports WHERE parent_id IS NULL AND created_at>=?", (since,)):
        e = os.path.splitext(r["nom"] or "")[1].lower() or "(sans extension)"
        exts[e] = exts.get(e, 0) + 1
    ext = [{"name": k, "n": v} for k, v in sorted(exts.items(), key=lambda x: -x[1])[:8]]
    restant = _rows(f"SELECT COUNT(*) AS n {_TODO}")[0]["n"]
    return jsonify({"clamav": q("clamav"), "yara": q("yara"), "ioc": q("ioc"),
                    "extensions": ext, "indexation_restante": restant})


@bp.route("/api/yara-check")
def yara_check():
    """Les règles YARA se compilent-elles réellement ? (le module installé ne suffit pas)"""
    from . import yara_scan
    ok, err = yara_scan.compile_status()
    return jsonify({"ok": ok, "erreur": err, "version_regles": yara_scan.rules_version() if ok else None})