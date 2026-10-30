"""
Agent de traitement et d'analyse de fichiers — point d'entrée Flask.
Lance le serveur : python app.py
Dashboard : http://127.0.0.1:5500
"""
import hmac
import os
import uuid

from flask import Flask, jsonify, render_template, request, redirect

from config import MAX_UPLOAD_MB, UPLOAD_DIR, AUTO_WATCH_ENABLED, WATCH_DIRS, HOST, PORT, API_TOKEN
from agent.pipeline import run_pipeline, list_reports, get_report
from agent.machines_api import bp as machines_bp
app = Flask(__name__)
app.register_blueprint(machines_bp)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# URL publique (ou locale) de secagent-server, utilisée uniquement pour
# construire le lien "Voir dans OpenSearch" par machine (voir /host/<nom>
# ci-dessous). secagent-server sait déjà rediriger vers Discover filtré
# sur cette machine (voir son propre flag -opensearch-dashboards-url) :
# on réutilise ce mécanisme plutôt que d'en refaire un ici.
SECAGENT_SERVER_URL = os.environ.get("SECAGENT_SERVER_URL", "").rstrip("/")


_LOCAL_ADDRS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def _is_authorized():
    """Autorise une requete sensible : jeton valide (en-tete X-API-Token) si un
    jeton est configure, sinon uniquement la machine locale. Evite qu'un agent
    expose sur le reseau (HOST=0.0.0.0) accepte des fichiers ou declenche des
    soumissions sandbox depuis n'importe qui."""
    if API_TOKEN:
        sent = request.headers.get("X-API-Token", "")
        if hmac.compare_digest(sent.encode(), API_TOKEN.encode()):
            return True
        # Le dashboard local n'envoie pas de jeton : tolere uniquement en local.
        return request.remote_addr in _LOCAL_ADDRS and request.headers.get("X-API-Token") is None
    return request.remote_addr in _LOCAL_ADDRS


def _forbidden():
    return jsonify({"erreur": "acces refuse : jeton X-API-Token valide requis (ou requete locale)"}), 403


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "fichier" not in request.files:
        return jsonify({"erreur": "aucun fichier recu (champ 'fichier' attendu)"}), 400

    f = request.files["fichier"]
    if f.filename == "":
        return jsonify({"erreur": "nom de fichier vide"}), 400

    archive_password = request.form.get("mot_de_passe") or None

    safe_name = f"{uuid.uuid4().hex}_{os.path.basename(f.filename)}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    f.save(save_path)

    try:
        report = run_pipeline(save_path, origine="manuel", archive_password=archive_password)
    except Exception as e:
        return jsonify({"erreur": f"echec de l'analyse: {e}"}), 500
    finally:
        if os.path.exists(save_path):
            try:
                os.remove(save_path)
            except Exception:
                pass

    return jsonify(report)


@app.route("/api/ingest-remote", methods=["POST"])
def ingest_remote():
    """Reçoit un fichier envoyé par un agent secagent distant (fichier
    téléchargé ou présent sur la machine surveillée — voir
    internal/cabinetnoir/client.go côté secagent). Même pipeline d'analyse
    que /api/analyze, avec en plus la machine d'origine (`host`).

    Corps : multipart/form-data, champ fichier "fichier" + champ texte
    "host" (nom de la machine, obligatoire). Requiert l'en-tete X-API-Token
    (CABINET_NOIR_API_TOKEN) ou une requete locale.
    """
    if not _is_authorized():
        return _forbidden()
    if "fichier" not in request.files:
        return jsonify({"erreur": "aucun fichier recu (champ 'fichier' attendu)"}), 400

    host = (request.form.get("host") or "").strip()
    if not host:
        return jsonify({"erreur": "champ 'host' manquant"}), 400

    f = request.files["fichier"]
    if f.filename == "":
        return jsonify({"erreur": "nom de fichier vide"}), 400

    safe_name = f"{uuid.uuid4().hex}_{os.path.basename(f.filename)}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    f.save(save_path)

    try:
        report = run_pipeline(save_path, origine="agent_distant")
    except Exception as e:
        return jsonify({"erreur": f"echec de l'analyse: {e}"}), 500
    finally:
        if os.path.exists(save_path):
            try:
                os.remove(save_path)
            except Exception:
                pass

    from agent.orchestrator import save_report
    report["host"] = host
    try:
        save_report(report)  # reecrit le JSON et met a jour l'index SQLite
    except Exception as e:
        print(f"[cabinet-noir] avertissement: ré-écriture du rapport avec host echouee: {e}")

    return jsonify(report)


@app.route("/host/<hostname>")
def host_redirect(hostname):
    """Clic sur une machine -> renvoie vers secagent-server, qui redirige
    lui-même vers OpenSearch Discover filtré sur cette machine."""
    if not SECAGENT_SERVER_URL:
        return jsonify({
            "erreur": "SECAGENT_SERVER_URL non configuré côté cabinet-noir — "
                      "impossible de rediriger vers le dashboard OpenSearch de secagent."
        }), 501
    return redirect(f"{SECAGENT_SERVER_URL}/host/{hostname}")


@app.route("/api/check-indicator", methods=["POST"])
def check_indicator():
    """Vérification manuelle d'un indicateur isolé (hash, domaine, URL ou
    IP) contre les sources de réputation, SANS déposer de fichier.

    Corps JSON attendu : {"indicateur": "...", "type": "hash|domaine|url|ip"}
    """
    from agent import threat_intel

    data = request.get_json(silent=True) or {}
    indicateur = (data.get("indicateur") or "").strip()
    type_ind = (data.get("type") or "").strip().lower()

    if not indicateur or type_ind not in ("hash", "domaine", "url", "ip"):
        return jsonify({
            "erreur": "requete invalide. Attendu : "
                      '{"indicateur": "...", "type": "hash|domaine|url|ip"}'
        }), 400

    resultat = threat_intel.check_indicator_manual(indicateur, type_ind)
    return jsonify(resultat)


@app.route("/api/status")
def status():
    from agent import yara_scan, clamav_scan, archive_handler, sandbox
    from config import ABUSEIPDB_API_KEY, OTX_API_KEY, ABUSECH_AUTH_KEY
    from agent.watcher import get_status as watch_status

    return jsonify({
        "yara": yara_scan._HAS_YARA,
        "clamav": clamav_scan._HAS_CLAMD,
        "threat_intelligence": {
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "otx": bool(OTX_API_KEY),
            "abusech_malwarebazaar_urlhaus": bool(ABUSECH_AUTH_KEY),
        },
        "archives_protegees": {
            "zip": True,
            "7z": archive_handler._HAS_PY7ZR,
            "rar": archive_handler._HAS_RARFILE,
        },
        "surveillance_automatique": watch_status(),
        "sandbox": sandbox.get_status(),
    })


@app.route("/api/sandbox/status")
def sandbox_status():
    from agent import sandbox
    return jsonify(sandbox.get_status())


@app.route("/api/sandbox/list")
def sandbox_list():
    from agent import sandbox
    return jsonify(sandbox.list_entries())


@app.route("/api/sandbox/submit/<entry_id>", methods=["POST"])
def sandbox_submit(entry_id):
    from agent import sandbox
    if not _is_authorized():
        return _forbidden()
    ok = sandbox.submit_now(entry_id)
    if not ok:
        return jsonify({"erreur": "soumission impossible (cle API absente, entree introuvable, ou deja en cours)"}), 400
    return jsonify({"succes": True})


@app.route("/api/watch/start", methods=["POST"])
def watch_start():
    from agent import watcher

    def _on_new_file(path):
        report = run_pipeline(path, origine="auto_watch")
        watcher.record_result(path, report)

    state = watcher.start(_on_new_file)
    return jsonify(state)


@app.route("/api/watch/stop", methods=["POST"])
def watch_stop():
    from agent import watcher
    return jsonify(watcher.stop())


@app.route("/api/watch/status")
def watch_status_route():
    from agent import watcher
    return jsonify(watcher.get_status())


@app.route("/api/watch/queue")
def watch_queue_route():
    from agent import watcher
    return jsonify(watcher.list_queue())


@app.route("/api/history")
def history():
    return jsonify(list_reports())


@app.route("/api/report/<report_id>")
def report_detail(report_id):
    report = get_report(report_id)
    if report is None:
        return jsonify({"erreur": "rapport introuvable"}), 404
    return jsonify(report)


def _start_auto_watch_if_enabled():
    if not AUTO_WATCH_ENABLED or not WATCH_DIRS:
        return
    from agent import watcher

    def _on_new_file(path):
        report = run_pipeline(path, origine="auto_watch")
        watcher.record_result(path, report)

    watcher.start(_on_new_file)
    print(f"[cabinet-noir] Surveillance automatique active sur : {WATCH_DIRS}")


if __name__ == "__main__":
    _start_auto_watch_if_enabled()

    from agent import sandbox
    sandbox.resume_pending_on_startup()
    try:
        sandbox.purge_old_samples()
    except Exception as e:
        print(f"[cabinet-noir] avertissement: purge sandbox impossible: {e}")

    if HOST not in ("127.0.0.1", "localhost", "::1") and not API_TOKEN:
        print("[cabinet-noir] ATTENTION : agent expose sur le reseau sans CABINET_NOIR_API_TOKEN ; "
              "/api/ingest-remote et la soumission sandbox restent reserves aux requetes locales.")

    app.run(host=HOST, port=PORT, debug=False, threaded=True)