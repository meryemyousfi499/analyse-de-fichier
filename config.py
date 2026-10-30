"""
Configuration centrale de l'agent d'analyse de fichiers.
Toutes les clés d'API sont optionnelles : l'agent fonctionne en mode
dégradé (sans Threat Intelligence externe) si elles sont absentes.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Chargement du fichier .env (clés API), sans dépendance externe ---
# Une variable déjà définie dans le terminal reste prioritaire sur le fichier.
_env_path = os.path.join(BASE_DIR, ".env")
if os.path.isfile(_env_path):
    with open(_env_path, encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
YARA_RULES_PATH = os.path.join(BASE_DIR, "rules", "generic_rules.yar")

for d in (UPLOAD_DIR, QUARANTINE_DIR, REPORTS_DIR):
    os.makedirs(d, exist_ok=True)

# --- Threat Intelligence (optionnel) ---
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
# Cle gratuite (Auth-Key) pour MalwareBazaar et URLhaus (projets abuse.ch).
# A obtenir gratuitement sur https://auth.abuse.ch/ . Sans elle, ces deux
# sources sont simplement ignorees (mode degrade), le reste de l'agent
# continue de fonctionner normalement.
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")

# Nombre max d'indicateurs de chaque type interroges par analyse, pour
# rester sous les quotas gratuits des APIs externes.
TI_MAX_LOOKUPS = int(os.environ.get("TI_MAX_LOOKUPS", "5"))

# --- ClamAV (optionnel, nécessite clamd démarré sur la machine) ---
CLAMD_HOST = os.environ.get("CLAMD_HOST", "127.0.0.1")
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))

# --- Seuils de score de risque ---
SCORE_BANDS = [
    (0, 29, "faible", "allow"),
    (30, 59, "moyen", "monitor"),
    (60, 79, "eleve", "quarantine"),
    (80, 100, "critique", "block"),
]

MAX_UPLOAD_MB = 100

# --- Sandbox dynamique (exécution réelle en environnement jetable) ---
# Analyse comportementale via l'API gratuite Hybrid Analysis : le fichier
# est réellement ouvert/exécuté dans une VM jetable distante, à la
# différence du reste du pipeline qui ne fait QUE lire le fichier sans
# jamais l'exécuter. Se dégrade proprement si la clé n'est pas configurée :
# les fichiers suspects sont quand même répertoriés (comme "à tester"),
# mais aucune soumission réseau n'est tentée.
HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
SANDBOX_REPORTS_DIR = os.path.join(BASE_DIR, "sandbox_reports")
for d in (SANDBOX_DIR, SANDBOX_REPORTS_DIR):
    os.makedirs(d, exist_ok=True)
# ID d'environnement Hybrid Analysis (160 = Windows 10 64-bit par défaut ;
# voir GET /api/v2/system/environments avec votre clé pour la liste complète).
SANDBOX_ENVIRONMENT_ID = int(os.environ.get("SANDBOX_ENVIRONMENT_ID", "160"))
SANDBOX_POLL_INTERVAL_S = float(os.environ.get("SANDBOX_POLL_INTERVAL_S", "15"))
SANDBOX_MAX_WAIT_S = float(os.environ.get("SANDBOX_MAX_WAIT_S", "600"))
# Niveaux de risque (issus de l'analyse STATIQUE) qui déclenchent
# automatiquement une mise en file pour test sandbox.
SANDBOX_AUTO_LEVELS = ("eleve", "critique")

# --- Surveillance automatique de dossiers (ex : Téléchargements) ---
# L'agent peut analyser tout seul chaque nouveau fichier qui apparait
# dans ces dossiers, sans attendre un depot manuel sur le dashboard.
def _default_watch_dirs():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Téléchargements"),
        UPLOAD_DIR,
    ]
    seen, out = set(), []
    for d in candidates:
        if os.path.isdir(d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out


_watch_env = os.environ.get("WATCH_DIRS", "")
WATCH_DIRS = [d.strip() for d in _watch_env.split(os.pathsep) if d.strip()] or _default_watch_dirs()

# Demarre automatiquement la surveillance au lancement de app.py.
# Peut aussi etre pilotee a la main via /api/watch/start et /api/watch/stop.
AUTO_WATCH_ENABLED = os.environ.get("AUTO_WATCH_ENABLED", "1") not in ("0", "false", "False")

# Delai (s) pour laisser un telechargement se terminer avant analyse
# (evite d'analyser un fichier encore en cours d'ecriture, ex: .crdownload/.part).
WATCH_STABILIZE_S = float(os.environ.get("WATCH_STABILIZE_S", "2"))
WATCH_POLL_INTERVAL_S = float(os.environ.get("WATCH_POLL_INTERVAL_S", "2"))

# Extensions temporaires de navigateur a ignorer tant qu'elles ne sont pas renommees
INCOMPLETE_DOWNLOAD_SUFFIXES = (".crdownload", ".part", ".partial", ".tmp", ".download")

# Un fichier deja present au demarrage de la surveillance mais dont la date
# de modification est tres recente (ex: telecharge juste avant de lancer
# l'agent) est quand meme traite comme un NOUVEAU telechargement prioritaire,
# et non enterre dans l'arriere-plan derriere des centaines d'anciens fichiers.
WATCH_RECENT_FILE_WINDOW_S = float(os.environ.get("WATCH_RECENT_FILE_WINDOW_S", "300"))

# --- Archives protegees par mot de passe (fichier "partage avec une cle") ---
# Taille max decompressee autorisee, pour eviter les bombes zip.
ARCHIVE_MAX_EXTRACT_MB = int(os.environ.get("ARCHIVE_MAX_EXTRACT_MB", "500"))
# Mots de passe courants essayes automatiquement si aucun n'est fourni
# (les partages "proteges" utilisent souvent un mot de passe convenu a l'avance,
# ex: "infected"/"virus" pour les echantillons de malware).
_default_pwds = os.environ.get("ARCHIVE_COMMON_PASSWORDS", "infected,malware,virus")
DEFAULT_ARCHIVE_PASSWORDS = [p for p in (x.strip() for x in _default_pwds.split(",")) if p]

# --- Protection contre les tres gros fichiers (video, ISO, installeur...) ---
# Sans cette limite, un enorme fichier binaire present dans un dossier
# surveille peut bloquer le thread d'analyse - et donc tout le serveur
# Python, qui ne libere pas le verrou d'interpreteur (GIL) pendant un
# `re.findall` - pendant plusieurs minutes. La quasi-totalite des IOC reels
# (scripts, documents, executables malveillants) tiennent tres largement
# sous cette limite.
MAX_PATTERN_SCAN_MB = int(os.environ.get("MAX_PATTERN_SCAN_MB", "25"))

# Taille max (Mo) chargee en memoire pour le calcul d'entropie globale d'un
# tres gros fichier. Au-dela, seul le debut du fichier est utilise pour le
# calcul - un echantillon suffisant pour estimer l'entropie, sans charger
# plusieurs Go en RAM ni ralentir l'analyse.
MAX_ENTROPY_READ_MB = int(os.environ.get("MAX_ENTROPY_READ_MB", "200"))

# ---------------------------------------------------------------------------
# Politique de l'orchestrateur (centralisee ici : plus aucun seuil disperse)
# ---------------------------------------------------------------------------
# Serveur Flask : par defaut en local uniquement. Mettre HOST=0.0.0.0 pour
# exposer l'agent sur le reseau (dans ce cas, definissez aussi API_TOKEN).
HOST = os.environ.get("CABINET_NOIR_HOST", "127.0.0.1")
PORT = int(os.environ.get("CABINET_NOIR_PORT", "5500"))
# Jeton exige (en-tete "X-API-Token") par /api/ingest-remote. Sans jeton
# configure, cet endpoint n'accepte que les requetes venant de la machine locale.
API_TOKEN = os.environ.get("CABINET_NOIR_API_TOKEN", "")

# Score statique minimal (0-100) a partir duquel la sandbox est demandee
# lorsqu'aucun signal fort independant n'existe. 70 = point de depart a calibrer.
SANDBOX_MIN_SCORE = int(os.environ.get("SANDBOX_MIN_SCORE", "70"))
# Taille max (octets) d'un fichier soumis a la sandbox.
SANDBOX_MAX_FILE_MB = int(os.environ.get("SANDBOX_MAX_FILE_MB", "50"))
# La sandbox Hybrid Analysis est un service EXTERNE : soumettre un fichier
# revient a le partager. Par defaut (0), les fichiers eligibles sont mis en
# file avec le statut "en_attente_validation" et ne partent qu'apres clic
# manuel sur "Soumettre". Mettre 1 pour autoriser l'envoi automatique.
SANDBOX_ALLOW_EXTERNAL_SUBMISSION = os.environ.get("SANDBOX_ALLOW_EXTERNAL_SUBMISSION", "0") in ("1", "true", "True")
# Parametres de partage envoyes a Hybrid Analysis (a verifier dans la doc
# de l'API v2 : une cle gratuite peut rendre les rapports publics).
SANDBOX_NO_SHARE_THIRD_PARTY = os.environ.get("SANDBOX_NO_SHARE_THIRD_PARTY", "1") in ("1", "true", "True")
SANDBOX_ALLOW_COMMUNITY_ACCESS = os.environ.get("SANDBOX_ALLOW_COMMUNITY_ACCESS", "0") in ("1", "true", "True")
# Duree de conservation (jours) des copies d'echantillons dans sandbox/.
SANDBOX_RETENTION_DAYS = int(os.environ.get("SANDBOX_RETENTION_DAYS", "7"))
# Extensions JAMAIS soumises seules a la sandbox (composants internes, medias).
SANDBOX_NEVER_STANDALONE_EXTENSIONS = (
    ".rels", ".xml", ".vml", ".emf", ".wmf", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".svg", ".css", ".json", ".txt", ".config",
)

# Archives : limites anti zip-bomb / recursion.
ARCHIVE_MAX_DEPTH = int(os.environ.get("ARCHIVE_MAX_DEPTH", "3"))
ARCHIVE_MAX_FILES = int(os.environ.get("ARCHIVE_MAX_FILES", "200"))

# Cache : un fichier deja analyse (meme SHA-256, memes regles YARA) depuis
# moins de CACHE_TTL_HOURS heures n'est pas re-analyse par la surveillance auto.
CACHE_TTL_HOURS = float(os.environ.get("CACHE_TTL_HOURS", "24"))
DB_PATH = os.path.join(BASE_DIR, "cabinet_noir.db")