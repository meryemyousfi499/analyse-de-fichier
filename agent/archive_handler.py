"""
Gestion des fichiers partagés sous forme d'archive protégée par un mot
de passe / une clé (.zip, .7z, .rar chiffrés) — cas fréquent des
échantillons partagés par email ou messagerie ("voici le fichier, mot
de passe : ...").

Comportement :
  - Si le fichier n'est pas une archive : ne fait rien (`est_archive: False`).
  - Si c'est une archive protégée : tente le mot de passe fourni par
    l'utilisateur, puis, à défaut, une petite liste de mots de passe
    courants (config.DEFAULT_ARCHIVE_PASSWORDS).
  - Chaque backend (zip/7z/rar) est optionnel et se dégrade proprement
    si la bibliothèque correspondante n'est pas installée.
  - Ne décompresse jamais plus que `ARCHIVE_MAX_EXTRACT_MB` (anti zip-bomb).
  - Les fichiers extraits sont ensuite réinjectés dans le pipeline
    d'analyse complet par l'appelant (agent/pipeline.py).
"""
import os
import shutil
import tempfile
import zipfile

from config import ARCHIVE_MAX_EXTRACT_MB, DEFAULT_ARCHIVE_PASSWORDS

try:
    import pyzipper  # zip AES (mots de passe modernes, WinZip/7zip AES)
    _HAS_PYZIPPER = True
except ImportError:
    _HAS_PYZIPPER = False

try:
    import py7zr
    _HAS_PY7ZR = True
except ImportError:
    _HAS_PY7ZR = False

try:
    import rarfile
    _HAS_RARFILE = True
except ImportError:
    _HAS_RARFILE = False

ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
MAX_EXTRACT_BYTES = ARCHIVE_MAX_EXTRACT_MB * 1024 * 1024


def _is_archive(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in ARCHIVE_EXTENSIONS:
        return ext
    # Detection par magic bytes au cas ou l'extension est trompeuse
    try:
        with open(path, "rb") as f:
            head = f.read(6)
        if head[:4] == b"PK\x03\x04":
            return ".zip"
        if head[:6] == b"7z\xbc\xaf\x27\x1c":
            return ".7z"
        if head[:4] == b"Rar!":
            return ".rar"
    except Exception:
        pass
    return None


def _candidate_passwords(user_password):
    candidates = []
    if user_password:
        candidates.append(user_password)
    candidates.extend(p for p in DEFAULT_ARCHIVE_PASSWORDS if p != user_password)
    candidates.append(None)  # essai sans mot de passe (archive non chiffree)
    return candidates


def _total_uncompressed_size(names_sizes):
    return sum(names_sizes)


def _extract_zip(path, dest_dir, password):
    infos = None
    opener = None
    if _HAS_PYZIPPER:
        try:
            zf = pyzipper.AESZipFile(path)
            infos = zf.infolist()
            opener = zf
        except Exception:
            opener = None
    if opener is None:
        zf = zipfile.ZipFile(path)
        infos = zf.infolist()
        opener = zf

    total_size = _total_uncompressed_size([i.file_size for i in infos])
    if total_size > MAX_EXTRACT_BYTES:
        opener.close()
        raise ValueError(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")

    pwd_bytes = password.encode() if password else None
    opener.extractall(dest_dir, pwd=pwd_bytes)
    opener.close()


def _extract_7z(path, dest_dir, password):
    with py7zr.SevenZipFile(path, mode="r", password=password) as z:
        names = z.getnames()
        total_size = sum((info.uncompressed for info in z.list()), 0)
        if total_size > MAX_EXTRACT_BYTES:
            raise ValueError(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")
        z.extractall(path=dest_dir)


def _extract_rar(path, dest_dir, password):
    with rarfile.RarFile(path) as rf:
        total_size = sum(i.file_size for i in rf.infolist())
        if total_size > MAX_EXTRACT_BYTES:
            raise ValueError(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")
        rf.extractall(path=dest_dir, pwd=password)


def handle_if_archive(filepath, password=None):
    """Retourne un dict décrivant si `filepath` est une archive, et le cas
    échéant tente de l'ouvrir (avec le mot de passe fourni ou des mots de
    passe courants) et retourne la liste des fichiers extraits."""
    ext = _is_archive(filepath)
    if not ext:
        return {"est_archive": False}

    backend_disponible = {
        ".zip": True,  # zipfile est toujours disponible (stdlib) ; pyzipper ameliore le support AES
        ".7z": _HAS_PY7ZR,
        ".rar": _HAS_RARFILE,
    }[ext]

    result = {
        "est_archive": True,
        "format": ext,
        "backend_disponible": backend_disponible,
        "extraction_reussie": False,
        "mot_de_passe_utilise": None,
        "fichiers_extraits": [],
        "erreur": None,
    }

    if not backend_disponible:
        result["erreur"] = (
            f"support {ext} non installe sur cette machine "
            f"({'py7zr' if ext == '.7z' else 'rarfile + unrar'} manquant) — "
            "contenu non inspecte, traite avec prudence."
        )
        return result

    dest_dir = tempfile.mkdtemp(prefix="cabinet_noir_extract_")
    extractor = {".zip": _extract_zip, ".7z": _extract_7z, ".rar": _extract_rar}[ext]

    last_error = None
    for pwd in _candidate_passwords(password):
        try:
            extractor(filepath, dest_dir, pwd)
            result["extraction_reussie"] = True
            result["mot_de_passe_utilise"] = "fourni_par_utilisateur" if pwd == password and pwd else (
                "mot_de_passe_courant_devine" if pwd else "aucun_(non_chiffree)"
            )
            break
        except Exception as e:
            last_error = e
            continue

    if not result["extraction_reussie"]:
        result["erreur"] = f"impossible d'ouvrir l'archive (mot de passe manquant/incorrect) : {last_error}"
        shutil.rmtree(dest_dir, ignore_errors=True)
        return result

    extracted = []
    for root, _dirs, files in os.walk(dest_dir):
        for name in files:
            extracted.append(os.path.join(root, name))
    result["fichiers_extraits"] = extracted
    result["_dest_dir_temporaire"] = dest_dir  # nettoyage a la charge de l'appelant si besoin
    return result
