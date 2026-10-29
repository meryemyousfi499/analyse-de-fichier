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

from config import (
    ARCHIVE_MAX_EXTRACT_MB, DEFAULT_ARCHIVE_PASSWORDS, ARCHIVE_MAX_FILES,
)

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

class ArchiveRefused(Exception):
    """Extraction refusee pour une raison de securite (zip-slip, bombe,
    trop de fichiers...) : inutile d'essayer d'autres mots de passe."""


ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
MAX_EXTRACT_BYTES = ARCHIVE_MAX_EXTRACT_MB * 1024 * 1024

# Formats « conteneurs » : techniquement des ZIP, mais ce sont des DOCUMENTS
# ou des paquets, pas des archives a ouvrir. Les extraire fait passer chaque
# composant interne (.rels, item1.xml, theme1.xml...) dans le pipeline comme
# s'il s'agissait d'un fichier independant. Ils sont analyses comme un tout
# (agent/specialized_analysis.py) et jamais extraits ici.
OOXML_EXTENSIONS = {
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
    ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
    ".odt", ".ods", ".odp", ".vsdx", ".vsdm",
}
PACKAGE_EXTENSIONS = {".jar", ".war", ".apk", ".aab", ".ipa", ".xpi", ".crx", ".nupkg", ".whl", ".epub"}


def container_kind(path):
    """Retourne "office_ooxml", "package" ou None si `path` n'est pas un
    document/paquet de type ZIP (par extension OU par structure interne)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in OOXML_EXTENSIONS:
        return "office_ooxml"
    if ext in PACKAGE_EXTENSIONS:
        return "package"
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"PK\x03\x04":
                return None
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except Exception:
        return None
    # Extension trompeuse (ex. "facture.zip" qui est un .docx renomme) :
    # on se fie a la structure interne.
    if "[Content_Types].xml" in names and any(
            n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names):
        return "office_ooxml"
    if "META-INF/MANIFEST.MF" in names or "AndroidManifest.xml" in names:
        return "package"
    return None


def _unsafe_member_name(name):
    """Vrai si un nom de membre d'archive pourrait sortir du dossier
    d'extraction (zip-slip : "../x", chemin absolu, lecteur Windows)."""
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 1 and n[1] == ":"):
        return True
    return any(part == ".." for part in n.split("/"))


def _is_archive(path):
    if container_kind(path):
        return None
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


def _safe_join(dest_dir, name):
    target = os.path.realpath(os.path.join(dest_dir, name))
    root = os.path.realpath(dest_dir)
    if target != root and not target.startswith(root + os.sep):
        raise ArchiveRefused(f"chemin d'extraction dangereux refuse : {name!r}")
    return target


def _extract_zip(path, dest_dir, password):
    opener = None
    if _HAS_PYZIPPER:
        try:
            opener = pyzipper.AESZipFile(path)
        except Exception:
            opener = None
    if opener is None:
        opener = zipfile.ZipFile(path)

    try:
        infos = [i for i in opener.infolist() if not i.is_dir()]
        if len(infos) > ARCHIVE_MAX_FILES:
            raise ArchiveRefused(f"trop de fichiers dans l'archive ({len(infos)} > {ARCHIVE_MAX_FILES}) : extraction refusee")
        total_size = _total_uncompressed_size([i.file_size for i in infos])
        if total_size > MAX_EXTRACT_BYTES:
            raise ArchiveRefused(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")

        pwd_bytes = password.encode() if password else None
        written = 0
        for info in infos:
            if _unsafe_member_name(info.filename):
                raise ArchiveRefused(f"chemin d'extraction dangereux refuse : {info.filename!r}")
            # Les liens symboliques (mode Unix 0o120000) ne sont jamais ecrits.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            target = _safe_join(dest_dir, info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            # Copie par blocs avec compteur reel : file_size peut mentir (zip bomb).
            with opener.open(info, pwd=pwd_bytes) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_EXTRACT_BYTES:
                        raise ArchiveRefused("limite de taille decompressee depassee pendant l'extraction (zip bomb probable)")
                    dst.write(chunk)
    finally:
        opener.close()


def _check_no_escape(dest_dir):
    root = os.path.realpath(dest_dir)
    for r, dirs, files in os.walk(dest_dir):
        for n in dirs + files:
            full = os.path.join(r, n)
            if os.path.islink(full) or not os.path.realpath(full).startswith(root):
                raise ArchiveRefused(f"element d'archive hors du dossier d'extraction : {n!r}")


def _extract_7z(path, dest_dir, password):
    with py7zr.SevenZipFile(path, mode="r", password=password) as z:
        names = z.getnames()
        if len(names) > ARCHIVE_MAX_FILES:
            raise ArchiveRefused(f"trop de fichiers dans l'archive ({len(names)} > {ARCHIVE_MAX_FILES}) : extraction refusee")
        if any(_unsafe_member_name(n) for n in names):
            raise ArchiveRefused("chemin d'extraction dangereux dans l'archive : extraction refusee")
        total_size = sum((info.uncompressed for info in z.list()), 0)
        if total_size > MAX_EXTRACT_BYTES:
            raise ArchiveRefused(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")
        z.extractall(path=dest_dir)
    _check_no_escape(dest_dir)


def _extract_rar(path, dest_dir, password):
    with rarfile.RarFile(path) as rf:
        infos = rf.infolist()
        if len(infos) > ARCHIVE_MAX_FILES:
            raise ArchiveRefused(f"trop de fichiers dans l'archive ({len(infos)} > {ARCHIVE_MAX_FILES}) : extraction refusee")
        if any(_unsafe_member_name(i.filename) for i in infos):
            raise ArchiveRefused("chemin d'extraction dangereux dans l'archive : extraction refusee")
        total_size = sum(i.file_size for i in infos)
        if total_size > MAX_EXTRACT_BYTES:
            raise ArchiveRefused(f"archive trop volumineuse une fois decompressee ({total_size} octets) : extraction refusee")
        rf.extractall(path=dest_dir, pwd=password)
    _check_no_escape(dest_dir)


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
        # Repartir d'un dossier vide : un essai rate peut avoir ecrit des fichiers partiels.
        shutil.rmtree(dest_dir, ignore_errors=True)
        os.makedirs(dest_dir, exist_ok=True)
        try:
            extractor(filepath, dest_dir, pwd)
            result["extraction_reussie"] = True
            result["mot_de_passe_utilise"] = "fourni_par_utilisateur" if pwd == password and pwd else (
                "mot_de_passe_courant_devine" if pwd else "aucun_(non_chiffree)"
            )
            break
        except ArchiveRefused as e:
            last_error = e
            result["extraction_refusee"] = True
            break
        except Exception as e:
            last_error = e
            continue

    if not result["extraction_reussie"]:
        if result.get("extraction_refusee"):
            result["erreur"] = f"extraction refusee par la politique de securite : {last_error}"
        else:
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
