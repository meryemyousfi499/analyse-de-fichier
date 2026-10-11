"""
Collecte des métadonnées du fichier : nom, extension, taille, type MIME réel,
chemin, propriétaire, droits, dates, et zone de téléchargement (Windows ADS).
"""
import os
import stat
import platform
from datetime import datetime

try:
    import magic
    _HAS_MAGIC = True
except ImportError:
    _HAS_MAGIC = False


def _human_size(n):
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} To"


def get_owner(path):
    try:
        import pwd
        st = os.stat(path)
        return pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        try:
            return str(os.stat(path).st_uid)
        except Exception:
            return "inconnu"


def get_zone_identifier(path):
    """Sur Windows, un fichier téléchargé porte un flux NTFS
    'Zone.Identifier' indiquant sa provenance (Internet, réseau...).
    Non applicable sous Linux/Mac -> retourne None."""
    if platform.system() != "Windows":
        return None
    try:
        zone_path = path + ":Zone.Identifier"
        with open(zone_path, "r") as f:
            return f.read()
    except Exception:
        return None


def collect_metadata(path):
    st = os.stat(path)
    real_mime = "inconnu"
    if _HAS_MAGIC:
        try:
            real_mime = magic.from_file(path, mime=True)
        except Exception:
            real_mime = "inconnu"

    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower().lstrip(".")

    return {
        "nom": name,
        "extension": ext or "(aucune)",
        "taille_octets": st.st_size,
        "taille_lisible": _human_size(st.st_size),
        "mime_reel": real_mime,
        "chemin": os.path.abspath(path),
        "proprietaire": get_owner(path),
        "permissions": stat.filemode(st.st_mode),
        "date_creation": datetime.fromtimestamp(st.st_ctime).isoformat(timespec="seconds"),
        "date_modification": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        "date_acces": datetime.fromtimestamp(st.st_atime).isoformat(timespec="seconds"),
        "zone_origine": get_zone_identifier(path),
    }
