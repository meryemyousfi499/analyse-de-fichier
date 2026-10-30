"""Application des regles YARA sur le fichier.

La variable externe `file_ext` (extension sans point, minuscules) est
fournie aux regles qui en ont besoin (ex. PE_Disguised_As_Document) : YARA
seul ne connait pas le nom du fichier analyse.

Les regles sont recompilees automatiquement quand le fichier .yar change
(plus besoin de redemarrer le serveur) et l'erreur de compilation exacte
est conservee pour etre affichee dans le dashboard.
"""
import hashlib
import os
import threading

from config import YARA_RULES_PATH

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

_lock = threading.Lock()
_compiled = None
_error = None
_mtime = None
_rules_version = None


def _load():
    """Retourne les regles compilees, ou None (l'erreur est alors dans _error)."""
    global _compiled, _error, _mtime, _rules_version
    if not _HAS_YARA:
        return None
    with _lock:
        try:
            m = os.path.getmtime(YARA_RULES_PATH)
        except OSError:
            _compiled, _error, _mtime, _rules_version = None, f"fichier de regles introuvable : {YARA_RULES_PATH}", None, "absent"
            return None
        if m == _mtime and (_compiled is not None or _error is not None):
            return _compiled
        _mtime, _rules_version = m, None
        try:
            _compiled = yara.compile(filepath=YARA_RULES_PATH, externals={"file_ext": ""})
            _error = None
        except Exception as e:  # noqa: BLE001
            _compiled, _error = None, str(e)
        return _compiled


def _get_compiled_rules():
    return _load() or False


def compile_status():
    """(ok, erreur) : les regles sont-elles reellement compilees ?"""
    if not _HAS_YARA:
        return False, "module yara-python non installe"
    _load()
    return _compiled is not None, _error


def rules_version():
    """Empreinte courte du fichier de regles : sert a invalider le cache
    quand les regles changent."""
    global _rules_version
    _load()
    if _rules_version is None:
        try:
            with open(YARA_RULES_PATH, "rb") as f:
                _rules_version = hashlib.sha256(f.read()).hexdigest()[:12]
        except OSError:
            _rules_version = "absent"
    return _rules_version


def scan_file(path, original_name=None):
    """`original_name` : nom/extension d'origine du fichier si `path` est un
    chemin temporaire (ex. fichier uploade renomme)."""
    if not _HAS_YARA:
        return {"disponible": False, "raison": "module yara-python non installe", "matches": []}

    rules = _load()
    if rules is None:
        return {"disponible": False, "raison": f"echec de compilation des regles YARA : {_error}", "matches": []}

    ext = os.path.splitext(original_name or path)[1].lstrip(".").lower()

    try:
        matches = rules.match(filepath=path, timeout=20, externals={"file_ext": ext})
    except Exception as e:
        return {"disponible": False, "raison": f"erreur de scan: {e}", "matches": []}

    results = []
    for m in matches:
        results.append({
            "regle": m.rule,
            "severite": m.meta.get("severity", "inconnue"),
            "description": m.meta.get("description", ""),
        })

    return {"disponible": True, "matches": results, "version_regles": rules_version()}