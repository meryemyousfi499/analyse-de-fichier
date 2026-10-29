"""Application des regles YARA sur le fichier.

La variable externe `file_ext` (extension sans point, minuscules) est
fournie aux regles qui en ont besoin (ex. PE_Disguised_As_Document) : YARA
seul ne connait pas le nom du fichier analyse.
"""
import hashlib
import os

from config import YARA_RULES_PATH

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

_compiled = None
_rules_version = None


def _get_compiled_rules():
    global _compiled
    if _compiled is None and _HAS_YARA:
        try:
            _compiled = yara.compile(filepath=YARA_RULES_PATH, externals={"file_ext": ""})
        except Exception:
            _compiled = False
    return _compiled


def rules_version():
    """Empreinte courte du fichier de regles : sert a invalider le cache
    quand les regles changent."""
    global _rules_version
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

    rules = _get_compiled_rules()
    if not rules:
        return {"disponible": False, "raison": "echec de compilation des regles YARA", "matches": []}

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
