"""Application des règles YARA (et point d'extension pour Sigma) sur le fichier."""
from config import YARA_RULES_PATH

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

_compiled = None


def _get_compiled_rules():
    global _compiled
    if _compiled is None and _HAS_YARA:
        try:
            _compiled = yara.compile(filepath=YARA_RULES_PATH)
        except Exception:
            _compiled = False
    return _compiled


def scan_file(path):
    if not _HAS_YARA:
        return {"disponible": False, "raison": "module yara-python non installe", "matches": []}

    rules = _get_compiled_rules()
    if not rules:
        return {"disponible": False, "raison": "echec de compilation des regles YARA", "matches": []}

    try:
        matches = rules.match(filepath=path, timeout=20)
    except Exception as e:
        return {"disponible": False, "raison": f"erreur de scan: {e}", "matches": []}

    results = []
    for m in matches:
        results.append({
            "regle": m.rule,
            "severite": m.meta.get("severity", "inconnue"),
            "description": m.meta.get("description", ""),
        })

    return {"disponible": True, "matches": results}
