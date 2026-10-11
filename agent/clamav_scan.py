"""
Détection antivirus multi-moteur via ClamAV (clamd).
Le résultat est traité comme UN indicateur parmi d'autres, jamais comme
décision finale à lui seul.
Nécessite que le démon clamd tourne sur la machine (non démarré par défaut).
"""
from config import CLAMD_HOST, CLAMD_PORT

try:
    import clamd
    _HAS_CLAMD = True
except ImportError:
    _HAS_CLAMD = False


def scan_with_clamav(path):
    if not _HAS_CLAMD:
        return {"disponible": False, "raison": "module python-clamd non installe"}

    try:
        cd = clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT)
        cd.ping()
    except Exception:
        return {"disponible": False, "raison": "clamd injoignable (service non demarre ?)"}

    try:
        result = cd.scan(path)
        status, signature = result.get(path, ("ERROR", None))
        return {
            "disponible": True,
            "infecte": status == "FOUND",
            "signature": signature,
            "statut_brut": status,
        }
    except Exception as e:
        return {"disponible": False, "raison": f"erreur de scan clamd: {e}"}
