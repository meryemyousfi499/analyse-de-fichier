
"""
Analyse antivirus via ClamAV dans Docker.
Le résultat est un indicateur parmi d'autres du pipeline Cabinet Noir.
"""

from config import CLAMD_HOST, CLAMD_PORT

try:
    import clamd
    _HAS_CLAMD = True
except ImportError:
    _HAS_CLAMD = False


def scan_with_clamav(path):
    if not _HAS_CLAMD:
        return {
            "disponible": False,
            "raison": "Module clamd non installe dans cet environnement Python",
        }

    # Vérifier la connexion au moteur ClamAV
    try:
        cd = clamd.ClamdNetworkSocket(
            host=CLAMD_HOST,
            port=CLAMD_PORT,
            timeout=60,
        )
        cd.ping()
    except Exception as e:
        return {
            "disponible": False,
            "raison": f"ClamAV injoignable : {e}",
        }

    # Envoyer le contenu du fichier au conteneur Docker
    try:
        with open(path, "rb") as fichier:
            result = cd.instream(fichier)

        status, signature = result.get("stream", ("ERROR", "Resultat absent"))

        if status == "ERROR":
            return {
                "disponible": False,
                "infecte": None,
                "signature": None,
                "statut_brut": status,
                "raison": f"ClamAV n'a pas pu analyser le fichier : {signature}",
            }

        return {
            "disponible": True,
            "infecte": status == "FOUND",
            "signature": signature,
            "statut_brut": status,
        }

    except Exception as e:
        return {
            "disponible": False,
            "infecte": None,
            "signature": None,
            "raison": f"Erreur pendant l'analyse ClamAV : {e}",
        }
