"""Calcul des empreintes cryptographiques SHA-256 / SHA-1 / MD5."""
import hashlib


def compute_hashes(path, chunk_size=1024 * 1024):
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def check_known_hash(hashes, known_malicious_db=None):
    """Compare le SHA-256 à une base locale de hashs connus malveillants.
    known_malicious_db : set() de hashs en minuscules, chargée par l'appelant
    (fichier local, base interne, ou résultat de threat_intel)."""
    if not known_malicious_db:
        return {"connu_malveillant": False, "source": None}
    if hashes["sha256"].lower() in known_malicious_db:
        return {"connu_malveillant": True, "source": "base_locale"}
    return {"connu_malveillant": False, "source": None}
