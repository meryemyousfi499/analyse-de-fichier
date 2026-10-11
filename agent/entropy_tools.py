"""
Mesure de l'entropie de Shannon et détection d'obfuscation
(Base64 massif, XOR simple à clé fixe, empilement de chaînes fragmentées).
"""
import math
import re
from collections import Counter

from config import MAX_PATTERN_SCAN_MB, MAX_ENTROPY_READ_MB

BASE64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Formats dont le contenu est nativement compresse/encode : une entropie
# proche de 8 y est NORMALE et attendue (compression DEFLATE/JPEG/LZMA...),
# ce n'est pas en soi un signe de chiffrement ou d'obfuscation. Sans cette
# distinction, une simple image PNG ou un .docx (qui est un zip) recoit a
# tort le meme message alarmant qu'un binaire chiffre/packe.
FORMATS_NATURELLEMENT_COMPRESSES = {
    "png", "jpeg", "gif", "zip_or_office_ooxml", "7zip", "rar", "gzip",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_verdict(entropy: float, real_type: str = None) -> str:
    naturellement_compresse = real_type in FORMATS_NATURELLEMENT_COMPRESSES

    if entropy < 4.5:
        return "faible (texte / code non compresse)"
    if entropy < 6.5:
        return "moyenne (binaire natif classique)"
    if entropy < 7.2:
        if naturellement_compresse:
            return "elevee - normale pour ce format deja compresse par nature (pas un signal d'alerte)"
        return "elevee (compression ou binaire dense)"

    if naturellement_compresse:
        return ("tres elevee - normale pour ce type de fichier (image/archive/document "
                "deja compresse), ce n'est PAS en soi un signe de chiffrement ou d'obfuscation")
    return "tres elevee (chiffrement, packer ou payload compresse probable)"


def detect_base64_blobs(data: bytes, min_len=80):
    blobs = BASE64_RE.findall(data)
    long_blobs = [b for b in blobs if len(b) >= min_len]
    return {
        "nombre_blobs_base64": len(long_blobs),
        "exemple": long_blobs[0][:60].decode(errors="ignore") + "..." if long_blobs else None,
    }


def detect_simple_xor(data: bytes, sample_size=4096):
    """Heuristique simple : teste un XOR mono-octet (clés 0-255) sur un
    échantillon et regarde si le résultat devient nettement plus lisible
    (ratio de caractères imprimables) qu'à l'origine -> indice de XOR faible."""
    sample = data[:sample_size]
    if not sample:
        return {"xor_simple_suspecte": False, "cle_probable": None}

    def printable_ratio(b):
        return sum(1 for c in b if 32 <= c <= 126) / len(b)

    base_ratio = printable_ratio(sample)
    best_key, best_ratio = None, base_ratio
    for key in range(1, 256):
        decoded = bytes(c ^ key for c in sample)
        ratio = printable_ratio(decoded)
        if ratio > best_ratio + 0.25:
            best_ratio, best_key = ratio, key

    return {
        "xor_simple_suspecte": best_key is not None,
        "cle_probable": hex(best_key) if best_key is not None else None,
    }


def analyze_entropy_and_obfuscation(path, real_type=None):
    limite_octets = MAX_ENTROPY_READ_MB * 1024 * 1024
    taille_totale = None
    with open(path, "rb") as f:
        data = f.read(limite_octets)
        # Verifie s'il restait du contenu au-dela de la limite, sans
        # charger le reste en memoire.
        contenu_tronque = bool(f.read(1))
        if contenu_tronque:
            f.seek(0, 2)
            taille_totale = f.tell()

    global_entropy = shannon_entropy(data)
    chunk_size = 65536
    chunk_entropies = [
        round(shannon_entropy(data[i:i + chunk_size]), 2)
        for i in range(0, len(data), chunk_size)
    ][:64]  # limite pour l'affichage dashboard

    result = {
        "entropie_globale": round(global_entropy, 3),
        "verdict_entropie": entropy_verdict(global_entropy, real_type),
        "format_naturellement_compresse": real_type in FORMATS_NATURELLEMENT_COMPRESSES,
        "entropie_par_bloc": chunk_entropies,
        # Le blob Base64 n'est cherche que sur les premiers MAX_PATTERN_SCAN_MB :
        # sur un tres gros fichier binaire, une regex sur le contenu integral
        # peut bloquer le thread d'analyse (et donc le serveur) pendant
        # plusieurs minutes.
        "base64": detect_base64_blobs(data[:MAX_PATTERN_SCAN_MB * 1024 * 1024]),
        "xor": detect_simple_xor(data),
        "contenu_tronque_pour_analyse": contenu_tronque,
    }
    if contenu_tronque:
        result["taille_totale_octets"] = taille_totale
        result["taille_analysee_octets"] = len(data)
    return result