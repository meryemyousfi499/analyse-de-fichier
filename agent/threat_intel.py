"""
Vérification des IOC extraits (IP, domaines, URLs, hashs) contre des
sources de réputation externes :

  - AbuseIPDB       -> IP
  - AlienVault OTX  -> domaines, URLs, hashs de fichiers
  - MalwareBazaar   -> hashs de fichiers (abuse.ch)
  - URLhaus         -> URLs et domaines (abuse.ch)

Chaque source est indépendante et se dégrade proprement (disponible=False
+ raison explicite) si la clé correspondante n'est pas configurée ou si
l'appel réseau échoue (hors-ligne, quota, timeout). L'absence d'une
source ne bloque jamais les autres ni le reste du pipeline.
"""
import requests

from config import ABUSEIPDB_API_KEY, OTX_API_KEY, ABUSECH_AUTH_KEY, TI_MAX_LOOKUPS

TIMEOUT = 8


# --------------------------------------------------------------------------
# AbuseIPDB — réputation d'IP
# --------------------------------------------------------------------------
def check_ip_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"disponible": False, "raison": "ABUSEIPDB_API_KEY non configuree"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "disponible": True,
            "source": "abuseipdb",
            "score_abus": data.get("abuseConfidenceScore"),
            "pays": data.get("countryCode"),
            "nombre_signalements": data.get("totalReports"),
            "signale": (data.get("abuseConfidenceScore") or 0) >= 25,
        }
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


# --------------------------------------------------------------------------
# AlienVault OTX — domaines, URLs, hashs
# --------------------------------------------------------------------------
def check_indicator_otx(indicator, indicator_type="domain"):
    if not OTX_API_KEY:
        return {"disponible": False, "raison": "OTX_API_KEY non configuree"}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "disponible": True,
            "source": "otx",
            "nombre_pulses": pulse_count,
            "signale": pulse_count > 0,
        }
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


def check_hash_otx(sha256):
    return check_indicator_otx(sha256, "file")


def check_url_otx(url):
    # OTX attend l'URL encodee dans le chemin ; requests s'en charge via `requests.utils.quote`.
    from urllib.parse import quote
    return check_indicator_otx(quote(url, safe=""), "url")


# --------------------------------------------------------------------------
# MalwareBazaar (abuse.ch) — base de hashs de malware confirmes
# --------------------------------------------------------------------------
def check_hash_malwarebazaar(sha256):
    if not ABUSECH_AUTH_KEY:
        return {"disponible": False, "raison": "ABUSECH_AUTH_KEY non configuree (cle gratuite sur https://auth.abuse.ch/)"}
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            data={"query": "get_info", "hash": sha256},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            info = (data.get("data") or [{}])[0]
            return {
                "disponible": True,
                "source": "malwarebazaar",
                "signale": True,
                "connu_malveillant": True,
                "signature": info.get("signature"),
                "type_fichier": info.get("file_type"),
                "tags": info.get("tags"),
            }
        return {"disponible": True, "source": "malwarebazaar", "signale": False, "connu_malveillant": False}
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


# --------------------------------------------------------------------------
# URLhaus (abuse.ch) — base d'URLs / domaines de distribution de malware
# --------------------------------------------------------------------------
def check_url_urlhaus(url):
    if not ABUSECH_AUTH_KEY:
        return {"disponible": False, "raison": "ABUSECH_AUTH_KEY non configuree (cle gratuite sur https://auth.abuse.ch/)"}
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            data={"url": url},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        signale = data.get("query_status") == "ok"
        return {
            "disponible": True,
            "source": "urlhaus",
            "signale": signale,
            "statut_url": data.get("url_status") if signale else None,
            "menace": data.get("threat") if signale else None,
        }
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


def check_domain_urlhaus(domain):
    if not ABUSECH_AUTH_KEY:
        return {"disponible": False, "raison": "ABUSECH_AUTH_KEY non configuree (cle gratuite sur https://auth.abuse.ch/)"}
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            data={"host": domain},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        signale = data.get("query_status") == "ok" and int(data.get("url_count") or 0) > 0
        return {
            "disponible": True,
            "source": "urlhaus",
            "signale": signale,
            "nombre_urls_malveillantes": data.get("url_count"),
        }
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


# --------------------------------------------------------------------------
# Vérification manuelle d'un indicateur isolé (hash, domaine, URL ou IP)
# saisi directement par l'utilisateur, sans passer par une analyse de
# fichier — utile pour "je veux vérifier moi-même" un indicateur reçu
# ailleurs (email, lien partagé, hash communiqué par un tiers, etc.)
# --------------------------------------------------------------------------
def check_indicator_manual(indicator, indicator_type):
    """indicator_type: 'hash' | 'domaine' | 'url' | 'ip'"""
    indicator = indicator.strip()
    resultats = {}

    if indicator_type == "ip":
        resultats["abuseipdb"] = check_ip_abuseipdb(indicator)

    elif indicator_type == "domaine":
        resultats["otx"] = check_indicator_otx(indicator, "domain")
        resultats["urlhaus"] = check_domain_urlhaus(indicator)

    elif indicator_type == "url":
        resultats["otx"] = check_url_otx(indicator)
        resultats["urlhaus"] = check_url_urlhaus(indicator)

    elif indicator_type == "hash":
        resultats["otx"] = check_hash_otx(indicator)
        resultats["malwarebazaar"] = check_hash_malwarebazaar(indicator)

    else:
        return {"erreur": f"type d'indicateur inconnu: {indicator_type} (attendu: hash, domaine, url, ip)"}

    au_moins_une_source_dispo = any(v.get("disponible") for v in resultats.values())
    signale = any(v.get("signale") for v in resultats.values() if v.get("disponible"))

    return {
        "indicateur": indicator,
        "type": indicator_type,
        "resultats": resultats,
        "au_moins_une_source_disponible": au_moins_une_source_dispo,
        "signale_malveillant": signale,
    }


# --------------------------------------------------------------------------
# Orchestration pour un jeu d'IOC extraits d'un fichier analysé
# --------------------------------------------------------------------------
def run_threat_intel(iocs, max_lookups=None):
    """Interroge les sources externes disponibles pour un sous-ensemble
    limité de chaque type d'IOC (pour éviter de dépasser les quotas
    gratuits en un seul scan). Chaque source manquante ou en échec est
    simplement absente/marquée indisponible : le reste continue de tourner."""
    max_lookups = max_lookups or TI_MAX_LOOKUPS
    results = {"ips": {}, "domaines": {}, "urls": {}, "hashs": {}}

    for ip in iocs.get("ips", [])[:max_lookups]:
        results["ips"][ip] = {"abuseipdb": check_ip_abuseipdb(ip)}

    for domain in iocs.get("domaines", [])[:max_lookups]:
        results["domaines"][domain] = {
            "otx": check_indicator_otx(domain, "domain"),
            "urlhaus": check_domain_urlhaus(domain),
        }

    for url in iocs.get("urls", [])[:max_lookups]:
        results["urls"][url] = {
            "otx": check_url_otx(url),
            "urlhaus": check_url_urlhaus(url),
        }

    # Hashs : ceux embarqués dans le fichier (chaînes SHA-256 trouvées à
    # l'intérieur), utile pour les scripts/rapports qui référencent d'autres
    # binaires. Le hash du fichier lui-même est vérifié séparément dans le
    # pipeline via check_known_hash + cette même fonction sur la liste
    # ["hashs_a_verifier"] si fournie par l'appelant.
    hashs_embed = iocs.get("hashs_embarques", {}).get("sha256", [])
    for h in (hashs_embed + iocs.get("hashs_a_verifier", []))[:max_lookups]:
        results["hashs"][h] = {
            "otx": check_hash_otx(h),
            "malwarebazaar": check_hash_malwarebazaar(h),
        }

    au_moins_une_source_dispo = any(
        v.get("disponible")
        for groupe in results.values()
        for entree in groupe.values()
        for v in entree.values()
    )
    resultats_signales = [
        {"indicateur": ind, "type": type_grp, "source": src}
        for type_grp, groupe in results.items()
        for ind, sources in groupe.items()
        for src, v in sources.items()
        if v.get("disponible") and v.get("signale")
    ]

    results["au_moins_une_source_disponible"] = au_moins_une_source_dispo
    results["indicateurs_signales"] = resultats_signales
    return results
