"""
Extraction d'IOC (IP, domaines, URLs, emails, hashs, chemins, clés de
registre, processus) et détection de chaînes de caractères suspectes
(LOLBins, obfuscation de commandes).
"""
import os
import re

from config import MAX_PATTERN_SCAN_MB

IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                        rb"(?:com|net|org|io|ru|cn|biz|info|xyz|top|club|online|site|link|icu|shop)\b")
URL_RE = re.compile(rb"\bhttps?://[^\s\"'<>]{4,300}")
EMAIL_RE = re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WIN_PATH_RE = re.compile(rb"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
UNIX_PATH_RE = re.compile(rb"/(?:bin|etc|tmp|usr|var|home|root)/[^\s\"'<>]{2,120}")
REGISTRY_RE = re.compile(rb"HK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]{2,200}")
MD5_RE = re.compile(rb"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(rb"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(rb"\b[a-fA-F0-9]{64}\b")

SUSPICIOUS_TOKENS = [
    "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "certutil",
    "wscript", "cscript", "bitsadmin", "curl", "wget", "/bin/bash",
    "invoke-expression", "iex(", "downloadstring", "frombase64string",
    "-encodedcommand", "net user", "vssadmin delete shadows", "schtasks",
    "reg add", "attrib +h", "vbscript", "shellcode", "createremotethread",
    "virtualallocex", "writeprocessmemory", "amsi.dll", "disablerealtimemonitoring",
]

# Domaines legitimes omnipresents (espaces de noms XML des formats Office /
# OpenDocument, W3C, Microsoft...). Ils apparaissent dans quasiment TOUS les
# .docx/.xlsx/.pptx/.rels/.svg et ne sont pas des indicateurs de compromission :
# les compter faussait le score et envoyait du bruit aux sources de threat intel.
BENIGN_DOMAIN_SUFFIXES = (
    "schemas.openxmlformats.org", "schemas.microsoft.com", "openxmlformats.org",
    "purl.org", "purl.oclc.org", "w3.org", "xmlsoft.org", "xml.org",
    "openoffice.org", "oasis-open.org", "docs.oasis-open.org", "libreoffice.org",
    "microsoft.com", "office.com", "office.net", "live.com", "windows.com",
    "windowsupdate.com", "digicert.com", "verisign.com", "sectigo.com",
    "globalsign.com", "symcache.com", "symantec.com", "entrust.net",
    "adobe.com", "apache.org", "mozilla.org", "python.org", "github.com",
    "example.com", "example.org", "example.net",
)


def _is_benign_domain(host):
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAIN_SUFFIXES)


def _host_of_url(url):
    m = re.match(r"https?://([^/:?#\s]+)", url, re.IGNORECASE)
    return m.group(1) if m else ""


def _is_benign_ip(ip):
    return ip in ("0.0.0.0", "255.255.255.255") or ip.startswith(("127.", "169.254."))


PROCESS_NAMES_RE = re.compile(
    rb"\b(?:svchost|explorer|lsass|winlogon|powershell|cmd|rundll32|"
    rb"regsvr32|mshta|wscript|cscript|taskhostw|conhost)\.exe\b", re.IGNORECASE)


def _decode_unique(matches, limit=50):
    seen = []
    for m in matches:
        try:
            s = m.decode(errors="ignore")
        except Exception:
            continue
        if s not in seen:
            seen.append(s)
        if len(seen) >= limit:
            break
    return seen


def extract_iocs(path):
    taille_totale = os.path.getsize(path)
    limite_octets = MAX_PATTERN_SCAN_MB * 1024 * 1024

    with open(path, "rb") as f:
        data = f.read(limite_octets)

    contenu_tronque = taille_totale > limite_octets

    text_lower = data.lower()

    suspicious_hits = []
    for token in SUSPICIOUS_TOKENS:
        count = text_lower.count(token.encode())
        if count:
            suspicious_hits.append({"chaine": token, "occurrences": count})

    all_ips = _decode_unique(IP_RE.findall(data), limit=200)
    all_domains = _decode_unique(DOMAIN_RE.findall(data), limit=200)
    all_urls = _decode_unique(URL_RE.findall(data), limit=200)
    all_emails = _decode_unique(EMAIL_RE.findall(data), limit=200)

    ips = [i for i in all_ips if not _is_benign_ip(i)][:50]
    domaines = [d for d in all_domains if not _is_benign_domain(d)][:50]
    urls = [u for u in all_urls if not _is_benign_domain(_host_of_url(u))][:50]
    emails = [e for e in all_emails if not _is_benign_domain(e.rsplit("@", 1)[-1])][:50]
    exclus = {
        "ips": len(all_ips) - len(ips) if len(all_ips) <= 50 else None,
        "domaines": len(all_domains) - len(domaines) if len(all_domains) <= 50 else None,
        "urls": len(all_urls) - len(urls) if len(all_urls) <= 50 else None,
    }

    iocs = {
        "ips": ips,
        "domaines": domaines,
        "urls": urls,
        "emails": emails,
        "exclus_domaines_legitimes": {k: v for k, v in exclus.items() if v},
        "chemins_windows": _decode_unique(WIN_PATH_RE.findall(data), limit=30),
        "chemins_unix": _decode_unique(UNIX_PATH_RE.findall(data), limit=30),
        "cles_registre": _decode_unique(REGISTRY_RE.findall(data), limit=30),
        "processus_mentionnes": sorted(set(_decode_unique(PROCESS_NAMES_RE.findall(data), limit=30))),
        "hashs_embarques": {
            "md5": _decode_unique(MD5_RE.findall(data), limit=10),
            "sha1": _decode_unique(SHA1_RE.findall(data), limit=10),
            "sha256": _decode_unique(SHA256_RE.findall(data), limit=10),
        },
        "chaines_suspectes": sorted(suspicious_hits, key=lambda x: -x["occurrences"]),
        "contenu_tronque_pour_analyse": contenu_tronque,
    }
    if contenu_tronque:
        iocs["taille_totale_octets"] = taille_totale
        iocs["taille_analysee_octets"] = len(data)

    iocs["score_indicateurs"] = (
        len(iocs["chaines_suspectes"]) * 3
        + len(iocs["urls"]) * 2
        + len(iocs["ips"])
        + len(iocs["domaines"])
    )
    return iocs