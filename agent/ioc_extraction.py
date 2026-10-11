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

    iocs = {
        "ips": _decode_unique(IP_RE.findall(data)),
        "domaines": _decode_unique(DOMAIN_RE.findall(data)),
        "urls": _decode_unique(URL_RE.findall(data)),
        "emails": _decode_unique(EMAIL_RE.findall(data)),
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