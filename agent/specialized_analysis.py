# agent/specialized_analysis.py

from pathlib import Path
import re
import zipfile


MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 500
MAX_ENTRY_BYTES = 2 * 1024 * 1024

SUSPICIOUS_SCRIPT_PATTERNS = {
    "powershell_encoded": re.compile(
        r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{12,}",
        re.IGNORECASE,
    ),
    "powershell_download": re.compile(
        r"(Invoke-WebRequest|DownloadString|Start-BitsTransfer)",
        re.IGNORECASE,
    ),
    "command_shell": re.compile(
        r"(cmd\.exe\s*/c|powershell(?:\.exe)?\s+-|/bin/(?:sh|bash))",
        re.IGNORECASE,
    ),
    "obfuscation": re.compile(
        r"(fromCharCode|chr\s*\(\s*\d+\s*\)|\\x[0-9a-f]{2})",
        re.IGNORECASE,
    ),
}

SUSPICIOUS_OFFICE_PATTERNS = {
    "auto_execution": re.compile(
        r"\b(AutoOpen|Document_Open|Workbook_Open|Auto_Close)\b",
        re.IGNORECASE,
    ),
    "powershell_reference": re.compile(
        r"\b(powershell|cmd\.exe|wscript\.exe|cscript\.exe)\b",
        re.IGNORECASE,
    ),
    "external_template": re.compile(
        r"TargetMode\s*=\s*[\"']External[\"']",
        re.IGNORECASE,
    ),
}


def _read_limited(path: Path, limit: int = MAX_TEXT_BYTES) -> bytes:
    with path.open("rb") as stream:
        return stream.read(limit)


def analyze_script(path: str) -> dict:
    """Recherche des indicateurs dans un script, sans l'exécuter."""
    file_path = Path(path)
    data = _read_limited(file_path)
    text = data.decode("utf-8", errors="replace")

    findings = []
    for name, pattern in SUSPICIOUS_SCRIPT_PATTERNS.items():
        if pattern.search(text):
            findings.append({
                "indicator": name,
                "description": f"Motif statique suspect détecté : {name}",
            })

    return {
        "tool": "specialized_script",
        "status": "termine",
        "file_type": "script",
        "truncated": file_path.stat().st_size > len(data),
        "findings": findings,
        "note": (
            "Une correspondance est un indicateur à vérifier, "
            "pas une preuve suffisante de malveillance."
        ),
    }


def analyze_pdf(path: str) -> dict:
    """Recherche des marqueurs PDF associés à des fonctionnalités sensibles."""
    file_path = Path(path)
    data = _read_limited(file_path)
    text = data.decode("latin-1", errors="ignore")

    indicators = {
        "/JavaScript": "/JavaScript" in text or "/JS" in text,
        "/OpenAction": "/OpenAction" in text,
        "/Launch": "/Launch" in text,
        "/EmbeddedFile": "/EmbeddedFile" in text,
        "/URI": "/URI" in text,
    }

    findings = [
        {"indicator": name, "description": f"Marqueur PDF présent : {name}"}
        for name, present in indicators.items()
        if present
    ]

    return {
        "tool": "specialized_pdf",
        "status": "termine",
        "file_type": "PDF",
        "findings": findings,
        "note": (
            "Les marqueurs PDF peuvent être légitimes. "
            "Une analyse structurelle approfondie nécessite un parseur spécialisé."
        ),
    }


def analyze_office_zip(path: str) -> dict:
    """
    Inspecte les noms et une quantité limitée de contenu des entrées OOXML.
    Ne décompresse pas les fichiers sur disque.
    """
    file_path = Path(path)
    findings = []
    inspected_entries = 0
    macros_present = False
    external_relationships = 0
    truncated = False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            entries = archive.infolist()

            if len(entries) > MAX_ARCHIVE_ENTRIES:
                entries = entries[:MAX_ARCHIVE_ENTRIES]
                truncated = True

            names = [entry.filename for entry in entries]

            if any(name.lower().endswith("vbaproject.bin") for name in names):
                macros_present = True
                findings.append({
                    "indicator": "vba_project",
                    "description": "Projet VBA présent dans le document Office.",
                })

            for entry in entries:
                inspected_entries += 1

                if entry.file_size > MAX_ENTRY_BYTES:
                    continue

                name = entry.filename.lower()

                if name.endswith(".rels"):
                    try:
                        with archive.open(entry, "r") as stream:
                            raw = stream.read(MAX_ENTRY_BYTES)
                        text = raw.decode("utf-8", errors="replace")

                        count = text.count('TargetMode="External"')
                        count += text.count("TargetMode='External'")
                        external_relationships += count
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        findings.append({
                            "indicator": "relationship_read_error",
                            "description": f"Impossible de lire une relation : {entry.filename}",
                        })

                if name.endswith((".xml", ".vml")):
                    try:
                        with archive.open(entry, "r") as stream:
                            raw = stream.read(MAX_ENTRY_BYTES)
                        text = raw.decode("utf-8", errors="replace")

                        for indicator, pattern in SUSPICIOUS_OFFICE_PATTERNS.items():
                            if pattern.search(text):
                                findings.append({
                                    "indicator": indicator,
                                    "description": (
                                        f"Indicateur {indicator} trouvé dans {entry.filename}"
                                    ),
                                })
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue

            if external_relationships:
                findings.append({
                    "indicator": "external_relationships",
                    "description": (
                        f"{external_relationships} relation(s) externe(s) repérée(s)."
                    ),
                })

    except (OSError, zipfile.BadZipFile, NotImplementedError) as exc:
        return {
            "tool": "specialized_office",
            "status": "echec",
            "file_type": "ZIP/OOXML",
            "findings": [],
            "error": str(exc),
        }

    return {
        "tool": "specialized_office",
        "status": "termine",
        "file_type": "ZIP/OOXML",
        "entries_inspected": inspected_entries,
        "macros_present": macros_present,
        "external_relationships": external_relationships,
        "truncated": truncated,
        "findings": findings,
        "note": (
            "Analyse statique limitée. Les macros ou relations externes "
            "ne prouvent pas à elles seules qu'un document est malveillant."
        ),
    }


def analyze_pe(path: str) -> dict:
    """Contrôles basiques du format PE sans charger ni exécuter le programme."""
    file_path = Path(path)
    findings = []

    with file_path.open("rb") as stream:
        header = stream.read(4096)

    if len(header) < 64 or not header.startswith(b"MZ"):
        return {
            "tool": "specialized_pe",
            "status": "non_applicable",
            "file_type": "PE/EXE",
            "findings": [],
            "note": "En-tête DOS/PE incomplet ou non reconnu.",
        }

    pe_offset = int.from_bytes(header[0x3C:0x40], "little")

    with file_path.open("rb") as stream:
        stream.seek(pe_offset)
        signature = stream.read(4)

    if signature != b"PE\x00\x00":
        findings.append({
            "indicator": "invalid_pe_signature",
            "description": "Signature PE absente à l'emplacement indiqué par l'en-tête.",
        })

    return {
        "tool": "specialized_pe",
        "status": "termine",
        "file_type": "PE/EXE",
        "pe_offset": pe_offset,
        "pe_signature_valid": signature == b"PE\x00\x00",
        "findings": findings,
        "note": (
            "Contrôle structurel minimal. Utiliser un parseur PE dédié "
            "pour une analyse plus approfondie."
        ),
    }


def analyze_specialized_file(file_path: str, detected_type: str) -> dict:
    """Point d'entrée commun pour l'analyse spécialisée."""
    path = Path(file_path)
    extension = path.suffix.lower()

    try:
        if extension in {
            ".ps1", ".psm1", ".bat", ".cmd", ".js",
            ".vbs", ".py", ".sh", ".hta",
        }:
            return analyze_script(str(path))

        if detected_type == "PDF" or extension == ".pdf":
            return analyze_pdf(str(path))

        if detected_type == "ZIP/OOXML" or extension in {
            ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
        }:
            return analyze_office_zip(str(path))

        if detected_type == "PE/EXE" or extension in {".exe", ".dll"}:
            return analyze_pe(str(path))

        return {
            "tool": "specialized_analysis",
            "status": "non_applicable",
            "file_type": detected_type,
            "findings": [],
            "note": "Aucun analyseur spécialisé n'est associé à ce type.",
        }

    except (OSError, ValueError, OverflowError) as exc:
        return {
            "tool": "specialized_analysis",
            "status": "echec",
            "file_type": detected_type,
            "findings": [],
            "error": str(exc),
        }