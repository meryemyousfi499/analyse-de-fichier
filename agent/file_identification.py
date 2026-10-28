# agent/file_identification.py

from pathlib import Path
import hashlib
import os


CHUNK_SIZE = 1024 * 1024

# Signatures simples et vérifiables. Une extension seule ne prouve pas le type.
MAGIC_SIGNATURES = {
    "PDF": [b"%PDF-"],
    "PE/EXE": [b"MZ"],
    "PNG": [b"\x89PNG\r\n\x1a\n"],
    "JPEG": [b"\xff\xd8\xff"],
    "GIF": [b"GIF87a", b"GIF89a"],
    "ZIP/OOXML": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "GZIP": [b"\x1f\x8b"],
    "RAR": [b"Rar!\x1a\x07"],
    "7Z": [b"7z\xbc\xaf\x27\x1c"],
    "ELF": [b"\x7fELF"],
}

EXTENSION_TYPES = {
    ".pdf": {"PDF"},
    ".exe": {"PE/EXE"},
    ".dll": {"PE/EXE"},
    ".png": {"PNG"},
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".gif": {"GIF"},
    ".zip": {"ZIP/OOXML"},
    ".docx": {"ZIP/OOXML"},
    ".xlsx": {"ZIP/OOXML"},
    ".pptx": {"ZIP/OOXML"},
    ".jar": {"ZIP/OOXML"},
    ".gz": {"GZIP"},
    ".rar": {"RAR"},
    ".7z": {"7Z"},
    ".elf": {"ELF"},
}


def identify_file(file_path: str) -> dict:
    """
    Retourne les métadonnées et l'identification basique d'un fichier.

    N'exécute jamais le fichier.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {path}")

    if not path.is_file():
        raise ValueError("Le chemin fourni ne correspond pas à un fichier.")

    sha256 = hashlib.sha256()
    size = 0
    header = b""

    with path.open("rb") as stream:
        header = stream.read(8192)
        size += len(header)
        sha256.update(header)

        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            sha256.update(chunk)

    extension = path.suffix.lower()
    detected_type = "INCONNU"

    for file_type, signatures in MAGIC_SIGNATURES.items():
        if any(header.startswith(signature) for signature in signatures):
            detected_type = file_type
            break

    expected_types = EXTENSION_TYPES.get(extension)
    extension_mismatch = bool(
        expected_types
        and detected_type != "INCONNU"
        and detected_type not in expected_types
    )

    return {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "extension": extension,
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "detected_type": detected_type,
        "extension_expected_types": sorted(expected_types) if expected_types else [],
        "extension_mismatch": extension_mismatch,
        "identification_note": (
            "Extension incohérente avec la signature détectée."
            if extension_mismatch
            else "Signature reconnue."
            if detected_type != "INCONNU"
            else "Type non identifié par les signatures intégrées."
        ),
    }