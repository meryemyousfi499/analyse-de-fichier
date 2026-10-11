"""
Vérification de cohérence : l'extension du fichier correspond-elle
à sa signature binaire réelle (magic bytes) ?
Ex : facture.pdf qui est en réalité un PE (MZ...) -> fortement suspect.
"""

MAGIC_SIGNATURES = [
    (b"MZ", "pe_executable", [".exe", ".dll", ".sys", ".scr", ".com"]),
    (b"\x7fELF", "elf_executable", [""]),
    (b"\xca\xfe\xba\xbe", "macho_universal", [""]),
    (b"\xfe\xed\xfa\xce", "macho", [""]),
    (b"%PDF", "pdf", [".pdf"]),
    (b"PK\x03\x04", "zip_or_office_ooxml", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_office_legacy", [".doc", ".xls", ".ppt", ".msi"]),
    (b"\x1f\x8b", "gzip", [".gz", ".tgz"]),
    (b"Rar!\x1a\x07", "rar", [".rar"]),
    (b"7z\xbc\xaf\x27\x1c", "7zip", [".7z"]),
    (b"\xff\xd8\xff", "jpeg", [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n", "png", [".png"]),
    (b"GIF8", "gif", [".gif"]),
    (b"%!PS", "postscript", [".ps", ".eps"]),
    (b"#!", "script_shebang", [".sh", ".py", ".pl", ".rb"]),
]


def detect_real_type(path):
    with open(path, "rb") as f:
        header = f.read(16)
    for sig, label, exts in MAGIC_SIGNATURES:
        if header.startswith(sig):
            return label, exts
    return "inconnu", []


def check_type_consistency(path, extension):
    ext = ("." + extension.lower()) if extension and not extension.startswith(".") else extension.lower()
    real_type, expected_exts = detect_real_type(path)

    if real_type == "inconnu":
        return {
            "type_reel_detecte": "inconnu",
            "extension_declaree": ext,
            "coherent": None,
            "alerte": False,
            "commentaire": "Signature binaire non reconnue par les règles internes.",
        }

    coherent = ext in expected_exts if expected_exts != [""] else True
    alerte = not coherent and real_type in (
        "pe_executable", "elf_executable", "macho", "macho_universal", "script_shebang",
    )

    commentaire = "Extension cohérente avec le contenu réel." if coherent else (
        f"ALERTE : le fichier déclaré '{ext}' est en réalité de type '{real_type}'. "
        f"Usurpation d'extension probable."
    )

    return {
        "type_reel_detecte": real_type,
        "extension_declaree": ext,
        "coherent": coherent,
        "alerte": alerte,
        "commentaire": commentaire,
    }
