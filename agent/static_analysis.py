"""
Analyse statique sans exécution :
 - Exécutables PE : imports, sections, entropie par section, packer probable
 - Documents Office : macros VBA (oletools), auto-exécution
 - PDF : JavaScript embarqué, actions d'ouverture, fichiers attachés, /Launch
"""
import os

from .entropy_tools import shannon_entropy

DANGEROUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA", "URLDownloadToFileA",
    "InternetOpenA", "WinExec", "ShellExecuteA", "CryptEncrypt", "IsDebuggerPresent",
    "NtUnmapViewOfSection", "RtlCreateUserThread", "AdjustTokenPrivileges",
}

KNOWN_PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", "petite", ".packed", ".nsp0", ".nsp1"}


def analyze_pe(path):
    try:
        import pefile
    except ImportError:
        return {"disponible": False, "raison": "module pefile non installe"}

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"disponible": False, "raison": f"echec de parsing PE: {e}"}

    imports = []
    dangerous_found = []
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode(errors="ignore") if entry.dll else "?"
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode(errors="ignore")
                    imports.append(f"{dll}!{fname}")
                    if fname in DANGEROUS_IMPORTS:
                        dangerous_found.append(fname)
    except Exception:
        pass

    sections = []
    packer_suspect = False
    for s in pe.sections:
        sname = s.Name.decode(errors="ignore").strip("\x00")
        sec_entropy = round(s.get_entropy(), 3)
        if sname.strip() in KNOWN_PACKER_SECTIONS:
            packer_suspect = True
        sections.append({
            "nom": sname,
            "taille_brute": s.SizeOfRawData,
            "entropie": sec_entropy,
            "executable": bool(s.Characteristics & 0x20000000),
            "ecriture": bool(s.Characteristics & 0x80000000),
        })

    has_signature = False
    try:
        addr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
        has_signature = size > 0 and addr > 0
    except Exception:
        pass

    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    machine = hex(pe.FILE_HEADER.Machine)

    return {
        "disponible": True,
        "type": "DLL" if is_dll else "EXE",
        "architecture": machine,
        "nombre_imports": len(imports),
        "imports_dangereux_detectes": sorted(set(dangerous_found)),
        "sections": sections,
        "packer_suspecte": packer_suspect,
        "signature_presente": has_signature,
        "point_entree": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "timestamp_compilation": pe.FILE_HEADER.TimeDateStamp,
    }


def analyze_office(path):
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {"disponible": False, "raison": "module oletools non installe"}

    try:
        vba = VBA_Parser(path)
    except Exception as e:
        return {"disponible": False, "raison": f"echec de parsing Office: {e}"}

    if not vba.detect_vba_macros():
        return {"disponible": True, "macros_presentes": False}

    autoexec, suspicious, iocs = [], [], []
    try:
        for kw_type, keyword, description in vba.analyze_macros():
            if kw_type == "AutoExec":
                autoexec.append(keyword)
            elif kw_type == "Suspicious":
                suspicious.append({"mot_cle": keyword, "description": description})
            elif kw_type == "IOC":
                iocs.append(keyword)
    except Exception:
        pass

    return {
        "disponible": True,
        "macros_presentes": True,
        "auto_execution": sorted(set(autoexec)),
        "mots_cles_suspects": suspicious,
        "iocs_macro": sorted(set(iocs)),
    }


def analyze_pdf(path):
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        return {"disponible": False, "raison": "module PyPDF2 non installe"}

    findings = {
        "disponible": True,
        "javascript_embarque": False,
        "action_ouverture": False,
        "fichiers_embarques": False,
        "action_launch": False,
        "nombre_pages": None,
    }

    # Scan brut du fichier pour objets PDF sensibles (plus fiable que le
    # parsing structurel seul, car ces objets sont parfois obfusqués).
    with open(path, "rb") as f:
        raw = f.read()

    if b"/JavaScript" in raw or b"/JS" in raw:
        findings["javascript_embarque"] = True
    if b"/OpenAction" in raw:
        findings["action_ouverture"] = True
    if b"/EmbeddedFile" in raw:
        findings["fichiers_embarques"] = True
    if b"/Launch" in raw:
        findings["action_launch"] = True

    try:
        reader = PdfReader(path)
        findings["nombre_pages"] = len(reader.pages)
    except Exception:
        pass

    return findings


def analyze_elf(path):
    try:
        with open(path, "rb") as f:
            header = f.read(64)
        ei_class = header[4]
        ei_data = header[5]
        return {
            "disponible": True,
            "classe": "64 bits" if ei_class == 2 else "32 bits",
            "endianness": "little-endian" if ei_data == 1 else "big-endian",
            "note": "Analyse ELF simplifiee (sans dependance externe). "
                    "Utiliser pyelftools/lief pour une analyse de sections/imports complete.",
        }
    except Exception as e:
        return {"disponible": False, "raison": str(e)}


def analyze_image(path, real_type):
    """Analyse minimale des formats image les plus courants, sans
    dependance externe (pas besoin de Pillow) :
      - dimensions de base (utile pour reperer un fichier trop petit/gros
        pour ce qu'il pretend etre) ;
      - detection de donnees ajoutees APRES la fin officielle du fichier
        (apres le chunk IEND pour un PNG, apres le marqueur FFD9 pour un
        JPEG, apres le trailer 0x3B pour un GIF). C'est une technique
        courante de dissimulation ("polyglotte") : le fichier reste une
        image parfaitement valide a l'ouverture, mais contient en realite
        une archive, un script ou un executable cache a la suite.
    """
    with open(path, "rb") as f:
        data = f.read()

    result = {"disponible": True, "dimensions": None, "donnees_ajoutees_apres_fin": False,
              "taille_donnees_ajoutees_octets": 0}

    try:
        if real_type == "png":
            if len(data) >= 24:
                width = int.from_bytes(data[16:20], "big")
                height = int.from_bytes(data[20:24], "big")
                result["dimensions"] = f"{width}x{height}"
            iend = data.rfind(b"IEND")
            if iend != -1:
                fin_officielle = iend + 4 + 4  # "IEND" + CRC 4 octets
                trailing = len(data) - fin_officielle
                if trailing > 0:
                    result["donnees_ajoutees_apres_fin"] = True
                    result["taille_donnees_ajoutees_octets"] = trailing

        elif real_type == "jpeg":
            # Recherche des marqueurs SOFx pour les dimensions (best-effort)
            i = 2
            while i < len(data) - 9:
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3):
                    height = int.from_bytes(data[i + 5:i + 7], "big")
                    width = int.from_bytes(data[i + 7:i + 9], "big")
                    result["dimensions"] = f"{width}x{height}"
                    break
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg_len = int.from_bytes(data[i + 2:i + 4], "big")
                i += 2 + seg_len
            fin_jpeg = data.rfind(b"\xff\xd9")
            if fin_jpeg != -1:
                trailing = len(data) - (fin_jpeg + 2)
                if trailing > 0:
                    result["donnees_ajoutees_apres_fin"] = True
                    result["taille_donnees_ajoutees_octets"] = trailing

        elif real_type == "gif":
            if len(data) >= 10:
                width = int.from_bytes(data[6:8], "little")
                height = int.from_bytes(data[8:10], "little")
                result["dimensions"] = f"{width}x{height}"
            fin_gif = data.rfind(b"\x3b")
            if fin_gif != -1:
                trailing = len(data) - (fin_gif + 1)
                if trailing > 0:
                    result["donnees_ajoutees_apres_fin"] = True
                    result["taille_donnees_ajoutees_octets"] = trailing
    except Exception:
        pass  # analyse best-effort : une erreur de parsing ne bloque jamais le reste

    return result


def run_static_analysis(path, real_type):
    result = {"type_analyse": real_type}
    if real_type == "pe_executable":
        result["pe"] = analyze_pe(path)
    elif real_type == "elf_executable":
        result["elf"] = analyze_elf(path)
    elif real_type in ("zip_or_office_ooxml", "ole_office_legacy"):
        result["office"] = analyze_office(path)
    elif real_type == "pdf":
        result["pdf"] = analyze_pdf(path)
    elif real_type in ("png", "jpeg", "gif"):
        result["image"] = analyze_image(path, real_type)
    else:
        result["note"] = (
            "Aucun module d'analyse de structure dedie a ce type de fichier "
            "(formats couverts en detail : executables PE/ELF, documents Office, PDF, "
            "images PNG/JPEG/GIF). Le fichier est neanmoins verifie par toutes les autres "
            "etapes du pipeline, qui s'appliquent a TOUT type de fichier sans exception : "
            "hash SHA-256 (comparaison a des bases de malwares connus), entropie/obfuscation, "
            "extraction d'IOC generiques (URLs, IP, domaines, commandes), regles YARA, "
            "antivirus ClamAV et Threat Intelligence externe."
        )
    return result
