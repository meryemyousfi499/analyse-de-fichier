# agent/decision_engine.py

from pathlib import Path


DEFAULT_MAX_SANDBOX_SIZE = 50 * 1024 * 1024

# Types qu'on évite d'envoyer automatiquement au sandbox sans décision explicite.
SENSITIVE_EXTENSIONS = {
    ".key", ".pem", ".p12", ".pfx",
    ".env", ".kdbx", ".sqlite", ".db",
}


def _clamav_detected(clamav_result: dict | None) -> bool:
    """Interprétation prudente des résultats ClamAV connus."""
    if not isinstance(clamav_result, dict):
        return False

    status = str(
        clamav_result.get("status")
        or clamav_result.get("statut")
        or ""
    ).strip().lower()

    if status in {"infected", "infecté", "infecte", "malicious", "malveillant"}:
        return True

    for key in ("infected", "is_infected", "malicious", "detected"):
        if clamav_result.get(key) is True:
            return True

    # Certaines implémentations renvoient le nom de signature dans ces champs.
    for key in ("signature", "virus_name", "threat_name"):
        value = clamav_result.get(key)
        if isinstance(value, str) and value.strip():
            return True

    return False


def decide_analysis(
    file_info: dict,
    clamav_result: dict | None = None,
    yara_result: dict | None = None,
    max_sandbox_size: int = DEFAULT_MAX_SANDBOX_SIZE,
    sandbox_enabled: bool = True,
    allow_sensitive_files: bool = False,
) -> dict:
    """
    Propose les analyses à effectuer en se basant sur des règles déterministes.

    Cette fonction ne soumet pas elle-même le fichier au sandbox.
    """
    path = Path(str(file_info.get("file_path", "")))
    extension = str(file_info.get("extension") or path.suffix).lower()
    size = int(file_info.get("size_bytes") or 0)
    detected_type = str(file_info.get("detected_type") or "INCONNU")

    clamav_positive = _clamav_detected(clamav_result)

    yara_positive = False
    if isinstance(yara_result, dict):
        yara_positive = (
            yara_result.get("detected") is True
            or yara_result.get("matched") is True
            or yara_result.get("matches") not in (None, [], "")
        )

    reasons = []
    alerts = []

    if file_info.get("extension_mismatch"):
        reasons.append("L'extension ne correspond pas à la signature détectée.")
        alerts.append("extension_mismatch")

    if clamav_positive:
        reasons.append("ClamAV a signalé une détection.")
        alerts.append("clamav_detection")

    if yara_positive:
        reasons.append("Une ou plusieurs règles YARA correspondent au fichier.")
        alerts.append("yara_detection")

    if detected_type == "INCONNU":
        reasons.append("Le type réel du fichier n'a pas été identifié.")

    specialized_types = {
        "PDF", "PE/EXE", "ZIP/OOXML", "ELF"
    }
    run_specialized = detected_type in specialized_types or extension in {
        ".ps1", ".psm1", ".bat", ".cmd", ".js", ".vbs",
        ".py", ".sh", ".html", ".hta", ".xml", ".rels",
    }

    sandbox_status = "a_evaluer"

    if not sandbox_enabled:
        sandbox_status = "desactive"
        reasons.append("Le sandbox est désactivé dans la configuration.")
    elif extension == ".rels":
        sandbox_status = "non_applicable"
        reasons.append(
            "Un fichier .rels isolé est un fichier de relations Office ; "
            "il faut analyser le document Office complet."
        )
    elif size > max_sandbox_size:
        sandbox_status = "non_applicable"
        reasons.append("Le fichier dépasse la taille maximale autorisée pour le sandbox.")
    elif extension in SENSITIVE_EXTENSIONS and not allow_sensitive_files:
        sandbox_status = "non_applicable"
        reasons.append(
            "Le fichier peut contenir des secrets ou des données sensibles ; "
            "soumission automatique bloquée."
        )
    elif clamav_positive or yara_positive or file_info.get("extension_mismatch"):
        sandbox_status = "a_soumettre"
        reasons.append("Des éléments justifient une analyse sandbox complémentaire.")
    else:
        sandbox_status = "a_evaluer"
        reasons.append(
            "Décider de la soumission à partir des résultats statiques et de la politique locale."
        )

    return {
        "run_static_analysis": True,
        "run_clamav": True,
        "run_yara": True,
        "run_specialized_analysis": run_specialized,
        "sandbox_status": sandbox_status,
        "alerts": alerts,
        "reasons": reasons,
        "clamav_detected": clamav_positive,
        "yara_detected": yara_positive,
    }