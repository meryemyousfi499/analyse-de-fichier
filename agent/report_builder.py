# agent/report_builder.py

from datetime import datetime, timezone
import json
from pathlib import Path


def _tool_status(result) -> str:
    if not isinstance(result, dict):
        return "inconnu"

    status = str(result.get("status", "inconnu")).lower()

    if status in {"error", "failed", "failure"}:
        return "echec"

    if status in {"pending", "queued"}:
        return "en_attente"

    if status in {"running", "processing"}:
        return "en_cours"

    if status in {"completed", "complete", "success", "finished"}:
        return "termine"

    return status


def build_report(
    file_info: dict,
    decision: dict,
    clamav_result=None,
    yara_result=None,
    specialized_result=None,
    sandbox_result=None,
    score_result=None,
) -> dict:
    """Construit un rapport normalisé pour le dashboard et l'historique."""
    tools = {
        "clamav": clamav_result or {"status": "non_execute"},
        "yara": yara_result or {"status": "non_execute"},
        "specialized_analysis": specialized_result or {"status": "non_execute"},
        "sandbox": sandbox_result or {"status": decision.get("sandbox_status", "inconnu")},
    }

    normalized_tools = {}
    for name, result in tools.items():
        if isinstance(result, dict):
            normalized_tools[name] = {
                **result,
                "status": _tool_status(result),
            }
        else:
            normalized_tools[name] = {
                "status": "inconnu",
                "raw_result": str(result),
            }

    alerts = list(decision.get("alerts", []))
    if score_result and isinstance(score_result, dict):
        extra_alerts = score_result.get("alerts", [])
        if isinstance(extra_alerts, list):
            alerts.extend(extra_alerts)

    # Déduplication en conservant l'ordre.
    alerts = list(dict.fromkeys(str(item) for item in alerts))

    if "clamav_detection" in alerts or "yara_detection" in alerts:
        verdict = "suspect"
    elif alerts:
        verdict = "a_verifier"
    else:
        verdict = "non_concluant"

    return {
        "schema_version": 1,
        "analysis_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file": {
            "file_name": file_info.get("file_name"),
            "extension": file_info.get("extension"),
            "size_bytes": file_info.get("size_bytes"),
            "sha256": file_info.get("sha256"),
            "detected_type": file_info.get("detected_type"),
            "extension_mismatch": file_info.get("extension_mismatch", False),
            "identification_note": file_info.get("identification_note"),
        },
        "verdict": verdict,
        "alerts": alerts,
        "decision": decision,
        "tools": normalized_tools,
        "score": score_result,
        "limitations": [
            "Un résultat inconnu ou une erreur d'outil ne signifie pas que le fichier est sain.",
            "Le verdict doit être confirmé à partir des preuves et des résultats détaillés.",
        ],
    }


def save_report(report: dict, output_dir: str) -> str:
    """Enregistre un rapport JSON dans le répertoire indiqué."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    analysis_id = str(report.get("analysis_id", "analysis"))
    output_path = destination / f"{analysis_id}.json"

    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)

    return str(output_path.resolve())