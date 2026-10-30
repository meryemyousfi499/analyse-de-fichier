"""
Verdict final : distinct du score.

Le score (0-100) mesure l'accumulation d'indices. Le verdict répond à une
autre question : « que peut-on conclure, et avec quelle confiance ? ».

    clean         aucun signal ET tous les contrôles requis ont réellement tourné
    suspect       indices sérieux mais sans preuve forte indépendante
    malicious     au moins une preuve forte (ClamAV, hash connu, sandbox...)
    inconclusive  analyse incomplète (outil absent/en erreur) sans signal fort

Règle centrale : un outil indisponible ou en erreur n'est JAMAIS une preuve
d'innocuité. Un score faible avec une couverture incomplète donne
« inconclusive » + revue humaine, pas « clean ».
"""
from .tool_result import COVERING_STATUSES

# Outils sans lesquels on ne peut pas affirmer qu'un fichier est sain.
REQUIRED_TOOLS = ("clamav", "yara", "analyse_statique")

VERDICT_CLEAN = "clean"
VERDICT_SUSPECT = "suspect"
VERDICT_MALICIOUS = "malicious"
VERDICT_INCONCLUSIVE = "inconclusive"

VERDICT_LABELS = {
    VERDICT_CLEAN: "Sain (analyse complète, aucun signal)",
    VERDICT_SUSPECT: "Suspect",
    VERDICT_MALICIOUS: "Malveillant (preuve forte)",
    VERDICT_INCONCLUSIVE: "Non concluant (analyse incomplète)",
}


def _coverage(tool_results, required=REQUIRED_TOOLS):
    covered, missing = [], []
    for name in required:
        res = tool_results.get(name)
        if res is not None and res.status in COVERING_STATUSES:
            covered.append(name)
        else:
            missing.append({
                "outil": name,
                "statut": res.status if res else "skipped",
                "raison": (res.error or res.summary) if res else "non lancé",
            })
    ratio = round(len(covered) / len(required), 2) if required else 1.0
    return {"requis": list(required), "couverts": covered, "ratio": ratio, "manquants": missing}


def _sandbox_signal(sandbox_entry):
    """Retourne "malicious" | "suspicious" | "clean" | None selon l'entrée sandbox."""
    if not sandbox_entry or sandbox_entry.get("statut") != "termine":
        return None
    v = str(sandbox_entry.get("verdict") or "").lower()
    if "malicious" in v:
        return "malicious"
    if "suspicious" in v:
        return "suspicious"
    if "no specific threat" in v or "whitelisted" in v or "no threat" in v:
        return "clean"
    return None


def compute_verdict(score_report, tool_results, hash_connu_malveillant=False,
                    ti_hash_malveillant=False, sandbox_entry=None, extra_required=()):
    """Calcule verdict, confiance et couverture.

    tool_results : dict nom -> ToolResult
    sandbox_entry : entrée sandbox terminée (corrélation a posteriori), ou None
    """
    score = score_report.get("score", 0)
    required = tuple(REQUIRED_TOOLS) + tuple(t for t in extra_required if t not in REQUIRED_TOOLS)
    coverage = _coverage(tool_results, required)

    strong, reasons = [], []
    clam = tool_results.get("clamav")
    if clam is not None and clam.status == "detected":
        strong.append("ClamAV a détecté une signature connue")
    if hash_connu_malveillant:
        strong.append("Hash connu comme malveillant (base locale)")
    if ti_hash_malveillant:
        strong.append("Hash confirmé malveillant par une source externe")

    sb = _sandbox_signal(sandbox_entry)
    if sb == "malicious":
        strong.append("La sandbox a conclu à un comportement malveillant")

    yara = tool_results.get("yara")
    yara_severe = bool(yara and yara.status == "detected" and any(
        f.get("severite") in ("critique", "eleve") for f in yara.findings))

    if strong:
        verdict = VERDICT_MALICIOUS
        reasons.extend(strong)
    elif score >= 60 or yara_severe or sb == "suspicious":
        verdict = VERDICT_SUSPECT
        if score >= 60:
            reasons.append(f"Score de risque élevé ({score}/100) sans preuve forte indépendante")
        if yara_severe:
            reasons.append("Règle YARA de sévérité élevée/critique déclenchée")
        if sb == "suspicious":
            reasons.append("La sandbox signale un comportement suspect")
    elif coverage["manquants"]:
        verdict = VERDICT_INCONCLUSIVE
        reasons.append(
            "Analyse incomplète : " + ", ".join(
                f"{m['outil']} ({m['statut']})" for m in coverage["manquants"]
            ) + " — l'absence de détection ne prouve pas que le fichier est sain."
        )
    elif score >= 30:
        verdict = VERDICT_SUSPECT
        reasons.append(f"Score moyen ({score}/100) : quelques indices à vérifier")
    else:
        verdict = VERDICT_CLEAN
        reasons.append("Tous les contrôles requis ont tourné et n'ont relevé aucun signal notable")

    if sb == "clean" and verdict == VERDICT_SUSPECT and not strong:
        reasons.append("La sandbox n'a pas confirmé de comportement malveillant (ne lève pas le doute à elle seule)")

    # Confiance : liée à la couverture et à la présence de preuves fortes.
    if verdict == VERDICT_MALICIOUS:
        confiance = "elevee"
    elif coverage["ratio"] < 0.67:
        confiance = "faible"
    elif verdict == VERDICT_CLEAN and coverage["ratio"] == 1.0:
        confiance = "moyenne"  # jamais "elevee" : l'absence de détection n'est pas une preuve
    else:
        confiance = "moyenne"

    return {
        "verdict": verdict,
        "libelle": VERDICT_LABELS[verdict],
        "confiance": confiance,
        "couverture": coverage,
        "preuves_fortes": strong,
        "raisons": reasons,
    }


def adjust_action(action, verdict):
    """Ajuste l'action recommandée en fonction du verdict : une analyse
    incomplète ne doit pas se terminer par « allow »."""
    if verdict == VERDICT_INCONCLUSIVE and action in ("allow", "monitor"):
        return "human_review"
    if verdict == VERDICT_MALICIOUS and action in ("allow", "monitor"):
        return "quarantine"
    return action