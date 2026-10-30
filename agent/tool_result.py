"""
Contrat de résultat unique pour tous les outils d'analyse.

Chaque outil historique (ClamAV, YARA, analyse statique, analyse spécialisée,
sandbox) renvoie son propre dictionnaire. Les adaptateurs ci-dessous les
convertissent en `ToolResult`, avec un statut commun :

    ok              l'outil s'est exécuté et n'a rien détecté
    detected        l'outil s'est exécuté et a détecté quelque chose
    error           l'outil a été lancé mais a échoué (≠ fichier sain !)
    unavailable     l'outil n'est pas installé / injoignable
    not_applicable  l'outil ne s'applique pas à ce fichier
    skipped         l'outil n'a pas été lancé (politique, limite, doublon...)
    pending         lancé en arrière-plan, résultat attendu plus tard (sandbox)

Règle de sécurité : `error`, `unavailable` et `skipped` ne sont JAMAIS
interprétés comme « sain ». Ils réduisent la couverture de l'analyse
(voir agent/verdict.py).
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

STATUS_OK = "ok"
STATUS_DETECTED = "detected"
STATUS_ERROR = "error"
STATUS_UNAVAILABLE = "unavailable"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_SKIPPED = "skipped"
STATUS_PENDING = "pending"      # lancé en arrière-plan (ex. sandbox), résultat à venir

ALL_STATUSES = (
    STATUS_OK, STATUS_DETECTED, STATUS_ERROR,
    STATUS_UNAVAILABLE, STATUS_NOT_APPLICABLE, STATUS_SKIPPED, STATUS_PENDING,
)
# Statuts qui signifient « l'outil a réellement regardé le fichier ».
COVERING_STATUSES = (STATUS_OK, STATUS_DETECTED)


@dataclass
class ToolResult:
    tool: str
    status: str
    duration_s: float = 0.0
    summary: str = ""
    findings: list = field(default_factory=list)
    error: Optional[str] = None
    raw: Any = None

    def to_dict(self, include_raw=False):
        d = asdict(self)
        if not include_raw:
            d.pop("raw", None)
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(
            tool=d.get("tool", "?"), status=d.get("status", STATUS_SKIPPED),
            duration_s=d.get("duration_s", 0.0), summary=d.get("summary", ""),
            findings=d.get("findings", []) or [], error=d.get("error"),
        )

    @property
    def covered(self):
        return self.status in COVERING_STATUSES


# ---------------------------------------------------------------------------
# Adaptateurs : format historique -> ToolResult
# ---------------------------------------------------------------------------

def from_clamav(raw, duration_s=0.0):
    raw = raw or {}
    if not raw.get("disponible"):
        reason = raw.get("raison", "ClamAV indisponible")
        # "n'a pas pu analyser" (ex. fichier trop gros pour instream) = erreur,
        # moteur absent/injoignable = indisponible.
        status = STATUS_ERROR if raw.get("statut_brut") == "ERROR" or "Erreur pendant" in reason \
            or "n'a pas pu analyser" in reason else STATUS_UNAVAILABLE
        return ToolResult("clamav", status, duration_s, reason, error=reason, raw=raw)
    if raw.get("infecte"):
        sig = raw.get("signature")
        return ToolResult("clamav", STATUS_DETECTED, duration_s, f"Signature : {sig}",
                          findings=[{"signature": sig}], raw=raw)
    return ToolResult("clamav", STATUS_OK, duration_s, "Aucune signature détectée", raw=raw)


def from_yara(raw, duration_s=0.0):
    raw = raw or {}
    if not raw.get("disponible"):
        reason = raw.get("raison", "YARA indisponible")
        status = STATUS_ERROR if reason.startswith(("erreur de scan", "echec de compilation")) \
            else STATUS_UNAVAILABLE
        return ToolResult("yara", status, duration_s, reason, error=reason, raw=raw)
    matches = raw.get("matches", [])
    if matches:
        return ToolResult("yara", STATUS_DETECTED, duration_s,
                          f"{len(matches)} règle(s) déclenchée(s)", findings=matches, raw=raw)
    return ToolResult("yara", STATUS_OK, duration_s, "Aucune règle déclenchée", raw=raw)


def from_static(raw, duration_s=0.0, error=None):
    if error:
        return ToolResult("analyse_statique", STATUS_ERROR, duration_s, error, error=error)
    return ToolResult("analyse_statique", STATUS_OK, duration_s, "Analyse structurelle effectuée", raw=raw)


def from_specialized(raw, duration_s=0.0):
    raw = raw or {}
    st = str(raw.get("status", "")).lower()
    tool = raw.get("tool", "analyse_specialisee")
    if st == "non_applicable":
        return ToolResult(tool, STATUS_NOT_APPLICABLE, duration_s, raw.get("note", ""), raw=raw)
    if st in ("echec", "error"):
        return ToolResult(tool, STATUS_ERROR, duration_s, raw.get("error", "échec"),
                          error=raw.get("error"), raw=raw)
    findings = raw.get("findings", [])
    if findings:
        return ToolResult(tool, STATUS_DETECTED, duration_s,
                          f"{len(findings)} indicateur(s)", findings=findings, raw=raw)
    return ToolResult(tool, STATUS_OK, duration_s, "Aucun indicateur", raw=raw)


def skipped(tool, reason):
    return ToolResult(tool, STATUS_SKIPPED, 0.0, reason)


def not_applicable(tool, reason):
    return ToolResult(tool, STATUS_NOT_APPLICABLE, 0.0, reason)