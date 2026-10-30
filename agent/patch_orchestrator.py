"""Applique les modifications à agent/orchestrator.py :
  - un indicateur signalé par une source fiable rend le fichier au moins « suspect » ;
  - tout fichier suspect/malveillant ou avec un indicateur signalé justifie un test sandbox.
Usage (depuis la racine du projet) :  python patch_orchestrator.py
Une copie de sauvegarde est créée : agent/orchestrator.py.bak"""
import shutil
import sys

PATH = "agent/orchestrator.py"
src = open(PATH, encoding="utf-8").read()

def sub(old, new):
    global src
    if src.count(old) != 1:
        sys.exit(f"Bloc introuvable ou ambigu (fichier déjà modifié ?) :\n{old[:80]}")
    src = src.replace(old, new, 1)

if "_ti_strong_flags" in src:
    sys.exit("orchestrator.py est déjà modifié.")

HELPER = '''def _ti_strong_flags(ti_res):
    """Indicateurs signalés par une source fiable (URLhaus, MalwareBazaar, AbuseIPDB)
    ou par au moins 3 pulses OTX. Un ou deux pulses OTX ne suffisent pas : de
    nombreux domaines légitimes y figurent."""
    out = []
    for grp in ("ips", "domaines", "urls", "hashs"):
        for ind, sources in ((ti_res or {}).get(grp) or {}).items():
            for name, r in sources.items():
                if r.get("disponible") and r.get("signale") and (name != "otx" or (r.get("nombre_pulses") or 0) >= 3):
                    out.append(ind)
                    break
    return out


'''
sub('def decide_sandbox(*, filename, size_bytes, score_report,\n                   clamav_detected, hash_connu, yara_severe, decision_hint):',
    HELPER + 'def decide_sandbox(*, filename, size_bytes, score_report,\n                   clamav_detected, hash_connu, yara_severe, decision_hint,\n                   ti_flags=(), verdict_label=""):')
sub('''        declencheurs.append(f"le score statique ({score_report['score']}) atteint le seuil {SANDBOX_MIN_SCORE}")''',
    '''        declencheurs.append(f"le score statique ({score_report['score']}) atteint le seuil {SANDBOX_MIN_SCORE}")
    if ti_flags:
        declencheurs.append(f"{len(ti_flags)} indicateur(s) extrait(s) signalé(s) par une source de réputation")
    if verdict_label in ("suspect", "malicious"):
        declencheurs.append(f"le verdict global est « {verdict_label} »")''')
sub('''    score_report["action_recommandee"] = verdict_mod.adjust_action(
        score_report["action_recommandee"], verdict["verdict"])''',
    '''    # Réputation : un indicateur signalé par une source fiable rend le fichier au moins suspect.
    ti_flags = _ti_strong_flags(ti_res)
    if ti_flags and verdict["verdict"] in (verdict_mod.VERDICT_CLEAN, verdict_mod.VERDICT_INCONCLUSIVE):
        verdict["verdict"] = verdict_mod.VERDICT_SUSPECT
        verdict["libelle"] = verdict_mod.VERDICT_LABELS[verdict_mod.VERDICT_SUSPECT]
        verdict["raisons"].append("Indicateur(s) signalé(s) par la réputation : " + ", ".join(ti_flags[:5]))
    if verdict["verdict"] == verdict_mod.VERDICT_SUSPECT and score_report["action_recommandee"] in ("allow", "monitor"):
        score_report["action_recommandee"] = "human_review"

    score_report["action_recommandee"] = verdict_mod.adjust_action(
        score_report["action_recommandee"], verdict["verdict"])''')
sub('        decision_hint=decision,\n    )',
    '        decision_hint=decision,\n        ti_flags=ti_flags, verdict_label=verdict["verdict"],\n    )')

shutil.copy(PATH, PATH + ".bak")
open(PATH, "w", encoding="utf-8").write(src)
print("orchestrator.py modifié (sauvegarde : orchestrator.py.bak)")