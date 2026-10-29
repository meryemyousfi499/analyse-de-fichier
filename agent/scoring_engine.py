"""
Moteur de scoring : fusionne tous les signaux (type, entropie, IOC,
YARA, ClamAV, ML, signature, TI) en un score de risque 0-100 avec
explication lisible, plutôt qu'un simple chiffre opaque.

Pondération : un hash connu malveillant ou une règle YARA critique
pèsent beaucoup plus qu'un indice isolé comme un nom de fichier étrange.
"""
from config import SCORE_BANDS

# Poids bruts, sur une base "un signal fort domine plusieurs signaux faibles"
WEIGHTS = {
    "hash_connu_malveillant": 100,
    "yara_critique": 45,
    "yara_eleve": 25,
    "yara_moyen": 12,
    "clamav_infecte": 40,
    "type_usurpe": 30,
    "pe_injection_apis": 20,
    "packer_suspecte": 12,
    "signature_absente": 6,
    "macros_auto_exec": 20,
    "pdf_js_launch": 18,
    "entropie_tres_elevee": 10,
    "donnees_cachees_apres_fin_fichier": 35,
    "ioc_suspects": 8,       # jusqu'a 3 paliers
    "ml_probabilite": 25,    # ponderation de la probabilite ML (0-1) * 25
    "ti_signale": 15,        # IP/domaine/URL signale par une source externe
    "ti_hash_malveillant": 60,  # hash du fichier confirme malveillant par une source externe
    "specialise_indicateurs": 10,  # indicateurs de l'analyse specialisee (Office/PDF/script)
}

# Indicateurs specialises qui ne comptent pas (informatifs, deja couverts ailleurs
# ou trop frequents dans des documents legitimes).
SPECIALIZED_IGNORED = {"/URI", "relationship_read_error"}


def band_for_score(score):
    for lo, hi, label, action in SCORE_BANDS:
        if lo <= score <= hi:
            return label, action
    return "inconnu", "human_review"


def compute_score(hash_check, type_check, entropy_data, static_result,
                   yara_result, clamav_result, iocs, ml_result, ti_result=None,
                   specialized_result=None):
    points = 0
    explications = []

    # --- Signal fort : hash connu ---
    if hash_check.get("connu_malveillant"):
        points += WEIGHTS["hash_connu_malveillant"]
        explications.append("Hash SHA-256 identifie comme malveillant dans une base connue.")

    # --- Signaux deja couverts par une autre source (anti double comptage) ---
    # Une meme caracteristique (type usurpe, macro auto-exec, API d'injection)
    # etait comptee deux fois : une fois par l'analyse structurelle et une
    # fois par la regle YARA correspondante. La regle reste affichee dans les
    # explications, mais ses points ne sont ajoutes qu'une seule fois.
    pe_info = static_result.get("pe", {}) if isinstance(static_result, dict) else {}
    office_info = static_result.get("office", {}) if isinstance(static_result, dict) else {}
    injection_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"}
    redundant_rules = set()
    if type_check.get("alerte"):
        redundant_rules.add("PE_Disguised_As_Document")
    if office_info.get("macros_presentes") and office_info.get("auto_execution"):
        redundant_rules.add("Suspicious_Office_AutoOpen_Shell")
    if pe_info.get("disponible") and injection_apis.intersection(pe_info.get("imports_dangereux_detectes", [])):
        redundant_rules.add("Suspicious_PE_Process_Injection_APIs")

    # --- YARA ---
    counted = [m for m in yara_result.get("matches", []) if m["regle"] not in redundant_rules]
    ignored = [m["regle"] for m in yara_result.get("matches", []) if m["regle"] in redundant_rules]
    severities = [m["severite"] for m in counted]
    if "critique" in severities:
        points += WEIGHTS["yara_critique"]
        rules = [m["regle"] for m in counted if m["severite"] == "critique"]
        explications.append(f"Regle(s) YARA critique(s) declenchee(s) : {', '.join(rules)}.")
    elif "eleve" in severities:
        points += WEIGHTS["yara_eleve"]
        rules = [m["regle"] for m in counted if m["severite"] == "eleve"]
        explications.append(f"Regle(s) YARA de severite elevee declenchee(s) : {', '.join(rules)}.")
    elif "moyen" in severities:
        points += WEIGHTS["yara_moyen"]
        rules = [m["regle"] for m in counted if m["severite"] == "moyen"]
        explications.append(f"Regle(s) YARA moderee(s) declenchee(s) : {', '.join(rules)}.")
    if ignored:
        explications.append(
            "Regle(s) YARA " + ", ".join(ignored) +
            " : meme signal que l'analyse structurelle, points comptes une seule fois."
        )

    # --- ClamAV ---
    if clamav_result.get("disponible") and clamav_result.get("infecte"):
        points += WEIGHTS["clamav_infecte"]
        explications.append(f"ClamAV a detecte la signature '{clamav_result.get('signature')}'.")

    # --- Cohérence de type ---
    if type_check.get("alerte"):
        points += WEIGHTS["type_usurpe"]
        explications.append(
            f"Fichier deguise : extension '{type_check['extension_declaree']}' "
            f"mais contenu reel de type '{type_check['type_reel_detecte']}'."
        )

    # --- Analyse statique PE ---
    pe = pe_info
    if pe.get("disponible"):
        dangerous = pe.get("imports_dangereux_detectes", [])
        if injection_apis.intersection(dangerous):
            points += WEIGHTS["pe_injection_apis"]
            explications.append("Combinaison d'API Windows typique d'une injection de processus.")
        if pe.get("packer_suspecte"):
            points += WEIGHTS["packer_suspecte"]
            explications.append("Sections binaires compatibles avec un packer connu (UPX/ASPack...).")
        if not pe.get("signature_presente"):
            points += WEIGHTS["signature_absente"]
            explications.append("Aucune signature numerique Authenticode presente.")

    # --- Office ---
    office = office_info
    if office.get("macros_presentes") and office.get("auto_execution"):
        points += WEIGHTS["macros_auto_exec"]
        explications.append("Macro Office avec auto-execution detectee (AutoOpen/Document_Open).")

    # --- PDF ---
    pdf = static_result.get("pdf", {}) if isinstance(static_result, dict) else {}
    if pdf.get("javascript_embarque") or pdf.get("action_launch"):
        points += WEIGHTS["pdf_js_launch"]
        explications.append("PDF contenant du JavaScript embarque et/ou une action /Launch.")

    # --- Image : donnees cachees apres la fin officielle du fichier ---
    image = static_result.get("image", {}) if isinstance(static_result, dict) else {}
    if image.get("donnees_ajoutees_apres_fin"):
        points += WEIGHTS["donnees_cachees_apres_fin_fichier"]
        taille = image.get("taille_donnees_ajoutees_octets", 0)
        explications.append(
            f"Des donnees ({taille} octets) sont dissimulees apres la fin officielle "
            "de l'image (technique de fichier polyglotte / steganographie de conteneur)."
        )

    # --- Analyse specialisee (agent/specialized_analysis.py) ---
    # Points ajoutes une seule fois, et uniquement pour des indicateurs non deja
    # comptes par l'analyse structurelle (macros auto-exec, JS/Launch PDF).
    if specialized_result and specialized_result.get("findings"):
        deja_compte = {"vba_project"} if office_info.get("macros_presentes") else set()
        deja_compte |= {"/JavaScript", "/Launch"} if (pdf.get("javascript_embarque") or pdf.get("action_launch")) else set()
        nouveaux = [f["indicator"] for f in specialized_result["findings"]
                    if f.get("indicator") not in SPECIALIZED_IGNORED
                    and f.get("indicator") not in deja_compte]
        if nouveaux:
            points += WEIGHTS["specialise_indicateurs"]
            explications.append(
                "Analyse specialisee : indicateur(s) a verifier -> " + ", ".join(sorted(set(nouveaux))) + "."
            )

    # --- Entropie ---
    # Un format nativement compresse (image, archive, docx/xlsx/pptx...) a
    # une entropie elevee par construction : ce n'est pas penalise, sinon
    # quasiment TOUS les PNG/JPEG/DOCX se retrouveraient signales a tort.
    if (entropy_data.get("entropie_globale", 0) >= 7.2
            and not entropy_data.get("format_naturellement_compresse")):
        points += WEIGHTS["entropie_tres_elevee"]
        explications.append("Entropie tres elevee : chiffrement, packer ou charge utile compressee probable.")

    # --- IOC ---
    ioc_score = iocs.get("score_indicateurs", 0)
    if ioc_score >= 15:
        points += WEIGHTS["ioc_suspects"] * 3
        explications.append("Volume important d'indicateurs suspects (URLs, IP, commandes).")
    elif ioc_score >= 6:
        points += WEIGHTS["ioc_suspects"] * 2
        explications.append("Plusieurs indicateurs suspects detectes dans le contenu.")
    elif ioc_score >= 1:
        points += WEIGHTS["ioc_suspects"]
        explications.append("Quelques indicateurs isoles detectes (a corroborer).")

    # --- ML heuristique ---
    # Le modele est alimente par les MEMES signaux que les regles ci-dessus
    # (type usurpe, packer, macros, IOC...) : quand ces signaux ont deja fait
    # monter le score, sa contribution est reduite pour ne pas les compter deux fois.
    proba = ml_result.get("probabilite_risque", 0)
    ml_factor = 0.4 if points >= 40 else 1.0
    points += proba * WEIGHTS["ml_probabilite"] * ml_factor
    if proba >= 0.5:
        explications.append(f"Le modele de scoring des features estime une probabilite de risque de {proba:.0%}.")

    # --- Threat Intelligence externe (AbuseIPDB / OTX / MalwareBazaar / URLhaus) ---
    if ti_result:
        # Hash du fichier analyse lui-meme, confirme malveillant par une source externe :
        # signal fort, au meme titre qu'un hash connu dans la base locale.
        hash_check_ti = ti_result.get("hash_fichier_analyse") or {}
        hash_flague_externe = any(
            r.get("disponible") and r.get("signale") for r in hash_check_ti.values()
        )
        if hash_flague_externe:
            points += WEIGHTS["ti_hash_malveillant"]
            sources = [s for s, r in hash_check_ti.items() if r.get("disponible") and r.get("signale")]
            explications.append(
                "Le hash SHA-256 du fichier est reconnu comme malveillant par : " + ", ".join(sources) + "."
            )

        def _flagged(groupe):
            return [ind for ind, sources in ti_result.get(groupe, {}).items()
                    if any(r.get("disponible") and r.get("signale") for r in sources.values())]

        flagged_ips = _flagged("ips")
        flagged_domains = _flagged("domaines")
        flagged_urls = _flagged("urls")
        flagged_hashes = _flagged("hashs")

        if flagged_ips or flagged_domains or flagged_urls or flagged_hashes:
            points += WEIGHTS["ti_signale"]
            explications.append(
                "Threat Intelligence : indicateur(s) signale(s) -> "
                f"IP: {flagged_ips or 'aucune'}, domaines: {flagged_domains or 'aucun'}, "
                f"URLs: {flagged_urls or 'aucune'}, hashs embarques: {flagged_hashes or 'aucun'}."
            )

    score = max(0, min(100, round(points)))
    band, action = band_for_score(score)

    if not explications:
        explications.append("Aucun signal notable detecte : fichier conforme aux attentes.")

    return {
        "score": score,
        "niveau": band,
        "action_recommandee": action,
        "explications": explications,
    }
