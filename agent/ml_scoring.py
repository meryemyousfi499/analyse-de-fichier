"""
Extraction de features et estimation d'une probabilité de risque.

Note honnête : sans jeu de données étiqueté (fichiers sains vs malveillants
propres à votre environnement), un vrai modèle XGBoost/Isolation Forest
n'a rien à apprendre de fiable. Ce module fournit donc :
  1. une extraction de features réutilisable (feature vector) ;
  2. un score heuristique pondéré basé sur ces features, qui sert de
     valeur par défaut raisonnable ;
  3. un point d'extension clair (`predict_with_model`) pour brancher un
     modèle entraîné dès que vous disposez de données d'entraînement
     (voir ml_train_example.py à la racine du projet).
"""
import os

FEATURE_WEIGHTS = {
    "taille_normalisee": 2,
    "entropie_globale": 8,
    "nb_imports_dangereux": 10,
    "packer_suspecte": 12,
    "signature_absente": 6,
    "macros_presentes": 8,
    "auto_execution": 10,
    "pdf_js_ou_launch": 10,
    "type_usurpe": 20,
    "nb_chaines_suspectes": 6,
    "nb_urls": 3,
    "base64_massif": 6,
    "xor_suspecte": 5,
}


def extract_features(metadata, type_check, entropy_data, static_result, iocs):
    pe = static_result.get("pe", {}) if isinstance(static_result, dict) else {}
    office = static_result.get("office", {}) if isinstance(static_result, dict) else {}
    pdf = static_result.get("pdf", {}) if isinstance(static_result, dict) else {}

    features = {
        "taille_normalisee": min(metadata["taille_octets"] / (10 * 1024 * 1024), 1.0),
        "entropie_globale": entropy_data["entropie_globale"] / 8.0,
        "nb_imports_dangereux": len(pe.get("imports_dangereux_detectes", [])) if pe.get("disponible") else 0,
        "packer_suspecte": 1 if pe.get("packer_suspecte") else 0,
        "signature_absente": 1 if (pe.get("disponible") and not pe.get("signature_presente")) else 0,
        "macros_presentes": 1 if office.get("macros_presentes") else 0,
        "auto_execution": 1 if office.get("auto_execution") else 0,
        "pdf_js_ou_launch": 1 if (pdf.get("javascript_embarque") or pdf.get("action_launch")) else 0,
        "type_usurpe": 1 if type_check.get("alerte") else 0,
        "nb_chaines_suspectes": len(iocs.get("chaines_suspectes", [])),
        "nb_urls": len(iocs.get("urls", [])),
        "base64_massif": 1 if entropy_data.get("base64", {}).get("nombre_blobs_base64", 0) >= 3 else 0,
        "xor_suspecte": 1 if entropy_data.get("xor", {}).get("xor_simple_suspecte") else 0,
    }
    return features


def heuristic_risk_score(features):
    """Retourne une probabilité 0-1 en normalisant une somme pondérée
    de features (bornées) par le poids total maximal possible."""
    raw = 0.0
    max_possible = 0.0
    for key, weight in FEATURE_WEIGHTS.items():
        value = features.get(key, 0)
        capped = min(value, 5) if key.endswith("dangereux") or key.startswith("nb_") else value
        raw += capped * weight
        max_possible += (5 if key.endswith("dangereux") or key.startswith("nb_") else 1) * weight

    probability = raw / max_possible if max_possible else 0.0
    return round(min(probability, 1.0), 4)


def predict_with_model(features, model_path=None):
    """Point d'extension : chargez ici un modèle entraîné (ex: XGBoost,
    Isolation Forest via joblib/pickle) et retournez une probabilité.
    Retombe automatiquement sur l'heuristique si aucun modèle n'est fourni."""
    if model_path and os.path.exists(model_path):
        try:
            import joblib
            model = joblib.load(model_path)
            vector = [[features[k] for k in sorted(features)]]
            proba = model.predict_proba(vector)[0][1]
            return round(float(proba), 4), "modele_entraine"
        except Exception:
            pass
    return heuristic_risk_score(features), "heuristique_ponderee"


def run_ml_scoring(metadata, type_check, entropy_data, static_result, iocs, model_path=None):
    features = extract_features(metadata, type_check, entropy_data, static_result, iocs)
    probability, method = predict_with_model(features, model_path=model_path)
    return {
        "features": features,
        "probabilite_risque": probability,
        "methode": method,
    }
