"""
Exemple (non exécuté par défaut) montrant comment entraîner un vrai
modèle XGBoost une fois que vous disposez d'un jeu de données étiqueté
(fichiers sains vs malveillants), puis le brancher dans agent/ml_scoring.py.

Usage prévu :
    1. Constituez un CSV `dataset.csv` avec les mêmes colonnes que celles
       retournées par `agent.ml_scoring.extract_features`, plus une colonne
       `label` (0 = sain, 1 = malveillant).
    2. pip install xgboost scikit-learn joblib --break-system-packages
    3. python ml_train_example.py
    4. Passez le chemin du modèle produit à `run_ml_scoring(..., model_path=...)`
       dans agent/pipeline.py.
"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
import xgboost as xgb
import joblib

FEATURE_COLUMNS = [
    "taille_normalisee", "entropie_globale", "nb_imports_dangereux",
    "packer_suspecte", "signature_absente", "macros_presentes",
    "auto_execution", "pdf_js_ou_launch", "type_usurpe",
    "nb_chaines_suspectes", "nb_urls", "base64_massif", "xor_suspecte",
]


def train_supervised(csv_path="dataset.csv", out_path="model_xgb.joblib"):
    df = pd.read_csv(csv_path)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = xgb.XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.08,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    print("Score de validation :", model.score(X_test, y_test))

    joblib.dump(model, out_path)
    print(f"Modele sauvegarde dans {out_path}")


def train_anomaly_detector(csv_path="dataset_sain_uniquement.csv", out_path="model_isoforest.joblib"):
    """Isolation Forest entraine uniquement sur des fichiers sains connus,
    pour detecter ce qui s'ecarte du comportement 'normal' observe."""
    df = pd.read_csv(csv_path)
    X = df[FEATURE_COLUMNS]
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(X)
    joblib.dump(model, out_path)
    print(f"Modele d'anomalies sauvegarde dans {out_path}")


if __name__ == "__main__":
    print("Ce script est un exemple : fournissez vos propres jeux de donnees avant de l'executer.")
