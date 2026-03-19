# =========================
# LIBRARIES
# =========================
import joblib
import numpy as np
import os

from app.config import (
    MODEL_PATH,
    SCALER_PATH,
    LE_PATH,
    FEATURE_PATH
)

# =========================
# IDS MODEL CLASS
# =========================
class IDSModel:

    def __init__(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.le = joblib.load(LE_PATH)
            self.feature_names = joblib.load(FEATURE_PATH)

        except Exception as e:
            raise RuntimeError(f"Erreur chargement modèle: {e}")

    # =========================
    # PREDICTION
    # =========================
    def predict(self, df):

        try:
            # -------- alignement features --------
            df = df.reindex(columns=self.feature_names, fill_value=0)

            # -------- scaling --------
            scaled = self.scaler.transform(df)

            # -------- prediction --------
            probs = self.model.predict_proba(scaled)[0]

            pred_idx = int(np.argmax(probs))
            confidence = float(np.max(probs))  # ⚠️ FLOAT OBLIGATOIRE

            verdict = self.le.inverse_transform([pred_idx])[0]

            return verdict, confidence

        except Exception as e:
            # fallback sécurité (important PME)
            return "ERROR", 0.0