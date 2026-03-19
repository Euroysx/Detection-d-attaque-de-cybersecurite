import joblib
import numpy as np
import pandas as pd
import os

from app.config import *


class IDSModel:

    def __init__(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.le = joblib.load(LE_PATH)
            self.feature_names = joblib.load(FEATURE_PATH)

            print("✅ IDS Model loaded successfully")

        except Exception as e:
            raise RuntimeError(f"❌ Model loading failed: {e}")

    def predict(self, df: pd.DataFrame):

        try:
            # =========================
            # VALIDATION INPUT
            # =========================
            if df is None or df.empty:
                raise ValueError("Input dataframe is empty")

            # =========================
            # ALIGNEMENT FEATURES (CRITIQUE)
            # =========================
            missing_cols = set(self.feature_names) - set(df.columns)

            if missing_cols:
                # on ajoute les colonnes manquantes
                for col in missing_cols:
                    df[col] = 0

            df = df[self.feature_names]

            # =========================
            # SCALING
            # =========================
            scaled = self.scaler.transform(df)

            # =========================
            # PREDICTION
            # =========================
            probs = self.model.predict_proba(scaled)

            # support batch + single
            pred_idx = np.argmax(probs, axis=1)
            confidences = np.max(probs, axis=1)

            verdicts = self.le.inverse_transform(pred_idx)

            # =========================
            # FORMAT SORTIE
            # =========================
            results = []

            for v, c in zip(verdicts, confidences):
                results.append({
                    "verdict": v,
                    "confidence": float(c)
                })

            return results if len(results) > 1 else results[0]

        except Exception as e:
            raise RuntimeError(f"Prediction failed: {e}")