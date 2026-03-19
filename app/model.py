import joblib
import numpy as np
from app.config import *

class IDSModel:

    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.le = joblib.load(LE_PATH)
        self.feature_names = joblib.load(FEATURE_PATH)

    def predict(self, df):

        # alignement strict features (CRITIQUE)
        df = df.reindex(columns=self.feature_names, fill_value=0)

        scaled = self.scaler.transform(df)

        probs = self.model.predict_proba(scaled)[0]
        pred_idx = int(np.argmax(probs))

        confidence = float(np.max(probs))
        verdict = self.le.inverse_transform([pred_idx])[0]

        return verdict, confidence