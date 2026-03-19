from fastapi import FastAPI, HTTPException
from app.schemas import NetworkFlow
from app.features import build_features
from app.model import IDSModel
from app.config import *

import warnings
warnings.filterwarnings("ignore")

app = FastAPI(title="IDS Sentinel API")

# load model ONCE (comme en prod)
model = IDSModel()

# =========================
# HEALTH
# =========================
@app.get("/")
def health():
    return {"status": "OK"}

# =========================
# PREDICT
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        # -------- features --------
        df, packets_s, avg_size = build_features(flow)

        # -------- prediction --------
        verdict, confidence = model.predict(df)

        # -------- risk engine --------
        if confidence < THRESHOLD_LOW:
            risk = "LOW"
        elif confidence < THRESHOLD_HIGH:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        # -------- decision engine --------
        if verdict == "BENIGN":
            action = "ALLOW"
        else:
            if risk == "LOW":
                action = "MONITOR"
            elif risk == "MEDIUM":
                action = "ALERT"
            else:
                action = "BLOCK"

        # -------- sécurité critique --------
        if packets_s > CRITICAL_PACKET_RATE:
            action = "BLOCK"
            risk = "CRITICAL"

        return {
            "verdict": verdict,
            "confidence": f"{confidence:.2%}",
            "risk_level": risk,
            "action": action,
            "details": {
                "packets_per_sec": round(packets_s, 2),
                "avg_packet_size": round(avg_size, 2)
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))