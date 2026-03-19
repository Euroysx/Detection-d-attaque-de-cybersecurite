from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import pandas as pd
import numpy as np
import os

# =========================
# INIT APP
# =========================
app = FastAPI(
    title="IDS Sentinel API",
    description="API de détection d'attaques réseau",
    version="1.0"
)

# =========================
# LOAD ARTIFACTS (SAFE)
# =========================
MODEL_PATH = "ids_xgboost.pkl"
SCALER_PATH = "ids_scaler.pkl"
LE_PATH = "ids_label_encoder.pkl"
FEATURE_PATH = "feature_names.pkl"

def load_artifacts():
    for path in [MODEL_PATH, SCALER_PATH, LE_PATH, FEATURE_PATH]:
        if not os.path.exists(path):
            raise RuntimeError(f"Fichier manquant: {path}")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LE_PATH)
    feature_names = joblib.load(FEATURE_PATH)

    return model, scaler, le, feature_names

model, scaler, le, feature_names = load_artifacts()

# =========================
# INPUT SCHEMA
# =========================
class NetworkFlow(BaseModel):
    destination_port: int = Field(..., ge=0, le=65535)
    flow_duration: int = Field(..., gt=0)
    total_fwd_packets: int = Field(..., ge=0)
    total_bwd_packets: int = Field(..., ge=0)
    flow_bytes_s: float = Field(..., ge=0)

# =========================
# HEALTH CHECK
# =========================
@app.get("/")
def health():
    return {"status": "API opérationnelle"}

# =========================
# PREDICTION
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        # -------- sécurité --------
        total_packets = flow.total_fwd_packets + flow.total_bwd_packets
        total_packets = max(total_packets, 1)

        flow_duration = max(flow.flow_duration, 1)

        # -------- feature engineering (IDENTIQUE TRAINING) --------
        flow_packets_s = total_packets / (flow_duration / 1_000_000)
        avg_packet_size = flow.flow_bytes_s / total_packets
        packet_length_mean = avg_packet_size

        # -------- dataframe --------
        data = {
            'Destination Port': float(flow.destination_port),
            'Flow Duration': float(flow_duration),
            'Total Fwd Packets': float(flow.total_fwd_packets),
            'Total Backward Packets': float(flow.total_bwd_packets),
            'Flow Bytes/s': float(flow.flow_bytes_s),
            'Flow Packets/s': float(flow_packets_s),
            'Average Packet Size': float(avg_packet_size),
            'Packet Length Mean': float(packet_length_mean)
        }

        df = pd.DataFrame([data])

        # -------- alignement strict (CRITIQUE) --------
        df = df.reindex(columns=feature_names, fill_value=0)

        # -------- scaling --------
        scaled = scaler.transform(df)

        # -------- prediction --------
        probs = model.predict_proba(scaled)
        pred_idx = int(np.argmax(probs))

        verdict = le.inverse_transform([pred_idx])[0]
        confidence = float(np.max(probs))

        return {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "action": "BLOCK" if verdict != "BENIGN" else "ALLOW",
            "details": {
                "packets_per_sec": round(flow_packets_s, 2),
                "avg_packet_size": round(avg_packet_size, 2)
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))