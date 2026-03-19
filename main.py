from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import pandas as pd
import numpy as np

# =========================
# INIT APP
# =========================
app = FastAPI(title="IDS Sentinel API")

# =========================
# LOAD MODELS
# =========================
try:
    model = joblib.load("ids_xgboost.pkl")
    scaler = joblib.load("ids_scaler.pkl")
    le = joblib.load("ids_label_encoder.pkl")
    feature_names = joblib.load("feature_names.pkl")
except Exception as e:
    raise RuntimeError(f"Erreur chargement modèle : {e}")

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
# PREDICTION ENDPOINT
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        # --- protection ---
        total_packets = flow.total_fwd_packets + flow.total_bwd_packets
        if total_packets == 0:
            total_packets = 1

        flow_duration = max(flow.flow_duration, 1)

        # --- feature engineering (SAFE) ---
        flow_packets_s = total_packets / max(flow_duration / 1_000_000, 1e-6)
        avg_packet_size = flow.flow_bytes_s / total_packets
        packet_length_mean = avg_packet_size

        # --- dataframe ---
        data = {
            'Destination Port': flow.destination_port,
            'Flow Duration': flow_duration,
            'Total Fwd Packets': flow.total_fwd_packets,
            'Total Backward Packets': flow.total_bwd_packets,
            'Flow Bytes/s': flow.flow_bytes_s,
            'Flow Packets/s': flow_packets_s,
            'Average Packet Size': avg_packet_size,
            'Packet Length Mean': packet_length_mean
        }

        df = pd.DataFrame([data])

        # --- sécurité colonnes ---
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0

        df = df[feature_names]

        # --- scaling ---
        scaled = scaler.transform(df)

        # --- prediction ---
        probs = model.predict_proba(scaled)
        pred_idx = int(np.argmax(probs))

        verdict = le.inverse_transform([pred_idx])[0]
        confidence = float(np.max(probs))

        return {
            "verdict": verdict,
            "confidence": f"{confidence:.2%}",
            "action": "BLOCK" if verdict != "BENIGN" else "ALLOW",
            "analysis": { 
                "packets_per_sec": round(flow_packets_s, 2),
                "avg_packet_size": round(avg_packet_size, 2)
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))