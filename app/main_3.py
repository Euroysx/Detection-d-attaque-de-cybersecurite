# =========================
# LIBRARIES
# =========================
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd

from app.model import IDSModel
from app.config import *

# =========================
# INIT APP
# =========================
app = FastAPI(title="IDS PME - Cyber Detection API")

ids = IDSModel()

# =========================
# INPUT SCHEMA
# =========================
class NetworkFlow(BaseModel):
    destination_port: int
    flow_duration: int
    total_fwd_packets: int
    total_bwd_packets: int
    flow_bytes_s: float

# =========================
# HEALTH CHECK
# =========================
@app.get("/")
def health():
    return {"status": "API opérationnelle"}

# =========================
# FEATURE ENGINEERING
# =========================
def build_features(flow: NetworkFlow):

    total_packets = flow.total_fwd_packets + flow.total_bwd_packets
    total_packets = max(total_packets, 1)

    duration = max(flow.flow_duration, 1)

    packets_s = total_packets / (duration / 1_000_000)
    avg_packet_size = flow.flow_bytes_s / total_packets
    ratio = flow.total_fwd_packets / max(flow.total_bwd_packets, 1)

    data = {
        'Destination Port': flow.destination_port,
        'Flow Duration': duration,
        'Total Fwd Packets': flow.total_fwd_packets,
        'Total Backward Packets': flow.total_bwd_packets,
        'Flow Bytes/s': flow.flow_bytes_s,
        'Flow Packets/s': packets_s,
        'Average Packet Size': avg_packet_size,
        'Packet Length Mean': avg_packet_size
    }

    return pd.DataFrame([data]), packets_s, ratio

# =========================
# PREDICTION ENDPOINT
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        df, packets_s, ratio = build_features(flow)

        result = ids.predict(df)

        verdict = result["verdict"]
        confidence = result["confidence"]

        # =========================
        # 🔥 PRIORITÉ COMPORTEMENT (IMPORTANT)
        # =========================

        is_ddos = (
            packets_s > CRITICAL_PACKET_RATE and
            flow.total_bwd_packets == 0
        )

        is_suspicious = (
            packets_s > 300_000 and
            (ratio > 10 or ratio < 0.1)
        )

        # =========================
        # 🔥 DECISION ENGINE CORRIGÉ
        # =========================

        # 1️⃣ CAS CRITIQUE → override total
        if is_ddos:
            action = "BLOCK"
            risk = "CRITICAL"

        # 2️⃣ CAS ML attaque
        elif verdict != "BENIGN":

            if confidence >= THRESHOLD_HIGH:
                action = "BLOCK"
                risk = "HIGH"

            elif confidence >= THRESHOLD_LOW:
                action = "ALERT"
                risk = "MEDIUM"

            else:
                action = "MONITOR"
                risk = "LOW"

        # 3️⃣ CAS comportement suspect
        elif is_suspicious:
            action = "ALERT"
            risk = "MEDIUM"

        # 4️⃣ CAS normal
        else:
            action = "ALLOW"
            risk = "LOW"

        # =========================
        # 🔥 SCORE AMÉLIORÉ
        # =========================
        score = min(100, int(
            (packets_s / 1_000_000) * 50 +   # poids + fort
            abs(ratio - 1) * 25 +
            (1 - confidence) * 25
        ))

        # =========================
        # RESPONSE
        # =========================
        return {
            "verdict": verdict,
            "confidence": f"{confidence:.2%}",
            "risk_level": risk,
            "attack_score": score,
            "action": action,
            "details": {
                "packets_per_sec": round(packets_s, 2),
                "fwd_bwd_ratio": round(ratio, 2),
                "flags": {
                    "ddos": is_ddos,
                    "suspicious": is_suspicious
                }
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))