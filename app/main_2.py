# =========================
# LIBRARIES
# =========================
from fastapi import FastAPI, HTTPException
from app.schemas import NetworkFlow
from app.features import build_features
from app.model import IDSModel
from app.config import *

import warnings
warnings.filterwarnings("ignore")

# =========================
# INIT
# =========================
app = FastAPI(title="IDS Sentinel API")

model = IDSModel()

# =========================
# HEALTH CHECK
# =========================
@app.get("/")
def health():
    return {"status": "OK"}

# =========================
# PREDICTION
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        # =========================
        # FEATURE ENGINEERING
        # =========================
        df, packets_s, avg_size = build_features(flow)

        total_packets = flow.total_fwd_packets + flow.total_bwd_packets
        ratio_fwd_bwd = flow.total_fwd_packets / max(flow.total_bwd_packets, 1)

        # =========================
        # MODEL PREDICTION
        # =========================
        verdict, confidence = model.predict(df)

        # =========================
        # RISK ENGINE (SCORING PME)
        # =========================
        score = 0

        # 🔹 modèle
        score += confidence * 50  # max 50

        # 🔹 débit anormal
        if packets_s > 1_000_000:
            score += 30
        elif packets_s > 300_000:
            score += 20
        elif packets_s > 100_000:
            score += 10

        # 🔹 asymétrie trafic (DDoS typique)
        if ratio_fwd_bwd > 10 or ratio_fwd_bwd < 0.1:
            score += 15

        # 🔹 taille anormale
        if avg_size > 10000:
            score += 10

        # cap score
        score = min(score, 100)

        # =========================
        # RISK LEVEL
        # =========================
        if score >= 80:
            risk = "CRITICAL"
        elif score >= 60:
            risk = "HIGH"
        elif score >= 40:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # =========================
        # DDoS DETECTION (SMART)
        # =========================
        is_ddos_pattern = (
            packets_s > 300_000 and
            flow.total_bwd_packets == 0
        )

        if is_ddos_pattern:
            risk = "CRITICAL"

        # =========================
        # DECISION ENGINE (COHÉRENT)
        # =========================
        if risk == "CRITICAL":
            action = "BLOCK"

        elif risk == "HIGH":
            action = "BLOCK"

        elif risk == "MEDIUM":
            action = "ALERT"

        else:
            action = "ALLOW"

        # =========================
        # SAFETY OVERRIDE
        # =========================
        # même si modèle dit BENIGN
        if verdict == "BENIGN" and risk in ["HIGH", "CRITICAL"]:
            action = "BLOCK"

        return {
            "verdict": verdict,
            "confidence": f"{confidence:.2%}",
            "risk_level": risk,
            "attack_score": round(score, 2),
            "action": action,
            "details": {
                "packets_per_sec": round(packets_s, 2),
                "avg_packet_size": round(avg_size, 2),
                "fwd_bwd_ratio": round(ratio_fwd_bwd, 2)
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))