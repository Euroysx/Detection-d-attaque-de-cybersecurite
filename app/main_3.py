# =========================
# LIBRARIES
# =========================
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd

from app.model import IDSModel
from app.config import (
    CRITICAL_PACKET_RATE,
    SUSPICIOUS_PACKET_RATE,
    THRESHOLD_LOW,
    THRESHOLD_HIGH
)

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
# INPUT VALIDATION (CRITIQUE)
# =========================
def validate_input(flow: NetworkFlow):

    if flow.flow_duration <= 0:
        return "Invalid duration"

    if flow.destination_port < 0 or flow.destination_port > 65535:
        return "Invalid port"

    if flow.total_fwd_packets == 0 and flow.total_bwd_packets == 0:
        return "Empty traffic"

    return None

# =========================
# FEATURE ENGINEERING
# =========================
def build_features(flow: NetworkFlow):

    total_packets = max(flow.total_fwd_packets + flow.total_bwd_packets, 1)
    duration = max(flow.flow_duration, 1)

    packets_s = total_packets / (duration / 1_000_000)
    avg_packet_size = flow.flow_bytes_s / total_packets

    if flow.total_bwd_packets == 0:
        ratio = float("inf")
    else:
        ratio = flow.total_fwd_packets / flow.total_bwd_packets

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
# BEHAVIOR ENGINE
# =========================
def detect_behavior(flow, packets_s, ratio):

    is_ddos = (
        packets_s > CRITICAL_PACKET_RATE and
        flow.total_bwd_packets == 0
    )

    is_scan = (
        packets_s > SUSPICIOUS_PACKET_RATE and
        (ratio > 10 or ratio < 0.1)
    )

    is_bruteforce = (
        flow.destination_port in [21, 22, 23] and
        packets_s > 10000 and
        ratio > 5
    )

    return is_ddos, is_scan, is_bruteforce

# =========================
# DECISION ENGINE
# =========================
def decide(verdict, confidence, packets_s, is_ddos, is_scan, is_bruteforce):

    if is_ddos:
        return "CRITICAL", "BLOCK"

    if verdict != "BENIGN":

        if confidence >= THRESHOLD_HIGH:
            return "HIGH", "BLOCK"

        elif confidence >= THRESHOLD_LOW:
            return "MEDIUM", "ALERT"

        else:
            return "LOW", "MONITOR"

    if is_bruteforce:
        if packets_s > 50000:
            return "HIGH", "BLOCK"
        else:
            return "MEDIUM", "ALERT"

    if is_scan:
        return "MEDIUM", "ALERT"

    return "LOW", "ALLOW"

# =========================
# SCORING ENGINE (CORRIGÉ)
# =========================
def compute_score(packets_s, ratio, confidence):

    # clamp ratio
    if ratio == float("inf"):
        safe_ratio = 100
    else:
        safe_ratio = min(ratio, 100)

    score = (
        (packets_s / 1_000_000) * 50 +
        min(abs(safe_ratio - 1), 10) * 10 +
        (1 - confidence) * 20
    )

    score = min(100, int(score))

    # cohérence avec ML
    if confidence > 0.8 and score > 80:
        score = 70

    return score

# =========================
# PREDICTION ENDPOINT
# =========================
@app.post("/predict")
def predict(flow: NetworkFlow):

    try:
        # -------- validation --------
        error = validate_input(flow)
        if error:
            return {
                "verdict": "INVALID",
                "confidence": "0%",
                "risk_level": "LOW",
                "attack_score": 0,
                "action": "REJECT",
                "details": {"reason": error}
            }

        # -------- features --------
        df, packets_s, ratio = build_features(flow)

        # -------- ML --------
        verdict, confidence = ids.predict(df)

        # -------- behavior --------
        is_ddos, is_scan, is_bruteforce = detect_behavior(flow, packets_s, ratio)

        # -------- decision --------
        risk, action = decide(
            verdict,
            confidence,
            packets_s,
            is_ddos,
            is_scan,
            is_bruteforce
        )

        # -------- score --------
        score = compute_score(packets_s, ratio, confidence)

        # -------- response --------
        return {
            "verdict": verdict,
            "confidence": f"{confidence:.2%}",
            "risk_level": risk,
            "attack_score": score,
            "action": action,
            "details": {
                "packets_per_sec": round(packets_s, 2),
                "fwd_bwd_ratio": round(
                    ratio if ratio != float("inf") else 100, 2
                ),
                "behavior_flags": {
                    "ddos": is_ddos,
                    "scan": is_scan,
                    "bruteforce": is_bruteforce
                }
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))