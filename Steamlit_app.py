import streamlit as st
import joblib
import pandas as pd
import numpy as np
import os

# =========================
# CONFIG PAGE
# =========================
st.set_page_config(
    page_title="IDS Sentinel",
    page_icon="🛡️",
    layout="centered"
)

# =========================
# LOAD MODELS (SAFE)
# =========================
@st.cache_resource
def load_artifacts():
    files = {
        "model": "ids_xgboost.pkl",
        "scaler": "ids_scaler.pkl",
        "encoder": "ids_label_encoder.pkl",
        "features": "feature_names.pkl"
    }

    for name, path in files.items():
        if not os.path.exists(path):
            st.error(f"❌ Fichier manquant: {path}")
            st.stop()

    return (
        joblib.load(files["model"]),
        joblib.load(files["scaler"]),
        joblib.load(files["encoder"]),
        joblib.load(files["features"])
    )

model, scaler, le, feature_names = load_artifacts()

# =========================
# UI HEADER
# =========================
st.title("🛡️ IDS Sentinel")
st.markdown("Détection intelligente d'attaques réseau (CIC-IDS2017)")

st.divider()

# =========================
# INPUTS
# =========================
st.subheader("📡 Paramètres du flux réseau")

col1, col2 = st.columns(2)

with col1:
    destination_port = st.number_input("Destination Port", 0, 65535, 80)
    flow_duration = st.number_input("Flow Duration", 1, 10_000_000, 1000)

with col2:
    total_fwd = st.number_input("Total Fwd Packets", 0, 100000, 10)
    total_bwd = st.number_input("Total Bwd Packets", 0, 100000, 10)

flow_bytes = st.number_input("Flow Bytes/s", 0.0, 1e9, 1000.0)

st.divider()

# =========================
# PREDICTION
# =========================
if st.button("🚀 Analyser le trafic"):

    try:
        # -------- sécurité --------
        total_packets = max(total_fwd + total_bwd, 1)
        flow_duration = max(flow_duration, 1)

        # -------- feature engineering --------
        flow_packets_s = total_packets / (flow_duration / 1_000_000)
        avg_packet_size = flow_bytes / total_packets
        packet_length_mean = avg_packet_size

        # -------- dataframe --------
        data = {
            'Destination Port': float(destination_port),
            'Flow Duration': float(flow_duration),
            'Total Fwd Packets': float(total_fwd),
            'Total Backward Packets': float(total_bwd),
            'Flow Bytes/s': float(flow_bytes),
            'Flow Packets/s': float(flow_packets_s),
            'Average Packet Size': float(avg_packet_size),
            'Packet Length Mean': float(packet_length_mean)
        }

        df = pd.DataFrame([data])

        # -------- alignement strict --------
        df = df.reindex(columns=feature_names, fill_value=0)

        # -------- scaling --------
        scaled = scaler.transform(df)

        # -------- prediction --------
        probs = model.predict_proba(scaled)
        pred_idx = int(np.argmax(probs))

        verdict = le.inverse_transform([pred_idx])[0]
        confidence = float(np.max(probs))

        # =========================
        # OUTPUT
        # =========================
        st.subheader("📊 Résultat")

        if verdict == "BENIGN":
            st.success(f"✅ Trafic normal ({confidence:.2%})")
        else:
            st.error(f"🚨 Attaque détectée : {verdict} ({confidence:.2%})")

        # détails techniques
        with st.expander("🔍 Détails techniques"):
            st.write({
                "Packets/sec": round(flow_packets_s, 2),
                "Avg Packet Size": round(avg_packet_size, 2),
                "Confidence": f"{confidence:.2%}"
            })

    except Exception as e:
        st.error(f"❌ Erreur : {e}")