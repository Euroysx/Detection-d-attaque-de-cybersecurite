import streamlit as st
import joblib
import pandas as pd
import numpy as np

st.set_page_config(page_title="IDS Sentinel", layout="centered")

st.title("🛡️ IDS Sentinel - Détection d'attaques réseau")
st.markdown("Simule un flux réseau et détecte s'il est malveillant.")

# =========================
# LOAD MODEL
# =========================
model = joblib.load("ids_model.pkl")
scaler = joblib.load("ids_scaler.pkl")
le = joblib.load("ids_label_encoder.pkl")
feature_names = joblib.load("feature_names.pkl")

# =========================
# INPUTS
# =========================
destination_port = st.number_input("Destination Port", 0, 65535, 80)
flow_duration = st.number_input("Flow Duration (µs)", min_value=1, value=1000000)
total_fwd_packets = st.number_input("Total Fwd Packets", min_value=0, value=10)
total_bwd_packets = st.number_input("Total Backward Packets", min_value=0, value=5)
flow_bytes_s = st.number_input("Flow Bytes/s", min_value=0.0, value=10000.0)

# =========================
# PREDICTION
# =========================
if st.button("Analyser"):

    total_packets = total_fwd_packets + total_bwd_packets
    if total_packets == 0:
        total_packets = 1

    flow_duration = max(flow_duration, 1)

    flow_packets_s = total_packets / max(flow_duration / 1_000_000, 1e-6)
    avg_packet_size = flow_bytes_s / total_packets
    packet_length_mean = avg_packet_size

    data = {
        'Destination Port': destination_port,
        'Flow Duration': flow_duration,
        'Total Fwd Packets': total_fwd_packets,
        'Total Backward Packets': total_bwd_packets,
        'Flow Bytes/s': flow_bytes_s,
        'Flow Packets/s': flow_packets_s,
        'Average Packet Size': avg_packet_size,
        'Packet Length Mean': packet_length_mean
    }

    df = pd.DataFrame([data])[feature_names]
    scaled = scaler.transform(df)

    probs = model.predict_proba(scaled)
    idx = int(np.argmax(probs))

    verdict = le.inverse_transform([idx])[0]
    confidence = float(np.max(probs))

    if verdict == "BENIGN":
        st.success(f"✔ Trafic normal ({confidence:.2%})")
    else:
        st.error(f"⚠️ Attaque détectée : {verdict} ({confidence:.2%})")

    st.markdown("### 🔍 Analyse")
    st.write({
        "packets_per_sec": round(flow_packets_s, 2),
        "avg_packet_size": round(avg_packet_size, 2)
    })