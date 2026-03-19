import streamlit as st
import requests

st.set_page_config(page_title="IDS Sentinel", layout="centered")

st.title("🛡️ IDS Sentinel - Détection d'attaques réseau")
st.markdown("Simule un flux réseau et détecte s'il est malveillant.")

# INPUTS
destination_port = st.number_input("Destination Port", 0, 65535, 80)
flow_duration = st.number_input("Flow Duration (µs)", min_value=1, value=1000000)
total_fwd_packets = st.number_input("Total Fwd Packets", min_value=0, value=10)
total_bwd_packets = st.number_input("Total Backward Packets", min_value=0, value=5)
flow_bytes_s = st.number_input("Flow Bytes/s", min_value=0.0, value=10000.0)

# CALL API
if st.button("Analyser"):

    payload = {
        "destination_port": destination_port,
        "flow_duration": flow_duration,
        "total_fwd_packets": total_fwd_packets,
        "total_bwd_packets": total_bwd_packets,
        "flow_bytes_s": flow_bytes_s
    }

    try:
        with st.spinner("Analyse en cours..."):
            response = requests.post("http://127.0.0.1:8000/predict", json=payload)

        if response.status_code != 200:
            st.error(f"Erreur serveur : {response.status_code}")
            st.stop()

        result = response.json()

        verdict = result["verdict"]
        confidence = result["confidence"]
        action = result["action"]

        # RESULT
        if verdict == "BENIGN":
            st.success(f"✔ Trafic normal ({confidence})")
        else:
            st.error(f"⚠️ Attaque détectée : {verdict} ({confidence})")

        st.markdown("### 🔍 Détails")
        st.write(result["analysis"])  # ✅ FIX ICI

    except Exception as e:
        st.error(f"Erreur API : {e}")