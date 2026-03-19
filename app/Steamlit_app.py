# =========================
# LIBRARIES
# =========================
import streamlit as st
import requests

# =========================
# CONFIG
# =========================
API_URL = "http://127.0.0.1:8000/predict"

st.set_page_config(page_title="IDS PME Dashboard", layout="centered")

st.title("🛡️ IDS Cybersecurity Dashboard")
st.markdown("Simulation et détection des attaques réseau")

# =========================
# INPUT FORM
# =========================
st.subheader("Entrée manuelle")

destination_port = st.number_input("Destination Port", 0, 65535, 80)
flow_duration = st.number_input("Flow Duration (µs)", 1, 1_000_000, 10000)
total_fwd_packets = st.number_input("Forward Packets", 0, 1_000_000, 1000)
total_bwd_packets = st.number_input("Backward Packets", 0, 1_000_000, 100)
flow_bytes_s = st.number_input("Flow Bytes/s", 0, 1_000_000_000, 1000000)

# =========================
# FUNCTION CALL API
# =========================
def call_api(data):
    try:
        response = requests.post(API_URL, json=data)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# =========================
# EXECUTE BUTTON
# =========================
if st.button(" Analyser le trafic"):
    
    payload = {
        "destination_port": destination_port,
        "flow_duration": flow_duration,
        "total_fwd_packets": total_fwd_packets,
        "total_bwd_packets": total_bwd_packets,
        "flow_bytes_s": flow_bytes_s
    }

    result = call_api(payload)

    if "error" in result:
        st.error(result["error"])
    else:
        st.success("Analyse terminée")

        st.write("### Résultat")
        st.json(result)

# =========================
# SIMULATIONS (IMPORTANT JURY)
# =========================
st.subheader("Simulations rapides")

col1, col2, col3 = st.columns(3)

# DDoS
if col1.button("DDoS"):
    payload = {
        "destination_port": 80,
        "flow_duration": 1000,
        "total_fwd_packets": 500000,
        "total_bwd_packets": 0,
        "flow_bytes_s": 100000000
    }
    st.json(call_api(payload))

# Scan
if col2.button("Port Scan"):
    payload = {
        "destination_port": 22,
        "flow_duration": 50000,
        "total_fwd_packets": 10000,
        "total_bwd_packets": 10,
        "flow_bytes_s": 1000000
    }
    st.json(call_api(payload))

# SSH Bruteforce
if col3.button("SSH Attack"):
    payload = {
        "destination_port": 22,
        "flow_duration": 10000,
        "total_fwd_packets": 20000,
        "total_bwd_packets": 100,
        "flow_bytes_s": 2000000
    }
    st.json(call_api(payload))

# =========================
# NORMAL TRAFFIC
# =========================
if st.button("Trafic normal"):
    payload = {
        "destination_port": 443,
        "flow_duration": 200000,
        "total_fwd_packets": 5000,
        "total_bwd_packets": 4800,
        "flow_bytes_s": 2000000
    }
    st.json(call_api(payload))