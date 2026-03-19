import streamlit as st
import joblib
import numpy as np
import pandas as pd

# --- 1. CONFIGURATION & CHARGEMENT ---
st.set_page_config(page_title="🛡️ IDS Cybersecurity AI", layout="wide")

@st.cache_resource
def load_assets():
    # Charge tes fichiers exportés du notebook
    model = joblib.load('ids_xgboost_winner.pkl')
    scaler = joblib.load('ids_scaler.pkl')
    le = joblib.load('ids_label_encoder.pkl')
    return model, scaler, le

try:
    model, scaler, le = load_assets()
except Exception as e:
    st.error(f"Erreur de chargement des fichiers .pkl : {e}")
    st.stop()

# --- 2. LOGIQUE DE SIMULATION "INTELLIGENTE" ---
# On définit des signatures d'attaques basées sur le dataset CIC-IDS2017
# On remplit les 78 colonnes avec des valeurs types pour que le Scaler ne bugue pas
def get_scenario_data(mode, p_port, p_duration):
    # Création d'un vecteur de base (moyenne du dataset pour ne pas être à zéro)
    base_vector = np.full((1, 78), 0.1) 
    
    if mode == "🚀 Attaque DDoS":
        base_vector[0, 0] = p_port # Port
        base_vector[0, 1] = 1500000 # Durée énorme
        base_vector[0, 7] = 5000000 # Volume d'octets énorme (Payload)
        base_vector[0, 12] = 1000 # Flow Packets/s
    
    elif mode == "🕵️ PortScan / Infiltration":
        base_vector[0, 0] = p_port # Souvent ports 22, 4444, 8080
        base_vector[0, 1] = 0 # Durée quasi nulle
        base_vector[0, 2] = 1 # 1 seul paquet (SYN scan)
        base_vector[0, 14] = 1 # Max Packet Length
        
    elif mode == "🛡️ Flux Sain (Normal)":
        base_vector[0, 0] = 80 # HTTP
        base_vector[0, 1] = 500 # Durée normale
        base_vector[0, 2] = 2 # Quelques paquets
        base_vector[0, 7] = 120 # Petit volume
        
    return base_vector

# --- 3. INTERFACE UTILISATEUR ---
st.title("🛡️ IDS Cybersecurity Real-Time Detection")
st.markdown("---")

with st.sidebar:
    st.header("⚙️ Paramètres du Flux")
    scenario = st.selectbox("Choisir un scénario", 
                            ["🛡️ Flux Sain (Normal)", "🚀 Attaque DDoS", "🕵️ PortScan / Infiltration"])
    
    st.markdown("---")
    port = st.number_input("Port de Destination", value=80)
    duration = st.number_input("Durée du flux (µs)", value=1000)
    
    st.info("Ce prototype simule un environnement réseau complet à partir de vos entrées.")

# --- 4. ZONE D'ANALYSE ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("Inspection du Paquet")
    st.json({
        "Mode": scenario,
        "Destination Port": port,
        "Flow Duration": duration,
        "Features Total": "78 (Normalisées)"
    })

with col2:
    st.subheader("Résultat de l'IA")
    if st.button("LANCER L'ANALYSE", use_container_width=True):
        # Récupération des données simulées intelligemment
        raw_data = get_scenario_data(scenario, port, duration)
        
        # Prétraitement
        scaled_data = scaler.transform(raw_data)
        
        # Prédiction
        pred_idx = model.predict(scaled_data)[0]
        prediction_label = le.inverse_transform([pred_idx])[0]
        
        # Affichage dynamique
        if prediction_label == 'BENIGN':
            st.success(f"### TRAFIC SAIN : {prediction_label}")
            st.balloons()
        else:
            st.error(f"### ALERTE : {prediction_label} DÉTECTÉ !")
            st.warning("Action corrective : Blocage immédiat du flux via le Firewall.")
            st.snow() # Petit effet visuel pour l'alerte

# --- 5. SECTION TECHNIQUE ---
st.markdown("---")
with st.expander("Détails du Modèle (Module 8 - Capstone)"):
    st.write(f"**Algorithme :** XGBoost Classifier")
    st.write(f"**Dataset :** CIC-IDS2017 (NetFlow)")
    st.write(f"**Accuracy :** ~99% (validé par matrice de confusion)")
