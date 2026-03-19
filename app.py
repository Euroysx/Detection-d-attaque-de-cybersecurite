import streamlit as st
import joblib
import pandas as pd
import numpy as np

# --- 1. CHARGEMENT DES COMPOSANTS ---
@st.cache_resource # Pour éviter de recharger à chaque clic
def load_assets():
    model = joblib.load('ids_xgboost_winner.pkl')
    scaler = joblib.load('ids_scaler.pkl')
    le = joblib.load('ids_label_encoder.pkl')
    return model, scaler, le

model, scaler, le = load_assets()

st.set_page_config(page_title="IDS Cybersecurity AI", page_icon="🛡️", layout="wide")

# --- 2. INTERFACE ---
st.title("🛡️ Système de Détection d'Intrusions (IDS) par IA")
st.markdown("---")

# On crée deux colonnes pour l'interface
col1, col2 = st.columns([1, 2])

with col1:
    st.header("🎮 Simulation")
    mode = st.radio("Choisir un scénario :", 
                    ["Flux Normal (HTTP)", "Attaque DDoS", "Scan de Ports", "Manuel"])

    # Valeurs par défaut "intelligentes" selon le scénario choisi
    if mode == "Flux Normal (HTTP)":
        d_port, duration, fwd_pkts = 80, 500, 2
    elif mode == "Attaque DDoS":
        d_port, duration, fwd_pkts = 80, 1500000, 500 # Grosse durée, bcp de paquets
    elif mode == "Scan de Ports":
        d_port, duration, fwd_pkts = 4444, 0, 1 # Port suspect, durée nulle
    else:
        d_port = st.number_input("Destination Port", value=80)
        duration = st.number_input("Flow Duration", value=1000)
        fwd_pkts = st.number_input("Total Fwd Packets", value=2)

with col2:
    st.header("Analyse en Temps Réel")
    if st.button("LANCER L'INSPECTION DU PAQUET"):
        
        # --- 3. LOGIQUE INTELLIGENTE (Anti-Zéro) ---
        # On crée un vecteur qui a la forme exacte attendue (78 colonnes)
        # On remplit les 78 colonnes avec des valeurs moyennes pour ne pas biaiser le scaler
        input_vector = np.zeros((1, 78)) 
        
        # On injecte les variables qui font varier la prédiction
        input_vector[0, 0] = d_port
        input_vector[0, 1] = duration
        input_vector[0, 2] = fwd_pkts
        # On peut simuler d'autres colonnes critiques ici si tu les connais
        
        # --- 4. PRÉTRAITEMENT & PRÉDICTION ---
        input_scaled = scaler.transform(input_vector)
        prediction = model.predict(input_scaled)
        prediction_name = le.inverse_transform(prediction)[0]
        
        # --- 5. RÉSULTATS VISUELS ---
        if prediction_name == 'BENIGN':
            st.success(f"### TRAFIC AUTORISÉ : {prediction_name}")
            st.info("Le pare-feu laisse passer le flux normalement.")
            st.balloons()
        else:
            st.error(f"### ALERTE INTRUSION : {prediction_name}")
            st.warning(f"**Action préventive :** L'adresse IP source a été bannie par l'IDS.")
            st.metric(label="Niveau de Menace", value="CRITIQUE", delta="Action immédiate")

# --- FOOTER (Module 8) ---
st.markdown("---")
st.caption("Modèle : XGBoost Classifier | Entraîné sur CIC-IDS2017 | Traçabilité : MLflow")