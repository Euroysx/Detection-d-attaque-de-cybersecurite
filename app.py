import streamlit as st
import joblib
import pandas as pd
import numpy as np

# 1. Chargement des composants
model = joblib.load('ids_xgboost_winner.pkl')
scaler = joblib.load('ids_scaler.pkl')
le = joblib.load('ids_label_encoder.pkl')

st.set_page_config(page_title="IDS Real-Time Detection", page_icon="🛡️")

st.title("Système de Détection d'Intrusions (IDS)")
st.write("Projet Capstone - Simulation d'analyse de trafic réseau")

# 2. Formulaire de saisie (Simulation d'un paquet réseau)
st.sidebar.header("Données du flux réseau")

# On simule les colonnes les plus importantes de ton dataset
# Note: Pour que ça marche, il faut envoyer le même nombre de colonnes que ton X_train
dest_port = st.sidebar.number_input("Destination Port", value=80)
flow_duration = st.sidebar.number_input("Flow Duration", value=1000)
total_fwd_pkts = st.sidebar.number_input("Total Fwd Packets", value=2)
total_bwd_pkts = st.sidebar.number_input("Total Backward Packets", value=1)

if st.button("ANALYSER LE TRAFIC"):
    # CRUCIAL: Ton modèle attend 78 colonnes (ou le nombre exact de ton notebook)
    # On crée un vecteur vide et on remplit les premières valeurs pour le test
    # Récupère le nombre exact de colonnes via ton notebook (X_train.shape[1])
    num_features = 78 
    input_vector = np.zeros((1, num_features))
    
    # Remplissage des valeurs saisies
    input_vector[0, 0] = dest_port
    input_vector[0, 1] = flow_duration
    input_vector[0, 2] = total_fwd_pkts
    input_vector[0, 3] = total_bwd_pkts
    
    # 3. Prétraitement (Même étape que le Module 6)
    input_scaled = scaler.transform(input_vector)
    
    # 4. Prédiction
    prediction = model.predict(input_scaled)
    prediction_name = le.inverse_transform(prediction)[0]
    
    # 5. Affichage du résultat (Simulation d'attaque)
    if prediction_name == 'BENIGN':
        st.success(f"TRAFIC SAIN : {prediction_name}")
        st.balloons()
    else:
        st.error(f"ALERTE INTRUSION : {prediction_name} détecté !")
        st.warning("Action : Le flux a été bloqué par le pare-feu.")