# 🛡️ IDS — Système de Détection d'Intrusions pour PME

Détection d'attaques réseau en temps réel avec **XGBoost** + **FastAPI** + **Streamlit**.

---

## 📁 Structure du projet

```
ids_app/
├── main.py              # API FastAPI (backend)
├── streamlit_app.py     # Dashboard Streamlit (frontend)
├── requirements.txt     # Dépendances Python
├── README.md
└── models/              # Dossier des modèles sauvegardés
    ├── ids_pipeline.pkl          # IQRCapper + RobustScaler
    ├── ids_xgb_binaire.pkl       # Modèle binaire (Normal/Attaque)
    ├── ids_xgb_multiclasse.pkl   # Modèle 15 classes
    ├── ids_label_encoder.pkl     # LabelEncoder
    ├── ids_features.pkl          # Liste des features
    └── ids_best_threshold.pkl    # Seuil optimal
```

---

## 🚀 Lancement

### 1. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 2. Copier les modèles
Copiez tous les fichiers `.pkl` issus du notebook dans le dossier `models/` :
```bash
mkdir models
cp ids_pipeline.pkl ids_xgb_binaire.pkl ids_xgb_multiclasse.pkl \
   ids_label_encoder.pkl ids_features.pkl ids_best_threshold.pkl models/
```

### 3. Lancer l'API FastAPI
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
→ API disponible sur http://localhost:8000  
→ Documentation Swagger : http://localhost:8000/docs

### 4. Lancer le Dashboard Streamlit
```bash
streamlit run streamlit_app.py
```
→ Dashboard disponible sur http://localhost:8501

---

## 🔌 Endpoints FastAPI

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Santé de l'API |
| POST | `/predict` | Analyse un flux JSON unique |
| POST | `/predict/batch` | Analyse un fichier CSV |
| GET | `/stats` | Statistiques globales |
| GET | `/history` | Historique complet |
| GET | `/history/recent` | 50 dernières alertes |
| DELETE | `/history` | Reset historique |

### Exemple /predict
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 80,
    "flow_duration": 38308,
    "total_fwd_packets": 1,
    "total_backward_packets": 1,
    "flow_bytes_per_s": 156.9,
    "flow_packets_per_s": 52.2,
    "average_packet_size": 6.0,
    "packet_length_mean": 6.0,
    "init_win_bytes_forward": 65535,
    "init_win_bytes_backward": 65535,
    "flow_iat_mean": 38308.0,
    "flow_iat_std": 0.0
  }'
```

---

## 🎯 Attaques détectables

| Attaque | Sévérité |
|---------|----------|
| DDoS | 🚨 CRITICAL |
| Heartbleed | 🚨 CRITICAL |
| Infiltration | 🚨 CRITICAL |
| Web Attack - SQL Injection | 🚨 CRITICAL |
| Bot | 🔴 HIGH |
| FTP-Patator | 🔴 HIGH |
| SSH-Patator | 🔴 HIGH |
| DoS GoldenEye / Hulk | 🔴 HIGH |
| Web Attack - XSS / Brute Force | 🔴 HIGH |
| DoS Slowhttptest / Slowloris | ⚠️ MEDIUM |
| PortScan | ⚠️ MEDIUM |

---

## 🧩 Architecture

```
Flux réseau brut
      |
      v
[FastAPI /predict]
      |
      v
[Pipeline sklearn]
  IQR Capping -> RobustScaler
      |
      v
[XGBoost Binaire]  -- seuil optimal -->  Sain / Attaque
      |
      | (si Attaque)
      v
[XGBoost Multi-classe]  -->  Type d'attaque (14 classes)
      |
      v
[Action + Blocage + Log]
      |
      v
[Streamlit Dashboard]
```
