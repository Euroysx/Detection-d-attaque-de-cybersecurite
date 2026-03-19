# 🔐 IDS Sentinel — Détection d’attaques réseau (Cybersecurity)

## 📌 Description

Ce projet implémente un **système de détection d’intrusion (IDS)** basé sur :

* 🧠 Machine Learning (XGBoost)
* 📊 Analyse comportementale réseau
* ⚙️ Moteur de décision (ALLOW / ALERT / BLOCK)

L’objectif est de détecter automatiquement des attaques réseau telles que :

* DDoS (DoS Hulk, etc.)
* Port Scanning
* Brute Force (SSH / FTP)
* Trafic suspect

---

## 🚀 Fonctionnalités

* ✅ Classification des flux réseau (BENIGN / ATTACK)
* ✅ Détection intelligente DDoS (pas juste threshold)
* ✅ Scoring cyber (0–100)
* ✅ Niveau de risque (LOW → CRITICAL)
* ✅ API REST avec FastAPI
* ✅ Système prêt pour PME (production-ready)

---

## 🧠 Architecture

```
app/
├── main.py            # API FastAPI
├── model.py           # Chargement & prédiction ML
├── features.py        # Feature engineering
├── security.py        # Logique IDS (rules engine)
├── config.py          # Paramètres système
└── schemas.py         # Schéma des inputs

models/
├── ids_xgboost.pkl
├── ids_scaler.pkl
├── ids_label_encoder.pkl
└── feature_names.pkl
```

---

## ⚙️ Installation

```bash
git clone https://github.com/TON-REPO.git
cd Detection-d-attaque-de-cybersecurite

pip install -r requirements.txt
```

---

## ▶️ Lancer l’API

```bash
python3 -m uvicorn app.main:app --reload
```

👉 Accès Swagger :

```
http://127.0.0.1:8000/docs
```

---

## 📡 Exemple de requête

### 🔥 Simulation DDoS

```json
{
  "destination_port": 80,
  "flow_duration": 1000,
  "total_fwd_packets": 500000,
  "total_bwd_packets": 0,
  "flow_bytes_s": 100000000
}
```

---

## 📊 Exemple de réponse

```json
{
  "verdict": "DoS Hulk",
  "confidence": "85.37%",
  "risk_level": "CRITICAL",
  "attack_score": 100,
  "action": "BLOCK"
}
```

---

## 🧠 Logique de détection

Le système combine :

### 1. Machine Learning

* Modèle XGBoost entraîné sur CIC-IDS
* Classification multi-classe

### 2. Analyse comportementale

* Packets/sec
* Ratio forward/backward
* Anomalies réseau

### 3. Moteur de décision

* Override en cas critique (DDoS)
* Gestion des faux positifs

---

## 🎯 Cas détectés

| Type        | Détection   |
| ----------- | ----------- |
| DDoS        | 🔴 CRITICAL |
| Scan        | 🟠 MEDIUM   |
| Brute Force | 🟠 MEDIUM   |
| Normal      | 🟢 LOW      |

---

## 🧪 Tests

Utiliser Swagger ou curl :

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
-H "Content-Type: application/json" \
-d '{ "destination_port": 80, "flow_duration": 1000, "total_fwd_packets": 500000, "total_bwd_packets": 0, "flow_bytes_s": 100000000 }'
```

---

## 🏢 Contexte PME

Ce système est conçu pour :

* Surveillance réseau automatisée
* Réduction des faux positifs
* Détection rapide d’attaques critiques
* Intégration facile (API REST)

---

## 📈 Améliorations futures

* Dashboard temps réel (Streamlit)
* Logs sécurité (audit trail)
* Détection avancée (Zero-day)
* Intégration SIEM

---

## 👨‍💻 Auteur

Projet réalisé dans le cadre d’un capstone en cybersécurité.

---

## 📜 Licence

GPL-3.0 License

