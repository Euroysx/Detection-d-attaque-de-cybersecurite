# Détection d'Attaques de Cybersécurité — IDS avec Machine Learning

Projet Capstone — Système de Détection d'Intrusions (IDS) basé sur l'apprentissage supervisé.
Une PME souhaitant détecter des intrusions réseau à partir de logs systèmes.

---

## Présentation

Ce projet implémente un système de détection d'intrusions réseau complet, de l'entraînement
du modèle jusqu'au déploiement en production via une API REST et un tableau de bord interactif.

Le modèle est entraîné sur le dataset **CIC-IDS2017** du Canadian Institute for Cybersecurity,
largement utilisé dans la recherche académique en cybersécurité.

Deux approches de classification sont étudiées :

- **Classification binaire** : distinguer le trafic normal (BENIGN) du trafic malveillant
- **Classification multi-classe** : identifier le type précis d'attaque parmi 14 classes

---

## Types d'attaques détectées

| Attaque | Sévérité | Description |
|---------|----------|-------------|
| DDoS | CRITICAL | Déni de service distribué |
| Heartbleed | CRITICAL | Exploitation de vulnérabilité OpenSSL |
| Infiltration | CRITICAL | Intrusion réseau |
| Web Attack - SQL Injection | CRITICAL | Injection SQL |
| Bot | HIGH | Trafic botnet |
| DoS GoldenEye | HIGH | Déni de service GoldenEye |
| DoS Hulk | HIGH | Déni de service Hulk |
| FTP-Patator | HIGH | Brute force FTP |
| SSH-Patator | HIGH | Brute force SSH |
| Web Attack - Brute Force | HIGH | Brute force web |
| Web Attack - XSS | HIGH | Cross-Site Scripting |
| DoS Slowhttptest | MEDIUM | Déni de service lent |
| DoS slowloris | MEDIUM | Déni de service Slowloris |
| PortScan | MEDIUM | Scan de ports |

---

## Architecture du projet

```
Detection-d-attaque-de-cybersecurite/
|
|-- IDS_PME_Cyber_Detection_FINAL.ipynb   Notebook d'entraînement complet
|
|-- app version 2/
    |-- main.py                           API FastAPI (backend)
    |-- streamlit_app.py                  Dashboard Streamlit (frontend)
    |-- traffic_simulator.py              Simulateur de trafic réseau
    |-- real_traffic_demo.py              Générateur de vrais paquets réseau
    |-- iqr_capper.py                     Transformer IQR custom (sklearn)
    |-- requirements.txt                  Dépendances Python
    |-- models/
        |-- ids_iqr_bounds.pkl            Bornes IQR Capping
        |-- ids_scaler.pkl                RobustScaler
        |-- ids_xgb_binaire.pkl           Modèle binaire XGBoost
        |-- ids_xgb_multiclasse.pkl       Modèle multi-classe XGBoost
        |-- ids_label_encoder.pkl         LabelEncoder
        |-- ids_features.pkl              Liste des 12 features
        |-- ids_best_threshold.pkl        Seuil optimal de détection
```

---

## Pipeline de traitement

```
Données brutes (CIC-IDS2017)
        |
        v
Nettoyage
Suppression doublons, NaN, valeurs infinies
Optimisation mémoire (float64 -> float32)
Anti data leakage (suppression IP, timestamps)
        |
        v
Encodage
LabelEncoder  : classes texte -> entiers (multi-classe)
Encodage binaire : 0 = BENIGN, 1 = Attaque
        |
        v
Split 80% Train / 20% Test
Stratifié sur le multi-classe
AVANT tout prétraitement numérique
        |
        v
Pipeline sklearn
IQRCapper (Tukey fences, factor=1.5) -> RobustScaler
fit() sur train uniquement — transform() sur train + test
        |
        v
SMOTE
Rééquilibrage des classes minoritaires (train uniquement)
Cible : 30% du volume de la classe dominante
        |
        v
XGBoost
Modèle binaire  : n_estimators=200, max_depth=6
Modèle multi    : n_estimators=150, max_depth=6
        |
        v
Évaluation
Cross-validation 5-fold (StratifiedKFold)
Threshold tuning (seuil optimal F1-Score)
Courbes Precision-Recall + ROC
Analyse détaillée des erreurs
```

---

## Résultats

| Approche | Accuracy | ROC-AUC |
|----------|----------|---------|
| Binaire — seuil 0.5 | ~99% | ~1.000 |
| Binaire — seuil optimal | ~98% | ~1.000 |
| Multi-classe (14 types) | ~98% | — |

Cross-validation 5-fold (binaire) : ~99% (+/- 0.001)

---

## Installation

### Prérequis

- Python 3.10+
- pip

### Installation des dépendances

```bash
cd "app version 2"
pip install -r requirements.txt
```

### Contenu de requirements.txt

```
fastapi
uvicorn[standard]
pydantic
python-multipart
slowapi
streamlit
plotly
xgboost
scikit-learn
imbalanced-learn
pandas
numpy
joblib
requests
```

---

## Lancement

### 1. Entraîner le modèle

Ouvrir et exécuter le notebook complet :

```
IDS_PME_Cyber_Detection_FINAL.ipynb
```

Les modèles sont automatiquement sauvegardés dans `app version 2/models/`.

### 2. Lancer l'API FastAPI

```bash
cd "app version 2"
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API disponible sur : http://localhost:8000
Documentation Swagger : http://localhost:8000/docs

### 3. Lancer le Dashboard Streamlit

```bash
streamlit run streamlit_app.py
```

Dashboard disponible sur : http://localhost:8501

### 4. Simuler du trafic réseau

```bash
# Simulation statistique en temps réel
python traffic_simulator.py --chaos --rate 2

# Demo avec vrais paquets réseau (localhost uniquement)
python real_traffic_demo.py --demo full
python real_traffic_demo.py --demo ddos
python real_traffic_demo.py --demo scan
```

---

## Endpoints API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | /health | Santé de l'API |
| POST | /predict | Analyse un flux JSON unique |
| POST | /predict/batch | Analyse un fichier CSV |
| GET | /stats | Statistiques globales (SQLite) |
| GET | /history | Historique complet |
| GET | /history/recent | 50 dernières alertes |
| DELETE | /history | Réinitialiser l'historique |

### Exemple de requête /predict

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "destination_port": 80,
    "flow_duration": 1293792,
    "total_fwd_packets": 3,
    "total_backward_packets": 7,
    "flow_bytes_per_s": 8991.4,
    "flow_packets_per_s": 7.73,
    "average_packet_size": 1163.3,
    "packet_length_mean": 1057.5,
    "init_win_bytes_forward": 8192,
    "init_win_bytes_backward": 229,
    "flow_iat_mean": 143754.7,
    "flow_iat_std": 430865.8
  }'
```

### Exemple de réponse

```json
{
  "is_attack": true,
  "attack_type": "DDoS",
  "severity": "CRITICAL",
  "confidence": 0.9997,
  "threshold_used": 0.55,
  "action": "Activer la limitation de debit. Contacter le FAI. Mitigation DDoS.",
  "blocked": true,
  "timestamp": "2024-03-20T10:23:45.123456",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "protocol": "TCP"
}
```

---

## Features utilisées

Les 12 features comportementales sélectionnées — aucune adresse IP, aucun identifiant :

| Feature | Description |
|---------|-------------|
| Destination Port | Port de destination du flux |
| Flow Duration | Durée totale du flux (microsecondes) |
| Total Fwd Packets | Nombre de paquets envoyés |
| Total Backward Packets | Nombre de paquets reçus |
| Flow Bytes/s | Débit en octets par seconde |
| Flow Packets/s | Débit en paquets par seconde |
| Average Packet Size | Taille moyenne des paquets |
| Packet Length Mean | Longueur moyenne des paquets |
| Init_Win_bytes_forward | Fenêtre TCP initiale (sens aller) |
| Init_Win_bytes_backward | Fenêtre TCP initiale (sens retour) |
| Flow IAT Mean | Inter-arrival time moyen |
| Flow IAT Std | Inter-arrival time écart-type |

---

## Fonctionnalités du Dashboard

- Tableau de bord temps réel avec KPIs (flux analysés, attaques détectées, flux bloqués)
- Graphiques interactifs : répartition des types d'attaques, distribution par sévérité
- Feed des dernières alertes avec code couleur par sévérité
- Analyse flux unique avec 9 scénarios prédéfinis validés
- Upload CSV pour analyse en batch
- Historique persistant avec export CSV
- Rafraîchissement automatique configurable

---

## Limites connues

- Le dataset CIC-IDS2017 date de 2017 — les attaques récentes ne sont pas couvertes
- Heartbleed (11 exemples) et SQL Injection (21 exemples) : SMOTE peu fiable sur si peu de données
- Bot : comportement réseau proche du trafic BENIGN, taux de confusion plus élevé
- En production, un outil comme CICFlowMeter serait nécessaire pour extraire les features depuis le vrai trafic réseau en temps réel

---

## Dataset

**CIC-IDS2017** — Canadian Institute for Cybersecurity  
https://www.unb.ca/cic/datasets/ids-2017.html

2 830 743 flux réseau capturés sur 5 jours  
15 classes (1 normale + 14 types d'attaques)  
308 381 doublons supprimés  
79 features originales — 12 sélectionnées

---

## Technologies utilisées

| Composant | Technologie |
|-----------|-------------|
| Modèle ML | XGBoost |
| Pipeline prétraitement | scikit-learn |
| Rééquilibrage | imbalanced-learn (SMOTE) |
| API REST | FastAPI |
| Base de données | SQLite |
| Dashboard | Streamlit + Plotly |
| Protection | Rate limiting (slowapi) |
| Logging | Python logging |

---

## Auteurs

* Konan Yannis Yobonou
* Mohand Ourabah Kherbouche

Projet Capstone — Detection d'attaques de cybersecurite IDS 
Dataset : CIC-IDS2017 (Canadian Institute for Cybersecurity)
