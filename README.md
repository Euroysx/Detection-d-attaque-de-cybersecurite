# EUROFLARE IDS v3

Systeme de Detection d'Intrusions hybride developpe dans le cadre d'un projet Capstone 2026 en cybersecurite. EUROFLARE combine un modele XGBoost entraine sur le dataset CIC-IDS2017 et un Isolation Forest pour detecter les attaques reseau connues ainsi que les menaces inconnues en temps reel.

lien steamlit: https://detection-d-attaque-de-cybersecurite-mxlodhzrxnydappuoz3rg8.streamlit.app/
---

## Architecture generale

Le systeme est compose de trois composantes principales :

- **Backend API** (`main.py`) — FastAPI exposant les endpoints de prediction, d'historique et de gestion des IPs. C'est le coeur du systeme : il charge les modeles ML, classe les flux reseau entrants et persiste tous les resultats dans une base SQLite.

- **Dashboard** (`euroflare.py`) — Interface Streamlit avec authentification par roles, visualisations en temps reel, threat map mondiale, simulateur d'attaques, analyste IA, et gestion des alertes.

- **Simulateur de trafic** (`attaque.py`) — Script Python generant du trafic d'attaque reel via proxies publics vers une cible HTTP de test, pour valider la detection en conditions proches du reel.

---

## Modele de detection

### Pipeline ML

```
Flux reseau
    --> IQR Capping (suppression des valeurs aberrantes)
    --> RobustScaler (normalisation)
    --> XGBoost Binaire (attaque / benin)
    --> XGBoost Multi-classe (identification du type)
```

### Fichiers de modeles (dossier `./models/`)

| Fichier | Contenu |
|---|---|
| `ids_xgb_binaire.pkl` | Classificateur binaire attaque/benin |
| `ids_xgb_multiclasse.pkl` | Classificateur 15 types d'attaques |
| `ids_label_encoder.pkl` | Encodeur des labels de classe |
| `ids_scaler.pkl` | RobustScaler ajuste sur CIC-IDS2017 |
| `ids_iqr_bounds.pkl` | Bornes IQR pour le capping |
| `ids_best_threshold.pkl` | Seuil optimal F1 (0.55) |

### Dataset

Entraine sur **CIC-IDS2017** — 2.8 millions de flux, SMOTE pour le reequilibrage des classes, validation croisee 5-fold.

- Precision binaire : 99.83%
- ROC-AUC : 1.0
- Seuil optimal F1 : 0.55

### Types d'attaques detectes (15 classes)

| Type | Severite |
|---|---|
| DDoS | CRITICAL |
| Heartbleed | CRITICAL |
| Infiltration | CRITICAL |
| Web Attack - Sql Injection | CRITICAL |
| Bot | HIGH |
| DoS GoldenEye | HIGH |
| DoS Hulk | HIGH |
| FTP-Patator | HIGH |
| SSH-Patator | HIGH |
| Web Attack - Brute Force | HIGH |
| Web Attack - XSS | HIGH |
| DoS Slowhttptest | MEDIUM |
| DoS slowloris | MEDIUM |
| PortScan | MEDIUM |
| BENIGN | INFO |

### Features utilisees (12 features CICFlowMeter)

```
Destination Port, Flow Duration, Total Fwd Packets,
Total Backward Packets, Flow Bytes/s, Flow Packets/s,
Average Packet Size, Packet Length Mean,
Init_Win_bytes_forward, Init_Win_bytes_backward,
Flow IAT Mean, Flow IAT Std
```

---

## Installation

### Prerequis

```
Python 3.10+
pip install fastapi uvicorn streamlit requests pandas numpy
pip install scikit-learn xgboost joblib plotly slowapi
pip install scapy reportlab
```

### Lancement

**1. Demarrer l'API backend**

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**2. Demarrer le dashboard**

```bash
streamlit run euroflare.py --server.port 8501
```

**3. Lancer le simulateur d'attaques (optionnel)**

```bash
python attaque.py
python attaque.py --turbo
python attaque.py --demo ddos
python attaque.py --demo sql
python attaque.py --demo bot
python attaque.py --demo brute
python attaque.py --demo scan
python attaque.py --demo slowloris
python attaque.py --rounds 3
python attaque.py --no-proxy-test
python attaque.py --target 192.168.1.1
```

---

## API — Endpoints

Base URL : `http://localhost:8000`

Documentation interactive : `http://localhost:8000/docs`

| Methode | Endpoint | Description |
|---|---|---|
| GET | `/health` | Statut de l'API, mode (production/demo), seuil actif |
| POST | `/predict` | Analyse un flux reseau unique (JSON) |
| POST | `/predict/batch` | Analyse un fichier CSV de logs |
| GET | `/stats` | Statistiques globales depuis SQLite |
| GET | `/history` | Historique pagine (limit, offset, attacks_only) |
| GET | `/history/recent` | 50 dernieres attaques detectees |
| DELETE | `/history` | Reinitialiser l'historique et les statistiques |
| GET | `/attacker-ips` | Liste des IPs attaquantes avec profil complet |
| POST | `/attacker-ips/{ip}/blacklist` | Ajouter une IP a la blacklist |
| DELETE | `/attacker-ips/{ip}/blacklist` | Retirer une IP de la blacklist |
| DELETE | `/attacker-ips/blacklist/all` | Vider toute la blacklist |

### Exemple de requete `/predict`

```json
{
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
  "flow_iat_std": 430865.8,
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "protocol": "TCP"
}
```

### Exemple de reponse

```json
{
  "is_attack": true,
  "attack_type": "DDoS",
  "severity": "CRITICAL",
  "confidence": 0.9731,
  "threshold_used": 0.55,
  "action": "Activer la limitation de debit. Contacter le FAI. Mitigation DDoS.",
  "blocked": true,
  "timestamp": "2026-04-17T11:46:18.123456",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "protocol": "TCP"
}
```

---

## Dashboard — Pages et roles

Acces : `http://localhost:8501`

### Comptes par defaut

| Identifiant | Mot de passe | Role |
|---|---|---|
| admin | ids2024 | Admin |
| analyst | analyst123 | Analyste |
| viewer | viewer456 | Observateur |

### Pages par role

| Page | Admin | Analyste | Observateur |
|---|---|---|---|
| Tableau de bord | oui | oui | oui |
| Threat Map Live | oui | oui | oui |
| Analyse Flux | oui | oui | non |
| Upload CSV / PCAP | oui | oui | non |
| Historique | oui | oui | oui |
| Statistiques Avancees | oui | oui | non |
| Modele XGBoost | oui | oui | non |
| Encyclopedie des Attaques | oui | oui | oui |
| Simulateur d'Attaques | oui | oui | non |
| Correlation & Incidents | oui | oui | non |
| Rapport PDF | oui | non | non |
| Blacklist IPs | oui | oui | non |
| Analyste IA | oui | oui | non |
| Forensique | oui | oui | non |
| Notifications Push | oui | non | non |
| Volume Reseau | oui | oui | non |
| Intelligence Menaces | oui | oui | non |
| A propos | oui | oui | oui |

---

## Fonctionnalites principales

**Detection en temps reel**
Chaque flux soumis via l'interface ou l'API est analyse par le pipeline ML en moins de 10ms. Le resultat inclut le type d'attaque, la severite, le niveau de confiance et l'action recommandee.

**Seuils adaptatifs**
Chaque type d'attaque dispose de son propre seuil de decision configurable depuis la page Modele XGBoost. Un seuil plus bas augmente la sensibilite (moins de faux negatifs), un seuil plus eleve reduit les fausses alarmes. Les modifications sont appliquees immediatement sans redemarrage.

**Threat Map Live**
Carte mondiale affichant les attaques en temps reel avec arcs animes. Les IPs publiques sont geolocalisees via ip-api.com. Les attaques provenant d'IPs privees (reseau local) sont representees par un arc orbital autour de la cible avec un marqueur d'alerte visuel.

**Upload CSV / PCAP**
Les fichiers CSV au format CICFlowMeter (jusqu'a 350 000 lignes) sont traites par chunks de 10 000 lignes avec une barre de progression. Les captures Wireshark PCAP sont parsees via Scapy avec extraction des features selon la specification CICFlowMeter officielle.

**Correlations et incidents**
Les alertes sont groupees par IP source sur des fenetres de 5 minutes. Une IP declenchant 3 types d'attaques differents ou plus est signalee comme intrusion multi-vecteurs avec un score de risque composite (0-100).

**Notifications**
Alertes automatiques sur Slack, Discord et Telegram pour les evenements CRITICAL et HIGH. Configuration via webhooks dans la sidebar, avec bouton de test.

**Analyste IA**
Interface de chat avec Ollama (llama3:8b en local) pour l'analyse des incidents, la recommandation d'actions et l'interpretation des alertes en langage naturel.

**Rapport PDF**
Generation d'un rapport complet (resume executif, repartition par type et severite, dernieres alertes, seuils adaptatifs, recommandations) exportable et planifiable par email via SMTP.

**Simulateur d'attaques**
Depuis le dashboard, generation de flux synthetiques bruites pour tester la detection par type d'attaque avec le seuil actif, affichage du taux de detection et suggestion d'ajustement si des flux passent inapercus.

---

## Base de donnees

SQLite avec mode WAL pour les ecritures concurrentes. Deux tables principales :

- `alerts` — historique complet de chaque flux analyse (timestamp, type, severite, confiance, IP source/destination, action)
- `attacker_ips` — profil agrege par IP attaquante (nombre d'attaques, types vus, severite maximale, statut blacklist)
- `stats` — compteurs globaux (total analyse, total attaques, total bloques)

Variables d'environnement :

```bash
MODEL_DIR=./models      # dossier des modeles .pkl
DB_PATH=./ids_history.db
LOG_PATH=./ids.log
API_KEY=                # optionnel, active l'authentification X-API-Key
```

---

## Stack technique

| Composante | Technologie |
|---|---|
| Backend API | FastAPI 2.0, Uvicorn |
| ML | XGBoost, Scikit-learn, SMOTE |
| Dashboard | Streamlit |
| Visualisation | Plotly |
| Capture reseau | Scapy |
| Base de donnees | SQLite (WAL mode) |
| Rate limiting | SlowAPI |
| Notifications | Slack / Discord / Telegram webhooks |
| IA locale | Ollama (llama3:8b) |
| Rapport | ReportLab |
| Dataset | CIC-IDS2017 (University of New Brunswick) |

---

## Structure des fichiers

```
.
├── main.py                  Backend FastAPI
├── euroflare.py             Dashboard Streamlit
├── attaque.py               Simulateur de trafic reel
├── models/
│   ├── ids_xgb_binaire.pkl
│   ├── ids_xgb_multiclasse.pkl
│   ├── ids_label_encoder.pkl
│   ├── ids_scaler.pkl
│   ├── ids_iqr_bounds.pkl
│   └── ids_best_threshold.pkl
├── ids_history.db           Base SQLite (generee automatiquement)
├── ids.log                  Fichier de logs (genere automatiquement)
└── blocked_ips.db           IPs bloquees persistees (generee automatiquement)
```

---

## Notes

- Si les fichiers `.pkl` sont absents du dossier `models/`, l'API demarre en **mode demo** : les predictions sont aleatoires mais tous les endpoints restent fonctionnels.
- Le simulateur de trafic (`attaque.py`) requiert un acces internet pour telecharger la liste de proxies publics depuis GitHub. L'option `--no-proxy-test` permet de sauter cette etape.
- La capture reseau en temps reel via Scapy necessite les droits root.
- Ollama doit etre lance separement (`ollama serve`) pour activer la page Analyste IA.
