# =========================
# CONFIG - PATHS
# =========================
import os

# dossier racine du projet
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# dossier models
MODEL_DIR = os.path.join(BASE_DIR, "models")

# fichiers modèles
MODEL_PATH = os.path.join(MODEL_DIR, "ids_xgboost.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "ids_scaler.pkl")
LE_PATH = os.path.join(MODEL_DIR, "ids_label_encoder.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")


# =========================
# CONFIG - IDS LOGIC
# =========================

THRESHOLD_LOW = 0.6
THRESHOLD_HIGH = 0.8

CRITICAL_PACKET_RATE = 1_000_000