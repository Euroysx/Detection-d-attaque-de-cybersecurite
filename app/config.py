# =========================
# MODEL PATHS
# =========================
MODEL_PATH = "models/ids_xgboost.pkl"
SCALER_PATH = "models/ids_scaler.pkl"
LE_PATH = "models/ids_label_encoder.pkl"
FEATURE_PATH = "models/feature_names.pkl"


# =========================
# ML THRESHOLDS
# =========================
THRESHOLD_LOW = 0.6
THRESHOLD_HIGH = 0.8


# =========================
# NETWORK THRESHOLDS
# =========================
CRITICAL_PACKET_RATE = 1_000_000      # DDoS massif
SUSPICIOUS_PACKET_RATE = 300_000      # scan / comportement anormal


# =========================
# SECURITY PORTS
# =========================
SENSITIVE_PORTS = [21, 22, 23]        # FTP, SSH, Telnet


# =========================
# SYSTEM SETTINGS
# =========================
MAX_RATIO = 1_000_000                 # protection overflow