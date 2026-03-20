# ================================================================
# IDS — STREAMLIT DASHBOARD
# Interface de supervision pour PME
# ================================================================
#
# LANCEMENT :
#   streamlit run streamlit_app.py
#
# PRÉREQUIS :
#   L'API FastAPI doit tourner sur http://localhost:8000
#   uvicorn main:app --reload
# ================================================================

import streamlit as st
import requests
import pandas as pd
import numpy as np
import json
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ================================================================
# CONFIGURATION
# ================================================================

API_URL = "http://localhost:8000"

SEVERITY_COLORS = {
    "INFO":     "#2ECC71",
    "MEDIUM":   "#F39C12",
    "HIGH":     "#E67E22",
    "CRITICAL": "#E74C3C",
}

SEVERITY_ICONS = {
    "INFO":     "✅",
    "MEDIUM":   "⚠️",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}

st.set_page_config(
    page_title="IDS — Détection d'Intrusions",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ================================================================
# CSS PERSONNALISÉ
# ================================================================

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 20px 30px;
        border-radius: 12px;
        margin-bottom: 20px;
        color: white;
    }
    .metric-card {
        background: #1e1e2e;
        border: 1px solid #333;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .alert-critical {
        background: rgba(231, 76, 60, 0.15);
        border-left: 4px solid #E74C3C;
        padding: 10px 15px;
        border-radius: 4px;
        margin: 5px 0;
    }
    .alert-high {
        background: rgba(230, 126, 34, 0.15);
        border-left: 4px solid #E67E22;
        padding: 10px 15px;
        border-radius: 4px;
        margin: 5px 0;
    }
    .alert-medium {
        background: rgba(243, 156, 18, 0.15);
        border-left: 4px solid #F39C12;
        padding: 10px 15px;
        border-radius: 4px;
        margin: 5px 0;
    }
    .alert-info {
        background: rgba(46, 204, 113, 0.1);
        border-left: 4px solid #2ECC71;
        padding: 10px 15px;
        border-radius: 4px;
        margin: 5px 0;
    }
    .blocked-badge {
        background: #E74C3C;
        color: white;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
    }
    .safe-badge {
        background: #2ECC71;
        color: white;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ================================================================
# FONCTIONS UTILITAIRES
# ================================================================

# Clé API — doit correspondre à IDS_API_KEY dans main.py
def call_api(endpoint: str, method: str = "GET", data: dict = None, files=None):
    """Appelle l'API FastAPI et gère les erreurs."""
    try:
        url = f"{API_URL}{endpoint}"
        if method == "GET":
            r = requests.get(url, timeout=10)
        elif method == "POST" and files:
            r = requests.post(url, files=files, timeout=30)
        elif method == "POST":
            r = requests.post(url, json=data, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, timeout=10)
        else:
            return None

        if r.status_code == 200:
            return r.json()
        else:
            st.error(f"Erreur API {r.status_code} : {r.text}")
            return None
    except requests.exceptions.ConnectionError:
        st.error("❌ Impossible de se connecter à l'API. Assurez-vous que FastAPI tourne sur localhost:8000")
        return None
    except Exception as e:
        st.error(f"Erreur : {str(e)}")
        return None


def severity_badge(severity: str) -> str:
    icon  = SEVERITY_ICONS.get(severity, "❓")
    color = SEVERITY_COLORS.get(severity, "#888")
    return f'<span style="color:{color}; font-weight:bold;">{icon} {severity}</span>'


def get_alert_class(severity: str) -> str:
    return {
        "CRITICAL": "alert-critical",
        "HIGH":     "alert-high",
        "MEDIUM":   "alert-medium",
        "INFO":     "alert-info",
    }.get(severity, "alert-info")


# ================================================================
# SIDEBAR
# ================================================================

with st.sidebar:
    st.markdown("## 🛡️ IDS Dashboard")
    st.markdown("---")

    # Status API
    health = call_api("/health")
    if health:
        status_color = "🟢" if health["status"] == "online" else "🔴"
        mode_label   = "🏭 Production" if health["models_loaded"] else "🎭 Démo"
        st.markdown(f"{status_color} **API** : En ligne")
        st.markdown(f"**Mode** : {mode_label}")
        st.markdown(f"**Seuil** : `{health['threshold']:.2f}`")
    else:
        st.markdown("🔴 **API** : Hors ligne")

    st.markdown("---")

    # Navigation
    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🔍 Analyse Flux", "📁 Upload CSV", "📜 Historique"],
        label_visibility="collapsed"
    )

    st.markdown("---")

    # Rafraîchissement automatique
    auto_refresh = st.toggle("🔄 Rafraîchissement auto", value=False)
    if auto_refresh:
        refresh_interval = st.slider("Intervalle (s)", 5, 60, 10)

    st.markdown("---")

    # Reset
    if st.button("🗑️ Reset historique", use_container_width=True):
        result = call_api("/history", method="DELETE")
        if result:
            st.success("Historique réinitialisé !")
            st.rerun()

# ================================================================
# PAGE : DASHBOARD
# ================================================================

if "📊 Dashboard" in page:

    # En-tête
    st.markdown("""
    <div class="main-header">
        <h1 style="margin:0;">🛡️ IDS — Tableau de Bord</h1>
        <p style="margin:5px 0 0 0; opacity:0.8;">Système de Détection d'Intrusions | CIC-IDS2017 | XGBoost</p>
    </div>
    """, unsafe_allow_html=True)

    # Chargement des stats
    stats = call_api("/stats")

    if stats:
        # ---- KPIs ----
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "🔍 Flux analysés",
                f"{stats['total_analyzed']:,}",
            )
        with col2:
            st.metric(
                "🚨 Attaques détectées",
                f"{stats['total_attacks']:,}",
                delta=f"{stats['attack_rate']}% du trafic",
                delta_color="inverse"
            )
        with col3:
            st.metric(
                "🔒 Flux bloqués",
                f"{stats['total_blocked']:,}",
            )
        with col4:
            safe = stats["total_analyzed"] - stats["total_attacks"]
            st.metric(
                "✅ Trafic sain",
                f"{safe:,}",
            )

        st.markdown("---")

        # ---- Graphiques ----
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("🎯 Répartition des types d'attaques")
            if stats["by_type"]:
                df_types = pd.DataFrame(
                    list(stats["by_type"].items()),
                    columns=["Type", "Nombre"]
                ).sort_values("Nombre", ascending=True)

                fig = px.bar(
                    df_types, x="Nombre", y="Type",
                    orientation="h",
                    color="Nombre",
                    color_continuous_scale="Reds",
                    title=""
                )
                fig.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    showlegend=False,
                    coloraxis_showscale=False,
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=350,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Aucune attaque détectée pour le moment.")

        with col_right:
            st.subheader("⚡ Répartition par sévérité")
            if stats["by_severity"]:
                df_sev = pd.DataFrame(
                    list(stats["by_severity"].items()),
                    columns=["Sévérité", "Nombre"]
                )
                colors_sev = [SEVERITY_COLORS.get(s, "#888") for s in df_sev["Sévérité"]]

                fig2 = px.pie(
                    df_sev, values="Nombre", names="Sévérité",
                    color="Sévérité",
                    color_discrete_map=SEVERITY_COLORS,
                    hole=0.4,
                )
                fig2.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=350,
                )
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("Aucune attaque détectée pour le moment.")

    # ---- Dernières alertes ----
    st.markdown("---")
    st.subheader("🔔 Dernières alertes")

    recent = call_api("/history/recent")
    if recent and recent["alerts"]:
        for alert in reversed(recent["alerts"][-10:]):
            css_class = get_alert_class(alert["severity"])
            icon      = SEVERITY_ICONS.get(alert["severity"], "❓")
            ts        = alert["timestamp"][:19].replace("T", " ")
            src       = alert.get("source_ip") or "N/A"
            dst       = alert.get("dest_ip")   or "N/A"

            st.markdown(f"""
            <div class="{css_class}">
                <strong>{icon} {alert['attack_type']}</strong>
                &nbsp;&nbsp;|&nbsp;&nbsp;
                Sévérité : <strong>{alert['severity']}</strong>
                &nbsp;&nbsp;|&nbsp;&nbsp;
                Confiance : <strong>{alert['confidence']*100:.1f}%</strong>
                &nbsp;&nbsp;|&nbsp;&nbsp;
                {src} → {dst}
                &nbsp;&nbsp;|&nbsp;&nbsp;
                <small>{ts}</small>
                &nbsp;&nbsp;
                <span class="blocked-badge">BLOQUÉ</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Aucune alerte enregistrée.")

    # Rafraîchissement auto
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()

# ================================================================
# PAGE : ANALYSE FLUX UNIQUE
# ================================================================

elif "🔍 Analyse Flux" in page:

    st.markdown("## 🔍 Analyse d'un flux réseau")
    st.markdown("Saisissez les caractéristiques d'un flux réseau pour l'analyser en temps réel.")

    # ---- Scénarios prédéfinis ----
    scenarios_data = {
        "Trafic normal (HTTP)": {
            "destination_port": 80, "flow_duration": 38308.0,
            "total_fwd_packets": 1.0, "total_backward_packets": 1.0,
            "flow_bytes_per_s": 156.9, "flow_packets_per_s": 52.2,
            "average_packet_size": 6.0, "packet_length_mean": 6.0,
            "init_win_bytes_forward": 65535.0, "init_win_bytes_backward": 65535.0,
            "flow_iat_mean": 38308.0, "flow_iat_std": 0.0,
        },
        "DDoS": {
            # Ligne reelle CIC-IDS2017 — proba=0.9997
            "destination_port": 80, "flow_duration": 1293792.0,
            "total_fwd_packets": 3.0, "total_backward_packets": 7.0,
            "flow_bytes_per_s": 8991.4, "flow_packets_per_s": 7.73,
            "average_packet_size": 1163.3, "packet_length_mean": 1057.5,
            "init_win_bytes_forward": 8192.0, "init_win_bytes_backward": 229.0,
            "flow_iat_mean": 143754.7, "flow_iat_std": 430865.8,
        },
        "DoS Hulk": {
            # Ligne reelle CIC-IDS2017 — proba=0.9997
            "destination_port": 80, "flow_duration": 1878.0,
            "total_fwd_packets": 3.0, "total_backward_packets": 6.0,
            "flow_bytes_per_s": 6377529.5, "flow_packets_per_s": 4792.3,
            "average_packet_size": 1330.8, "packet_length_mean": 1197.7,
            "init_win_bytes_forward": 29200.0, "init_win_bytes_backward": 235.0,
            "flow_iat_mean": 234.75, "flow_iat_std": 229.13,
        },
        "DoS GoldenEye": {
            # Ligne reelle CIC-IDS2017 — proba=0.9998
            "destination_port": 80, "flow_duration": 8557778.0,
            "total_fwd_packets": 8.0, "total_backward_packets": 5.0,
            "flow_bytes_per_s": 1404.7, "flow_packets_per_s": 1.52,
            "average_packet_size": 924.7, "packet_length_mean": 858.6,
            "init_win_bytes_forward": 29200.0, "init_win_bytes_backward": 235.0,
            "flow_iat_mean": 713148.2, "flow_iat_std": 1693213.6,
        },
        "FTP-Patator": {
            # Ligne reelle CIC-IDS2017 — proba=0.9991
            "destination_port": 21, "flow_duration": 9711548.0,
            "total_fwd_packets": 9.0, "total_backward_packets": 15.0,
            "flow_bytes_per_s": 30.07, "flow_packets_per_s": 2.47,
            "average_packet_size": 12.17, "packet_length_mean": 11.68,
            "init_win_bytes_forward": 29200.0, "init_win_bytes_backward": 227.0,
            "flow_iat_mean": 422241.2, "flow_iat_std": 1098758.4,
        },
        "SSH-Patator": {
            # Ligne reelle CIC-IDS2017 — proba=0.9995
            "destination_port": 22, "flow_duration": 11931559.0,
            "total_fwd_packets": 20.0, "total_backward_packets": 33.0,
            "flow_bytes_per_s": 398.4, "flow_packets_per_s": 4.44,
            "average_packet_size": 89.68, "packet_length_mean": 88.02,
            "init_win_bytes_forward": 29200.0, "init_win_bytes_backward": 247.0,
            "flow_iat_mean": 229453.1, "flow_iat_std": 619141.6,
        },
        "PortScan": {
            # Ligne reelle CIC-IDS2017 — proba=0.9984
            "destination_port": 22, "flow_duration": 625.0,
            "total_fwd_packets": 2.0, "total_backward_packets": 1.0,
            "flow_bytes_per_s": 16000.0, "flow_packets_per_s": 4800.0,
            "average_packet_size": 4.0, "packet_length_mean": 3.0,
            "init_win_bytes_forward": 1024.0, "init_win_bytes_backward": 29200.0,
            "flow_iat_mean": 312.5, "flow_iat_std": 249.6,
        },
        "Bot": {
            # Ligne reelle CIC-IDS2017 — proba=0.9898
            "destination_port": 8080, "flow_duration": 80105.0,
            "total_fwd_packets": 4.0, "total_backward_packets": 3.0,
            "flow_bytes_per_s": 4244.4, "flow_packets_per_s": 87.4,
            "average_packet_size": 48.57, "packet_length_mean": 42.5,
            "init_win_bytes_forward": 8192.0, "init_win_bytes_backward": 237.0,
            "flow_iat_mean": 13350.8, "flow_iat_std": 31571.8,
        },
        "DoS slowloris": {
            # Ligne reelle CIC-IDS2017 — proba=0.9704
            "destination_port": 80, "flow_duration": 507661.0,
            "total_fwd_packets": 4.0, "total_backward_packets": 2.0,
            "flow_bytes_per_s": 455.0, "flow_packets_per_s": 11.82,
            "average_packet_size": 38.5, "packet_length_mean": 33.0,
            "init_win_bytes_forward": 29200.0, "init_win_bytes_backward": 235.0,
            "flow_iat_mean": 101532.2, "flow_iat_std": 226626.6,
        },
    }

    # Valeurs par défaut initiales (trafic normal)
    _defaults = {
        "destination_port": 80, "flow_duration": 38308.0,
        "total_fwd_packets": 1.0, "total_backward_packets": 1.0,
        "flow_bytes_per_s": 156.9, "flow_packets_per_s": 52.2,
        "average_packet_size": 6.0, "packet_length_mean": 6.0,
        "init_win_bytes_forward": 65535.0, "init_win_bytes_backward": 65535.0,
        "flow_iat_mean": 38308.0, "flow_iat_std": 0.0,
    }
    for k, v in _defaults.items():
        if f"flux_{k}" not in st.session_state:
            st.session_state[f"flux_{k}"] = v
    if "flux_scenario_loaded" not in st.session_state:
        st.session_state["flux_scenario_loaded"] = ""

    # Sélecteur EN DEHORS du formulaire pour éviter les rechargements aléatoires
    scenario = st.selectbox(
        "⚡ Charger un scénario prédéfini :",
        ["-- Personnalisé --", "Trafic normal (HTTP)", "DDoS", "DoS Hulk",
         "DoS GoldenEye", "DoS slowloris", "FTP-Patator", "SSH-Patator",
         "PortScan", "Bot"]
    )

    # Quand un nouveau scénario est choisi -> injecter ses valeurs dans session_state
    if scenario != "-- Personnalisé --" and scenario != st.session_state["flux_scenario_loaded"]:
        for k, v in scenarios_data[scenario].items():
            st.session_state[f"flux_{k}"] = v
        st.session_state["flux_scenario_loaded"] = scenario
        st.rerun()
    elif scenario == "-- Personnalisé --":
        st.session_state["flux_scenario_loaded"] = ""

    # Formulaire avec valeurs stables depuis session_state
    with st.form("flow_form"):
        st.markdown("### 📡 Paramètres du flux")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("**Informations réseau**")
            source_ip = st.text_input("IP Source", "192.168.1.100")
            dest_ip   = st.text_input("IP Destination", "10.0.0.1")
            protocol  = st.selectbox("Protocole", ["TCP", "UDP", "ICMP"])
            dest_port = st.number_input(
                "Port destination", 0, 65535,
                value=int(st.session_state["flux_destination_port"])
            )

        with col2:
            st.markdown("**Métriques de flux**")
            flow_duration = st.number_input(
                "Durée du flux (µs)", 0.0, 1e9,
                value=float(st.session_state["flux_flow_duration"])
            )
            fwd_packets = st.number_input(
                "Paquets forward", 0.0, 1e6,
                value=float(st.session_state["flux_total_fwd_packets"])
            )
            bwd_packets = st.number_input(
                "Paquets backward", 0.0, 1e6,
                value=float(st.session_state["flux_total_backward_packets"])
            )
            flow_bytes = st.number_input(
                "Débit octets/s", 0.0, 1e9,
                value=float(st.session_state["flux_flow_bytes_per_s"])
            )
            flow_pkts = st.number_input(
                "Débit paquets/s", 0.0, 1e6,
                value=float(st.session_state["flux_flow_packets_per_s"])
            )

        with col3:
            st.markdown("**Métriques paquets**")
            avg_pkt_size = st.number_input(
                "Taille moy. paquet", 0.0, 65535.0,
                value=float(st.session_state["flux_average_packet_size"])
            )
            pkt_len_mean = st.number_input(
                "Longueur moy. paquet", 0.0, 65535.0,
                value=float(st.session_state["flux_packet_length_mean"])
            )
            win_fwd = st.number_input(
                "Fenêtre TCP forward", -1.0, 65535.0,
                value=float(st.session_state["flux_init_win_bytes_forward"])
            )
            win_bwd = st.number_input(
                "Fenêtre TCP backward", -1.0, 65535.0,
                value=float(st.session_state["flux_init_win_bytes_backward"])
            )
            iat_mean = st.number_input(
                "IAT moyen", 0.0, 1e9,
                value=float(st.session_state["flux_flow_iat_mean"])
            )
            iat_std = st.number_input(
                "IAT écart-type", 0.0, 1e9,
                value=float(st.session_state["flux_flow_iat_std"])
            )

        st.markdown("---")
        submitted = st.form_submit_button("🔍 Analyser ce flux", use_container_width=True)

    if submitted:
        payload = {
            "destination_port":        dest_port,
            "flow_duration":           flow_duration,
            "total_fwd_packets":       fwd_packets,
            "total_backward_packets":  bwd_packets,
            "flow_bytes_per_s":        flow_bytes,
            "flow_packets_per_s":      flow_pkts,
            "average_packet_size":     avg_pkt_size,
            "packet_length_mean":      pkt_len_mean,
            "init_win_bytes_forward":  win_fwd,
            "init_win_bytes_backward": win_bwd,
            "flow_iat_mean":           iat_mean,
            "flow_iat_std":            iat_std,
            "source_ip":               source_ip,
            "dest_ip":                 dest_ip,
            "protocol":                protocol,
        }

        with st.spinner("Analyse en cours..."):
            result = call_api("/predict", method="POST", data=payload)

        if result:
            st.markdown("---")
            st.markdown("### 📋 Résultat de l'analyse")

            if result["is_attack"]:
                severity = result["severity"]
                color    = SEVERITY_COLORS.get(severity, "#E74C3C")
                icon     = SEVERITY_ICONS.get(severity, "🚨")

                st.markdown(f"""
                <div style="background:rgba(231,76,60,0.15); border:2px solid {color};
                            border-radius:12px; padding:20px; margin:10px 0;">
                    <h2 style="color:{color}; margin:0;">{icon} ATTAQUE DÉTECTÉE — FLUX BLOQUÉ</h2>
                    <h3 style="color:white; margin:5px 0;">{result['attack_type']}</h3>
                </div>
                """, unsafe_allow_html=True)

                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Sévérité",  result["severity"])
                col_b.metric("Confiance", f"{result['confidence']*100:.1f}%")
                col_c.metric("Seuil",     f"{result['threshold_used']:.2f}")

                st.error(f"🔒 **Action recommandée :** {result['action']}")

            else:
                st.markdown("""
                <div style="background:rgba(46,204,113,0.15); border:2px solid #2ECC71;
                            border-radius:12px; padding:20px; margin:10px 0;">
                    <h2 style="color:#2ECC71; margin:0;">✅ TRAFIC SAIN — AUCUNE MENACE</h2>
                </div>
                """, unsafe_allow_html=True)

                col_a, col_b = st.columns(2)
                col_a.metric("Confiance", f"{result['confidence']*100:.1f}%")
                col_b.metric("Seuil utilisé", f"{result['threshold_used']:.2f}")

            # Détails JSON
            with st.expander("📄 Détails complets (JSON)"):
                st.json(result)

# ================================================================
# PAGE : UPLOAD CSV
# ================================================================

elif "📁 Upload CSV" in page:

    st.markdown("## 📁 Analyse d'un fichier CSV de logs")
    st.markdown("Uploadez un fichier CSV de logs réseau pour une analyse en batch.")

    # Instructions
    with st.expander("📋 Format attendu du CSV"):
        st.markdown("""
        Le CSV doit contenir les colonnes suivantes (noms CIC-IDS2017) :
        
        | Colonne | Description |
        |---------|-------------|
        | `Destination Port` | Port de destination |
        | `Flow Duration` | Durée du flux |
        | `Total Fwd Packets` | Paquets forward |
        | `Total Backward Packets` | Paquets backward |
        | `Flow Bytes/s` | Débit octets/s |
        | `Flow Packets/s` | Débit paquets/s |
        | `Average Packet Size` | Taille moyenne paquet |
        | `Packet Length Mean` | Longueur moyenne |
        | `Init_Win_bytes_forward` | Fenêtre TCP forward |
        | `Init_Win_bytes_backward` | Fenêtre TCP backward |
        | `Flow IAT Mean` | IAT moyen |
        | `Flow IAT Std` | IAT écart-type |
        """)

    uploaded_file = st.file_uploader(
        "Choisir un fichier CSV",
        type=["csv"],
        help="Fichier CSV de logs réseau au format CIC-IDS2017"
    )

    if uploaded_file:
        # Aperçu du fichier
        df_preview = pd.read_csv(uploaded_file)
        uploaded_file.seek(0)  # Reset pour l'envoi

        st.markdown(f"**Aperçu** : {len(df_preview):,} lignes | {len(df_preview.columns)} colonnes")
        st.dataframe(df_preview.head(5), use_container_width=True)

        if st.button("🚀 Lancer l'analyse", use_container_width=True, type="primary"):
            with st.spinner(f"Analyse de {len(df_preview):,} flux en cours..."):
                files = {"file": (uploaded_file.name, uploaded_file, "text/csv")}
                result = call_api("/predict/batch", method="POST", files=files)

            if result:
                summary = result["summary"]
                results = result["results"]

                # KPIs
                st.markdown("---")
                st.markdown("### 📊 Résultats de l'analyse")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Flux analysés",    f"{summary['total_analyzed']:,}")
                col2.metric("Attaques",          f"{summary['total_attacks']:,}",
                            delta=f"{summary['attack_rate']}%", delta_color="inverse")
                col3.metric("Flux bloqués",      f"{summary['total_blocked']:,}")
                col4.metric("Trafic sain",
                            f"{summary['total_analyzed'] - summary['total_attacks']:,}")

                # Graphique des types d'attaques
                if summary["attack_types"]:
                    st.markdown("---")
                    col_g1, col_g2 = st.columns(2)

                    with col_g1:
                        st.markdown("**Types d'attaques détectées**")
                        df_at = pd.DataFrame(
                            list(summary["attack_types"].items()),
                            columns=["Type", "Nombre"]
                        ).sort_values("Nombre", ascending=False)

                        fig = px.bar(df_at, x="Type", y="Nombre",
                                     color="Nombre", color_continuous_scale="Reds")
                        fig.update_layout(
                            plot_bgcolor="rgba(0,0,0,0)",
                            paper_bgcolor="rgba(0,0,0,0)",
                            font_color="white",
                            showlegend=False,
                            xaxis_tickangle=45,
                            height=350,
                        )
                        st.plotly_chart(fig, use_container_width=True)

                    with col_g2:
                        st.markdown("**Distribution Sain vs Attaque**")
                        fig2 = px.pie(
                            values=[summary["total_analyzed"] - summary["total_attacks"],
                                    summary["total_attacks"]],
                            names=["Trafic Sain", "Attaques"],
                            color_discrete_sequence=["#2ECC71", "#E74C3C"],
                            hole=0.4,
                        )
                        fig2.update_layout(
                            plot_bgcolor="rgba(0,0,0,0)",
                            paper_bgcolor="rgba(0,0,0,0)",
                            font_color="white",
                            height=350,
                        )
                        st.plotly_chart(fig2, use_container_width=True)

                # Tableau des résultats
                st.markdown("---")
                st.markdown("### 📋 Détail des flux analysés")

                df_results = pd.DataFrame(results)
                df_results_display = df_results[[
                    "timestamp", "is_attack", "attack_type",
                    "severity", "confidence", "blocked",
                    "source_ip", "dest_ip"
                ]].copy()
                df_results_display.columns = [
                    "Timestamp", "Attaque?", "Type",
                    "Sévérité", "Confiance", "Bloqué",
                    "IP Source", "IP Dest"
                ]
                df_results_display["Confiance"] = df_results_display["Confiance"].apply(
                    lambda x: f"{x*100:.1f}%"
                )

                # Filtre
                filter_attacks = st.checkbox("Afficher uniquement les attaques", value=False)
                if filter_attacks:
                    df_results_display = df_results_display[df_results_display["Attaque?"] == True]

                st.dataframe(df_results_display, use_container_width=True, height=400)

                # Téléchargement
                csv_export = df_results_display.to_csv(index=False)
                st.download_button(
                    "📥 Télécharger les résultats (CSV)",
                    csv_export,
                    "ids_results.csv",
                    "text/csv",
                    use_container_width=True,
                )

# ================================================================
# PAGE : HISTORIQUE
# ================================================================

elif "📜 Historique" in page:

    st.markdown("## 📜 Historique des alertes")

    col_opt1, col_opt2 = st.columns(2)
    with col_opt1:
        limit = st.slider("Nombre d'entrées", 10, 500, 100)
    with col_opt2:
        attacks_only = st.checkbox("Attaques uniquement", value=True)

    history = call_api(f"/history?limit={limit}&attacks_only={str(attacks_only).lower()}")

    if history and history["history"]:
        st.markdown(f"**{history['count']} entrées**")

        df_hist = pd.DataFrame(history["history"])

        # Graphique temporel
        if len(df_hist) > 1 and "timestamp" in df_hist.columns:
            df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])
            df_hist_attacks = df_hist[df_hist["is_attack"] == True]

            if not df_hist_attacks.empty:
                st.markdown("**Timeline des attaques**")
                fig_timeline = px.scatter(
                    df_hist_attacks,
                    x="timestamp",
                    y="attack_type",
                    color="severity",
                    color_discrete_map=SEVERITY_COLORS,
                    size="confidence",
                    hover_data=["source_ip", "dest_ip", "confidence"],
                    title="",
                )
                fig_timeline.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    height=350,
                    margin=dict(l=0, r=0, t=10, b=0),
                )
                st.plotly_chart(fig_timeline, use_container_width=True)

        # Tableau
        cols_display = ["timestamp", "attack_type", "severity",
                        "confidence", "blocked", "source_ip", "action"]
        cols_present = [c for c in cols_display if c in df_hist.columns]
        st.dataframe(df_hist[cols_present], use_container_width=True, height=450)

        # Export
        csv_hist = df_hist.to_csv(index=False)
        st.download_button(
            "📥 Exporter l'historique (CSV)",
            csv_hist,
            f"ids_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "text/csv",
            use_container_width=True,
        )
    else:
        st.info("Aucune entrée dans l'historique.")
