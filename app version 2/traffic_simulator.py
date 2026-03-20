#!/usr/bin/env python3
# ================================================================
# IDS — SIMULATEUR DE TRAFIC RÉSEAU EN TEMPS RÉEL
# ================================================================
#
# Ce script simule un flux de trafic réseau réaliste et l'envoie
# en continu à l'API FastAPI pour une démonstration live.
#
# LANCEMENT :
#   python traffic_simulator.py
#   python traffic_simulator.py --rate 2      # 2 flux/seconde
#   python traffic_simulator.py --attack ddos  # forcer une attaque
#   python traffic_simulator.py --chaos        # mode chaos (beaucoup d'attaques)
#
# PRÉREQUIS :
#   L'API FastAPI doit tourner : uvicorn main:app --reload
# ================================================================

import requests
import random
import time
import argparse
import sys
from datetime import datetime
from typing import Optional

# ================================================================
# CONFIGURATION
# ================================================================

API_URL  = "http://localhost:8000"
ENDPOINT = f"{API_URL}/predict"

# Couleurs terminal
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# Icônes par sévérité
SEVERITY_ICONS = {
    "INFO":     f"{GREEN}✅{RESET}",
    "MEDIUM":   f"{YELLOW}⚠️ {RESET}",
    "HIGH":     f"{RED}🔴{RESET}",
    "CRITICAL": f"{RED}{BOLD}🚨{RESET}",
}

# ================================================================
# PROFILS DE TRAFIC RÉALISTE
# ================================================================
# Chaque profil correspond à un type de trafic réel observé dans
# CIC-IDS2017. Les valeurs sont des distributions réalistes.

TRAFFIC_PROFILES = {

    # ---- TRAFIC NORMAL ----
    "BENIGN_HTTP": {
        "label":    "Trafic HTTP normal",
        "weight":   40,  # probabilité relative
        "params": {
            "destination_port":       lambda: random.choice([80, 443, 8080, 8443]),
            "flow_duration":          lambda: random.randint(1000, 500000),
            "total_fwd_packets":      lambda: random.randint(1, 50),
            "total_backward_packets": lambda: random.randint(1, 50),
            "flow_bytes_per_s":       lambda: random.uniform(100, 50000),
            "flow_packets_per_s":     lambda: random.uniform(10, 500),
            "average_packet_size":    lambda: random.uniform(40, 1500),
            "packet_length_mean":     lambda: random.uniform(40, 1500),
            "init_win_bytes_forward": lambda: random.choice([65535, 8192, 32768]),
            "init_win_bytes_backward":lambda: random.choice([65535, 8192, 32768]),
            "flow_iat_mean":          lambda: random.uniform(1000, 100000),
            "flow_iat_std":           lambda: random.uniform(0, 50000),
        }
    },

    "BENIGN_DNS": {
        "label":    "Trafic DNS normal",
        "weight":   15,
        "params": {
            "destination_port":       lambda: 53,
            "flow_duration":          lambda: random.randint(100, 5000),
            "total_fwd_packets":      lambda: random.randint(1, 3),
            "total_backward_packets": lambda: random.randint(1, 3),
            "flow_bytes_per_s":       lambda: random.uniform(200, 5000),
            "flow_packets_per_s":     lambda: random.uniform(100, 2000),
            "average_packet_size":    lambda: random.uniform(40, 80),
            "packet_length_mean":     lambda: random.uniform(40, 80),
            "init_win_bytes_forward": lambda: 0,
            "init_win_bytes_backward":lambda: 0,
            "flow_iat_mean":          lambda: random.uniform(100, 2000),
            "flow_iat_std":           lambda: random.uniform(0, 500),
        }
    },

    "BENIGN_SSH": {
        "label":    "Trafic SSH normal",
        "weight":   5,
        "params": {
            "destination_port":       lambda: 22,
            "flow_duration":          lambda: random.randint(10000, 5000000),
            "total_fwd_packets":      lambda: random.randint(10, 200),
            "total_backward_packets": lambda: random.randint(10, 200),
            "flow_bytes_per_s":       lambda: random.uniform(500, 10000),
            "flow_packets_per_s":     lambda: random.uniform(5, 100),
            "average_packet_size":    lambda: random.uniform(80, 500),
            "packet_length_mean":     lambda: random.uniform(80, 500),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(5000, 500000),
            "flow_iat_std":           lambda: random.uniform(1000, 100000),
        }
    },

    # ---- ATTAQUES ----
    "DDOS": {
        "label":    "DDoS",
        "weight":   5,
        "params": {
            "destination_port":       lambda: random.choice([80, 443]),
            "flow_duration":          lambda: random.randint(100, 2000),
            "total_fwd_packets":      lambda: random.randint(1000, 100000),
            "total_backward_packets": lambda: 0,
            "flow_bytes_per_s":       lambda: random.uniform(1000000, 50000000),
            "flow_packets_per_s":     lambda: random.uniform(100000, 5000000),
            "average_packet_size":    lambda: random.uniform(40, 80),
            "packet_length_mean":     lambda: random.uniform(40, 80),
            "init_win_bytes_forward": lambda: random.randint(512, 2048),
            "init_win_bytes_backward":lambda: 0,
            "flow_iat_mean":          lambda: random.uniform(0.1, 5.0),
            "flow_iat_std":           lambda: random.uniform(0, 2.0),
        }
    },

    "DOS_HULK": {
        "label":    "DoS Hulk",
        "weight":   5,
        "params": {
            "destination_port":       lambda: 80,
            "flow_duration":          lambda: random.randint(500, 5000),
            "total_fwd_packets":      lambda: random.randint(100, 5000),
            "total_backward_packets": lambda: random.randint(0, 10),
            "flow_bytes_per_s":       lambda: random.uniform(500000, 5000000),
            "flow_packets_per_s":     lambda: random.uniform(50000, 500000),
            "average_packet_size":    lambda: random.uniform(200, 800),
            "packet_length_mean":     lambda: random.uniform(200, 800),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: random.randint(0, 512),
            "flow_iat_mean":          lambda: random.uniform(1, 20),
            "flow_iat_std":           lambda: random.uniform(0, 10),
        }
    },

    "DOS_SLOWLORIS": {
        "label":    "DoS slowloris",
        "weight":   3,
        "params": {
            "destination_port":       lambda: 80,
            "flow_duration":          lambda: random.randint(10000000, 60000000),
            "total_fwd_packets":      lambda: random.randint(5, 20),
            "total_backward_packets": lambda: random.randint(0, 5),
            "flow_bytes_per_s":       lambda: random.uniform(1, 100),
            "flow_packets_per_s":     lambda: random.uniform(0.1, 2),
            "average_packet_size":    lambda: random.uniform(40, 200),
            "packet_length_mean":     lambda: random.uniform(40, 200),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(1000000, 5000000),
            "flow_iat_std":           lambda: random.uniform(100000, 1000000),
        }
    },

    "DOS_GOLDENEYE": {
        "label":    "DoS GoldenEye",
        "weight":   3,
        "params": {
            "destination_port":       lambda: 80,
            "flow_duration":          lambda: random.randint(1000, 50000),
            "total_fwd_packets":      lambda: random.randint(50, 500),
            "total_backward_packets": lambda: random.randint(0, 50),
            "flow_bytes_per_s":       lambda: random.uniform(10000, 500000),
            "flow_packets_per_s":     lambda: random.uniform(1000, 50000),
            "average_packet_size":    lambda: random.uniform(100, 600),
            "packet_length_mean":     lambda: random.uniform(100, 600),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: random.randint(0, 1024),
            "flow_iat_mean":          lambda: random.uniform(10, 1000),
            "flow_iat_std":           lambda: random.uniform(5, 500),
        }
    },

    "PORTSCAN": {
        "label":    "PortScan",
        "weight":   5,
        "params": {
            "destination_port":       lambda: random.randint(1, 65535),
            "flow_duration":          lambda: random.randint(1, 50),
            "total_fwd_packets":      lambda: random.randint(1, 3),
            "total_backward_packets": lambda: 0,
            "flow_bytes_per_s":       lambda: random.uniform(1000, 50000),
            "flow_packets_per_s":     lambda: random.uniform(10000, 5000000),
            "average_packet_size":    lambda: random.uniform(40, 80),
            "packet_length_mean":     lambda: random.uniform(40, 80),
            "init_win_bytes_forward": lambda: random.randint(512, 2048),
            "init_win_bytes_backward":lambda: -1,
            "flow_iat_mean":          lambda: random.uniform(1, 10),
            "flow_iat_std":           lambda: random.uniform(0, 5),
        }
    },

    "FTP_PATATOR": {
        "label":    "FTP-Patator",
        "weight":   3,
        "params": {
            "destination_port":       lambda: 21,
            "flow_duration":          lambda: random.randint(10000, 500000),
            "total_fwd_packets":      lambda: random.randint(5, 20),
            "total_backward_packets": lambda: random.randint(3, 15),
            "flow_bytes_per_s":       lambda: random.uniform(500, 5000),
            "flow_packets_per_s":     lambda: random.uniform(10, 200),
            "average_packet_size":    lambda: random.uniform(50, 200),
            "packet_length_mean":     lambda: random.uniform(50, 200),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(5000, 100000),
            "flow_iat_std":           lambda: random.uniform(1000, 50000),
        }
    },

    "SSH_PATATOR": {
        "label":    "SSH-Patator",
        "weight":   3,
        "params": {
            "destination_port":       lambda: 22,
            "flow_duration":          lambda: random.randint(100000, 2000000),
            "total_fwd_packets":      lambda: random.randint(10, 30),
            "total_backward_packets": lambda: random.randint(5, 20),
            "flow_bytes_per_s":       lambda: random.uniform(100, 2000),
            "flow_packets_per_s":     lambda: random.uniform(5, 50),
            "average_packet_size":    lambda: random.uniform(60, 300),
            "packet_length_mean":     lambda: random.uniform(60, 300),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(10000, 200000),
            "flow_iat_std":           lambda: random.uniform(5000, 100000),
        }
    },

    "WEB_BRUTE_FORCE": {
        "label":    "Web Attack - Brute Force",
        "weight":   3,
        "params": {
            "destination_port":       lambda: random.choice([80, 443, 8080]),
            "flow_duration":          lambda: random.randint(5000, 100000),
            "total_fwd_packets":      lambda: random.randint(3, 15),
            "total_backward_packets": lambda: random.randint(2, 10),
            "flow_bytes_per_s":       lambda: random.uniform(200, 5000),
            "flow_packets_per_s":     lambda: random.uniform(20, 500),
            "average_packet_size":    lambda: random.uniform(200, 1000),
            "packet_length_mean":     lambda: random.uniform(200, 1000),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(1000, 20000),
            "flow_iat_std":           lambda: random.uniform(500, 10000),
        }
    },

    "WEB_XSS": {
        "label":    "Web Attack - XSS",
        "weight":   2,
        "params": {
            "destination_port":       lambda: random.choice([80, 443]),
            "flow_duration":          lambda: random.randint(10000, 200000),
            "total_fwd_packets":      lambda: random.randint(5, 25),
            "total_backward_packets": lambda: random.randint(3, 20),
            "flow_bytes_per_s":       lambda: random.uniform(500, 10000),
            "flow_packets_per_s":     lambda: random.uniform(20, 400),
            "average_packet_size":    lambda: random.uniform(300, 1400),
            "packet_length_mean":     lambda: random.uniform(300, 1400),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(2000, 40000),
            "flow_iat_std":           lambda: random.uniform(1000, 20000),
        }
    },

    "WEB_SQL": {
        "label":    "Web Attack - SQL Injection",
        "weight":   2,
        "params": {
            "destination_port":       lambda: random.choice([80, 443, 3306]),
            "flow_duration":          lambda: random.randint(5000, 150000),
            "total_fwd_packets":      lambda: random.randint(4, 20),
            "total_backward_packets": lambda: random.randint(2, 15),
            "flow_bytes_per_s":       lambda: random.uniform(300, 8000),
            "flow_packets_per_s":     lambda: random.uniform(15, 300),
            "average_packet_size":    lambda: random.uniform(400, 1400),
            "packet_length_mean":     lambda: random.uniform(400, 1400),
            "init_win_bytes_forward": lambda: 65535,
            "init_win_bytes_backward":lambda: 65535,
            "flow_iat_mean":          lambda: random.uniform(1500, 30000),
            "flow_iat_std":           lambda: random.uniform(500, 15000),
        }
    },

    "BOT": {
        "label":    "Bot",
        "weight":   3,
        "params": {
            "destination_port":       lambda: random.choice([80, 443, 6667, 8080]),
            "flow_duration":          lambda: random.randint(100000, 10000000),
            "total_fwd_packets":      lambda: random.randint(20, 200),
            "total_backward_packets": lambda: random.randint(15, 150),
            "flow_bytes_per_s":       lambda: random.uniform(50, 2000),
            "flow_packets_per_s":     lambda: random.uniform(1, 50),
            "average_packet_size":    lambda: random.uniform(60, 400),
            "packet_length_mean":     lambda: random.uniform(60, 400),
            "init_win_bytes_forward": lambda: random.choice([65535, 8192]),
            "init_win_bytes_backward":lambda: random.choice([65535, 8192]),
            "flow_iat_mean":          lambda: random.uniform(10000, 1000000),
            "flow_iat_std":           lambda: random.uniform(5000, 500000),
        }
    },
}

# IPs simulées
SOURCE_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.20",
    "10.0.0.5", "10.0.0.12", "10.0.0.99",
    "172.16.0.3", "172.16.0.7",
    "203.0.113.42",   # IP externe suspecte
    "198.51.100.88",  # IP externe suspecte
    "185.220.101.45", # IP Tor connue
]
DEST_IPS = [
    "192.168.1.1", "10.0.0.1", "172.16.0.1",
    "192.168.1.100", "10.0.0.50",
]

# ================================================================
# GÉNÉRATION DE FLUX
# ================================================================

def generate_flow(force_profile: Optional[str] = None,
                  chaos_mode: bool = False) -> dict:
    """
    Génère un flux réseau simulé.
    
    Paramètres
    ----------
    force_profile : str optionnel — forcer un profil spécifique
    chaos_mode    : bool — augmente la probabilité d'attaques
    """
    if force_profile and force_profile in TRAFFIC_PROFILES:
        profile_key = force_profile
    else:
        profiles = list(TRAFFIC_PROFILES.keys())
        weights  = [TRAFFIC_PROFILES[p]["weight"] for p in profiles]

        # Mode chaos : multiplier les poids des attaques par 5
        if chaos_mode:
            weights = [
                w * 5 if p not in ("BENIGN_HTTP", "BENIGN_DNS", "BENIGN_SSH")
                else w
                for p, w in zip(profiles, weights)
            ]

        profile_key = random.choices(profiles, weights=weights, k=1)[0]

    profile = TRAFFIC_PROFILES[profile_key]
    params  = {k: v() for k, v in profile["params"].items()}

    # Métadonnées
    params["source_ip"] = random.choice(SOURCE_IPS)
    params["dest_ip"]   = random.choice(DEST_IPS)
    params["protocol"]  = random.choice(["TCP", "UDP"])

    return params, profile["label"]


def send_flow(flow: dict) -> Optional[dict]:
    """Envoie un flux à l'API FastAPI."""
    try:
        r = requests.post(ENDPOINT, json=flow, timeout=5)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.exceptions.ConnectionError:
        print(f"\n{RED}ERREUR : Impossible de se connecter à l'API.")
        print(f"Assurez-vous que FastAPI tourne sur localhost:8000{RESET}")
        print(f"Commande : uvicorn main:app --reload\n")
        return None
    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")
        return None


def print_result(result: dict, profile_label: str, flow_num: int):
    """Affiche un résultat de façon lisible dans le terminal."""
    ts       = datetime.now().strftime("%H:%M:%S")
    src      = result.get("source_ip", "N/A")
    dst      = result.get("dest_ip", "N/A")
    severity = result.get("severity", "INFO")
    icon     = SEVERITY_ICONS.get(severity, "❓")

    if result["is_attack"]:
        color = RED if severity in ("CRITICAL", "HIGH") else YELLOW
        print(
            f"{BOLD}[{ts}]{RESET} #{flow_num:04d} "
            f"{icon} {color}{BOLD}{result['attack_type']:<30}{RESET} "
            f"| Sév: {color}{severity:<8}{RESET} "
            f"| Conf: {result['confidence']*100:5.1f}% "
            f"| {src} -> {dst} "
            f"| {RED}BLOQUÉ{RESET}"
        )
    else:
        print(
            f"{BOLD}[{ts}]{RESET} #{flow_num:04d} "
            f"{GREEN}✅ BENIGN{RESET}{'':24} "
            f"| Sév: {GREEN}INFO    {RESET} "
            f"| Conf: {result['confidence']*100:5.1f}% "
            f"| {src} -> {dst}"
        )


def print_stats(total: int, attacks: int, blocked: int, by_type: dict):
    """Affiche un résumé des statistiques."""
    safe_rate    = ((total - attacks) / total * 100) if total > 0 else 0
    attack_rate  = (attacks / total * 100) if total > 0 else 0

    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  STATISTIQUES SESSION{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"  Flux analysés  : {BOLD}{total:,}{RESET}")
    print(f"  Trafic sain    : {GREEN}{total - attacks:,} ({safe_rate:.1f}%){RESET}")
    print(f"  Attaques       : {RED}{attacks:,} ({attack_rate:.1f}%){RESET}")
    print(f"  Flux bloqués   : {RED}{blocked:,}{RESET}")

    if by_type:
        print(f"\n  {BOLD}Types d'attaques détectées :{RESET}")
        for attack_type, count in sorted(by_type.items(),
                                          key=lambda x: x[1], reverse=True):
            bar = "█" * min(count, 30)
            print(f"    {attack_type:<35} {bar} {count}")

    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")

# ================================================================
# BOUCLE PRINCIPALE
# ================================================================

def run_simulator(rate: float = 1.0,
                  force_attack: Optional[str] = None,
                  chaos_mode: bool = False,
                  max_flows: Optional[int] = None):
    """
    Lance la simulation de trafic réseau en continu.

    Paramètres
    ----------
    rate         : float — flux par seconde (défaut 1.0)
    force_attack : str   — forcer un type d'attaque spécifique
    chaos_mode   : bool  — mode chaos (80% d'attaques)
    max_flows    : int   — arrêter après N flux (None = infini)
    """
    delay = 1.0 / rate

    # En-tête
    print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"{BOLD}{BLUE}  IDS — SIMULATEUR DE TRAFIC RÉSEAU EN TEMPS RÉEL{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"  API          : {CYAN}{API_URL}{RESET}")
    print(f"  Débit        : {CYAN}{rate} flux/seconde{RESET}")
    print(f"  Mode chaos   : {RED if chaos_mode else GREEN}"
          f"{'OUI ⚡' if chaos_mode else 'NON'}{RESET}")
    if force_attack:
        print(f"  Attaque forcée: {RED}{force_attack}{RESET}")
    print(f"\n  {YELLOW}Ctrl+C pour arrêter{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")

    # Mapping nom court -> clé profil
    attack_map = {
        "ddos":      "DDOS",
        "dos":       "DOS_HULK",
        "portscan":  "PORTSCAN",
        "ssh":       "SSH_PATATOR",
        "ftp":       "FTP_PATATOR",
        "xss":       "WEB_XSS",
        "sql":       "WEB_SQL",
        "brute":     "WEB_BRUTE_FORCE",
        "bot":       "BOT",
        "slowloris": "DOS_SLOWLORIS",
        "goldeneye": "DOS_GOLDENEYE",
    }

    profile_key = attack_map.get(force_attack.lower(), None) if force_attack else None

    # Compteurs locaux
    total_local   = 0
    attacks_local = 0
    blocked_local = 0
    by_type_local = {}

    try:
        while True:
            if max_flows and total_local >= max_flows:
                break

            # Génération du flux
            flow, profile_label = generate_flow(
                force_profile=profile_key,
                chaos_mode=chaos_mode
            )

            # Envoi à l'API
            result = send_flow(flow)

            if result is None:
                print(f"{RED}Attente de l'API...{RESET}")
                time.sleep(3)
                continue

            total_local += 1

            if result["is_attack"]:
                attacks_local += 1
                blocked_local += 1
                t = result["attack_type"]
                by_type_local[t] = by_type_local.get(t, 0) + 1

            # Affichage
            print_result(result, profile_label, total_local)

            # Stats toutes les 20 requêtes
            if total_local % 20 == 0:
                print_stats(total_local, attacks_local,
                            blocked_local, by_type_local)

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Simulation arrêtée par l'utilisateur.{RESET}")
        print_stats(total_local, attacks_local, blocked_local, by_type_local)
        print(f"{GREEN}Dashboard Streamlit : http://localhost:8501{RESET}\n")


# ================================================================
# POINT D'ENTRÉE
# ================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simulateur de trafic réseau pour l'IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python traffic_simulator.py                    # 1 flux/seconde, mixte
  python traffic_simulator.py --rate 5           # 5 flux/seconde
  python traffic_simulator.py --chaos            # mode chaos (beaucoup d'attaques)
  python traffic_simulator.py --attack ddos      # forcer des attaques DDoS
  python traffic_simulator.py --attack portscan  # forcer des PortScans
  python traffic_simulator.py --max 100          # arrêter après 100 flux

Types d'attaques disponibles :
  ddos, dos, portscan, ssh, ftp, xss, sql, brute, bot, slowloris, goldeneye
        """
    )

    parser.add_argument(
        "--rate", type=float, default=1.0,
        help="Nombre de flux par seconde (défaut: 1.0)"
    )
    parser.add_argument(
        "--attack", type=str, default=None,
        help="Forcer un type d'attaque spécifique"
    )
    parser.add_argument(
        "--chaos", action="store_true",
        help="Mode chaos : beaucoup d'attaques simultanées"
    )
    parser.add_argument(
        "--max", type=int, default=None,
        help="Nombre maximum de flux à envoyer"
    )

    args = parser.parse_args()

    run_simulator(
        rate=args.rate,
        force_attack=args.attack,
        chaos_mode=args.chaos,
        max_flows=args.max,
    )
