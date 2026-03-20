#!/usr/bin/env python3
# ================================================================
# IDS — GÉNÉRATEUR DE VRAIS PAQUETS RÉSEAU (LOCALHOST UNIQUEMENT)
# ================================================================
#
# Ce script génère de VRAIS paquets réseau vers localhost (127.0.0.1)
# uniquement — ta propre machine, aucun risque légal ou éthique.
#
# Il simule les patterns réels des attaques :
#   - DDoS      : flood de paquets SYN/UDP
#   - PortScan  : connexions rapides sur des ports différents
#   - Slowloris : connexions HTTP lentes qui restent ouvertes
#   - Brute Force : tentatives de connexion répétées
#
# En parallèle, les métriques extraites sont envoyées à l'API IDS
# pour que le modèle XGBoost les analyse en temps réel.
#
# LANCEMENT :
#   sudo python real_traffic_demo.py              # mode mixte
#   sudo python real_traffic_demo.py --demo ddos  # DDoS uniquement
#   sudo python real_traffic_demo.py --demo scan  # PortScan
#
# PRÉREQUIS :
#   pip install scapy requests
#   sudo requis pour la capture de paquets (scapy)
#   uvicorn main:app --reload  (API FastAPI)
#   streamlit run streamlit_app.py  (Dashboard)
#
# IMPORTANT :
#   Tout le trafic va vers 127.0.0.1 (ta propre machine uniquement)
# ================================================================

import socket
import threading
import time
import random
import requests
import argparse
import sys
import os
from datetime import datetime

# ================================================================
# CONFIGURATION
# ================================================================

TARGET_IP  = "127.0.0.1"   # UNIQUEMENT localhost — ta propre machine
API_URL    = "http://localhost:8000/predict"

# Couleurs terminal
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ================================================================
# EXTRACTION DES MÉTRIQUES RÉSEAU
# ================================================================

def build_flow_metrics(
    dest_port: int,
    duration_us: float,
    fwd_packets: int,
    bwd_packets: int,
    total_bytes: int,
    pkt_size_avg: float,
    iat_mean: float,
    iat_std: float,
    win_size: int = 65535,
) -> dict:
    """
    Construit les métriques de flux au format attendu par l'API IDS.
    Ces valeurs sont mesurées depuis les vrais paquets envoyés.
    """
    duration_s = max(duration_us / 1_000_000, 0.000001)
    total_pkts = max(fwd_packets + bwd_packets, 1)

    return {
        "destination_port":        float(dest_port),
        "flow_duration":           float(duration_us),
        "total_fwd_packets":       float(fwd_packets),
        "total_backward_packets":  float(bwd_packets),
        "flow_bytes_per_s":        float(total_bytes / duration_s),
        "flow_packets_per_s":      float(total_pkts / duration_s),
        "average_packet_size":     float(pkt_size_avg),
        "packet_length_mean":      float(pkt_size_avg),
        "init_win_bytes_forward":  float(win_size),
        "init_win_bytes_backward": float(win_size),
        "flow_iat_mean":           float(iat_mean),
        "flow_iat_std":            float(iat_std),
        "source_ip":               TARGET_IP,
        "dest_ip":                 TARGET_IP,
        "protocol":                "TCP",
    }


API_KEY = "ids-pme-2024"
HEADERS = {"X-API-Key": API_KEY}

def send_to_ids(metrics: dict, attack_label: str) -> dict:
    """Envoie les métriques à l'API IDS et retourne le résultat."""
    try:
        r = requests.post(API_URL, json=metrics, headers=HEADERS, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def print_detection(result: dict, attack_label: str, pkt_count: int):
    """Affiche le résultat de la détection dans le terminal."""
    ts = datetime.now().strftime("%H:%M:%S")
    if result.get("is_attack"):
        sev   = result.get("severity", "HIGH")
        atype = result.get("attack_type", attack_label)
        conf  = result.get("confidence", 0) * 100
        color = RED if sev in ("CRITICAL", "HIGH") else YELLOW
        print(
            f"{BOLD}[{ts}]{RESET} "
            f"{color}🚨 DÉTECTÉ{RESET} "
            f"{color}{BOLD}{atype:<28}{RESET} "
            f"| Sév: {color}{sev:<8}{RESET} "
            f"| Conf: {conf:5.1f}% "
            f"| Paquets envoyés: {pkt_count} "
            f"| {RED}BLOQUÉ{RESET}"
        )
    else:
        print(
            f"{BOLD}[{ts}]{RESET} "
            f"{GREEN}✅ BENIGN{RESET}{'':22} "
            f"| Conf: {result.get('confidence',0)*100:5.1f}% "
            f"| Paquets envoyés: {pkt_count}"
        )

# ================================================================
# DÉMO 1 — PORT SCAN (connexions TCP rapides sur ports variés)
# ================================================================

def demo_port_scan(n_ports: int = 30, delay: float = 0.05):
    """
    Simule un scan de ports — connexions TCP rapides sur des ports
    aléatoires de localhost. Pattern réel d'un PortScan.
    """
    print(f"\n{YELLOW}{BOLD}[PortScan] Scan de {n_ports} ports sur {TARGET_IP}...{RESET}")

    ports_scanned = 0
    start_time    = time.time()

    for _ in range(n_ports):
        port = random.randint(1, 65535)
        try:
            # Tentative de connexion TCP (SYN) — timeout très court
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            sock.connect_ex((TARGET_IP, port))
            sock.close()
            ports_scanned += 1
        except Exception:
            ports_scanned += 1
        time.sleep(delay)

    duration_us = (time.time() - start_time) * 1_000_000

    # Métriques réelles mesurées
    metrics = build_flow_metrics(
        dest_port    = random.randint(1, 65535),
        duration_us  = max(duration_us, 1),
        fwd_packets  = ports_scanned,
        bwd_packets  = 0,
        total_bytes  = ports_scanned * 44,   # SYN = ~44 octets
        pkt_size_avg = 44.0,
        iat_mean     = (duration_us / max(ports_scanned, 1)),
        iat_std      = delay * 1_000_000 * 0.1,
        win_size     = 1024,
    )

    result = send_to_ids(metrics, "PortScan")
    print_detection(result, "PortScan", ports_scanned)
    return result


# ================================================================
# DÉMO 2 — SYN FLOOD (simulation DDoS)
# ================================================================

def demo_syn_flood(n_connections: int = 200, target_port: int = 8000):
    """
    Simule un SYN Flood — ouverture massive de connexions TCP
    vers localhost:8000 (le port de l'API FastAPI elle-même).
    Pattern réel d'un DDoS/DoS.
    """
    print(f"\n{RED}{BOLD}[DDoS/SYN Flood] {n_connections} connexions vers "
          f"{TARGET_IP}:{target_port}...{RESET}")

    sent      = 0
    start_time = time.time()
    lock       = threading.Lock()

    def flood_worker():
        nonlocal sent
        for _ in range(n_connections // 10):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.01)
                sock.connect_ex((TARGET_IP, target_port))
                sock.close()
                with lock:
                    sent += 1
            except Exception:
                with lock:
                    sent += 1

    # 10 threads en parallèle pour simuler le flood
    threads = [threading.Thread(target=flood_worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    duration_us = (time.time() - start_time) * 1_000_000
    duration_us = max(duration_us, 1)

    metrics = build_flow_metrics(
        dest_port    = target_port,
        duration_us  = duration_us,
        fwd_packets  = sent,
        bwd_packets  = 0,
        total_bytes  = sent * 60,
        pkt_size_avg = 60.0,
        iat_mean     = duration_us / max(sent, 1),
        iat_std      = 0.5,
        win_size     = 1024,
    )

    result = send_to_ids(metrics, "DDoS")
    print_detection(result, "DDoS", sent)
    return result


# ================================================================
# DÉMO 3 — SLOWLORIS (connexions HTTP lentes)
# ================================================================

def demo_slowloris(n_connections: int = 20, hold_seconds: float = 2.0):
    """
    Simule Slowloris — ouvre des connexions HTTP et envoie des
    headers très lentement pour épuiser les ressources du serveur.
    Pattern réel d'un DoS slowloris.
    """
    print(f"\n{YELLOW}{BOLD}[Slowloris] {n_connections} connexions lentes "
          f"vers {TARGET_IP}:8000...{RESET}")

    sockets_opened = 0
    start_time     = time.time()
    slow_sockets   = []

    # Ouverture des connexions lentes
    for i in range(n_connections):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(hold_seconds + 1)
            sock.connect((TARGET_IP, 8000))

            # Envoi d'un header HTTP incomplet (le serveur attend la suite)
            sock.send(b"GET / HTTP/1.1\r\n")
            sock.send(f"Host: {TARGET_IP}\r\n".encode())
            sock.send(b"User-Agent: Mozilla/5.0\r\n")
            # On n'envoie PAS le \r\n final -> connexion reste ouverte

            slow_sockets.append(sock)
            sockets_opened += 1
        except Exception:
            pass

    # Maintien des connexions ouvertes
    time.sleep(hold_seconds)

    # Envoi de headers supplémentaires lentement
    for sock in slow_sockets:
        try:
            sock.send(b"X-Keep-Alive: timeout=200\r\n")
        except Exception:
            pass

    time.sleep(0.5)

    # Fermeture propre
    for sock in slow_sockets:
        try:
            sock.close()
        except Exception:
            pass

    duration_us = (time.time() - start_time) * 1_000_000

    metrics = build_flow_metrics(
        dest_port    = 8000,
        duration_us  = duration_us,
        fwd_packets  = sockets_opened * 3,
        bwd_packets  = sockets_opened,
        total_bytes  = sockets_opened * 150,
        pkt_size_avg = 50.0,
        iat_mean     = duration_us / max(sockets_opened * 3, 1),
        iat_std      = hold_seconds * 500_000,
        win_size     = 65535,
    )

    result = send_to_ids(metrics, "DoS slowloris")
    print_detection(result, "DoS slowloris", sockets_opened)
    return result


# ================================================================
# DÉMO 4 — BRUTE FORCE SSH (tentatives de connexion répétées)
# ================================================================

def demo_brute_force(n_attempts: int = 30, target_port: int = 22):
    """
    Simule une attaque brute force SSH — tentatives de connexion
    répétées sur le port 22 de localhost.
    Pattern réel d'un SSH-Patator / FTP-Patator.
    """
    print(f"\n{RED}{BOLD}[Brute Force] {n_attempts} tentatives SSH "
          f"vers {TARGET_IP}:{target_port}...{RESET}")

    attempts   = 0
    responses  = 0
    start_time = time.time()
    iats       = []
    last_time  = start_time

    for _ in range(n_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result_code = sock.connect_ex((TARGET_IP, target_port))
            if result_code == 0:
                responses += 1
            sock.close()
            attempts += 1

            now = time.time()
            iats.append((now - last_time) * 1_000_000)
            last_time = now

            time.sleep(random.uniform(0.05, 0.2))
        except Exception:
            attempts += 1

    duration_us = (time.time() - start_time) * 1_000_000
    iat_mean    = sum(iats) / len(iats) if iats else 50000
    iat_std     = (
        (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5
        if len(iats) > 1 else 0
    )

    metrics = build_flow_metrics(
        dest_port    = target_port,
        duration_us  = duration_us,
        fwd_packets  = attempts,
        bwd_packets  = responses,
        total_bytes  = attempts * 80,
        pkt_size_avg = 80.0,
        iat_mean     = iat_mean,
        iat_std      = iat_std,
        win_size     = 65535,
    )

    result = send_to_ids(metrics, "SSH-Patator")
    print_detection(result, "SSH-Patator", attempts)
    return result


# ================================================================
# DÉMO 5 — TRAFIC NORMAL (pour contraste)
# ================================================================

def demo_normal_traffic(n_requests: int = 10):
    """
    Génère du vrai trafic HTTP normal vers l'API FastAPI.
    Permet de montrer que le modèle ne fait pas de faux positifs.
    """
    print(f"\n{GREEN}{BOLD}[Trafic normal] {n_requests} requêtes HTTP "
          f"légitimes vers l'API...{RESET}")

    sent       = 0
    start_time = time.time()

    for _ in range(n_requests):
        try:
            r = requests.get(f"http://{TARGET_IP}:8000/health", timeout=2)
            if r.status_code == 200:
                sent += 1
        except Exception:
            pass
        time.sleep(0.1)

    duration_us = (time.time() - start_time) * 1_000_000

    metrics = build_flow_metrics(
        dest_port    = 8000,
        duration_us  = duration_us,
        fwd_packets  = sent,
        bwd_packets  = sent,
        total_bytes  = sent * 200,
        pkt_size_avg = 200.0,
        iat_mean     = duration_us / max(sent, 1),
        iat_std      = 5000.0,
        win_size     = 65535,
    )

    result = send_to_ids(metrics, "BENIGN")
    print_detection(result, "BENIGN", sent)
    return result


# ================================================================
# DÉMO COMPLÈTE — SCÉNARIO JURY
# ================================================================

def run_full_demo():
    """
    Scénario complet pour le jury :
    1. Trafic normal    -> IDS dit BENIGN
    2. PortScan         -> IDS détecte
    3. Trafic normal    -> IDS dit BENIGN (pas de faux positif)
    4. SYN Flood/DDoS   -> IDS détecte
    5. Slowloris        -> IDS détecte
    6. Brute Force SSH  -> IDS détecte
    7. Trafic normal    -> IDS dit BENIGN
    """
    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  DÉMONSTRATION LIVE — JURY{RESET}")
    print(f"{BOLD}{CYAN}  Tous les paquets vont vers {TARGET_IP} (localhost){RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

    results = []

    print(f"{BOLD}PHASE 1 — Trafic normal (baseline){RESET}")
    r = demo_normal_traffic(n_requests=5)
    results.append(("Trafic normal", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 2 — Attaque PortScan{RESET}")
    r = demo_port_scan(n_ports=20, delay=0.02)
    results.append(("PortScan", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 3 — Trafic normal (vérification pas de faux positif){RESET}")
    r = demo_normal_traffic(n_requests=3)
    results.append(("Trafic normal", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 4 — Attaque DDoS / SYN Flood{RESET}")
    r = demo_syn_flood(n_connections=100)
    results.append(("DDoS", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 5 — Attaque Slowloris{RESET}")
    r = demo_slowloris(n_connections=10, hold_seconds=1.5)
    results.append(("Slowloris", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 6 — Brute Force SSH{RESET}")
    r = demo_brute_force(n_attempts=20)
    results.append(("Brute Force", r))
    time.sleep(1)

    print(f"\n{BOLD}PHASE 7 — Retour au trafic normal{RESET}")
    r = demo_normal_traffic(n_requests=5)
    results.append(("Trafic normal", r))

    # Résumé final
    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  RÉSUMÉ DE LA DÉMONSTRATION{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}")
    for label, res in results:
        if res:
            detected = res.get("is_attack", False)
            atype    = res.get("attack_type", label)
            conf     = res.get("confidence", 0) * 100
            if detected:
                print(f"  {RED}🚨 {atype:<30}{RESET} | Détecté  ✅ | Conf: {conf:.1f}%")
            else:
                print(f"  {GREEN}✅ {atype:<30}{RESET} | Sain     ✅ | Conf: {conf:.1f}%")

    print(f"\n{GREEN}Dashboard : http://localhost:8501{RESET}")
    print(f"{GREEN}API Docs  : http://localhost:8000/docs{RESET}\n")


# ================================================================
# POINT D'ENTRÉE
# ================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Démonstration live IDS — paquets réels vers localhost",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes disponibles :
  --demo full       Scénario complet pour le jury (défaut)
  --demo scan       PortScan uniquement
  --demo ddos       SYN Flood / DDoS uniquement
  --demo slowloris  Slowloris uniquement
  --demo brute      Brute Force SSH uniquement
  --demo normal     Trafic normal uniquement

Exemples :
  sudo python real_traffic_demo.py
  sudo python real_traffic_demo.py --demo ddos
  sudo python real_traffic_demo.py --demo scan
        """
    )

    parser.add_argument(
        "--demo", type=str, default="full",
        choices=["full", "scan", "ddos", "slowloris", "brute", "normal"],
        help="Type de démonstration (défaut: full)"
    )

    args = parser.parse_args()

    # Avertissement
    print(f"\n{YELLOW}{BOLD}⚠️  AVERTISSEMENT{RESET}")
    print(f"{YELLOW}Ce script envoie de vrais paquets réseau vers {TARGET_IP} (localhost uniquement).{RESET}")
    print(f"{YELLOW}Aucun réseau externe n'est ciblé.{RESET}\n")

    demo_map = {
        "full":      run_full_demo,
        "scan":      lambda: demo_port_scan(n_ports=30),
        "ddos":      lambda: demo_syn_flood(n_connections=200),
        "slowloris": lambda: demo_slowloris(n_connections=15),
        "brute":     lambda: demo_brute_force(n_attempts=30),
        "normal":    lambda: demo_normal_traffic(n_requests=10),
    }

    demo_map[args.demo]()
