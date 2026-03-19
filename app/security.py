from app.config import *

def detect_behavior(packets_s, ratio, flow):

    is_ddos = (
        packets_s > CRITICAL_PACKET_RATE and
        flow.total_bwd_packets == 0
    )

    is_scan = (
        packets_s > SUSPICIOUS_PACKET_RATE and
        (ratio > 10 or ratio < 0.1)
    )

    is_bruteforce = (
        flow.destination_port in [21, 22, 23] and
        packets_s > 10000 and
        ratio > 5
    )

    return is_ddos, is_scan, is_bruteforce


def compute_risk(verdict, confidence, is_ddos, is_scan, is_bruteforce):

    if is_ddos:
        return "CRITICAL"

    if verdict != "BENIGN":
        if confidence >= THRESHOLD_HIGH:
            return "HIGH"
        elif confidence >= THRESHOLD_LOW:
            return "MEDIUM"
        else:
            return "LOW"

    if is_scan or is_bruteforce:
        return "MEDIUM"

    return "LOW"


def decide_action(verdict, risk):

    if risk == "CRITICAL":
        return "BLOCK"

    if verdict != "BENIGN":
        if risk == "HIGH":
            return "BLOCK"
        elif risk == "MEDIUM":
            return "ALERT"
        else:
            return "MONITOR"

    if risk == "MEDIUM":
        return "ALERT"

    return "ALLOW"


def compute_score(packets_s, ratio, confidence):

    score = (
        (packets_s / 1_000_000) * 40 +
        abs(ratio - 1) * 20 +
        (1 - confidence) * 40
    )

    return min(100, int(score))