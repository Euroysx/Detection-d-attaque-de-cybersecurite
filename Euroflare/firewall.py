"""
EUROFLARE IDS v3 — Module Firewall & Routeur
=============================================
Blocage reseau reel via iptables (Linux), netsh (Windows),
et integration routeur via SSH (Cisco/MikroTik/pfSense API).

Utilisation standalone :
    python firewall.py block 192.168.1.100
    python firewall.py unblock 192.168.1.100
    python firewall.py list
    python firewall.py flush

Utilisation depuis main.py (FastAPI) :
    from firewall import FirewallManager
    fw = FirewallManager()
    fw.block_ip("192.168.1.100", reason="DDoS detected", severity="CRITICAL")
"""

import subprocess
import platform
import logging
import sqlite3
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional
import ipaddress

# ── Config ───────────────────────────────────────────────────────────────────

DB_PATH      = os.getenv("BLOCK_DB_PATH", "./blocked_ips.db")
LOG_PATH     = os.getenv("FW_LOG_PATH",   "./firewall.log")
CHAIN_NAME   = "EUROFLARE_BLOCK"          # chaine iptables dediee
ROUTER_HOST  = os.getenv("ROUTER_HOST",  "")   # IP du routeur (optionnel)
ROUTER_USER  = os.getenv("ROUTER_USER",  "admin")
ROUTER_PASS  = os.getenv("ROUTER_PASS",  "")
ROUTER_TYPE  = os.getenv("ROUTER_TYPE",  "mikrotik")  # cisco | mikrotik | pfsense

OS = platform.system()  # "Linux", "Windows", "Darwin"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FIREWALL] %(levelname)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("euroflare.firewall")

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Evite de bloquer des IPs du reseau interne par accident."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def run(cmd: list[str], check=True) -> tuple[int, str, str]:
    """Execute une commande systeme et retourne (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        log.error(f"Timeout sur commande : {' '.join(cmd)}")
        return 1, "", "timeout"
    except FileNotFoundError:
        log.error(f"Commande introuvable : {cmd[0]}")
        return 1, "", f"{cmd[0]} not found"

# ════════════════════════════════════════════════════════════════════════════
# BASE DE DONNEES — persistance des IPs bloquees
# ════════════════════════════════════════════════════════════════════════════

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            reason      TEXT,
            severity    TEXT DEFAULT 'HIGH',
            blocked_at  TEXT,
            attack_count INTEGER DEFAULT 1,
            auto_block  INTEGER DEFAULT 0,
            router_sent INTEGER DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS block_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            action     TEXT,
            ip         TEXT,
            method     TEXT,
            success    INTEGER,
            detail     TEXT,
            ts         TEXT
        )
    """)
    con.commit()
    con.close()

def db_add(ip, reason, severity, auto=False):
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT INTO blocked_ips (ip, reason, severity, blocked_at, auto_block)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            attack_count = attack_count + 1,
            severity     = excluded.severity,
            reason       = excluded.reason,
            blocked_at   = excluded.blocked_at
    """, (ip, reason, severity, datetime.utcnow().isoformat(), int(auto)))
    con.commit(); con.close()

def db_remove(ip):
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    con.commit(); con.close()

def db_list() -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT ip, reason, severity, blocked_at, attack_count, auto_block FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    con.close()
    return [{"ip":r[0],"reason":r[1],"severity":r[2],"blocked_at":r[3],"count":r[4],"auto":bool(r[5])} for r in rows]

def db_log(action, ip, method, success, detail=""):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute(
            "INSERT INTO block_log (action,ip,method,success,detail,ts) VALUES (?,?,?,?,?,?)",
            (action, ip, method, int(success), detail, datetime.utcnow().isoformat())
        )
        con.commit(); con.close()
    except Exception:
        pass

def is_blocked(ip: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    con.close()
    return row is not None

# ════════════════════════════════════════════════════════════════════════════
# IPTABLES — Linux
# ════════════════════════════════════════════════════════════════════════════

class IPTablesFirewall:
    """Bloque les IPs via iptables sur Linux en utilisant une chaine dediee."""

    def setup_chain(self):
        """Cree la chaine EUROFLARE_BLOCK si elle n'existe pas encore."""
        # Verifier si la chaine existe
        code, _, _ = run(["iptables", "-L", CHAIN_NAME, "-n"], check=False)
        if code != 0:
            run(["iptables", "-N", CHAIN_NAME])
            # Lier la chaine a INPUT et FORWARD
            run(["iptables", "-I", "INPUT",   "-j", CHAIN_NAME])
            run(["iptables", "-I", "FORWARD", "-j", CHAIN_NAME])
            log.info(f"Chaine iptables '{CHAIN_NAME}' creee et liee a INPUT/FORWARD")

    def block(self, ip: str) -> bool:
        self.setup_chain()
        # Verifier si la regle existe deja
        code, out, _ = run(["iptables", "-C", CHAIN_NAME, "-s", ip, "-j", "DROP"], check=False)
        if code == 0:
            log.info(f"[iptables] {ip} deja bloque")
            return True
        code, out, err = run(["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
        success = code == 0
        if success:
            log.info(f"[iptables] BLOQUE : {ip}")
        else:
            log.error(f"[iptables] ERREUR blocage {ip} : {err}")
        db_log("block", ip, "iptables", success, err if not success else "")
        return success

    def unblock(self, ip: str) -> bool:
        code, _, err = run(["iptables", "-D", CHAIN_NAME, "-s", ip, "-j", "DROP"], check=False)
        success = code == 0
        if success:
            log.info(f"[iptables] DEBLOQUE : {ip}")
        else:
            log.warning(f"[iptables] Regle non trouvee pour {ip} (deja retiree ?)")
        db_log("unblock", ip, "iptables", success)
        return success

    def flush(self):
        """Supprime toutes les regles de la chaine EUROFLARE_BLOCK."""
        run(["iptables", "-F", CHAIN_NAME], check=False)
        log.info(f"[iptables] Chaine {CHAIN_NAME} videe")

    def list_blocked(self) -> list[str]:
        _, out, _ = run(["iptables", "-L", CHAIN_NAME, "-n", "--line-numbers"], check=False)
        ips = []
        for line in out.splitlines():
            parts = line.split()
            # Format : num  DROP  all  --  IP  0.0.0.0/0
            if len(parts) >= 5 and parts[1] == "DROP":
                ips.append(parts[4])
        return ips

    def save_rules(self):
        """Persiste les regles iptables pour survie au reboot."""
        if os.path.exists("/etc/debian_version"):
            run(["iptables-save", "-f", "/etc/iptables/rules.v4"], check=False)
        elif os.path.exists("/etc/redhat-release"):
            run(["service", "iptables", "save"], check=False)
        log.info("[iptables] Regles sauvegardees")


# ════════════════════════════════════════════════════════════════════════════
# NETSH / WINDOWS FIREWALL
# ════════════════════════════════════════════════════════════════════════════

class WindowsFirewall:
    """Bloque les IPs via Windows Defender Firewall (netsh advfirewall)."""

    def _rule_name(self, ip: str) -> str:
        return f"EUROFLARE_BLOCK_{ip.replace('.', '_')}"

    def block(self, ip: str) -> bool:
        name = self._rule_name(ip)
        # Supprimer d'abord si existe (idempotent)
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], check=False)
        code, _, err = run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "enable=yes", "profile=any"
        ])
        success = code == 0
        if success:
            # Aussi bloquer en sortie
            run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}_OUT",
                "dir=out", "action=block",
                f"remoteip={ip}",
                "enable=yes", "profile=any"
            ], check=False)
            log.info(f"[netsh] BLOQUE : {ip}")
        else:
            log.error(f"[netsh] ERREUR blocage {ip} : {err}")
        db_log("block", ip, "netsh", success, err if not success else "")
        return success

    def unblock(self, ip: str) -> bool:
        name = self._rule_name(ip)
        code1, _, _ = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],        check=False)
        code2, _, _ = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}_OUT"],    check=False)
        success = code1 == 0 or code2 == 0
        log.info(f"[netsh] {'DEBLOQUE' if success else 'NON TROUVE'} : {ip}")
        db_log("unblock", ip, "netsh", success)
        return success

    def flush(self):
        """Supprime toutes les regles EUROFLARE_BLOCK."""
        _, out, _ = run(["netsh", "advfirewall", "firewall", "show", "rule", "name=EUROFLARE_BLOCK*"], check=False)
        # Simple : supprimer par prefixe de nom
        for line in out.splitlines():
            if line.startswith("Rule Name:") and "EUROFLARE_BLOCK" in line:
                name = line.split(":", 1)[1].strip()
                run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], check=False)
        log.info("[netsh] Toutes les regles EUROFLARE_BLOCK supprimees")

    def list_blocked(self) -> list[str]:
        _, out, _ = run(["netsh", "advfirewall", "firewall", "show", "rule", "name=EUROFLARE_BLOCK*"], check=False)
        ips = []
        current_ip = None
        for line in out.splitlines():
            if "RemoteIP:" in line:
                ip = line.split(":", 1)[1].strip()
                if ip and ip not in ips:
                    ips.append(ip)
        return ips


# ════════════════════════════════════════════════════════════════════════════
# ROUTEUR SSH — Cisco IOS / MikroTik RouterOS
# ════════════════════════════════════════════════════════════════════════════

class RouterFirewall:
    """
    Bloque les IPs directement sur le routeur via SSH.
    Supporte : Cisco IOS, MikroTik RouterOS, pfSense via API REST.
    Necessite : pip install paramiko requests
    """

    def __init__(self, host=ROUTER_HOST, user=ROUTER_USER, password=ROUTER_PASS, router_type=ROUTER_TYPE):
        self.host        = host
        self.user        = user
        self.password    = password
        self.router_type = router_type

    def _ssh_exec(self, commands: list[str]) -> tuple[bool, str]:
        """Execute des commandes SSH sur le routeur."""
        try:
            import paramiko
        except ImportError:
            log.error("paramiko non installe : pip install paramiko")
            return False, "paramiko missing"

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password, timeout=10)
            output = []
            for cmd in commands:
                _, stdout, stderr = client.exec_command(cmd)
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                if out: output.append(out)
                if err: output.append(f"ERR: {err}")
                time.sleep(0.3)
            client.close()
            return True, "\n".join(output)
        except Exception as e:
            log.error(f"[SSH Router] Erreur connexion {self.host} : {e}")
            return False, str(e)

    def block_cisco(self, ip: str) -> bool:
        """
        Cisco IOS — ajoute une ACL de blocage.
        Necessite une ACL nommee 'EUROFLARE_BLOCK' existante sur le routeur.
        Commande : ip access-list extended EUROFLARE_BLOCK / deny ip host <IP> any
        """
        commands = [
            "configure terminal",
            "ip access-list extended EUROFLARE_BLOCK",
            f"deny ip host {ip} any",
            f"deny ip any host {ip}",
            "exit",
            "exit",
            "write memory",  # Sauvegarde la config
        ]
        success, out = self._ssh_exec(commands)
        log.info(f"[Cisco] {'BLOQUE' if success else 'ERREUR'} : {ip} | {out[:100]}")
        db_log("block", ip, "cisco_ssh", success, out[:200])
        return success

    def unblock_cisco(self, ip: str) -> bool:
        commands = [
            "configure terminal",
            "ip access-list extended EUROFLARE_BLOCK",
            f"no deny ip host {ip} any",
            f"no deny ip any host {ip}",
            "exit",
            "exit",
            "write memory",
        ]
        success, out = self._ssh_exec(commands)
        log.info(f"[Cisco] {'DEBLOQUE' if success else 'ERREUR'} : {ip}")
        db_log("unblock", ip, "cisco_ssh", success)
        return success

    def block_mikrotik(self, ip: str) -> bool:
        """
        MikroTik RouterOS — ajoute une regle dans IP Firewall Filter.
        Bloque en input ET forward pour couvrir trafic vers routeur et reseau.
        """
        commands = [
            # Bloquer en entree (trafic vers le routeur lui-meme)
            f'/ip firewall filter add chain=input src-address={ip} action=drop comment="EUROFLARE_BLOCK_{ip}"',
            # Bloquer en transit (trafic vers le LAN)
            f'/ip firewall filter add chain=forward src-address={ip} action=drop comment="EUROFLARE_BLOCK_{ip}"',
        ]
        success, out = self._ssh_exec(commands)
        log.info(f"[MikroTik] {'BLOQUE' if success else 'ERREUR'} : {ip} | {out[:100]}")
        db_log("block", ip, "mikrotik_ssh", success, out[:200])
        return success

    def unblock_mikrotik(self, ip: str) -> bool:
        """Supprime les regles MikroTik correspondant a l'IP."""
        # D'abord trouver les IDs des regles
        find_cmd = f'/ip firewall filter print where comment="EUROFLARE_BLOCK_{ip}"'
        success_find, out = self._ssh_exec([find_cmd])
        if not success_find:
            return False
        # Supprimer par commentaire
        remove_cmd = f'/ip firewall filter remove [find comment="EUROFLARE_BLOCK_{ip}"]'
        success, out = self._ssh_exec([remove_cmd])
        log.info(f"[MikroTik] {'DEBLOQUE' if success else 'ERREUR'} : {ip}")
        db_log("unblock", ip, "mikrotik_ssh", success)
        return success

    def block_pfsense(self, ip: str) -> bool:
        """
        pfSense — utilise l'API REST fauxapi ou pfSense-API.
        Necessite : pip install requests
        Configure PFSENSE_HOST, PFSENSE_KEY, PFSENSE_SECRET en env vars.
        """
        try:
            import requests
        except ImportError:
            log.error("requests non installe : pip install requests")
            return False

        pfsense_host   = os.getenv("PFSENSE_HOST", self.host)
        pfsense_key    = os.getenv("PFSENSE_KEY",  "")
        pfsense_secret = os.getenv("PFSENSE_SECRET", "")

        if not pfsense_key:
            log.error("[pfSense] PFSENSE_KEY non configure")
            return False

        # pfSense API v1 — endpoint firewall rules
        url = f"https://{pfsense_host}/api/v1/firewall/rule"
        headers = {"Authorization": f"{pfsense_key} {pfsense_secret}", "Content-Type": "application/json"}
        payload = {
            "type": "block",
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "any",
            "src": ip,
            "dst": "any",
            "descr": f"EUROFLARE_BLOCK_{ip}",
            "top": True,  # Inserer en haut des regles
        }

        try:
            resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
            success = resp.status_code in (200, 201)
            log.info(f"[pfSense] {'BLOQUE' if success else 'ERREUR'} : {ip} | HTTP {resp.status_code}")
            db_log("block", ip, "pfsense_api", success, resp.text[:200])

            if success:
                # Appliquer les changements (pfSense necessite un apply)
                requests.post(f"https://{pfsense_host}/api/v1/firewall/apply",
                              headers=headers, verify=False, timeout=10)
            return success
        except Exception as e:
            log.error(f"[pfSense] Exception : {e}")
            db_log("block", ip, "pfsense_api", False, str(e))
            return False

    def block(self, ip: str) -> bool:
        if not self.host:
            return False
        if self.router_type == "cisco":
            return self.block_cisco(ip)
        elif self.router_type == "mikrotik":
            return self.block_mikrotik(ip)
        elif self.router_type == "pfsense":
            return self.block_pfsense(ip)
        else:
            log.error(f"Type de routeur inconnu : {self.router_type}")
            return False

    def unblock(self, ip: str) -> bool:
        if not self.host:
            return False
        if self.router_type == "cisco":
            return self.unblock_cisco(ip)
        elif self.router_type == "mikrotik":
            return self.unblock_mikrotik(ip)
        else:
            return False


# ════════════════════════════════════════════════════════════════════════════
# FIREWALL MANAGER — facade unifiee
# ════════════════════════════════════════════════════════════════════════════

class FirewallManager:
    """
    Interface unifiee qui choisit automatiquement le bon backend
    selon le systeme d'exploitation et la configuration.

    Utilisation depuis main.py FastAPI :

        from firewall import FirewallManager
        fw = FirewallManager()

        # Bloquer automatiquement apres detection
        fw.block_ip("1.2.3.4", reason="DDoS detected", severity="CRITICAL")

        # Retirer du blocage
        fw.unblock_ip("1.2.3.4")

        # Recharger toutes les IPs bloquees au demarrage
        fw.restore_all_rules()
    """

    def __init__(self):
        init_db()
        if OS == "Linux":
            self.local   = IPTablesFirewall()
            log.info("Backend local : iptables (Linux)")
        elif OS == "Windows":
            self.local   = WindowsFirewall()
            log.info("Backend local : netsh (Windows)")
        else:
            self.local   = None
            log.warning(f"OS non supporte pour blocage local : {OS}")

        self.router = RouterFirewall() if ROUTER_HOST else None
        if self.router:
            log.info(f"Backend routeur : {ROUTER_TYPE} @ {ROUTER_HOST}")

    def block_ip(self, ip: str, reason: str = "IDS detection", severity: str = "HIGH", auto: bool = True) -> dict:
        """
        Bloque une IP sur le pare-feu local ET sur le routeur si configure.
        Retourne un dict avec le statut de chaque methode.
        """
        result = {"ip": ip, "local": False, "router": False, "already_blocked": False}

        # Verifier si deja bloquee
        if is_blocked(ip):
            result["already_blocked"] = True
            log.info(f"[Manager] {ip} deja dans la blacklist")
            return result

        # Protection : ne pas bloquer les IPs privees par erreur
        if is_private_ip(ip):
            log.warning(f"[Manager] REFUSE : {ip} est une IP privee — blocage ignore")
            result["error"] = "private_ip"
            return result

        # Bloquer en local
        if self.local:
            result["local"] = self.local.block(ip)

        # Bloquer sur le routeur
        if self.router:
            result["router"] = self.router.block(ip)

        # Sauvegarder en base si au moins un blocage a reussi
        if result["local"] or result["router"]:
            db_add(ip, reason, severity, auto)
            log.info(f"[Manager] IP BLOQUEE : {ip} | raison={reason} | sev={severity} | local={result['local']} | router={result['router']}")

            # Sauvegarder les regles iptables (survie au reboot)
            if OS == "Linux" and result["local"]:
                self.local.save_rules()
        else:
            log.error(f"[Manager] ECHEC blocage {ip} — aucune methode n'a reussi")

        return result

    def unblock_ip(self, ip: str) -> dict:
        """Retire le blocage d'une IP partout."""
        result = {"ip": ip, "local": False, "router": False}

        if self.local:
            result["local"] = self.local.unblock(ip)
        if self.router:
            result["router"] = self.router.unblock(ip)

        db_remove(ip)
        log.info(f"[Manager] IP DEBLOQUEE : {ip} | local={result['local']} | router={result['router']}")
        return result

    def restore_all_rules(self):
        """
        Reapplique toutes les regles depuis la base de donnees.
        A appeler au demarrage de l'API pour restaurer l'etat apres reboot.
        """
        blocked = db_list()
        log.info(f"[Manager] Restauration de {len(blocked)} IP(s) bloquee(s)...")
        for entry in blocked:
            ip = entry["ip"]
            if self.local:
                self.local.block(ip)
            if self.router:
                self.router.block(ip)
        log.info("[Manager] Restauration terminee")

    def get_all_blocked(self) -> list[dict]:
        """Retourne toutes les IPs bloquees avec leurs details."""
        return db_list()

    def flush_all(self):
        """Supprime TOUS les blocages — utiliser avec precaution."""
        if self.local:
            self.local.flush()
        # Vider la base
        con = sqlite3.connect(DB_PATH)
        con.execute("DELETE FROM blocked_ips")
        con.commit(); con.close()
        log.warning("[Manager] TOUS les blocages ont ete supprimes")

    def auto_block_on_detection(self, ip: str, attack_type: str, severity: str, confidence: float):
        """
        Bloc automatique selon des regles de severite.
        A appeler depuis l'endpoint /predict de l'API apres chaque detection.

        Regles :
        - CRITICAL + confiance > 90% → blocage automatique immediat
        - HIGH     + confiance > 95% → blocage automatique
        - Meme IP vue 5 fois ou plus → blocage automatique quelle que soit la severite
        """
        # Compter les occurrences de cette IP
        con = sqlite3.connect(DB_PATH)
        row = con.execute("SELECT attack_count FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
        con.close()
        occurrence = row[0] if row else 0

        should_block = False
        reason_auto  = ""

        if severity == "CRITICAL" and confidence >= 0.90:
            should_block = True
            reason_auto  = f"Auto-block: {attack_type} CRITICAL conf={confidence:.2f}"
        elif severity == "HIGH" and confidence >= 0.95:
            should_block = True
            reason_auto  = f"Auto-block: {attack_type} HIGH conf={confidence:.2f}"
        elif occurrence >= 4:
            should_block = True
            reason_auto  = f"Auto-block: {occurrence+1} attaques repetees depuis cette IP"

        if should_block and not is_blocked(ip):
            log.warning(f"[AUTO-BLOCK] {ip} → {reason_auto}")
            return self.block_ip(ip, reason=reason_auto, severity=severity, auto=True)

        return None


# ════════════════════════════════════════════════════════════════════════════
# INTEGRATION main.py — exemple de code a ajouter dans l'API FastAPI
# ════════════════════════════════════════════════════════════════════════════
"""
Dans main.py, ajouter apres les imports existants :

    from firewall import FirewallManager
    fw = FirewallManager()

Dans init_db() ou au demarrage de l'app :

    fw.restore_all_rules()  # Restaurer les regles apres reboot

Dans l'endpoint /predict, apres la prediction :

    if result["is_attack"]:
        fw.auto_block_on_detection(
            ip        = data.source_ip,
            attack_type = result["attack_type"],
            severity    = result["severity"],
            confidence  = result["confidence"]
        )

Dans l'endpoint POST /attacker-ips/{ip}/blacklist :

    @app.post("/attacker-ips/{ip}/blacklist")
    def blacklist_ip(ip: str):
        result = fw.block_ip(ip, reason="Manual blacklist", severity="HIGH", auto=False)
        return result

Dans l'endpoint DELETE /attacker-ips/{ip}/blacklist :

    @app.delete("/attacker-ips/{ip}/blacklist")
    def unblacklist_ip(ip: str):
        result = fw.unblock_ip(ip)
        return result
"""


# ════════════════════════════════════════════════════════════════════════════
# CLI — utilisation standalone
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="EUROFLARE Firewall Manager — blocage reseau reel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python firewall.py block 1.2.3.4
  python firewall.py block 1.2.3.4 --reason "DDoS detected" --severity CRITICAL
  python firewall.py unblock 1.2.3.4
  python firewall.py list
  python firewall.py flush
  python firewall.py restore
        """
    )
    parser.add_argument("action", choices=["block","unblock","list","flush","restore"])
    parser.add_argument("ip",     nargs="?",  default=None)
    parser.add_argument("--reason",   default="Manual block via CLI")
    parser.add_argument("--severity", default="HIGH", choices=["INFO","MEDIUM","HIGH","CRITICAL"])
    args = parser.parse_args()

    fw = FirewallManager()

    if args.action == "block":
        if not args.ip:
            print("Erreur : IP requise pour block")
            sys.exit(1)
        result = fw.block_ip(args.ip, reason=args.reason, severity=args.severity, auto=False)
        print(f"\nResultat : {json.dumps(result, indent=2)}")

    elif args.action == "unblock":
        if not args.ip:
            print("Erreur : IP requise pour unblock")
            sys.exit(1)
        result = fw.unblock_ip(args.ip)
        print(f"\nResultat : {json.dumps(result, indent=2)}")

    elif args.action == "list":
        blocked = fw.get_all_blocked()
        if not blocked:
            print("\nAucune IP bloquee.")
        else:
            print(f"\n{len(blocked)} IP(s) bloquee(s) :\n")
            print(f"{'IP':<18} {'Severite':<10} {'Auto':<6} {'Attaques':<10} {'Date'}")
            print("-" * 70)
            for e in blocked:
                auto = "Oui" if e["auto"] else "Non"
                print(f"{e['ip']:<18} {e['severity']:<10} {auto:<6} {e['count']:<10} {e['blocked_at'][:19]}")
            print()

    elif args.action == "flush":
        confirm = input("ATTENTION : Cela supprime TOUS les blocages. Confirmer ? (oui/non) : ")
        if confirm.lower() == "oui":
            fw.flush_all()
            print("Tous les blocages supprimes.")
        else:
            print("Annule.")

    elif args.action == "restore":
        fw.restore_all_rules()
        print("Regles restaurees depuis la base de donnees.")
