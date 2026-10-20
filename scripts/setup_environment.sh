#!/usr/bin/env bash
# ==============================================================================
# Script: setup_environment.sh
# Purpose: Automated Provisioning & Hardening for SSH Honeypot VM
# Target OS: Ubuntu 22.04 LTS
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Starting Enterprise SSH Honeypot Environment Setup...${NC}"

# 1. Verify Sudo Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run this script with sudo or as root.${NC}"
    exit 1
fi

# 2. System Packages & Prerequisites
echo -e "${GREEN}[+] Updating system packages and installing prerequisites...${NC}"
apt-get update -y && apt-get upgrade -y
apt-get install -y \
    curl \
    git \
    ufw \
    iptables \
    iptables-persistent \
    python3 \
    python3-pip \
    python3-venv \
    jq

# 3. Docker Installation
if ! command -v docker &> /dev/null; then
    echo -e "${GREEN}[+] Installing Docker CE...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm -f get-docker.sh
    systemctl enable --now docker
    
    # Add non-root user to docker group if running under sudo
    REAL_USER="${SUDO_USER:-$USER}"
    if [ "$REAL_USER" != "root" ]; then
        usermod -aG docker "$REAL_USER"
        echo -e "${YELLOW}[!] User '${REAL_USER}' added to docker group. Please log out and back in for this to take full effect.${NC}"
    fi
else
    echo -e "${BLUE}[i] Docker is already installed.${NC}"
fi

# 4. Prepare Local Data Directories & Permissions
echo -e "${GREEN}[+] Initializing persistent telemetry directories...${NC}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$PROJECT_ROOT/data/logs"
mkdir -p "$PROJECT_ROOT/data/downloads"
mkdir -p "$PROJECT_ROOT/data/tty"

# Cowrie inside container runs as UID 1000 by default
chown -R 1000:1000 "$PROJECT_ROOT/data"
chmod -R 775 "$PROJECT_ROOT/data"

# 5. Python Analytics Environment Setup
echo -e "${GREEN}[+] Setting up Python virtual environment for Threat Intelligence parsing...${NC}"
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    python3 -m venv "$PROJECT_ROOT/.venv"
fi
"$PROJECT_ROOT/.venv/bin/pip" install --upgrade pip
"$PROJECT_ROOT/.venv/bin/pip" install -r "$PROJECT_ROOT/requirements.txt"

# 6. Network Security & Firewall Guidance
echo -e "${BLUE}===================================================================${NC}"
echo -e "${GREEN}[✔] Environment Provisioning Complete!${NC}"
echo -e "${YELLOW}[!] CRITICAL OPERATIONAL STEP FOR HOST SSH:${NC}"
echo -e "By default, Cowrie listens on port 2222."
echo -e "If you want real attackers on port 22 to hit Cowrie without losing host access:"
echo -e "  1. Move the real Ubuntu SSH daemon to port 22222 (edit /etc/ssh/sshd_config)."
echo -e "  2. Restart sshd: systemctl restart ssh"
echo -e "  3. Redirect external port 22 to Cowrie container port 2222 via iptables:"
echo -e "     sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
echo -e "===================================================================${NC}"
