# Phase 1 & 2: Environment Deployment & Hardening Guide

## 1. Overview
This guide provides an end-to-end operational walkthrough to provision an isolated Linux Virtual Machine (VM), install Docker, deploy Cowrie using Docker Compose, and establish monitoring pipelines.

---

## 2. Infrastructure Prerequisites
- **Host OS:** Windows 10/11 or macOS with VirtualBox 7.x installed.
- **Virtual Machine:** Ubuntu Server 22.04 LTS (Minimal installation).
- **Compute Specs:** 2 vCPUs, 2048 MB RAM, 20 GB dynamically allocated disk.
- **Network Configuration:**
  - **Adapter 1 (NAT):** Outbound internet access to pull containers and packages.
  - **Adapter 2 (Host-Only):** Secure, isolated host-to-guest administrative SSH access (e.g., `192.168.56.x`).

---

## 3. Host System & VM Provisioning

### Step 3.1: VM Operating System Installation
1. Boot Ubuntu Server ISO and select standard minimal installation.
2. Configure default administrator account:
   - User: `honeypot`
   - Hostname: `honeypot-sensor-01`
3. Enable `Install OpenSSH server`.
4. After initial boot, verify network interfaces:
   ```bash
   ip a
   ```

### Step 3.2: Automated Provisioning via Setup Script
Clone this repository inside the Ubuntu VM and execute the provisioning script:
```bash
git clone https://github.com/secbymorchid/ssh-honeypot-project.git
cd ssh-honeypot-project
chmod +x scripts/*.sh
sudo ./scripts/setup_environment.sh
```

The script will automatically:
- Install system security tools (`ufw`, `iptables-persistent`, `jq`, `python3-venv`).
- Install Docker Engine & Docker Compose plugin.
- Configure local directories (`data/logs`, `data/downloads`, `data/tty`) with proper permissions (UID 1000).
- Initialize the Python virtual environment with required dependencies.

---

## 4. SSH Port Redirection & Hardening

To capture external attackers scanning standard port 22 while preserving administrative access to your real Ubuntu host:

### Step 4.1: Relocate Host SSH Daemon
1. Edit the OpenSSH daemon configuration:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
2. Change the default port:
   ```text
   Port 22222
   ```
3. Restart OpenSSH:
   ```bash
   sudo systemctl restart ssh
   ```
4. Verify you can connect on port 22222:
   ```bash
   ssh -p 22222 honeypot@<VM_IP>
   ```

### Step 4.2: Redirect Port 22 to Cowrie (Port 2222)
Route inbound connections destined for standard SSH port 22 to the Cowrie honeypot container listening on port 2222:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo netfilter-persistent save
```

---

## 5. Honeypot Stack Deployment

Launch the Cowrie container using Docker Compose:
```bash
docker compose up -d
```

### Verification & Health Checks
1. Inspect running status:
   ```bash
   docker compose ps
   ```
2. Monitor real-time Cowrie logs:
   ```bash
   docker compose logs -f cowrie
   ```
3. Test local honeypot connectivity:
   ```bash
   ssh -p 2222 root@localhost
   ```
   *(Password: `root` or `123456` as defined in `config/userdb.txt`)*

---

## 6. Automated Attack Simulation (Testing Pipeline)

To validate the logging, detection, and analytics pipeline without exposing the sensor to the public internet, run the automated adversary simulation script:

```bash
chmod +x scripts/simulate_attack.sh
./scripts/simulate_attack.sh 127.0.0.1 2222
```

This script emulates real-world attack stages:
1. **Credential Spraying (T1110.001):** High-velocity password guessing against common administrative accounts.
2. **Honey Account Compromise (T1078):** Successful authentication using credentials seeded in `config/userdb.txt`.
3. **Environmental Discovery (T1082, T1033, T1016):** Execution of discovery commands (`uname -a`, `cat /proc/cpuinfo`, `id`, `ifconfig`).
4. **Malware Staging & Anti-Forensics (T1105, T1070.004):** Simulated dropper retrieval (`wget`) and log tampering commands (`history -c`).

---

## 7. Telemetry Processing & Report Generation

Once traffic has been captured in `data/logs/cowrie.json`:

1. Run the Python analysis engine:
   ```bash
   ./scripts/parse_logs.py --input data/logs/cowrie.json --output data/threat_intelligence_report.json
   ```

2. For testing without exposing the honeypot to the public internet:
   ```bash
   ./scripts/parse_logs.py --generate-sample
   ```

3. Import `dashboards/kibana_dashboard_export.ndjson` into Kibana under:
   **Management > Stack Management > Saved Objects > Import**.
