# Enterprise Threat Intelligence & SSH Honeypot Architecture

## 1. Executive Summary & Objective
This project demonstrates an enterprise-grade deployment of a low-interaction SSH honeypot (**Cowrie**) designed to safely intercept, analyze, and visualize real-world adversary behavior. In an era where automated adversary scanning occurs within minutes of exposing a public IP, proactive threat intelligence collection is essential for modern Security Operations Centers (SOCs) and Threat Intelligence teams.

The primary objective is to simulate an authentic, vulnerable SSH Linux server in an isolated environment to:
- Capture raw brute-force attempts and automated botnet reconnaissance.
- Identify attacker tactics, techniques, and procedures (**TTPs**) aligned with the **MITRE ATT&CK® Enterprise Framework**.
- Enrich telemetry with geolocation and IP reputation scoring.
- Translate low-level log data into actionable intelligence for executive and operational decision-makers.

---

## 2. Enterprise Defense-in-Depth Architecture

To guarantee absolute containment and prevent honeypot escape or host compromise, the infrastructure adheres to a three-tier defense-in-depth model:

```
[ Internet / Adversary Scanners ]
               │
               ▼  (Public IP: External SSH port 22)
┌─────────────────────────────────────────────────────────────┐
│ 1. Host Isolation Layer (Windows 11)                        │
│    - Physical Host Machine                                  │
│    - Host-Only / NAT Network Segregation                    │
└──────────────────────────────┬──────────────────────────────┘
                               │ VirtualBox Hypervisor
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Virtual Machine Enclave (Ubuntu Server 22.04 LTS)        │
│    - Dedicated non-root service account (`honeypot`)        │
│    - Host SSH moved to non-standard administration port     │
│    - UFW Firewall & iptables NAT port redirection           │
└──────────────────────────────┬──────────────────────────────┘
                               │ Docker Engine Bridge
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Application Sandbox (Cowrie Container)                   │
│    - Low-interaction simulated shell environment            │
│    - Fake filesystem & simulated process table              │
│    - Immutable configuration (`ro` volume mounts)           │
│    - Telemetry isolated to local persistent storage         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. MITRE ATT&CK® Enterprise Matrix Mapping

Adversary activity captured by the honeypot is parsed and systematically categorized against the MITRE ATT&CK framework:

| Tactic | Technique ID | Technique Name | Honeypot Indicator / Trigger |
| :--- | :--- | :--- | :--- |
| **Initial Access / Credential Access** | `T1110.001` | Brute Force: Password Guessing | High-volume dictionary attacks against `root`, `admin`, `ubuntu` |
| **Persistence / Defense Evasion** | `T1078` | Valid Accounts | Successful authentication using honey credentials from `userdb.txt` |
| **Discovery** | `T1082` | System Information Discovery | Attacker commands: `uname -a`, `cat /proc/cpuinfo`, `cat /etc/issue` |
| **Discovery** | `T1016` | System Network Configuration Discovery | Attacker commands: `ifconfig`, `ip addr`, `netstat -tuln` |
| **Discovery** | `T1033` | System Owner/User Discovery | Attacker commands: `whoami`, `id`, `w`, `who` |
| **Discovery** | `T1057` | Process Discovery | Attacker commands: `ps aux`, `ps -ef`, `top` |
| **Command and Control / Execution** | `T1105` | Ingress Tool Transfer | Dropping scripts via `curl`, `wget`, `tftp`, or `ftp` |
| **Execution** | `T1059.004` | Command and Scripting: Unix Shell | Automated execution of staging scripts (`bash -i`, `sh`) |
| **Defense Evasion** | `T1070.004` | Indicator Removal: File Deletion | Anti-forensic commands: `rm -rf /var/log`, `history -c` |

---

## 4. Governance, Legal & Regulatory Compliance (MGSI Alignment)

Operating an active threat intelligence probe requires strict adherence to information systems governance and privacy legislation:

### 4.1. RGPD / GDPR Compliance (Recital 49)
Under the European General Data Protection Regulation (GDPR), IP addresses are classified as personal data (pseudonymous identifiers). However, processing malicious IP addresses in this honeypot is legally grounded in **Recital 49**:
> *"The processing of personal data to the extent strictly necessary and proportionate for the purposes of ensuring network and information security [...] constitutes a legitimate interest of the data controller concerned."*

**Governance Safeguards:**
- **Data Minimization:** No personally identifiable information (PII) belonging to legitimate internal users is processed.
- **Git Hygiene & Public Disclosure:** Raw telemetry containing live malicious IPs is strictly excluded via `.gitignore` to prevent unauthorized dissemination.
- **Data Retention:** Raw telemetry is purged after report generation.

### 4.2. ISO/IEC 27001:2022 & NIST SP 800-53 Mapping
- **ISO 27001 Control A.8.16 (Monitoring Activities):** Provides external threat monitoring and baseline intrusion pattern analysis.
- **ISO 27001 Control A.8.23 (Information Security in Network Services):** Validates network segregation mechanisms and service hardening.
- **NIST SP 800-53 SI-4 (Information System Monitoring):** Automates the collection of unauthorized connection attempts and anomalous system calls.

---

## 5. Threat Modeling & Risk Mitigation Matrix

| Identified Risk | Risk Severity | Technical Mitigation Strategy |
| :--- | :---: | :--- |
| **Container Breakout / Privilege Escalation** | High | Hardened container runtime (`no-new-privileges:true`), CPU/memory limits (`deploy.resources`), and low-interaction Cowrie shell that never spawns real root kernel processes. |
| **Host Network Pivoting** | High | Honeypot VM sits on a dedicated Docker bridge network with no route to the host's private LAN subnet. |
| **ISP Abuse Complaints** | Medium | The honeypot operates purely in **passive reception mode**; outbound scanning or retaliation against attacker IPs is strictly prohibited in configuration and firewall rules. |
| **Log Leakage / Contamination** | Low | Central `.gitignore` policy strictly excludes `data/*` while maintaining code templates and sanitized reports. |
