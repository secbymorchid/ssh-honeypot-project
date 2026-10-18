# Phase 1: Project Scope & Risk Assessment

## 1. Project Objective
The objective of this project is to deploy a low-interaction SSH honeypot (Cowrie) in an isolated Linux environment. The system will be designed to simulate a vulnerable SSH server, capture malicious login attempts, record attacker commands, and visualize the collected threat intelligence via an analytics dashboard (Kibana). This project serves as a practical demonstration of network security, threat intelligence gathering, and log analysis.

## 2. Scope Definition

### In-Scope
- Deployment of a Cowrie SSH honeypot.
- Isolated network environment (Virtual Machine).
- Logging of brute-force attempts, source IP addresses, and attacker commands.
- Parsing raw JSON logs using a custom Python script.
- Visualization of attack data via Kibana dashboards.

### Out-of-Scope
- High-interaction honeypots (where attackers gain real OS-level access).
- Telnet honeypot deployment (focus is strictly on SSH).
- Deployment on production or corporate networks.
- Active retaliation or scanning against attacking IPs.

## 3. Risk Assessment & Mitigation Strategy

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Host Compromise** | High: An attacker exploits a vulnerability in the honeypot to gain control of the host machine. | **Isolation:** Deploy exclusively within a dedicated Virtual Machine (VM) or Docker container. Ensure the VM has no access to the local host network or sensitive data. |
| **Legal / ISP Flags** | Medium: Internet Service Provider (ISP) flags the connection due to inbound malicious traffic. | **Port Obfuscation:** Do not listen on the default SSH port (22). Listen on a high, non-standard port (e.g., 2222). Review local laws regarding honeypot usage. |
| **Data Privacy (Log Leaks)** | Medium: Pushing real-world malicious IPs and payloads to a public GitHub repository. | **Git Hygiene:** The `.gitignore` file strictly excludes the `data/` directory. Raw logs will never be committed. Only sanitized reports and scripts will be pushed. |
| **Resource Exhaustion** | Low: Botnet traffic overwhelms the VM's CPU/RAM. | **Resource Limits:** Use a low-interaction honeypot like Cowrie (which is lightweight) and allocate limited resources (e.g., 1 vCPU, 2GB RAM) to the VM. |

## 4. Success Metrics
The project will be considered successful if:
1. The honeypot is successfully deployed and accessible from the internet.
2. The system captures at least 100 unique brute-force attempts within the first 72 hours.
3. The Python parser successfully extracts actionable data (IPs, usernames, passwords, commands) from the JSON logs.
4. A Kibana dashboard is successfully built and displays at least 3 distinct visualizations (e.g., Geographic Attack Map, Top Attacking IPs, Top Attempted Usernames).
