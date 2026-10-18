# Enterprise SSH Honeypot & Threat Intelligence Dashboard

## Project Overview
This project demonstrates the deployment, configuration, and analysis of a low-interaction SSH honeypot (Cowrie) within an isolated Linux environment. The primary goal is to simulate a vulnerable target, capture real-world malicious traffic, analyze attacker behavior (brute-force attempts, executed commands), and visualize the resulting threat intelligence.

This project serves as a practical application of network security, Linux administration, threat intelligence, and log analysis.

## System Architecture
*(Note: Architecture diagram will be updated following Phase 1 completion)*

- **Target Environment:** Isolated Linux Virtual Machine (Ubuntu/Debian)
- **Honeypot Engine:** Cowrie (SSH/Telnet)
- **Log Parsing:** Custom Python processing scripts
- **Threat Intelligence Enrichment:** GeoIP2 and AbuseIPDB API integration
- **Visualization:** Kibana / Elasticsearch or Streamlit Dashboard
- **Deployment Method:** Python Virtual Environment / Docker

## Tech Stack
*(Technologies utilized: Python, Linux, Cowrie, Docker, Kibana)*

## Project Roadmap & Status
- **Phase 1:** Project Planning & Environment Setup
- **Phase 2:** Honeypot Deployment & Configuration (Cowrie)
- **Phase 3:** Data Collection & Log Generation
- **Phase 4:** Log Analysis & Threat Intelligence
- **Phase 5:** Visualization & Dashboarding
- **Phase 6:** Final Documentation & Threat Report

## Security & Disclaimer
This honeypot is deployed in an **isolated and controlled environment**. Logs collected during operation will contain real IP addresses of automated scanning bots and malicious actors.

**Note:** Raw log files are excluded from this repository via `.gitignore` to protect sensitive data and prevent the accidental distribution of malicious payloads. Only configuration templates, automation scripts, and sanitized reports are committed to version control.

## Repository Structure
- **`/config`**: Cowrie configuration files and environment parameter templates.
- **`/data`**: Ignored directory where raw JSON and NDJSON telemetry logs are stored locally.
- **`/docs`**: Detailed project documentation, setup guides, and threat analysis reports.
- **`/dashboards`**: Exported dashboard configurations.
- **`/scripts`**: Python automation, data processing, and parsing scripts.
