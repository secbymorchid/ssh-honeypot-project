#!/usr/bin/env bash
# ==============================================================================
# Script: start_honeypot.sh
# Purpose: Orchestrates Cowrie container lifecycle and checks health status
# ==============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[*] Launching Cowrie SSH Honeypot stack via Docker Compose..."
docker compose up -d

echo "[+] Waiting for container to initialize..."
sleep 3

# Verify container is running
if docker compose ps | grep -q "Up\|running"; then
    echo "[✔] Cowrie Honeypot is active and listening on port 2222!"
    echo "---------------------------------------------------------"
    echo "Useful Commands:"
    echo "  - View live logs:     docker compose logs -f"
    echo "  - Check status:       docker compose ps"
    echo "  - Stop honeypot:      docker compose down"
    echo "  - Parse telemetry:    ./scripts/parse_logs.py --input data/logs/cowrie.json"
    echo "---------------------------------------------------------"
else
    echo "[!] Container failed to start. Showing logs:"
    docker compose logs
    exit 1
fi
