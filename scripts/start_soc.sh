#!/usr/bin/env bash
# Start the Sentinel-E SOC server (ingestion + detection engine + dashboard).
# Creates the virtualenv and installs aiohttp on first run.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

if [ ! -d .venv ]; then
  echo "[*] Creating virtualenv and installing dependencies …"
  python3 -m venv .venv
  ./.venv/bin/pip -q install --upgrade pip
  ./.venv/bin/pip -q install aiohttp
fi

echo "[*] Starting Sentinel-E SOC server on http://0.0.0.0:8770/ …"
echo "    Open http://100.91.16.98:8770/ in a browser."
exec ./.venv/bin/python detection/server.py
