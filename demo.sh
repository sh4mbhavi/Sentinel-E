#!/usr/bin/env bash
# =============================================================================
#  Sentinel-E — hardware-free demo launcher
# =============================================================================
#  Runs the ENTIRE platform on this one machine. No Raspberry Pi, no attacker
#  box, no Tailscale. A local telemetry generator emits realistic attack
#  telemetry that the real detection engine evaluates live, and you watch all
#  seven ATT&CK stages light up on the dashboard.
#
#  Usage:   ./demo.sh
#  Then open the printed URL in your browser.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PORT=8770
VENV=.venv

# --- dependencies: a local virtualenv with aiohttp (the only 3rd-party dep) ---
if [ ! -d "$VENV" ]; then
  echo "[*] First run: creating virtualenv and installing dependencies…"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" -q install --upgrade pip
  "$VENV/bin/pip" -q install aiohttp
fi

# --- free the port if a previous instance is still bound ---
if command -v pkill >/dev/null 2>&1; then pkill -f "detection/server.py" 2>/dev/null || true; fi
sleep 1

# --- clean slate so the demo starts at zero ---
rm -f detection/demo_alerts.jsonl detection/demo_alerts.db

export SENTINEL_CONFIG=config/demo.conf.json

cat <<'BANNER'

   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ███████╗
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      ██╔════╝
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║█████╗█████╗
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║╚════╝██╔══╝
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ███████╗
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚══════╝
              R E A L - T I M E   S O C   D E T E C T I O N   P L A T F O R M
BANNER

echo
echo "  [*] Hardware-free demo starting — no external hosts required."
echo "  [*] Open the dashboard now:   http://localhost:${PORT}/"
echo "  [*] A simulated adversary begins its seven-stage attack ~7s after load;"
echo "      watch the kill chain, ATT&CK matrix, charts and alert feed react live."
echo "  [*] Press Ctrl+C to stop."
echo

exec "$VENV/bin/python" detection/server.py
