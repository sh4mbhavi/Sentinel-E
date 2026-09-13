#!/usr/bin/env bash
# Deploy Sentinel-E telemetry files to the Raspberry Pi target and (re)start the
# vulnerable camera panel with logging enabled. Run this once from the SOC box.
set -euo pipefail
KEY=~/.ssh/pi_key
PI=clupai@100.119.99.36
DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Copying telemetry files to the Pi …"
scp -i "$KEY" -q "$DIR/pi/camera_panel.py"    "$PI:/home/clupai/camera_panel.py"
scp -i "$KEY" -q "$DIR/pi/sentinel_sensor.py" "$PI:/home/clupai/sentinel_sensor.py"

echo "[*] (Re)starting the camera panel on the Pi …"
ssh -i "$KEY" "$PI" "mkdir -p /home/clupai/sentinel; pkill -f '[c]amera_panel' || true"
sleep 1
ssh -i "$KEY" -f "$PI" \
  "cd /home/clupai && setsid nohup python3 camera_panel.py >/home/clupai/sentinel/panel.out 2>&1 </dev/null; sleep 2"
sleep 2
CODE=$(ssh -i "$KEY" "$PI" "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/login")
echo "[*] Panel HTTP status: $CODE  (200 = up)"
echo "[✓] Pi deployment complete. The SOC server launches the sensor over SSH automatically."
