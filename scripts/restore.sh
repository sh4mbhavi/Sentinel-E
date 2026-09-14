#!/usr/bin/env bash
# =============================================================================
#  Sentinel-E — revert the blue-team mitigations, restoring the vulnerable range.
#
#  Undoes everything scripts/harden.sh applied, returning the target to its
#  exploitable state so the attack chain works again (red -> blue -> red loop).
#
#  Usage (from the SOC):  ./scripts/restore.sh
# =============================================================================
set -uo pipefail
KEY=~/.ssh/pi_key
PI=clupai@100.119.99.36
DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Restoring the vulnerable panel…"
scp -i "$KEY" -q "$DIR/pi/camera_panel.py" "$PI:/home/clupai/camera_panel.py"

echo "[*] Reverting host mitigations on the target…"
ssh -i "$KEY" "$PI" 'sudo -n bash -s' <<'EOF'
set +e
# --- lift the immutable flag so state can change again ---
chattr -i /etc/passwd 2>/dev/null && echo "  [+] /etc/passwd mutable again"
# --- restart the vulnerable panel ---
chown clupai:clupai /home/clupai/camera_panel.py 2>/dev/null || true
pkill -f '[c]amera_panel' || true
sleep 1
# start the panel as the unprivileged web-service user, not root
runuser -u clupai -- bash -c 'cd /home/clupai && setsid nohup python3 camera_panel.py >/home/clupai/sentinel/panel.out 2>&1 </dev/null' &
sleep 1
echo "  [+] vulnerable panel running: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/login)"
# --- remove the egress deny rules ---
if command -v nft >/dev/null 2>&1; then
  nft delete table inet sentinel_harden 2>/dev/null && echo "  [+] egress rules removed" || true
fi
# --- SSH is left at its default; the attack's persistence stage re-enables root
#     login itself. (The backdoor account is created fresh by the attack.)
echo "[✓] Vulnerable range restored."
EOF

echo
echo "[✓] Restore complete. The attack chain will succeed again."
echo "    (Reset the SOC baseline before your next run: ./scripts/start_soc.sh)"
