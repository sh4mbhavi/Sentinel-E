#!/usr/bin/env bash
# =============================================================================
#  Sentinel-E — apply blue-team mitigations to the hardware target.
#
#  Transforms the vulnerable range into a hardened one so the SAME attack now
#  fails. Every change is reversible with scripts/restore.sh.
#
#  Mitigations applied (mapped to docs/MITIGATIONS.md):
#    * T1059 injection  -> deploy the hardened panel (input allowlist, no shell)
#    * T1110 brute-force-> hardened panel enforces login rate-limiting/lockout
#    * T1136 persistence-> remove backdoor, PermitRootLogin off, immutable passwd
#    * T1571/T1041 C2/exfil -> egress default-deny to known C2/exfil ports
#
#  The telemetry sensor keeps running, so the SOC still SEES the (now failing)
#  attack — you watch it get detected and stopped.
#
#  Usage (from the SOC):  ./scripts/harden.sh
# =============================================================================
set -uo pipefail
KEY=~/.ssh/pi_key
PI=clupai@100.119.99.36
DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Deploying the HARDENED panel (fixes command injection + adds login lockout)…"
scp -i "$KEY" -q "$DIR/pi/camera_panel_hardened.py" "$PI:/home/clupai/camera_panel_hardened.py"

echo "[*] Applying host mitigations on the target…"
ssh -i "$KEY" "$PI" 'sudo -n bash -s' <<'EOF'
set -e
# --- back up the vulnerable panel, swap in the hardened one, restart ---
[ -f /home/clupai/camera_panel.vulnerable.py ] || cp /home/clupai/camera_panel.py /home/clupai/camera_panel.vulnerable.py
cp /home/clupai/camera_panel_hardened.py /home/clupai/camera_panel.py
pkill -f '[c]amera_panel' || true
sleep 1
cd /home/clupai && setsid nohup python3 camera_panel.py >/home/clupai/sentinel/panel.out 2>&1 </dev/null &
sleep 1
echo "  [+] hardened panel running: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/login)"

# --- persistence hardening: remove backdoor, disable root SSH, lock passwd ---
userdel -f backdoor 2>/dev/null && echo "  [+] backdoor account removed" || true
usermod -L root 2>/dev/null || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$f"; done 2>/dev/null
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
echo "  [+] PermitRootLogin no; root locked"
chattr +i /etc/passwd 2>/dev/null && echo "  [+] /etc/passwd made immutable (no new accounts)" || echo "  [!] chattr unavailable (skipped)"

# --- egress default-deny to known C2 / exfil ports (reverse shell, exfil) ---
if command -v nft >/dev/null 2>&1; then
  nft delete table inet sentinel_harden 2>/dev/null || true
  nft add table inet sentinel_harden
  nft add chain inet sentinel_harden out '{ type filter hook output priority 0 ; policy accept ; }'
  nft add rule inet sentinel_harden out ct state new tcp dport '{ 4444, 1337, 9001, 9002, 5555, 8888, 8000 }' drop
  echo "  [+] egress blocked to C2/exfil ports (nftables table: sentinel_harden)"
else
  echo "  [!] nft unavailable — egress rule skipped (injection fix still blocks the chain)"
fi
echo "[✓] Target hardened."
EOF

echo
echo "[✓] Mitigations applied. Re-run the attack and watch it fail:"
echo "      • recon/brute are still detected as attempts, but gain nothing"
echo "      • injection is rejected -> no shell -> no privesc, persistence, or exfil"
echo "    Revert everything with:  ./scripts/restore.sh"
