#!/usr/bin/env python3
"""
Sentinel-E Pi sensor  --  runs ON THE RASPBERRY PI (the target), as root.

It merges THREE genuinely real-time, event-driven telemetry sources into a
single newline-delimited JSON stream on stdout. The SOC (Fedora) runs this
script over a persistent SSH connection and reads that stdout stream live, so
there is NO polling anywhere in the pipeline:

  1. journalctl -f      -> panel app events (login/ping), sudo (privesc), sshd
  2. tcpdump -l         -> TCP SYNs: inbound = recon scan, outbound = C2/exfil
  3. inotifywait -m     -> changes/access to /etc/passwd, /etc/shadow,
                           sshd_config and the sensitive secret file

Each emitted line is a JSON object with at least: ts, source, event.
Sources: "panel", "auth", "net", "file". The SOC-side detection engine turns
these raw observations into correlated, MITRE-mapped alerts.

Root is required for tcpdump (packet capture), journald (reading sudo/auth
records) and inotify on /root and /etc. It is launched via passwordless sudo
from the SOC:  ssh pi 'sudo python3 /home/clupai/sentinel/sentinel_sensor.py'
"""
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone

# --- what to watch (kept in sync with config/sentinel.conf.json on the SOC) ---
IFACE = os.environ.get("SENTINEL_IFACE", "tailscale0")
SOC_IP = os.environ.get("SENTINEL_SOC_IP", "100.91.16.98")  # exclude mgmt traffic
WATCH_FILES = ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
               "/root/camera_config.secret"]

_emit_lock = threading.Lock()


def emit(source, event, **fields):
    """Write one JSON telemetry record to stdout, line-buffered and flushed."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event": event,
        **fields,
    }
    line = json.dumps(record)
    with _emit_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# SOURCE 1: journald  (panel app events + sudo/privesc + sshd)
# ---------------------------------------------------------------------------
def watch_journal():
    """Follow the systemd journal and re-emit relevant records in real time."""
    proc = subprocess.Popen(
        ["journalctl", "-f", "-n", "0", "-o", "json", "--no-pager"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        try:
            j = json.loads(line)
        except ValueError:
            continue
        ident = j.get("SYSLOG_IDENTIFIER", "")
        comm = j.get("_COMM", "")
        msg = j.get("MESSAGE", "")
        if not isinstance(msg, str):
            continue

        # (a) Our vulnerable panel logs a JSON payload under identifier camera_panel.
        if ident == "camera_panel":
            try:
                payload = json.loads(msg)
                emit("panel", payload.get("event", "panel"), **{
                    k: v for k, v in payload.items()
                    if k not in ("source", "event")})
            except ValueError:
                pass
            continue

        # (b) sudo usage -> privilege escalation signal. journald records the
        #     invoking user and the target command. "USER=root" == became uid 0.
        if comm == "sudo" and "COMMAND=" in msg:
            m = re.search(r"(\w+)\s*:.*?USER=(\w+)\s*;\s*COMMAND=(.*)", msg)
            if m:
                emit("auth", "sudo",
                     invoking_user=m.group(1),
                     target_user=m.group(2),
                     command=m.group(3).strip())
            continue

        # (c) sshd authentication + session events (lateral movement / exfil login).
        if comm == "sshd":
            low = msg.lower()
            if "accepted" in low or "failed password" in low or "session opened" in low:
                emit("auth", "sshd", detail=msg.strip())
            continue


# ---------------------------------------------------------------------------
# SOURCE 2: tcpdump  (network SYNs -> recon scan + outbound C2/exfil)
# ---------------------------------------------------------------------------
# Capture bare SYNs (connection attempts). SYN-only means "opening a connection".
# tcpdump -tt gives epoch ts; -n no DNS; -l line-buffered for real-time.
_TCP_LINE = re.compile(
    r"IP6?\s+([0-9a-f:.]+?)\.(\d+)\s+>\s+([0-9a-f:.]+?)\.(\d+):")


def _local_ips():
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True)
        return set(out.split())
    except Exception:
        return set()


def watch_network():
    local = _local_ips()
    proc = subprocess.Popen(
        ["tcpdump", "-i", IFACE, "-l", "-n", "-tt",
         "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        m = _TCP_LINE.search(line)
        if not m:
            continue
        src_ip, src_port, dst_ip, dst_port = m.group(1), int(m.group(2)), \
            m.group(3), int(m.group(4))
        # Ignore ONLY the SOC's SSH management/telemetry channel (port 22 between
        # the SOC and this host) so the sensor never flags its own control link.
        # All other SOC-sourced traffic is kept: in the reproducible demo the SOC
        # host stands in for the Kali attacker and drives recon / C2 / exfil.
        if (dst_port == 22 and src_ip == SOC_IP) or \
           (src_port == 22 and dst_ip == SOC_IP):
            continue
        direction = "inbound" if dst_ip in local else \
                    ("outbound" if src_ip in local else "transit")
        emit("net", "syn", direction=direction,
             src_ip=src_ip, src_port=src_port,
             dst_ip=dst_ip, dst_port=dst_port)


# ---------------------------------------------------------------------------
# SOURCE 3: inotify  (passwd/shadow/sshd_config changes + secret-file access)
# ---------------------------------------------------------------------------
def _uid0_accounts():
    """Return the set of usernames with UID 0 currently in /etc/passwd."""
    users = set()
    try:
        with open("/etc/passwd") as f:
            for row in f:
                parts = row.split(":")
                if len(parts) > 2 and parts[2] == "0":
                    users.add(parts[0])
    except Exception:
        pass
    return users


def _watch_config_changes():
    """Watch config files for MODIFICATION only (never 'access', which floods:
    /etc/passwd is read by every NSS lookup on the system)."""
    baseline_uid0 = _uid0_accounts()
    cfg = [p for p in ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"]
           if os.path.exists(p)]
    proc = subprocess.Popen(
        ["inotifywait", "-m", "-q",
         "-e", "modify", "-e", "create", "-e", "attrib", "-e", "moved_to",
         "--format", "%e|%w"] + cfg,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        line = line.strip()
        if "|" not in line:
            continue
        events, path = line.split("|", 1)
        if path == "/etc/passwd":
            current = _uid0_accounts()
            new_uid0 = current - baseline_uid0
            if new_uid0:
                baseline_uid0 = current
                for user in new_uid0:
                    # Persistence IoC: a brand-new UID-0 (root-equivalent) account.
                    emit("file", "passwd_uid0_added", path=path, account=user)
            else:
                emit("file", "passwd_modified", path=path, events=events)
        else:
            emit("file", "config_modified", path=path, events=events)


def _watch_secret_access():
    """Watch ONLY the sensitive secret file, ONLY for read/access events."""
    secret = "/root/camera_config.secret"
    if not os.path.exists(secret):
        return
    proc = subprocess.Popen(
        ["inotifywait", "-m", "-q", "-e", "access", "--format", "%e|%w", secret],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        line = line.strip()
        if "|" not in line:
            continue
        events, path = line.split("|", 1)
        # Sensitive-file READ -> half of the exfiltration signal.
        emit("file", "secret_access", path=path, events=events)


def main():
    emit("sensor", "online", iface=IFACE, watching=[p for p in WATCH_FILES if os.path.exists(p)])
    threads = [
        threading.Thread(target=watch_journal, daemon=True),
        threading.Thread(target=watch_network, daemon=True),
        threading.Thread(target=_watch_config_changes, daemon=True),
        threading.Thread(target=_watch_secret_access, daemon=True),
    ]
    for t in threads:
        t.start()
    # Block forever; the SOC kills the SSH channel to stop us.
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
