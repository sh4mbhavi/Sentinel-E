#!/usr/bin/env python3
"""
Sentinel-E hardware-free demo — local telemetry generator ("simulated sensor").

This is the heart of the hardware-free demo. It emits the EXACT same
newline-delimited JSON telemetry schema the real Raspberry Pi sensor produces
(sources: net / panel / auth / file), representing a full seven-stage intrusion.

Crucially, this program raises NO alerts of its own. It emits only raw
observations; the unmodified detection engine (detection/rules.py) applies its
real sliding-window thresholds and correlation logic and decides every alert.
The demo genuinely crosses each rule's threshold — e.g. it emits enough distinct
port-scan SYNs to trip the recon window, enough failed logins to trip the
brute-force window, and a sensitive-file read plus an egress channel inside the
exfil correlation window. Nothing is pre-canned; the engine does the detecting.

The SOC server spawns this locally (via detection/ingest.py in demo mode) and
reads its stdout as a live event stream, exactly as it reads the real sensor.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

TARGET = os.environ.get("SENTINEL_TARGET_IP", "10.10.10.5")       # simulated IoT device
ATTACKER = os.environ.get("SENTINEL_ATTACKER_IP", "10.13.37.37")  # simulated adversary
LOOP = os.environ.get("SENTINEL_DEMO_LOOP", "0") == "1"
# Pacing (seconds). Tunable via env for faster/slower demos.
WARMUP = float(os.environ.get("SENTINEL_DEMO_WARMUP", "7"))
GAP = float(os.environ.get("SENTINEL_DEMO_GAP", "3.2"))

_port_seq = 40000


def emit(source, event, **fields):
    """Write one raw telemetry record to stdout (line-buffered, flushed)."""
    rec = {"ts": datetime.now(timezone.utc).isoformat(),
           "source": source, "event": event, **fields}
    sys.stdout.write(json.dumps(rec) + "\n")
    sys.stdout.flush()


def _ephemeral():
    global _port_seq
    _port_seq += 7
    return _port_seq


def syn(direction, src_ip, dst_ip, dst_port):
    emit("net", "syn", direction=direction, src_ip=src_ip, src_port=_ephemeral(),
         dst_ip=dst_ip, dst_port=dst_port)


# ---------------------------------------------------------------------------
# Benign warm-up — a little legitimate baseline so the console looks alive and
# the attack clearly stands out. None of this crosses a detection threshold.
# ---------------------------------------------------------------------------
def warmup():
    emit("panel", "login", src_ip="10.10.10.22", username="admin", success=True)
    for p in (443, 123, 80):
        syn("outbound", TARGET, "10.10.10.1", p)   # normal egress (NTP/HTTPS)
    emit("panel", "ping", host="8.8.8.8")           # a legitimate diagnostic ping
    time.sleep(WARMUP)


# ---------------------------------------------------------------------------
# The seven-stage intrusion, as raw telemetry.
# ---------------------------------------------------------------------------
def stage_recon():
    # T1046 — a port sweep: many distinct destination ports from one source in a
    # short window. The engine's recon rule counts distinct ports and fires.
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993,
             1723, 3306, 3389, 5900, 8080, 8443]
    for p in ports:
        syn("inbound", ATTACKER, TARGET, p)
        time.sleep(0.08)


def stage_brute():
    # T1110 — repeated failed authentications from one source, then success.
    for pw in ("admin", "12345", "password", "root", "camera",
               "letmein", "default"):
        emit("panel", "login", src_ip=ATTACKER, username="admin", success=False)
        time.sleep(0.35)
    emit("panel", "login", src_ip=ATTACKER, username="admin", success=True)


def stage_injection():
    # T1059 — shell metacharacters / command substitution in the ping host field.
    emit("panel", "ping", src_ip=ATTACKER, host="8.8.8.8$(id)")


def stage_reverse_shell():
    # T1571 — the compromised device dials out to a non-standard C2 port.
    syn("outbound", TARGET, ATTACKER, 4444)


def stage_privesc():
    # T1548 — the web service account escalates to uid 0 via sudo.
    emit("auth", "sudo", invoking_user="www-data", target_user="root",
         command="/bin/bash")


def stage_persistence():
    # T1136 — a new UID-0 backdoor account, plus an sshd_config change.
    emit("file", "passwd_uid0_added", path="/etc/passwd", account="backdoor")
    time.sleep(1.0)
    emit("file", "config_modified", path="/etc/ssh/sshd_config", events="MODIFY")


def stage_exfil():
    # T1041/T1048 — a sensitive file is read AND leaves the device over an
    # inbound scp/SSH session; the engine correlates the two within its window.
    emit("file", "secret_access", path="/root/camera_config.secret", events="ACCESS")
    time.sleep(1.0)
    syn("inbound", ATTACKER, TARGET, 22)   # scp pull channel


STAGES = [
    ("Reconnaissance",        stage_recon),
    ("Credential brute-force", stage_brute),
    ("Command injection",     stage_injection),
    ("Reverse shell / C2",    stage_reverse_shell),
    ("Privilege escalation",  stage_privesc),
    ("Persistence",           stage_persistence),
    ("Exfiltration",          stage_exfil),
]


def run_attack():
    for i, (name, fn) in enumerate(STAGES, 1):
        # progress goes to stderr so it never pollutes the JSON telemetry stream
        print(f"[sim] stage {i}/7 -> {name}", file=sys.stderr, flush=True)
        fn()
        if i < len(STAGES):
            time.sleep(GAP)


def main():
    emit("sensor", "online", iface="demo", target=TARGET, attacker=ATTACKER,
         mode="hardware-free demo")
    warmup()
    while True:
        run_attack()
        if not LOOP:
            break
        # brief lull, then a fresh wave (dashboard keeps living)
        time.sleep(25)
    # keep the stream open so the SOC shows the sensor as connected
    while True:
        time.sleep(30)
        emit("net", "syn", direction="outbound", src_ip=TARGET,
             src_port=_ephemeral(), dst_ip="10.10.10.1", dst_port=443)


if __name__ == "__main__":
    main()
