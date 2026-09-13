# Sentinel-E — Architecture

This document describes the system precisely enough to draw **three diagrams**
directly from the text. For each diagram every component, connection, direction,
data payload, and label is listed explicitly.

---

## Diagram 1 — Network / Topology

**Purpose:** show the three tiers on the Tailscale overlay, the attack direction,
and the real-time telemetry flow.

### Nodes (draw as boxes)

| Label | Sub-label | IP (Tailscale) | Role | Suggested colour |
|-------|-----------|----------------|------|------------------|
| **Attacker** | Kali Linux | `100.65.92.63` | Red team | red |
| **IoT Target** | Raspberry Pi — IPCam-2000 panel | `100.119.99.36` | Victim device | amber |
| **Sentinel-E SOC** | Fedora laptop | `100.91.16.98` | Blue team / this platform | blue |

Enclose all three in a rounded container labelled **“Tailscale overlay network
(WireGuard, 100.64.0.0/10)”**.

### Connections (draw as arrows)

1. **Attacker → Target**, label **“Attack traffic”**, solid red arrow.
   Sub-labels along it: `nmap scan`, `hydra login brute-force`, `HTTP $(...)
   command injection → :8080`.
2. **Target → SOC**, label **“Real-time telemetry”**, solid blue arrow.
   Sub-label: `persistent SSH (port 22) carrying the live JSON sensor stream`.
3. **Target → Attacker**, label **“Reverse shell / exfil (C2)”**, dashed red
   arrow. Sub-label: `outbound TCP :4444 and data egress`.
   *(In the self-contained replay this egress points at the SOC standing in for
   Kali; annotate as “→ attacker (Kali in a live engagement)”.)*

**Attacker attribution (demo):** the reproducible `replay.py` sources stages 1–3
from the SOC host (Kali runs no SSH server we can drive, and WireGuard prevents
source-IP spoofing). With `demo.attacker_attribution: true`, the engine
attributes that stand-in traffic to `network.attacker_ip`, so the console shows
a single coherent adversary origin (`100.65.92.63`) for recon/brute/injection.
This is display attribution, **not** spoofing; Pi-origin stages 4–7 keep the
Pi's real IP. Draw the attacker box as the labelled origin of stages 1–3.

### Endpoints to annotate on the Target box
`camera_panel.py` listening on **:8080**; `sentinel_sensor.py` running as **root**.

---

## Diagram 2 — Detection Data-Flow Pipeline

**Purpose:** trace one event from attack to dashboard. Draw left-to-right as a
pipeline; each arrow is labelled with the data that flows and its direction.

### Stages (draw as boxes, left to right)

1. **Attack on the Pi**
   *Box contents:* nmap / hydra / `$(...)` injection / sudo / useradd /
   secret read.

2. **Pi emits events** — three parallel sensor sources feeding one merger:
   - `journalctl -f -o json` → panel login/ping events, `sudo` (privesc), `sshd`.
   - `tcpdump` on `tailscale0` → inbound SYNs (recon), outbound SYNs (C2/exfil).
   - `inotifywait -m` → `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`
     (modify) and `/root/camera_config.secret` (access).
   *These three converge into* **`sentinel_sensor.py`** *which prints a single
   newline-delimited JSON stream to stdout.*
   *Arrow out, labelled:* `NDJSON telemetry (1 line per observation)`.

3. **Real-time forward** — **persistent SSH** from the SOC runs the sensor as
   root and reads its stdout live.
   *Arrow labelled:* `ssh -i pi_key … sudo python3 sentinel_sensor.py (stdout streamed)`.
   *Direction:* Pi → SOC. **No polling** — event-driven `tail`-style stream.
   *(Design note: the primary transport is this persistent-SSH live stream.
   rsyslog forwarding is the documented alternative; both are real-time.)*

4. **SOC ingestion** — **`detection/ingest.py`** (asyncio subprocess reader).
   Parses each JSON line, timestamps it with the SOC clock, auto-reconnects on
   drop. *Arrow labelled:* `parsed event dict`.

5. **Detection engine** — **`detection/rules.py`** (`DetectionEngine`).
   Applies the seven rules with sliding windows + correlation.
   *Arrow labelled:* `raised alert (stage, MITRE, severity, src_ip, description)`.

6. **Alert store** — **`detection/store.py`** writes each alert to
   **`alerts.jsonl`** and **`alerts.db` (SQLite)** in parallel.
   *Arrow (dashed, downward):* `persist`.

7. **WebSocket fan-out** — **`detection/server.py`** pushes every alert +
   updated counters + fired-stage set to all connected browsers.
   *Arrow labelled:* `JSON message over ws:// (type=alert/telemetry/status)`.

8. **Live dashboard** — **`dashboard/index.html`** renders the alert feed, kill
   chain, ATT&CK matrix, counters, topology and timeline.
   *Arrow (upward, dashed) back to server:* `GET /api/bootstrap (history replay
   on connect)`.

### Data payload examples to label on the arrows
- Sensor line: `{"ts":…,"source":"panel","event":"login","src_ip":…,"success":false}`
- Alert: `{"stage":"brute_force","technique_id":"T1110","severity":"high",…}`

---

## Diagram 3 — Attack-to-Detection Mapping

**Purpose:** one row per kill-chain stage mapping IoC → detection rule → MITRE →
severity. Draw as a 7-row table (or a swim-lane with these columns).

| # | Kill-chain stage | Indicator of Compromise (IoC) | Detection rule (in `rules.py`) | Telemetry source | MITRE ATT&CK | Severity |
|---|------------------|-------------------------------|--------------------------------|------------------|--------------|----------|
| 1 | Reconnaissance | ≥10 distinct destination ports probed from one source IP within 15 s | sliding-window count of distinct ports per source on inbound SYNs | `tcpdump` (net) | **T1046** Network Service Discovery | medium |
| 2 | Weaponisation / Delivery | ≥5 failed `/login` POSTs from one IP within 20 s | sliding-window count of failed logins per source IP | panel (journald) | **T1110** Brute Force | high |
| 3 | Exploitation | shell metacharacters / `$(...)` in the ping `host` field | regex match against a metacharacter/command-substitution set | panel (journald) | **T1059** Command & Scripting Interpreter | high |
| 4 | Installation | outbound connection from the Pi to a non-standard port (4444, 1337, 9001…) | outbound SYN with `dst_port ∈ suspicious_ports` | `tcpdump` (net) | **T1571** Non-Standard Port | critical |
| 5 | Exploitation / Installation | web/service user (`clupai`) becomes uid 0 via sudo | `sudo` record with `invoking_user ∈ web_users` and `target_user = root` | `journalctl` (auth) | **T1548** Abuse Elevation Control Mechanism | critical |
| 6 | Command & Control | new UID-0 line appears in `/etc/passwd`; `sshd_config` modified | inotify modify event + diff of UID-0 accounts vs baseline; sshd_config change | `inotifywait` (file) | **T1136** Create Account | critical |
| 7 | Actions on Objectives | `/root/camera_config.secret` read **and** an outbound transfer within 60 s | correlation of `secret_access` (inotify) with any outbound egress | `inotifywait` + `tcpdump` | **T1041 / T1048** Exfiltration | critical |

### Correlation note (for the diagram’s footnote)
Stage 7 is the only rule that **correlates two signals**: a sensitive-file read
alone is not exfiltration, and an outbound connection alone is not exfiltration
— the alert fires only when both occur inside the configurable
`correlation_window_seconds` (default 60 s). This is drawn as an **AND gate**
combining the `inotify access` and `tcpdump outbound` inputs.

---

## Thresholds (from `config/sentinel.conf.json`)

All detection thresholds are configuration, not code:
`recon.distinct_ports=10 / window=15s`, `brute_force.failed_logins=5 /
window=20s`, `reverse_shell.suspicious_ports=[4444,1337,9001,9002,5555,8888]`,
`privesc.web_users=[clupai,www-data,nobody]`,
`exfiltration.correlation_window=60s`. Tuning sensitivity is a config edit and a
restart — no code change.
