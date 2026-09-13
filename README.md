# Sentinel-E — Real-Time IoT Threat Detection Platform

Sentinel-E is a miniature **Security Operations Centre (SOC)** that watches a
deliberately-vulnerable IoT security camera and detects a full red-team attack
chain **as it happens**, in real time, then visualises it on a live web console.

It was built for a university ethical-hacking (red vs blue) assignment. A Kali
attacker compromises a Raspberry Pi camera panel through seven stages; Sentinel-E
(the blue team) streams telemetry off the Pi, runs detection rules, and lights up
each kill-chain stage on the dashboard the moment it fires.

> **Everything here is real.** The detections consume live telemetry from the Pi
> over the network; the attack replay actually exploits the panel's command-
> injection vulnerability. Nothing is faked or pre-recorded.

---

## Architecture at a glance

```
   ATTACKER                 TARGET (IoT)                    SOC (this platform)
   Kali                     Raspberry Pi                    Fedora laptop
   100.65.92.63             100.119.99.36                   100.91.16.98
   ──────────               ────────────                    ─────────────
   nmap / hydra   ───────▶  camera_panel.py (:8080)
   $(...) inject  ───────▶  vulnerable ping tool
                            sentinel_sensor.py (root)
                              ├ journalctl -f  (app + sudo + sshd)
                              ├ tcpdump        (recon + C2 + exfil egress)
                              └ inotifywait    (/etc/passwd, secret file)
                                     │
                                     │  persistent SSH, live JSON stream
                                     ▼
                            detection/ingest.py  ──▶  detection/rules.py
                                                          │ (7 detection rules)
                                                          ▼
                                                     alert store (JSONL + SQLite)
                                                          │
                                                          ▼  websocket
                                                     LIVE DASHBOARD  (:8770)
```

All three machines sit on a **Tailscale** overlay network. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the three full diagrams
(topology, detection data-flow, attack-to-detection mapping).

---

## The seven-stage attack chain (what Sentinel-E detects)

| # | Stage | IoC | MITRE | Kill-chain | Severity |
|---|-------|-----|-------|-----------|----------|
| 1 | Reconnaissance | many ports probed from one IP in a short window | **T1046** Network Service Discovery | Reconnaissance | medium |
| 2 | Credential brute-force | many failed `/login` POSTs from one IP | **T1110** Brute Force | Weaponisation/Delivery | high |
| 3 | Command injection | shell metachars / `$(...)` in the ping `host` field | **T1059** Command & Scripting Interpreter | Exploitation | high |
| 4 | Reverse shell / C2 | outbound Pi connection to non-standard port (4444) | **T1571** Non-Standard Port | Installation | critical |
| 5 | Privilege escalation | web user `clupai` → uid 0 via sudo in the auth log | **T1548** Abuse Elevation Control | Exploitation/Installation | critical |
| 6 | Persistence | new UID-0 account in `/etc/passwd`; `sshd_config` change | **T1136** Create Account | Command & Control | critical |
| 7 | Exfiltration | read of `/root/camera_config.secret` + outbound transfer | **T1041/T1048** Exfiltration | Actions on Objectives | critical |

---

## Components

| Path | Runs on | What it is |
|------|---------|-----------|
| `pi/camera_panel.py` | Pi `:8080` | The vulnerable panel, **modified** to log every login/ping as structured JSON (to a JSONL file + syslog). The vulnerability is left intact. |
| `pi/sentinel_sensor.py` | Pi (root) | Real-time sensor merging `journalctl`/`tcpdump`/`inotifywait` into one JSON stream on stdout. |
| `detection/ingest.py` | SOC | Holds a persistent SSH connection to the Pi and reads the sensor stream live (no polling). |
| `detection/rules.py` | SOC | The detection engine: seven stateful rules, correlation, MITRE/severity metadata. |
| `detection/store.py` | SOC | Alert persistence (JSON-lines **and** SQLite). |
| `detection/server.py` | SOC | The main asyncio server: ingest → engine → store → websocket → dashboard. |
| `dashboard/index.html` | SOC (browser) | The live SOC console. |
| `attack/replay.py` | SOC | Reproducible attack driver that runs the whole chain against the Pi. |
| `config/sentinel.conf.json` | SOC | All tunable thresholds and the network map. |

---

## Prerequisites

* **SOC (Fedora):** Python 3.9+, an SSH key to the Pi at `~/.ssh/pi_key`,
  Tailscale up. The only third-party dependency is `aiohttp` (installed into a
  local venv automatically by `scripts/start_soc.sh`).
* **Pi:** Python 3, Flask, `tcpdump`, `inotify-tools`, and passwordless `sudo`
  for the sensor (already provisioned on the assignment Pi).

Ports: panel **8080** (Pi), dashboard **8770** (SOC). *(8760 is deliberately
avoided — it's used by an unrelated dashboard on this laptop.)*

---

## Run it (three terminals)

```bash
# 1) One-time: deploy telemetry to the Pi and start the panel with logging
./scripts/deploy_pi.sh

# 2) Start the SOC — ingestion + detection + dashboard (creates the venv on first run)
./scripts/start_soc.sh
#    → open http://100.91.16.98:8770/  in a browser

# 3) Trigger the attack — TWO options:

#   (a) REAL attack from the Kali box (genuine source IPs, no relabeling).
#       Copy the runbook to Kali (100.65.92.63) and run it there:
#         scp attack/kali_attack.sh kali@100.65.92.63:~ ; ssh kali 'chmod +x kali_attack.sh && ./kali_attack.sh'
#       Requires demo.attacker_attribution=false (the current setting). Stages
#       1-3 show Kali's real IP; stages 4-7 run on the Pi and show the Pi's IP.

#   (b) Self-contained replay from the SOC (no Kali needed; for a quick local demo):
python3 attack/replay.py            # full pace, good for screen recording
python3 attack/replay.py --fast     # quicker
python3 attack/replay.py --cleanup  # remove the backdoor account either path creates
```

The dashboard shows the kill chain filling in, the ATT&CK matrix highlighting,
counters ticking, and the alert feed streaming — all live over websockets.

> **Note on source IPs.** The detection rules are **source-agnostic** — they
> read the true origin of every observation (tcpdump captures the real SYN
> source; the panel logs the real HTTP `remote_addr`). So a genuine attack from
> Kali is displayed with real IPs: stages 1–3 → `100.65.92.63`, stages 4–7 →
> the Pi `100.119.99.36` (those run on the Pi via the injection point).
>
> `config/sentinel.conf.json → demo.attacker_attribution` controls one optional
> cosmetic behaviour and nothing else:
> * **`false` (current setting):** no relabeling — every alert shows its genuine
>   observed source IP. Use this for the real Kali attack (`attack/kali_attack.sh`).
> * **`true`:** for the self-contained `attack/replay.py`, which runs from the
>   SOC standing in for Kali, the engine *attributes* SOC-origin stand-in traffic
>   to the attacker IP so stages 1–3 still show one coherent adversary origin.
>   This is display attribution, **not** source-IP spoofing.

---

## Reproduce the demo from scratch

```bash
git clone <this-repo> sentinel-e && cd sentinel-e
./scripts/deploy_pi.sh          # push telemetry + start panel on the Pi
./scripts/start_soc.sh &        # start the SOC server
sleep 5
python3 attack/replay.py        # fire the chain; watch http://100.91.16.98:8770/
```

Alerts persist to `detection/alerts.jsonl` and `detection/alerts.db`; the
dashboard replays recent history on reconnect.

---

## Security notes

* **No secrets are committed.** The SSH key lives at `~/.ssh/pi_key` and is
  referenced by path only; `/root/camera_config.secret` stays on the Pi.
* The panel's command-injection vulnerability is **intentional** — it is the
  thing being attacked and detected. See [`docs/MITIGATIONS.md`](docs/MITIGATIONS.md)
  for how each of the seven weaknesses would be fixed in production.

## Documentation

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — three diagrams described in full.
* [`docs/MITIGATIONS.md`](docs/MITIGATIONS.md) — the blue-team fix for every stage.
* [`pi/README.md`](pi/README.md) — the Pi-side files and telemetry sources.
