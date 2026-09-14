# Sentinel-E — Real-Time SOC Detection Platform

Sentinel-E is a lightweight **Security Operations Centre (SOC)** platform. It
ingests live host and network telemetry, applies a **detection ruleset mapped to
MITRE ATT&CK** across the cyber kill chain, correlates the results into
prioritised alerts, and streams them to a live web console in real time.

The ruleset targets **common intrusion techniques** rather than any single
exploit — network reconnaissance, credential brute-forcing, command injection /
RCE, command-and-control over non-standard ports, privilege escalation,
persistence, and data exfiltration. Every rule is **behavioural and
threshold-driven**: it fires on the activity pattern (e.g. "one source touches
many ports in a short window"), not on a hardcoded signature, so it generalises
to any monitored host emitting the same telemetry.

To prove the pipeline end to end, Sentinel-E is validated against a live
adversary scenario: a Kali attacker compromising a deliberately-vulnerable IoT
security camera (a Raspberry Pi admin panel) through a full seven-stage kill
chain. The SOC streams telemetry off the target, detects every stage as it
happens, and lights up the kill chain and ATT&CK matrix on the dashboard.

It was built for a university ethical-hacking (red vs blue) assignment.

> **Everything here is real.** Detections run on live telemetry streamed from the
> monitored host; the validation attack genuinely exploits the target. Nothing is
> faked or pre-recorded.

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

## Detection coverage — common attack techniques (MITRE ATT&CK)

Sentinel-E ships behavioural detection rules for the technique classes below.
Each rule is configurable in `config/sentinel.conf.json` and mapped to a MITRE
ATT&CK technique and cyber-kill-chain phase. The IoT-camera scenario exercises
all of them in sequence, but the rules apply to **any** monitored host that
emits the same authentication, process, network and file-integrity telemetry.

| Technique class | What the rule detects (behavioural) | MITRE ATT&CK | Kill-chain phase | Severity |
|---|---|---|---|---|
| Network reconnaissance | one source probing many distinct ports in a short window | **T1046** Network Service Discovery | Reconnaissance | medium |
| Credential brute-force | repeated failed authentications from one source | **T1110** Brute Force | Weaponisation / Delivery | high |
| Command injection / RCE | shell metacharacters / command-substitution in web input | **T1059** Command & Scripting Interpreter | Exploitation | high |
| C2 / reverse shell | outbound connection to a non-standard / suspicious port | **T1571** Non-Standard Port | Installation | critical |
| Privilege escalation | a service/web user escalating to uid 0 via sudo | **T1548** Abuse Elevation Control Mechanism | Exploitation / Installation | critical |
| Persistence | a new UID-0 account or an `sshd_config` modification | **T1136** Create Account | Command & Control | critical |
| Data exfiltration | sensitive-file read correlated with an outbound transfer | **T1041 / T1048** Exfiltration | Actions on Objectives | critical |

Coverage is extensible by design: a new detection is a rule in
`detection/rules.py` plus a threshold in the config — no architectural change.

### Validation scenario — the seven-stage attack chain

The rules above are demonstrated against a real intrusion of the IoT camera:
recon (nmap) → brute-force (hydra) → command injection (`$(...)` filter bypass)
→ reverse shell → sudo privilege escalation → backdoor account + `sshd` change →
secret-file exfiltration. The exact indicator of compromise for each stage is
mapped in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (Diagram 3).

---

## Components

| Path | Runs on | What it is |
|------|---------|-----------|
| `pi/camera_panel.py` | Pi `:8080` | The vulnerable panel, **modified** to log every login/ping as structured JSON (to a JSONL file + syslog). The vulnerability is left intact. |
| `pi/sentinel_sensor.py` | Pi (root) | Real-time sensor merging `journalctl`/`tcpdump`/`inotifywait` into one JSON stream on stdout. |
| `detection/ingest.py` | SOC | Holds a persistent SSH connection to the Pi and reads the sensor stream live (no polling). |
| `detection/rules.py` | SOC | The detection engine: one behavioural rule per technique class, event correlation, and MITRE/kill-chain/severity metadata. |
| `detection/store.py` | SOC | Alert persistence (JSON-lines **and** SQLite). |
| `detection/server.py` | SOC | The main asyncio server: ingest → engine → store → websocket → dashboard. |
| `dashboard/index.html` | SOC (browser) | The live SOC console. |
| `attack/replay.py` | SOC | Reproducible validation harness that runs the whole attack chain against the target. |
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
