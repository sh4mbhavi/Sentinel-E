<div align="center">

# ⣿ SENTINEL-E

### Real-Time SOC Detection Platform & IoT Cyber Range

**Stream live host and network telemetry, detect a full adversary kill chain as it happens, and watch it unfold on a real-time security console — mapped end-to-end to MITRE ATT&CK.**

[![License: MIT](https://img.shields.io/badge/License-MIT-d8b0c1.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-1f6feb.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux-303030.svg)](#)
[![ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-7_techniques-ff8090.svg)](#-mitre-attck-coverage)
[![Demo](https://img.shields.io/badge/demo-hardware--free-8fe6b0.svg)](#-quickstart--clone-and-run-in-60-seconds)
[![Status](https://img.shields.io/badge/status-active-8fe6b0.svg)](#)

</div>

---

## What is Sentinel-E?

**Sentinel-E is a self-contained Security Operations Centre (SOC) in a box.** It ingests a live stream of host and network telemetry, runs a behavioural detection engine whose rules are mapped to the MITRE ATT&CK framework, correlates findings across the cyber kill chain, and streams prioritised alerts to a professional real-time web console, no page refresh, no polling, no batch jobs.

It ships with a complete **IoT cyber range**: a deliberately vulnerable smart-camera admin panel as the target, a scripted adversary that drives a genuine seven-stage intrusion, and the blue-team detection stack that catches every stage live. Every alert on the dashboard is produced by the detection engine reasoning over real telemetry, nothing is pre-recorded or faked.

Two ways to run it:

- 🖥️ **Hardware-free demo** — one command, one machine, no external hosts. A local telemetry generator emits the exact event schema a compromised device produces; the unmodified engine detects the whole kill chain live. *You can experience the entire platform in under a minute.*
- 🔌 **Full hardware cyber range** — a real target device, a real attacker box, and real network telemetry streamed to the SOC over a mesh overlay, for hands-on red-vs-blue training against a live host.

---

## ✨ Features

- **Genuinely real-time pipeline** — event-driven telemetry ingestion → detection engine → alert store → WebSocket → live dashboard. Millisecond latency, zero polling.
- **Behavioural detection engine** — seven stateful rules with sliding-window thresholds and cross-signal correlation. Rules fire on *activity patterns*, not brittle signatures, and generalise to any monitored host emitting the same telemetry.
- **Full MITRE ATT&CK mapping** — every detection is tagged with its technique ID, tactic, and cyber-kill-chain phase, and rendered on a live ATT&CK matrix.
- **Professional SOC console** — a dark, high-contrast operations dashboard: KPI tiles, alert-volume and severity charts, a live SIEM-style alert table, the ATT&CK matrix, a cyber-kill-chain tracker, a detection-rule catalogue, and live telemetry-source health.
- **Kill-chain correlation** — raw observations are stitched into the correct attack stage with severity, source attribution, and human-readable context.
- **Hardware-free demo mode** — the entire platform on a laptop, no lab required.
- **Pluggable telemetry** — swap between the local demo generator and a real multi-source hardware sensor (`journalctl` + `tcpdump` + `inotify`) via one config flag.
- **Durable alert store** — every alert persisted to JSON-Lines *and* SQLite; the dashboard replays recent history on reconnect.

---

## 🏛️ Architecture at a glance

```
        ADVERSARY                 TARGET (IoT device)              SENTINEL-E SOC
   ┌───────────────┐          ┌──────────────────────┐        ┌────────────────────┐
   │ recon (nmap)  │  attack  │  vulnerable panel     │        │  ingestion          │
   │ brute (hydra) │ ───────▶ │  :8080  (web login +  │        │   (live stream)     │
   │ $(...) inject │          │   command injection)  │        │        │            │
   │ C2 / exfil    │ ◀─────── │                       │        │        ▼            │
   └───────────────┘   pull   │  telemetry sensor     │        │  detection engine   │
                              │   ├ auth  (journald)  │  live  │   7 ATT&CK rules    │
                              │   ├ net   (tcpdump)   │ ─────▶ │        │            │
                              │   └ files (inotify)   │ stream │        ▼            │
                              └──────────────────────┘        │   alert store       │
                                                              │   (JSONL + SQLite)  │
                                                              │        │            │
                                                              │        ▼  WebSocket │
                                                              │   LIVE DASHBOARD    │
                                                              │        :8770        │
                                                              └────────────────────┘

   Hardware-free demo: the target + adversary + sensor above are replaced by a single
   local telemetry generator. The ingestion → engine → store → dashboard path is identical.
```

Full component-by-component breakdown, data-flow, and diagrams: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## 🚀 Quickstart — clone and run in 60 seconds

No Raspberry Pi, no attacker box, no network setup. Just Python 3.9+.

```bash
git clone https://github.com/sh4mbhavi/Sentinel-E.git
cd Sentinel-E
./demo.sh            # or:  python3 demo.py
```

Then open **http://localhost:8770/** in your browser.

The launcher bootstraps a virtualenv, installs the single dependency (`aiohttp`), and starts the platform. About seven seconds after the dashboard loads, a simulated adversary begins a seven-stage intrusion, watch the **cyber kill chain fill in, the ATT&CK matrix light up, the charts climb, and the alert feed stream** in real time as each stage is detected.

> **It's real detection.** The demo emits raw telemetry (the same schema a compromised device produces) and the **unmodified detection engine** decides every alert by crossing its real thresholds and correlation windows. No alert is hard-coded.

**Prefer containers?** The same demo runs anywhere Docker does:

```bash
docker compose up --build      # then open http://localhost:8770/
```

---

## 🧭 Usage paths

### 1. Hardware-free demo (recommended first run)

```bash
./demo.sh
```
Everything runs locally. Ideal for evaluating the platform, screen-recording the detection flow, or developing new rules. Details: **[LAB_GUIDE.md](LAB_GUIDE.md) → Demo Mode**.

### 2. Full hardware cyber range

Run the SOC on one machine and point it at a real target device streaming live telemetry, then drive the attack from a separate adversary host. This is the hands-on red-vs-blue range.

```bash
./scripts/deploy_pi.sh     # provision the target device's telemetry + vulnerable panel
./scripts/start_soc.sh     # start ingestion + detection + dashboard on the SOC
# then execute the attack chain from the adversary host (see the lab guide)
```

Full walkthrough — environment setup, stage-by-stage attack, what to observe, and the mitigation exercises: **[LAB_GUIDE.md](LAB_GUIDE.md)**.

---

## 🎯 MITRE ATT&CK coverage

Sentinel-E ships behavioural detections for the following technique classes. Each rule is threshold-driven and configurable in `config/*.conf.json`.

| # | Kill-chain phase | Detection (behavioural) | MITRE ATT&CK | Severity |
|---|------------------|-------------------------|--------------|----------|
| 1 | Reconnaissance | one source probing many distinct ports in a short window | **T1046** — Network Service Discovery | `medium` |
| 2 | Weaponisation / Delivery | repeated failed authentications from one source | **T1110** — Brute Force | `high` |
| 3 | Exploitation | shell metacharacters / command substitution in web input | **T1059** — Command & Scripting Interpreter | `high` |
| 4 | Installation | outbound connection to a non-standard C2 port | **T1571** — Non-Standard Port | `critical` |
| 5 | Privilege Escalation | a service account escalating to uid 0 via sudo | **T1548** — Abuse Elevation Control Mechanism | `critical` |
| 6 | Command & Control | new UID-0 account or `sshd_config` modification | **T1136** — Create Account | `critical` |
| 7 | Actions on Objectives | sensitive-file read correlated with an egress channel | **T1041 / T1048** — Exfiltration | `critical` |

Coverage is extensible by design, a new detection is a rule in `detection/rules.py` plus a threshold in config. Full IoC-to-rule mapping: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) → Attack-to-Detection Mapping**.

---

## 🗂️ Repository layout

```
Sentinel-E/
├── demo.sh / demo.py         # one-command hardware-free demo launchers
├── demo/                     # local telemetry generator (simulated sensor)
├── detection/                # the SOC core
│   ├── server.py             #   asyncio app: ingest → engine → store → WebSocket
│   ├── ingest.py             #   pluggable live telemetry ingestion (demo | hardware)
│   ├── rules.py              #   behavioural detection engine (7 ATT&CK rules)
│   └── store.py              #   alert persistence (JSON-Lines + SQLite)
├── dashboard/                # real-time SOC web console (single-page, WebSocket)
├── pi/                       # hardware target: vulnerable panel + multi-source sensor
├── attack/                   # adversary drivers (attack chain, replay harness)
├── config/                   # detection thresholds & profiles (hardware / demo)
├── scripts/                  # deployment & run helpers
└── docs/                     # architecture & mitigations
```

Every script and component is documented in **[SCRIPTS.md](SCRIPTS.md)**.

---

## 📚 Documentation

| Document | What's inside |
|----------|---------------|
| **[LAB_GUIDE.md](LAB_GUIDE.md)** | Hands-on red-vs-blue cyber-range worksheet: setup, the attack stage-by-stage, detection walkthrough, and mitigation exercises. |
| **[SCRIPTS.md](SCRIPTS.md)** | Technical manifest of every script and component — purpose, how to run, dependencies. |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | System architecture, three data-flow diagrams, and the full attack-to-detection mapping. |
| **[docs/MITIGATIONS.md](docs/MITIGATIONS.md)** | Blue-team hardening: the concrete fix that neutralises each technique. |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | How to add detections, extend telemetry, and contribute. |

---

## 🛡️ Responsible use

Sentinel-E includes offensive tooling and an intentionally vulnerable service **for defensive research and controlled lab use only**. Run the attack drivers exclusively against the bundled target, the hardware-free demo, or hardware you own and are authorised to test. Never point them at systems you do not control.

---

## 📄 License

Released under the [MIT License](LICENSE).
