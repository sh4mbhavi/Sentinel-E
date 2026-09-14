# Sentinel-E — Component & Script Manifest

A technical index of every component in the platform: what it does, how to run it, and what it depends on. Components are grouped by role.

**Runtime dependency:** the entire SOC runs on Python 3.9+ with a single third-party package, `aiohttp` (HTTP + WebSocket server). The launchers install it into a local `.venv` automatically. The hardware sensor additionally uses `tcpdump` and `inotify-tools` on the target.

---

## Launchers

### `demo.sh` · `demo.py`
- **Purpose:** one-command start of the **hardware-free demo** — bootstraps the virtualenv, installs `aiohttp`, wipes the demo alert store, and starts the SOC with the demo profile (`SENTINEL_CONFIG=config/demo.conf.json`).
- **Run:** `./demo.sh` (bash) or `python3 demo.py` (cross-platform).
- **Depends on:** Python 3.9+. Everything else is provisioned on first run.
- **Result:** dashboard on `http://localhost:8770/`; a simulated seven-stage attack begins ~7s after load.

---

## SOC core — `detection/`

### `detection/server.py`
- **Purpose:** the asyncio application that ties the platform together — starts ingestion, runs the detection engine on every event, persists alerts, and serves the dashboard + WebSocket. Selects its run profile from `SENTINEL_CONFIG` (defaults to the hardware config).
- **Run (hardware):** `./.venv/bin/python detection/server.py` — or via `./scripts/start_soc.sh`.
- **Run (demo):** `SENTINEL_CONFIG=config/demo.conf.json ./.venv/bin/python detection/server.py` — or via `./demo.sh`.
- **Depends on:** `aiohttp`, and the sibling modules below.
- **Serves:** `GET /` (dashboard), `GET /api/meta`, `GET /api/bootstrap`, `GET /ws` (live WebSocket).

### `detection/ingest.py`
- **Purpose:** pluggable, self-healing telemetry ingestion. In **demo mode** it spawns the local generator (`demo/sim_sensor.py`); in **hardware mode** it holds a persistent SSH stream from the target's sensor. Either way it reads newline-delimited JSON events live and auto-reconnects on drop.
- **Run:** used by `server.py`; not run directly.
- **Depends on:** the active config's `sensor.mode`; in hardware mode, an SSH key to the target.

### `detection/rules.py`
- **Purpose:** the **detection engine** (`DetectionEngine`). Seven stateful, behavioural rules with sliding-window thresholds and cross-signal correlation, plus the `STAGES` catalogue (MITRE technique, kill-chain phase, severity) that the dashboard renders from. Evaluates each telemetry event and returns any raised alerts.
- **Run:** imported by `server.py`. Unit-testable directly by constructing `DetectionEngine(config)` and feeding it event dicts.
- **Depends on:** the config's `detection` thresholds and `network` map.

### `detection/store.py`
- **Purpose:** alert persistence. Every alert is written to **JSON-Lines** (greppable) and **SQLite** (queryable, survives restarts). Recent history is replayed to reconnecting dashboards.
- **Run:** used by `server.py`.
- **Depends on:** the config's `storage` paths (separate files for demo vs hardware).

---

## Telemetry generators (sensors)

### `demo/sim_sensor.py`
- **Purpose:** the **local telemetry generator** for the hardware-free demo. Emits the real sensor's NDJSON schema (`net` / `panel` / `auth` / `file`) for a full seven-stage intrusion. Emits **raw observations only** — the engine decides every alert. Genuinely crosses each rule's threshold/correlation window.
- **Run:** spawned by `ingest.py` in demo mode. Standalone: `SENTINEL_TARGET_IP=… SENTINEL_ATTACKER_IP=… python3 demo/sim_sensor.py`.
- **Tuning:** `SENTINEL_DEMO_WARMUP`, `SENTINEL_DEMO_GAP` (pacing), `SENTINEL_DEMO_LOOP=1` (continuous).
- **Depends on:** Python standard library only.

### `pi/sentinel_sensor.py`
- **Purpose:** the **hardware target sensor** (runs on the device as root). Merges three real, event-driven telemetry sources — `journalctl -f` (auth/sudo/sshd), `tcpdump` (network SYNs), and `inotifywait` (file integrity on `/etc/passwd`, `sshd_config`, and the sensitive file) — into a single JSON stream on stdout. No polling.
- **Run:** launched remotely by the SOC over SSH (see `ingest.py`); not started manually.
- **Depends on:** `tcpdump`, `inotify-tools`, root (for packet capture, journald, and `/root` inotify).

### `pi/camera_panel.py`
- **Purpose:** the **intentionally vulnerable target** — a smart-camera admin panel (Flask, `:8080`) with a weak login and a "network diagnostics" ping tool whose `host` field is command-injectable (a naive blacklist bypassable with `$(...)`). Modified to emit structured login/ping telemetry. The vulnerability is deliberate.
- **Run (on the target):** `python3 camera_panel.py` — deployed and started by `scripts/deploy_pi.sh`.
- **Depends on:** Flask.

---

## Adversary tooling — `attack/`

### `attack/kali_attack.sh`
- **Purpose:** the **real red-team runbook** — the genuine seven-stage chain executed *from the attacker host* against the hardware target (nmap recon, brute-force, `$(...)` injection driving reverse shell / privesc / persistence / exfil). Real source IPs, no relabeling.
- **Run (on the attacker):** `chmod +x kali_attack.sh && ./kali_attack.sh`.
- **Depends on:** `nmap`, `curl`, `nc` (`hydra` optional).

### `attack/replay.py`
- **Purpose:** a **reproducible attack/validation harness** that drives the full chain and can reset lab state. Useful for repeatable demos and CI-style verification of the hardware pipeline.
- **Run:** `python3 attack/replay.py [--fast]` to attack; `python3 attack/replay.py --cleanup` to remove backdoor artifacts and revert SSH hardening on the target.
- **Depends on:** Python standard library; SSH access for `--cleanup`.

---

## Deployment & operations — `scripts/`

### `scripts/deploy_pi.sh`
- **Purpose:** provisions the **hardware target** — copies the vulnerable panel and the sensor to the device and (re)starts the panel with logging enabled.
- **Run (from the SOC):** `./scripts/deploy_pi.sh`.
- **Depends on:** SSH key access to the target (configured in `config/sentinel.conf.json`).

### `scripts/start_soc.sh`
- **Purpose:** starts the **SOC** for the hardware range — creates the venv/deps on first run and launches `detection/server.py` with the hardware profile.
- **Run:** `./scripts/start_soc.sh`.
- **Depends on:** Python 3.9+.

### `scripts/harden.sh` · `scripts/restore.sh`
- **Purpose:** the **blue-team mitigation toggle**. `harden.sh` applies the full defence-in-depth posture to the target — swaps in the hardened panel (input allowlist, no-shell exec, login lockout), removes the backdoor, disables root SSH, makes `/etc/passwd` immutable, and adds egress default-deny to known C2/exfil ports. `restore.sh` reverses every change, returning the range to its exploitable state. This makes the red → blue → red loop a two-command exercise.
- **Run (from the SOC):** `./scripts/harden.sh` to apply, `./scripts/restore.sh` to revert.
- **Depends on:** SSH access to the target; `nft` on the target for the egress rule (skipped gracefully if absent).
- **Result after harden:** re-running the attack fails — recon/brute are still detected as attempts but gain nothing; injection is rejected, so there is no shell and therefore no privilege escalation, persistence, or exfiltration.

### `pi/camera_panel_hardened.py`
- **Purpose:** the **mitigated panel** — the same product with the two application-layer vulnerabilities fixed (allowlisted, shell-free ping diagnostics; rate-limited login with lockout). Deployed by `harden.sh`; the original vulnerable panel is preserved and restored by `restore.sh`.

---

## Configuration — `config/`

### `config/sentinel.conf.json`
- **Purpose:** the **hardware profile** — network map (target/attacker/SOC), detection thresholds, dashboard port, storage paths, and `sensor.mode: hardware`.

### `config/demo.conf.json`
- **Purpose:** the **demo profile** — illustrative IPs, `sensor.mode: demo`, a separate demo alert store, and identical detection thresholds so the demo exercises the exact same rules.

> All detection tuning (window sizes, thresholds, suspicious ports, correlation window) lives in these files — changing sensitivity is a config edit, not a code change.

---

## Presentation — `dashboard/`

### `dashboard/index.html`
- **Purpose:** the **real-time SOC console** — a single self-contained page (WebSocket client, inline SVG charts, no external runtime dependencies) rendering the KPI tiles, alert-volume and severity charts, cyber kill chain, ATT&CK matrix, detection-rule catalogue, telemetry-source health, and the live SIEM-style alert table with a detail drawer.
- **Run:** served by `detection/server.py`; open the dashboard URL in a browser.
- **Depends on:** a modern browser. The scaffolding, kill chain, ATT&CK matrix, and rule catalogue are rendered from the engine's `STAGES` catalogue, so new detections appear automatically.
