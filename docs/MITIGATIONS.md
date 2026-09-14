# Sentinel-E — Mitigations & Hardening Playbook

Detection is half of the defence; prevention is the other half. For every
technique Sentinel-E detects — demonstrated here against the platform's
seven-stage reference intrusion — this playbook gives the concrete control that
**stops** it (or sharply raises the attacker's cost) on a production host or IoT
device. Detection tells you an attack happened; these fixes stop it happening.

Controls are ordered along the kill chain, so a fix applied early protects every
stage that would otherwise follow. Together they form a defence-in-depth posture
you can apply and then re-run the attack against to prove it fails (see the
mitigations exercise in [`../LAB_GUIDE.md`](../LAB_GUIDE.md)).

---

## 1. Reconnaissance — port scanning (T1046)

**Weakness:** every port is reachable from any host on the network; a scan maps
the attack surface freely.

**Mitigations**
- **Host firewall / default-deny.** `nftables`/`ufw` allowing only the ports the
  device actually serves (e.g. 8080 from the management subnet) and dropping the
  rest. A scan then sees one port, not twenty.
- **Network segmentation.** Put IoT devices on their own VLAN with an ACL that
  permits only the management host to reach them. On Tailscale, use **ACLs** so
  only the SOC/admin tags can open the panel.
- **Rate-limit / tarpit** new connections (`nft ... limit rate`) so scanning is
  slow and noisy.

---

## 2. Credential brute-force (T1110)

**Weakness:** the panel accepts unlimited login attempts against a weak,
default-style credential (`admin` / `camera1`).

**Mitigations**
- **Account lockout / exponential backoff** after N failed attempts per source.
- **Rate-limit `/login`** (e.g. Flask-Limiter: 5/min per IP).
- **Strong, unique credentials**; force a password change on first boot; ban
  known-default passwords.
- **Multi-factor authentication** for administrative access.
- **`fail2ban`** watching the panel log (which Sentinel-E already produces) to
  auto-ban offending IPs at the firewall.

---

## 3. Command injection / filter bypass (T1059)

**Weakness:** the ping tool concatenates user input into a shell command
(`subprocess.check_output("ping -c 2 " + host, shell=True)`), and the only
defence is a **blacklist** that `$(...)` trivially bypasses.

**Mitigations**
- **Never build shell strings from input.** Drop `shell=True` and pass an
  argument list: `subprocess.run(["ping", "-c", "2", host])`. The input can no
  longer be interpreted as shell syntax.
- **Positive input validation (allowlist),** not blacklist: accept only a valid
  hostname/IP, e.g. `^[A-Za-z0-9.-]{1,253}$` or `ipaddress.ip_address(host)`,
  and reject everything else.
- **Least privilege:** run the panel as a dedicated unprivileged user in a
  container/namespace so even successful injection gains little.

---

## 4. Reverse shell / C2 on a non-standard port (T1571)

**Weakness:** the device can open arbitrary **outbound** connections, so a shell
can call home on any port.

**Mitigations**
- **Egress filtering / default-deny outbound.** IoT devices rarely need to
  initiate connections; allow only the specific destinations/ports required
  (e.g. NTP, the vendor update server) and drop the rest. This alone kills most
  reverse shells and exfil.
- **DNS egress control** and disallow raw outbound to arbitrary IPs.
- **Application allow-listing** so `bash`/`nc` spawned by the web service is
  blocked or alerted (AppArmor/SELinux profile for the panel process).

---

## 5. Privilege escalation via sudo (T1548)

**Weakness:** the web user (`clupai`) has **passwordless `sudo`** to run
anything as root, so injection instantly becomes root.

**Mitigations**
- **Remove `NOPASSWD: ALL`.** The service account should have *no* sudo.
- If some privileged action is genuinely required, grant a **narrow sudoers
  rule** for exactly that command with fixed arguments — never a general shell.
- **Run the panel under a dedicated low-privilege service account** isolated
  from interactive/admin users, with a restrictive systemd unit
  (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`).

---

## 6. Persistence — backdoor account + sshd change (T1136)

**Weakness:** an attacker with root adds a second UID-0 account to
`/etc/passwd` and enables `PermitRootLogin` for durable access.

**Mitigations**
- **File integrity monitoring** on `/etc/passwd`, `/etc/shadow`,
  `/etc/ssh/sshd_config` (AIDE/auditd) — Sentinel-E already watches these; pair
  detection with **immutable** attributes (`chattr +i`) where feasible.
- **Harden SSH:** `PermitRootLogin no`, key-only auth
  (`PasswordAuthentication no`), `AllowUsers` allowlist; manage `sshd_config`
  via configuration management so drift is reverted automatically.
- **Alert/deny on any new UID-0 account**; audit accounts regularly.
- **Fix stage 5** (remove NOPASSWD sudo) — without root, none of this is
  possible.

---

## 7. Exfiltration of the secret config (T1041 / T1048)

**Weakness:** a sensitive file (`/root/camera_config.secret`) can be read and
copied off the device over the network.

**Mitigations**
- **Egress controls** (as in stage 4) stop the outbound transfer channel.
- **Encrypt secrets at rest** and load them into memory only when needed; don't
  leave plaintext credentials in a world-referenced path.
- **Least-privilege file permissions** and **auditd watches** on sensitive files
  (`auditctl -w /root/camera_config.secret -p r`) so any read is logged.
- **Data-loss-prevention / anomaly detection** on egress volume and
  destinations.

---

## Defence-in-depth summary

| Layer | Control | Stages stopped |
|-------|---------|----------------|
| Network | Firewall, VLAN/Tailscale ACLs, **egress default-deny** | 1, 4, 7 |
| Application | Allowlist input, drop `shell=True`, rate-limit, MFA | 2, 3 |
| Host | Remove NOPASSWD sudo, least-priv service account, hardened systemd unit | 3, 5 |
| Integrity | FIM + immutable configs, hardened `sshd` | 6 |
| Monitoring | Sentinel-E detections + `fail2ban` + `auditd` | all (detect/respond) |

No single control is sufficient; the fixes reinforce each other. Removing
passwordless sudo (5) and adding egress filtering (4/7) are the highest-impact
changes — together they neutralise the entire post-exploitation half of the
chain.
