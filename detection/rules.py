"""
Sentinel-E detection engine — stateful rules for the 7-stage attack chain.

The engine is fed already-parsed telemetry events (dicts from the Pi sensor /
panel). It is deliberately *event-driven*: each incoming event is evaluated
against the rules immediately, and any resulting alerts are returned to the
caller (the server), which persists them and pushes them to the dashboard.

Design notes
------------
* Sliding-window rules (recon, brute force) use the SOC's own arrival time, not
  the Pi-supplied timestamp, because the two clocks are not guaranteed to be in
  sync. The Pi timestamp is preserved in the alert for display ("observed at").
* Each stage has a short cooldown so a single burst of activity raises ONE alert
  rather than hundreds — the analyst sees "brute force from X", not 50 lines.
* Every alert carries full context: MITRE technique, kill-chain phase, severity.
"""
import re
import time
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# Stage catalogue: the single source of truth for MITRE / kill-chain / severity.
# The dashboard renders its kill-chain row and ATT&CK matrix straight from this.
# ---------------------------------------------------------------------------
STAGES = {
    "recon": {
        "num": 1, "name": "Reconnaissance",
        "technique_id": "T1046", "technique_name": "Network Service Discovery",
        "phase": "Reconnaissance", "severity": "medium",
    },
    "brute_force": {
        "num": 2, "name": "Credential Brute-Force",
        "technique_id": "T1110", "technique_name": "Brute Force",
        "phase": "Weaponisation / Delivery", "severity": "high",
    },
    "injection": {
        "num": 3, "name": "Command Injection",
        "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
        "phase": "Exploitation", "severity": "high",
    },
    "reverse_shell": {
        "num": 4, "name": "Reverse Shell / C2",
        "technique_id": "T1571", "technique_name": "Non-Standard Port",
        "phase": "Installation", "severity": "critical",
    },
    "privesc": {
        "num": 5, "name": "Privilege Escalation",
        "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism",
        "phase": "Exploitation / Installation", "severity": "critical",
    },
    "persistence": {
        "num": 6, "name": "Persistence",
        "technique_id": "T1136", "technique_name": "Create Account",
        "phase": "Command and Control", "severity": "critical",
    },
    "exfiltration": {
        "num": 7, "name": "Exfiltration",
        "technique_id": "T1041 / T1048", "technique_name": "Exfiltration Over C2 / Alternative Protocol",
        "phase": "Actions on Objectives", "severity": "critical",
    },
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class DetectionEngine:
    def __init__(self, config):
        self.cfg = config["detection"]
        self.pi_ip = config["network"]["pi_ip"]
        self._alert_seq = 0

        # sliding-window state
        self._recon = defaultdict(deque)        # src_ip -> deque[(t, dst_port)]
        self._brute = defaultdict(deque)         # src_ip -> deque[t]

        # correlation state for exfiltration (sensitive read + outbound transfer)
        self._last_secret_access = 0.0
        self._last_outbound_xfer = (0.0, None)   # (t, dst_ip)

        # per-stage cooldown so a burst -> a single alert
        self._last_fired = {}                     # (stage, key) -> t
        self._cooldowns = {
            "recon": 20, "brute_force": 20, "injection": 3,
            "reverse_shell": 10, "privesc": 5, "persistence": 5, "exfiltration": 15,
        }

        # precompile injection regexes
        self._injection_re = [re.compile(p) for p in self.cfg["injection"]["patterns"]]

    # -- helpers ------------------------------------------------------------
    def _cooldown_ok(self, stage, key, now):
        last = self._last_fired.get((stage, key), 0)
        if now - last < self._cooldowns.get(stage, 5):
            return False
        self._last_fired[(stage, key)] = now
        return True

    def _alert(self, stage, src_ip, description, observed_ts=None, **extra):
        self._alert_seq += 1
        meta = STAGES[stage]
        from datetime import datetime, timezone
        return {
            "id": self._alert_seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "observed_ts": observed_ts,
            "stage": stage,
            "stage_num": meta["num"],
            "stage_name": meta["name"],
            "technique_id": meta["technique_id"],
            "technique_name": meta["technique_name"],
            "phase": meta["phase"],
            "severity": meta["severity"],
            "src_ip": src_ip or "n/a",
            "description": description,
            "detail": extra,
        }

    # -- main entry point ---------------------------------------------------
    def process(self, ev):
        """Evaluate one telemetry event; return a list of raised alerts (0..n)."""
        now = time.monotonic()
        src = ev.get("source")
        alerts = []

        # ---- STAGE 1: Reconnaissance (nmap) -------------------------------
        # Rule: >= distinct_ports different destination ports hit by one source
        # within window_seconds => port scan.
        if src == "net" and ev.get("event") == "syn" and ev.get("direction") == "inbound":
            ip = ev.get("src_ip")
            win = self.cfg["recon"]["window_seconds"]
            dq = self._recon[ip]
            dq.append((now, ev.get("dst_port")))
            while dq and now - dq[0][0] > win:
                dq.popleft()
            distinct = {p for _, p in dq}
            if len(distinct) >= self.cfg["recon"]["distinct_ports"] and \
                    self._cooldown_ok("recon", ip, now):
                alerts.append(self._alert(
                    "recon", ip,
                    f"Port scan: {len(distinct)} distinct ports probed from {ip} "
                    f"in {win}s (nmap-style service discovery).",
                    observed_ts=ev.get("ts"),
                    ports=sorted(distinct)))

        # ---- STAGE 4 & exfil-correlation: outbound connections ------------
        if src == "net" and ev.get("event") == "syn" and ev.get("direction") == "outbound":
            dport = ev.get("dst_port")
            dst = ev.get("dst_ip")
            # reverse shell / C2 on a non-standard port
            if dport in self.cfg["reverse_shell"]["suspicious_ports"] and \
                    self._cooldown_ok("reverse_shell", f"{dst}:{dport}", now):
                alerts.append(self._alert(
                    "reverse_shell", self.pi_ip,
                    f"Outbound connection from target to {dst}:{dport} — "
                    f"non-standard C2/reverse-shell port.",
                    observed_ts=ev.get("ts"), dst_ip=dst, dst_port=dport))
            # remember any egress for exfil correlation
            self._last_outbound_xfer = (now, dst)
            alerts += self._maybe_exfil(now, ev.get("ts"))

        # ---- STAGE 2: Brute force (hydra) ---------------------------------
        if src == "panel" and ev.get("event") == "login" and ev.get("success") is False:
            ip = ev.get("src_ip")
            win = self.cfg["brute_force"]["window_seconds"]
            dq = self._brute[ip]
            dq.append(now)
            while dq and now - dq[0] > win:
                dq.popleft()
            if len(dq) >= self.cfg["brute_force"]["failed_logins"] and \
                    self._cooldown_ok("brute_force", ip, now):
                alerts.append(self._alert(
                    "brute_force", ip,
                    f"{len(dq)} failed logins from {ip} in {win}s against the "
                    f"camera panel — credential brute-force.",
                    observed_ts=ev.get("ts"), attempts=len(dq)))

        # ---- STAGE 3: Command injection -----------------------------------
        if src == "panel" and ev.get("event") == "ping":
            host = ev.get("host", "") or ""
            hit = next((rx.pattern for rx in self._injection_re if rx.search(host)), None)
            if hit and self._cooldown_ok("injection", ev.get("src_ip"), now):
                alerts.append(self._alert(
                    "injection", ev.get("src_ip"),
                    f"Shell metacharacters in ping 'host' field: {host!r} "
                    f"(matched /{hit}/) — command injection / filter bypass.",
                    observed_ts=ev.get("ts"), host=host, pattern=hit))

        # ---- STAGE 5: Privilege escalation --------------------------------
        if src == "auth" and ev.get("event") == "sudo":
            if ev.get("invoking_user") in self.cfg["privesc"]["web_users"] and \
                    ev.get("target_user") == "root" and \
                    self._cooldown_ok("privesc", ev.get("invoking_user"), now):
                alerts.append(self._alert(
                    "privesc", self.pi_ip,
                    f"Web/service user '{ev.get('invoking_user')}' escalated to "
                    f"root via sudo: {ev.get('command')}",
                    observed_ts=ev.get("ts"),
                    invoking_user=ev.get("invoking_user"),
                    command=ev.get("command")))

        # ---- STAGE 6: Persistence -----------------------------------------
        if src == "file":
            if ev.get("event") == "passwd_uid0_added" and \
                    self._cooldown_ok("persistence", ev.get("account"), now):
                alerts.append(self._alert(
                    "persistence", self.pi_ip,
                    f"New UID-0 (root-equivalent) account '{ev.get('account')}' "
                    f"added to /etc/passwd — backdoor account persistence.",
                    observed_ts=ev.get("ts"), account=ev.get("account")))
            elif ev.get("event") == "config_modified" and \
                    "sshd_config" in ev.get("path", "") and \
                    self._cooldown_ok("persistence", "sshd_config", now):
                alerts.append(self._alert(
                    "persistence", self.pi_ip,
                    "sshd_config modified — likely enabling root login for "
                    "persistent remote access.",
                    observed_ts=ev.get("ts"), path=ev.get("path")))

        # ---- STAGE 7: Exfiltration (sensitive read + egress) --------------
        if src == "file" and ev.get("event") == "secret_access":
            self._last_secret_access = now
            alerts += self._maybe_exfil(now, ev.get("ts"))

        return alerts

    def _maybe_exfil(self, now, observed_ts):
        """Fire exfiltration only when a sensitive-file read and an outbound
        transfer occur within the correlation window."""
        win = self.cfg["correlation_window_seconds"]
        xfer_t, xfer_dst = self._last_outbound_xfer
        if self._last_secret_access and xfer_t and \
                abs(now - self._last_secret_access) <= win and \
                (now - xfer_t) <= win and \
                self._cooldown_ok("exfiltration", "secret", now):
            return [self._alert(
                "exfiltration", self.pi_ip,
                f"Sensitive file /root/camera_config.secret was read and data "
                f"was sent outbound to {xfer_dst} within {win}s — data exfiltration.",
                observed_ts=observed_ts, dst_ip=xfer_dst)]
        return []
