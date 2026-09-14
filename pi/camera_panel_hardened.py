from flask import Flask, request, render_template_string, redirect, session
import subprocess
import json
import logging
import logging.handlers
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

# =============================================================================
#  IPCam-2000 admin panel — HARDENED build.
#
#  This is the mitigated counterpart of camera_panel.py. It is functionally the
#  same product but with the two application-layer vulnerabilities fixed:
#
#    * Command injection (T1059): the ping "host" field is now validated against
#      a strict ALLOWLIST and executed WITHOUT a shell (argument list). Shell
#      metacharacters / command substitution can no longer reach a shell.
#
#    * Credential brute-force (T1110): the login endpoint now enforces
#      per-source rate-limiting with lockout after repeated failures.
#
#  Telemetry is still emitted (so the SOC keeps full visibility), but blocked
#  input is logged as a distinct, benign event that carries no executed command.
#  Deploy this with scripts/harden.sh; revert with scripts/restore.sh.
# =============================================================================

EVENT_LOG_PATH = "/home/clupai/sentinel/camera_events.jsonl"

_syslog = logging.getLogger("camera_panel")
_syslog.setLevel(logging.INFO)
try:
    _h = logging.handlers.SysLogHandler(address="/dev/log")
    _h.setFormatter(logging.Formatter("camera_panel: %(message)s"))
    _syslog.addHandler(_h)
except Exception:
    pass


def log_event(event_type, **fields):
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": "panel",
        "event": event_type,
        "src_ip": request.remote_addr,
        **fields,
    }
    line = json.dumps(record)
    try:
        import os
        os.makedirs("/home/clupai/sentinel", exist_ok=True)
        with open(EVENT_LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        _syslog.info(line)
    except Exception:
        pass


app = Flask(__name__)
app.secret_key = "ipcam2000_secret"

VALID_USER = "admin"
VALID_PASS = "camera1"

# --- MITIGATION: login rate-limiting / lockout (T1110) ----------------------
LOCK_THRESHOLD = 5          # failed attempts...
LOCK_WINDOW = 30            # ...within this many seconds...
LOCK_DURATION = 60          # ...locks the source IP for this long.
_fail_times = defaultdict(deque)   # ip -> deque[timestamps]
_locked_until = {}                 # ip -> unix time

# --- MITIGATION: strict host allowlist for the diagnostics tool (T1059) ------
# A valid ping target is a hostname or IPv4 address: letters, digits, dots and
# hyphens only. Anything else (metacharacters, $(...), spaces) is rejected
# outright and never reaches a shell — because there is no shell.
HOST_ALLOWLIST = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


STYLE = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9; }
  .topbar { background: linear-gradient(90deg,#111826,#1b2434); border-bottom: 2px solid #2f81f7;
    padding: 12px 24px; display: flex; align-items: center; gap: 14px; }
  .topbar .logo { width: 34px; height: 34px; border-radius: 6px; background: #2f81f7;
    display: flex; align-items: center; justify-content: center; font-weight: 700; color: #fff; font-size: 18px; }
  .topbar h1 { font-size: 17px; font-weight: 600; letter-spacing: .3px; }
  .topbar .model { font-size: 12px; color: #7d8794; margin-left: 4px; }
  .topbar .right { margin-left: auto; font-size: 12px; color: #7d8794; display:flex; gap:16px; align-items:center;}
  .status-dot { width:9px; height:9px; border-radius:50%; background:#3fb950; display:inline-block; margin-right:6px; }
  .layout { display: flex; min-height: calc(100vh - 60px); }
  .sidebar { width: 210px; background: #0f1520; border-right: 1px solid #21262d; padding: 16px 0; }
  .sidebar .item { padding: 11px 22px; font-size: 14px; color: #9aa4b2; cursor: default; border-left: 3px solid transparent; }
  .sidebar .item.active { color: #fff; background: #161d2b; border-left: 3px solid #2f81f7; }
  .main { flex: 1; padding: 26px 32px; }
  .card { background: #0f1520; border: 1px solid #21262d; border-radius: 8px; padding: 22px; margin-bottom: 22px; }
  .card h2 { font-size: 15px; font-weight: 600; margin-bottom: 16px; color:#e6edf3; border-bottom:1px solid #21262d; padding-bottom:10px;}
  .feed { background: #05070c; border:1px solid #21262d; border-radius:6px; height: 300px; display:flex; align-items:center; justify-content:center; position: relative; overflow: hidden; }
  .feed .live { position:absolute; top:12px; left:14px; background:#da3633; color:#fff; font-size:11px; font-weight:700; padding:3px 8px; border-radius:3px; letter-spacing:.5px;}
  .feed .ts { position:absolute; bottom:12px; right:14px; color:#9aa4b2; font-size:12px; font-family: monospace;}
  .feed .noise { color:#30363d; font-size:13px; letter-spacing:2px;}
  .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  table { width:100%; font-size:13px; }
  table td { padding:7px 0; border-bottom:1px solid #1a212c; color:#9aa4b2;}
  table td.k { color:#7d8794; width:45%;}
  table td.v { color:#c9d1d9; }
  input[type=text]{ background:#05070c; border:1px solid #30363d; color:#c9d1d9; padding:9px 12px; border-radius:6px; width:280px; font-size:13px; }
  button, input[type=submit]{ background:#2f81f7; color:#fff; border:none; padding:9px 18px; border-radius:6px; font-size:13px; font-weight:600; cursor:pointer; }
  pre { background:#05070c; border:1px solid #21262d; border-radius:6px; padding:14px; margin-top:14px; font-size:12.5px; color:#8b949e; white-space:pre-wrap; max-height: 260px; overflow:auto; }
  a { color:#2f81f7; text-decoration:none; }
  .hint{ color:#6e7681; font-size:12px; margin-bottom:12px; }
  .login-wrap{ display:flex; align-items:center; justify-content:center; height: calc(100vh - 60px); }
  .login-card{ background:#0f1520; border:1px solid #21262d; border-radius:10px; padding:34px 38px; width:340px; }
  .login-card h2{ font-size:18px; margin-bottom:4px; color:#e6edf3;}
  .login-card p.sub{ font-size:12.5px; color:#7d8794; margin-bottom:22px;}
  .login-card label{ display:block; font-size:12px; color:#7d8794; margin:14px 0 6px;}
  .login-card input{ width:100%; }
  .login-card button{ width:100%; margin-top:22px; }
  .err{ color:#f85149; font-size:12.5px; margin-top:14px;}
  .footer{ text-align:center; color:#484f58; font-size:11px; margin-top:20px;}
</style>
"""

TOPBAR = """
<div class="topbar">
  <div class="logo">IP</div>
  <h1>IPCam-2000 <span class="model">/ NVR Management Console</span></h1>
  <div class="right">
    <span><span class="status-dot"></span>System Online</span>
    <span>Firmware v1.2.5</span>
    <span>admin</span>
  </div>
</div>
"""

LOGIN_PAGE = """
<!DOCTYPE html><html><head><title>IPCam-2000 | Sign In</title>""" + STYLE + """</head>
<body>""" + TOPBAR + """
<div class="login-wrap"><div class="login-card">
  <h2>Sign in</h2><p class="sub">IPCam-2000 Network Video Management</p>
  <form method="POST" action="/login">
    <label>Username</label><input type="text" name="user" autocomplete="off" placeholder="Username">
    <label>Password</label><input type="password" name="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <div class="footer">Hangzhou Vision Systems &middot; Model IPC-2000-POE</div>
</div></div></body></html>
"""

PANEL_PAGE = """
<!DOCTYPE html><html><head><title>IPCam-2000 | Console</title>""" + STYLE + """
<script>function tick(){var d=new Date();var el=document.getElementById('ts');if(el){el.textContent=d.toLocaleString();}}
setInterval(tick,1000);window.onload=tick;</script></head>
<body>""" + TOPBAR + """
<div class="layout"><div class="sidebar">
  <div class="item">Live View</div><div class="item">Playback</div><div class="item">Configuration</div>
  <div class="item">Storage</div><div class="item">Network</div><div class="item active">Maintenance</div>
  <div class="item">System Log</div><div class="item"><a href="/logout">Sign Out</a></div>
</div><div class="main">
  <div class="grid">
    <div class="card"><h2>Channel 1 &mdash; Live View</h2>
      <div class="feed"><div class="live">&#9679; LIVE</div><div class="noise">NO SIGNAL &middot; CH01</div><div class="ts" id="ts"></div></div></div>
    <div class="card"><h2>Device Information</h2><table>
      <tr><td class="k">Model</td><td class="v">IPC-2000-POE</td></tr>
      <tr><td class="k">Firmware</td><td class="v">V1.2.5 build 2024</td></tr>
      <tr><td class="k">Serial No.</td><td class="v">IPC2000-A3F91C</td></tr>
      <tr><td class="k">Channels</td><td class="v">4 (1 active)</td></tr>
      <tr><td class="k">Resolution</td><td class="v">1920x1080 @ 25fps</td></tr>
      <tr><td class="k">Uptime</td><td class="v">14 days, 06:12:44</td></tr></table></div>
  </div>
  <div class="card"><h2>Maintenance &mdash; Network Diagnostics</h2>
    <p class="hint">Ping a host to verify network connectivity from the device.</p>
    <form method="POST" action="/ping">
      <input type="text" name="host" placeholder="e.g. 8.8.8.8"><button type="submit">Run Ping Test</button></form>
    {% if output %}<pre>{{ output }}</pre>{% endif %}
  </div>
</div></div></body></html>
"""


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template_string(PANEL_PAGE, output=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        now = time.time()
        # MITIGATION: reject any attempt from a locked-out source.
        if now < _locked_until.get(ip, 0):
            log_event("login", username=request.form.get("user"),
                      success=False, blocked="rate_limited")
            return render_template_string(
                LOGIN_PAGE,
                error="Too many failed attempts. This client is temporarily locked out.")
        user = request.form.get("user")
        if user == VALID_USER and request.form.get("password") == VALID_PASS:
            session["logged_in"] = True
            _fail_times.pop(ip, None)
            log_event("login", username=user, success=True)
            return redirect("/")
        # record the failure and lock out if the threshold is crossed
        dq = _fail_times[ip]
        dq.append(now)
        while dq and now - dq[0] > LOCK_WINDOW:
            dq.popleft()
        log_event("login", username=user, success=False)
        if len(dq) >= LOCK_THRESHOLD:
            _locked_until[ip] = now + LOCK_DURATION
            dq.clear()
        return render_template_string(LOGIN_PAGE, error="Invalid username or password.")
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/ping", methods=["POST"])
def ping():
    if not session.get("logged_in"):
        return redirect("/login")
    host = request.form.get("host", "")

    # MITIGATION: positive input validation (allowlist). Anything that is not a
    # plain hostname/IP is rejected and logged as a blocked event — it is never
    # passed to a command interpreter.
    if not HOST_ALLOWLIST.fullmatch(host):
        log_event("ping_blocked", host=host, reason="input_validation")
        return render_template_string(
            PANEL_PAGE,
            output="Error: invalid host. Enter a valid hostname or IP address.")

    log_event("ping", host=host)
    # MITIGATION: no shell. Arguments are passed as a list, so the input cannot
    # be interpreted as shell syntax even if the allowlist were bypassed.
    try:
        output = subprocess.run(
            ["ping", "-c", "2", host],
            capture_output=True, text=True, timeout=10).stdout or "(no output)"
    except Exception as e:
        output = str(e)
    return render_template_string(PANEL_PAGE, output=output)


if __name__ == "__main__":
    print("IPCam-2000 admin console (HARDENED) online at http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080)
