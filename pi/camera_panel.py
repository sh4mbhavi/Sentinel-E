from flask import Flask, request, render_template_string, redirect, session
import subprocess
# --- Sentinel-E telemetry additions ------------------------------------------
# The following imports/logging setup are the ONLY functional change to the
# original vulnerable panel. They emit a structured record for every login and
# ping attempt so the SOC can detect brute-force and command-injection activity
# in real time. The vulnerability itself is deliberately left intact.
import json
import logging
import logging.handlers
from datetime import datetime, timezone

# Two sinks per event:
#   1) a JSON-lines file on the Pi (durable local audit trail), and
#   2) the local syslog/journald with identifier "camera_panel", which the
#      Sentinel-E sensor tails in real time and forwards to the SOC.
EVENT_LOG_PATH = "/home/clupai/sentinel/camera_events.jsonl"

_syslog = logging.getLogger("camera_panel")
_syslog.setLevel(logging.INFO)
try:
    _h = logging.handlers.SysLogHandler(address="/dev/log")
    # The "camera_panel:" prefix becomes the SYSLOG_IDENTIFIER the sensor filters on.
    _h.setFormatter(logging.Formatter("camera_panel: %(message)s"))
    _syslog.addHandler(_h)
except Exception:
    pass


def log_event(event_type, **fields):
    """Emit one structured telemetry record to the JSONL file and to syslog."""
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
    # Syslog message is the JSON payload itself so the sensor can re-emit it verbatim.
    try:
        _syslog.info(line)
    except Exception:
        pass
# -----------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "ipcam2000_secret"

# --- Login credentials (attacker must discover/defeat these) ---
VALID_USER = "admin"
VALID_PASS = "camera1"   # weak default-style credential

# ---------------------------------------------------------------------------
# Shared CSS/theme so login and panel look like one real product.
# ---------------------------------------------------------------------------
STYLE = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9;
  }
  .topbar {
    background: linear-gradient(90deg,#111826,#1b2434);
    border-bottom: 2px solid #2f81f7;
    padding: 12px 24px; display: flex; align-items: center; gap: 14px;
  }
  .topbar .logo {
    width: 34px; height: 34px; border-radius: 6px;
    background: #2f81f7; display: flex; align-items: center; justify-content: center;
    font-weight: 700; color: #fff; font-size: 18px;
  }
  .topbar h1 { font-size: 17px; font-weight: 600; letter-spacing: .3px; }
  .topbar .model { font-size: 12px; color: #7d8794; margin-left: 4px; }
  .topbar .right { margin-left: auto; font-size: 12px; color: #7d8794; display:flex; gap:16px; align-items:center;}
  .status-dot { width:9px; height:9px; border-radius:50%; background:#3fb950; display:inline-block; margin-right:6px; }

  .layout { display: flex; min-height: calc(100vh - 60px); }
  .sidebar {
    width: 210px; background: #0f1520; border-right: 1px solid #21262d; padding: 16px 0;
  }
  .sidebar .item {
    padding: 11px 22px; font-size: 14px; color: #9aa4b2; cursor: default;
    border-left: 3px solid transparent;
  }
  .sidebar .item.active { color: #fff; background: #161d2b; border-left: 3px solid #2f81f7; }
  .sidebar .item:hover { background: #131a26; }

  .main { flex: 1; padding: 26px 32px; }
  .card {
    background: #0f1520; border: 1px solid #21262d; border-radius: 8px;
    padding: 22px; margin-bottom: 22px;
  }
  .card h2 { font-size: 15px; font-weight: 600; margin-bottom: 16px; color:#e6edf3;
             border-bottom:1px solid #21262d; padding-bottom:10px;}
  .feed {
    background: #05070c; border:1px solid #21262d; border-radius:6px;
    height: 300px; display:flex; align-items:center; justify-content:center;
    position: relative; overflow: hidden;
  }
  .feed .live { position:absolute; top:12px; left:14px; background:#da3633; color:#fff;
    font-size:11px; font-weight:700; padding:3px 8px; border-radius:3px; letter-spacing:.5px;}
  .feed .ts { position:absolute; bottom:12px; right:14px; color:#9aa4b2; font-size:12px;
    font-family: monospace;}
  .feed .noise { color:#30363d; font-size:13px; letter-spacing:2px;}
  .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  table { width:100%; font-size:13px; }
  table td { padding:7px 0; border-bottom:1px solid #1a212c; color:#9aa4b2;}
  table td.k { color:#7d8794; width:45%;}
  table td.v { color:#c9d1d9; }
  input[type=text]{
    background:#05070c; border:1px solid #30363d; color:#c9d1d9;
    padding:9px 12px; border-radius:6px; width:280px; font-size:13px;
  }
  button, input[type=submit]{
    background:#2f81f7; color:#fff; border:none; padding:9px 18px; border-radius:6px;
    font-size:13px; font-weight:600; cursor:pointer;
  }
  button:hover{ background:#1f6feb; }
  pre {
    background:#05070c; border:1px solid #21262d; border-radius:6px;
    padding:14px; margin-top:14px; font-size:12.5px; color:#8b949e; white-space:pre-wrap;
    max-height: 260px; overflow:auto;
  }
  a { color:#2f81f7; text-decoration:none; }
  .hint{ color:#6e7681; font-size:12px; margin-bottom:12px; }

  /* login */
  .login-wrap{ display:flex; align-items:center; justify-content:center; height: calc(100vh - 60px); }
  .login-card{ background:#0f1520; border:1px solid #21262d; border-radius:10px;
    padding:34px 38px; width:340px; }
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
    <span>Firmware v1.2.4</span>
    <span>admin</span>
  </div>
</div>
"""

LOGIN_PAGE = """
<!DOCTYPE html><html><head><title>IPCam-2000 | Sign In</title>""" + STYLE + """</head>
<body>
""" + TOPBAR + """
<div class="login-wrap">
  <div class="login-card">
    <h2>Sign in</h2>
    <p class="sub">IPCam-2000 Network Video Management</p>
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="user" autocomplete="off" placeholder="Username">
      <label>Password</label>
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Sign In</button>
    </form>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <div class="footer">Hangzhou Vision Systems &middot; Model IPC-2000-POE</div>
  </div>
</div>
</body></html>
"""

PANEL_PAGE = """
<!DOCTYPE html><html><head><title>IPCam-2000 | Console</title>""" + STYLE + """
<script>
  function tick(){
    var d=new Date();
    var el=document.getElementById('ts');
    if(el){el.textContent=d.toLocaleString();}
  }
  setInterval(tick,1000);window.onload=tick;
</script>
</head>
<body>
""" + TOPBAR + """
<div class="layout">
  <div class="sidebar">
    <div class="item">Live View</div>
    <div class="item">Playback</div>
    <div class="item">Configuration</div>
    <div class="item">Storage</div>
    <div class="item">Network</div>
    <div class="item active">Maintenance</div>
    <div class="item">System Log</div>
    <div class="item"><a href="/logout">Sign Out</a></div>
  </div>
  <div class="main">
    <div class="grid">
      <div class="card">
        <h2>Channel 1 &mdash; Live View</h2>
        <div class="feed">
          <div class="live">&#9679; LIVE</div>
          <div class="noise">NO SIGNAL &middot; CH01</div>
          <div class="ts" id="ts"></div>
        </div>
      </div>
      <div class="card">
        <h2>Device Information</h2>
        <table>
          <tr><td class="k">Model</td><td class="v">IPC-2000-POE</td></tr>
          <tr><td class="k">Firmware</td><td class="v">V1.2.4 build 2024</td></tr>
          <tr><td class="k">Serial No.</td><td class="v">IPC2000-A3F91C</td></tr>
          <tr><td class="k">Channels</td><td class="v">4 (1 active)</td></tr>
          <tr><td class="k">Resolution</td><td class="v">1920x1080 @ 25fps</td></tr>
          <tr><td class="k">Uptime</td><td class="v">14 days, 06:12:44</td></tr>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>Maintenance &mdash; Network Diagnostics</h2>
      <p class="hint">Ping a host to verify network connectivity from the device.</p>
      <form method="POST" action="/ping">
        <input type="text" name="host" placeholder="e.g. 8.8.8.8">
        <button type="submit">Run Ping Test</button>
      </form>
      {% if output %}<pre>{{ output }}</pre>{% endif %}
    </div>
  </div>
</div>
</body></html>
"""

@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template_string(PANEL_PAGE, output=None)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("user")
        if user == VALID_USER and request.form.get("password") == VALID_PASS:
            session["logged_in"] = True
            # Telemetry: successful authentication.
            log_event("login", username=user, success=True)
            return redirect("/")
        # Telemetry: failed authentication -> feeds the brute-force detector.
        log_event("login", username=user, success=False)
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

    # Telemetry: record the RAW host value BEFORE any filtering so the SOC's
    # injection detector sees exactly what the attacker submitted.
    log_event("ping", host=host)

    # --- INPUT FILTER: naive blacklist (bypassable) ---
    blacklist = [";", "&&", "|", "`", "whoami", "cat ", "&"]
    for bad in blacklist:
        if bad in host:
            return render_template_string(PANEL_PAGE,
                output="Error: invalid characters detected in host field.")

    # Still VULNERABLE: input concatenated into a shell command.
    command = "ping -c 2 " + host
    try:
        output = subprocess.check_output(command, shell=True,
                                         stderr=subprocess.STDOUT, timeout=10).decode()
    except subprocess.CalledProcessError as e:
        output = e.output.decode()
    except Exception as e:
        output = str(e)
    return render_template_string(PANEL_PAGE, output=output)

if __name__ == "__main__":
    print("IPCam-2000 admin console online at http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080)
