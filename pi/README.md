# `pi/` — files that live on the Raspberry Pi target (`100.119.99.36`)

These are **copies** of the files Sentinel-E installs/modifies on the Pi, kept
in the repo so the whole system is captured in one place. They actually run on
the Pi under `/home/clupai/`.

| File | Runs on Pi as | Purpose |
|------|---------------|---------|
| `camera_panel.py` | `/home/clupai/camera_panel.py` (user `clupai`, port 8080) | The deliberately vulnerable IPCam admin panel, **modified** to emit structured JSON telemetry (to `/home/clupai/sentinel/camera_events.jsonl` and to syslog under identifier `camera_panel`) for every login and ping. The command-injection vulnerability is deliberately left intact. |
| `sentinel_sensor.py` | `/home/clupai/sentinel_sensor.py` (run as root via `sudo`) | The real-time telemetry sensor. Merges three event-driven sources — `journalctl -f`, `tcpdump`, and `inotifywait` — into a single newline-JSON stream on stdout, which the SOC consumes over a persistent SSH connection. |

## Telemetry sources merged by `sentinel_sensor.py`

1. **`journalctl -f -o json`** — panel app events (login/ping), `sudo` usage
   (privilege escalation), and `sshd` auth. Event-driven follow, no polling.
2. **`tcpdump` on `tailscale0`** — bare TCP SYNs. Inbound SYNs to many ports =
   reconnaissance; outbound SYNs from the Pi to non-standard ports = reverse
   shell / C2 / exfil. The SOC's own SSH management channel (port 22) is
   excluded so the sensor never flags itself.
3. **`inotifywait -m`** — modification of `/etc/passwd`, `/etc/shadow`,
   `/etc/ssh/sshd_config` (persistence), and read/access of
   `/root/camera_config.secret` (exfiltration).

## Deploy (done automatically by the SOC-side setup, shown here for reference)

```bash
scp -i ~/.ssh/pi_key pi/camera_panel.py    clupai@100.119.99.36:/home/clupai/camera_panel.py
scp -i ~/.ssh/pi_key pi/sentinel_sensor.py clupai@100.119.99.36:/home/clupai/sentinel_sensor.py
# panel is (re)started on the Pi:
ssh -i ~/.ssh/pi_key clupai@100.119.99.36 'cd /home/clupai && setsid nohup python3 camera_panel.py >/home/clupai/sentinel/panel.out 2>&1 </dev/null'
```

The sensor itself is **not** started on the Pi directly — the SOC launches it
over SSH and reads its stdout live (see `../detection/ingest.py`).
