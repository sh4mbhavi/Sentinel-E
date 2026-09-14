"""
Real-time telemetry ingestion for Sentinel-E.

Two interchangeable telemetry sources, selected by `sensor.mode` in the config:

  * hardware mode (default) — opens a PERSISTENT SSH connection to the target and
    runs the sensor as root; the sensor's stdout is a live newline-JSON stream we
    read line-by-line as it arrives. Genuinely event-driven — no interval, no
    snapshot, no polling. New activity appears here within milliseconds.

  * demo mode — spawns the LOCAL telemetry generator (demo/sim_sensor.py) and
    reads its stdout the same way. This is what powers the hardware-free demo:
    identical event schema, identical downstream pipeline, no external hosts.

Either way, if the stream drops (target reboot, network blip, generator restart)
we reconnect automatically with a short backoff, so the pipeline is self-healing.
"""
import asyncio
import json
import os
import sys


class Ingestor:
    def __init__(self, config, on_event, on_status=None):
        net = config["network"]
        self.pi_ip = net["pi_ip"]
        self.user = net["pi_ssh_user"]
        self.key = os.path.expanduser(net["pi_ssh_key"])
        self.soc_ip = net["soc_ip"]
        self.iface = net["monitor_iface"]
        self.attacker_ip = net.get("attacker_ip", "10.13.37.37")
        self.mode = config.get("sensor", {}).get("mode", "hardware")
        self.on_event = on_event            # async callable(event_dict)
        self.on_status = on_status          # async callable(status_str)
        self._stop = False

    def _root(self):
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _cmd(self):
        """Return (argv, extra_env) for the telemetry source in the active mode."""
        if self.mode == "demo":
            # Local generator — no SSH, no external hosts. Uses this interpreter.
            argv = [sys.executable, "-u",
                    os.path.join(self._root(), "demo", "sim_sensor.py")]
            env = {"SENTINEL_TARGET_IP": self.pi_ip,
                   "SENTINEL_ATTACKER_IP": self.attacker_ip}
            return argv, env
        # hardware mode: run the sensor as root on the target over persistent SSH;
        # pass SOC identity so it can exclude its own management channel.
        remote = (
            f"sudo SENTINEL_IFACE={self.iface} SENTINEL_SOC_IP={self.soc_ip} "
            f"python3 -u /home/clupai/sentinel_sensor.py")
        argv = [
            "ssh", "-i", self.key,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            f"{self.user}@{self.pi_ip}", remote,
        ]
        return argv, {}

    async def _status(self, s):
        if self.on_status:
            await self.on_status(s)

    async def run(self):
        backoff = 2
        while not self._stop:
            where = "local generator" if self.mode == "demo" \
                else f"sensor on {self.pi_ip}"
            await self._status(f"connecting to {where} …")
            argv, extra_env = self._cmd()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env={**os.environ, **extra_env})
            except Exception as e:
                await self._status(f"sensor spawn failed: {e}")
                await asyncio.sleep(backoff)
                continue

            await self._status("sensor stream connected")
            backoff = 2
            try:
                async for raw in proc.stdout:
                    line = raw.decode(errors="replace").strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    await self.on_event(ev)
            finally:
                if proc.returncode is None:
                    proc.terminate()
                await self._status("sensor stream disconnected — retrying")
            if not self._stop:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 15)

    def stop(self):
        self._stop = True
