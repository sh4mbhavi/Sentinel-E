"""
Real-time telemetry ingestion for Sentinel-E.

Opens a PERSISTENT SSH connection to the Pi and runs the sensor as root; the
sensor's stdout is a live newline-JSON stream that we read line-by-line as it
arrives. This is genuinely event-driven — there is no interval, no snapshot,
no polling. New activity on the Pi appears here within milliseconds.

If the SSH connection drops (Pi reboot, network blip) we reconnect
automatically with a short backoff, so the pipeline is self-healing.
"""
import asyncio
import json
import os


class Ingestor:
    def __init__(self, config, on_event, on_status=None):
        net = config["network"]
        self.pi_ip = net["pi_ip"]
        self.user = net["pi_ssh_user"]
        self.key = os.path.expanduser(net["pi_ssh_key"])
        self.soc_ip = net["soc_ip"]
        self.iface = net["monitor_iface"]
        self.on_event = on_event            # async callable(event_dict)
        self.on_status = on_status          # async callable(status_str)
        self._stop = False

    def _ssh_cmd(self):
        # Run the sensor as root on the Pi; pass SOC identity so it can exclude
        # its own management channel. -tt not used (no PTY) so stdout stays clean.
        remote = (
            f"sudo SENTINEL_IFACE={self.iface} SENTINEL_SOC_IP={self.soc_ip} "
            f"python3 -u /home/clupai/sentinel_sensor.py")
        return [
            "ssh", "-i", self.key,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            f"{self.user}@{self.pi_ip}", remote,
        ]

    async def _status(self, s):
        if self.on_status:
            await self.on_status(s)

    async def run(self):
        backoff = 2
        while not self._stop:
            await self._status(f"connecting to sensor on {self.pi_ip} …")
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self._ssh_cmd(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
            except Exception as e:
                await self._status(f"ssh spawn failed: {e}")
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
