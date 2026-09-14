#!/usr/bin/env python3
"""
Sentinel-E SOC server — the heart of the platform (runs on Fedora).

One asyncio process that:
  1. ingests the Pi's live telemetry stream (detection/ingest.py),
  2. runs the detection engine on every event (detection/rules.py),
  3. persists raised alerts (detection/store.py), and
  4. serves the live SOC dashboard over HTTP + WebSocket, pushing every alert
     and kill-chain update to connected browsers instantly.

Run:  ./.venv/bin/python detection/server.py
Then open http://<soc-ip>:8770/
"""
import asyncio
import json
import os
import sys
import weakref

from aiohttp import web, WSMsgType

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from rules import DetectionEngine, STAGES, SEVERITY_RANK  # noqa: E402
from store import AlertStore  # noqa: E402
from ingest import Ingestor  # noqa: E402


def load_config():
    # SENTINEL_CONFIG selects the active profile; defaults to the hardware config.
    # The hardware-free demo sets it to config/demo.conf.json.
    path = os.environ.get("SENTINEL_CONFIG",
                          os.path.join(ROOT, "config", "sentinel.conf.json"))
    if not os.path.isabs(path):
        path = os.path.join(ROOT, path)
    with open(path) as f:
        return json.load(f)


class SOCServer:
    def __init__(self, config):
        self.cfg = config
        self.engine = DetectionEngine(config)
        self.store = AlertStore(
            os.path.join(ROOT, config["storage"]["alerts_jsonl"]),
            os.path.join(ROOT, config["storage"]["alerts_db"]))
        self.ingestor = Ingestor(config, self.on_event, self.on_status)
        self._ws = weakref.WeakSet()        # connected dashboard sockets
        self.sensor_status = "offline"
        # live aggregate state pushed to the dashboard
        self.counts = {"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        self.fired_stages = set()           # stage keys that have triggered

    # -- websocket fan-out --------------------------------------------------
    async def broadcast(self, msg):
        dead = []
        for ws in list(self._ws):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws.discard(ws)

    # -- ingest callbacks ---------------------------------------------------
    async def on_status(self, status):
        self.sensor_status = status
        await self.broadcast({"type": "status", "sensor": status})

    async def on_event(self, ev):
        # Optional: surface raw telemetry to the dashboard's event ticker.
        await self.broadcast({"type": "telemetry", "event": ev})
        for alert in self.engine.process(ev):
            self.store.save(alert)
            self.counts["total"] += 1
            self.counts[alert["severity"]] = self.counts.get(alert["severity"], 0) + 1
            self.fired_stages.add(alert["stage"])
            await self.broadcast({
                "type": "alert",
                "alert": alert,
                "counts": self.counts,
                "fired_stages": sorted(self.fired_stages),
            })

    # -- http handlers ------------------------------------------------------
    async def index(self, request):
        with open(os.path.join(ROOT, "dashboard", "index.html")) as f:
            return web.Response(text=f.read(), content_type="text/html")

    async def api_meta(self, request):
        """Static metadata the dashboard needs to render its scaffolding."""
        return web.json_response({
            "stages": STAGES,
            "network": self.cfg["network"],
        })

    async def api_bootstrap(self, request):
        """Alert history + current aggregate state for a (re)connecting client."""
        history = self.store.recent(limit=200)
        counts = {"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        fired = set()
        for a in history:
            counts["total"] += 1
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            fired.add(a["stage"])
        # keep live counters in sync with what we just loaded
        self.counts = counts
        self.fired_stages = fired
        return web.json_response({
            "history": history, "counts": counts,
            "fired_stages": sorted(fired), "sensor_status": self.sensor_status,
        })

    async def ws_handler(self, request):
        ws = web.WebSocketResponse(heartbeat=20)
        await ws.prepare(request)
        self._ws.add(ws)
        await ws.send_json({"type": "status", "sensor": self.sensor_status})
        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            self._ws.discard(ws)
        return ws

    # -- lifecycle ----------------------------------------------------------
    async def start_background(self, app):
        app["ingest_task"] = asyncio.create_task(self.ingestor.run())

    async def cleanup_background(self, app):
        self.ingestor.stop()
        app["ingest_task"].cancel()

    def build_app(self):
        app = web.Application()
        app.router.add_get("/", self.index)
        app.router.add_get("/api/meta", self.api_meta)
        app.router.add_get("/api/bootstrap", self.api_bootstrap)
        app.router.add_get("/ws", self.ws_handler)
        app.router.add_static("/static/", os.path.join(ROOT, "dashboard"))
        app.on_startup.append(self.start_background)
        app.on_cleanup.append(self.cleanup_background)
        return app


def main():
    cfg = load_config()
    soc = SOCServer(cfg)
    host = cfg["dashboard"]["host"]
    port = cfg["dashboard"]["port"]
    print(f"SENTINEL-E SOC server on http://{host}:{port}/  "
          f"(open http://{cfg['network']['soc_ip']}:{port}/)")
    web.run_app(soc.build_app(), host=host, port=port, print=None)


if __name__ == "__main__":
    main()
