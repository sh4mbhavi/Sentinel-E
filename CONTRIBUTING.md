# Contributing to Sentinel-E

Contributions are welcome — new detections, telemetry sources, dashboard improvements, and documentation all move the platform forward. This guide covers the common extension points.

## Getting set up

```bash
git clone https://github.com/sh4mbhavi/Sentinel-E.git
cd Sentinel-E
./demo.sh          # bootstraps a virtualenv and runs the platform locally
```

The only runtime dependency is `aiohttp` (installed automatically into `.venv`). Python 3.9+ is required.

## Project shape

- **`detection/`** — the SOC core (ingestion, engine, store, server). Start here for detection logic.
- **`demo/sim_sensor.py`** — the local telemetry generator that powers the hardware-free demo.
- **`pi/`** — the hardware target: the vulnerable panel and the multi-source sensor.
- **`dashboard/index.html`** — the single-page real-time console.
- **`config/`** — detection thresholds and run profiles.

See [SCRIPTS.md](SCRIPTS.md) for a full component manifest and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow.

## Adding a detection rule

1. Add the rule's metadata (name, MITRE technique, kill-chain phase, severity) to `STAGES` in `detection/rules.py`.
2. Implement the detection in `DetectionEngine.process()` — consume the relevant telemetry event(s), apply your threshold/correlation, and return an alert via `self._alert(...)`.
3. Expose any thresholds in `config/*.conf.json` rather than hard-coding them.
4. Extend `demo/sim_sensor.py` to emit the telemetry your rule detects, so the rule is exercised by the demo.
5. Run `./demo.sh` and confirm your detection fires live.

The dashboard renders its kill chain, ATT&CK matrix, and rule catalogue directly from `STAGES`, so new rules appear automatically.

## Adding a telemetry source

The engine consumes source-tagged JSON events (`net`, `panel`, `auth`, `file`). Emit new event types from a sensor (hardware or the demo generator) using the same schema, then handle them in `process()`. Ingestion is source-agnostic — it simply reads newline-delimited JSON from the active telemetry stream.

## Guidelines

- Keep detections **behavioural** — fire on activity patterns, not brittle static signatures.
- Keep thresholds in **config**, not code.
- Keep the **demo** and **hardware** paths working and separate.
- Never commit secrets, keys, or credentials.
- Match the existing code style and comment density; explain *why* a rule works.

## Responsible use

This repository contains offensive tooling and an intentionally vulnerable service. Only run the attack drivers against the bundled demo target or hardware you own and are authorised to test.
