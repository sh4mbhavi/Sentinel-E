#!/usr/bin/env python3
"""
Sentinel-E — hardware-free demo launcher (cross-platform Python entry point).

Equivalent to ./demo.sh for environments without bash. Runs the entire platform
locally: a simulated sensor emits realistic attack telemetry that the real
detection engine evaluates live on the dashboard. No Pi, attacker box, or
Tailscale required.

Usage:  python3 demo.py
Then open http://localhost:8770/ in your browser.
"""
import os
import subprocess
import sys
import venv

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, ".venv")
PORT = 8770


def venv_python():
    if os.name == "nt":
        return os.path.join(VENV, "Scripts", "python.exe")
    return os.path.join(VENV, "bin", "python")


def ensure_deps():
    py = venv_python()
    if not os.path.exists(py):
        print("[*] First run: creating virtualenv and installing dependencies…")
        venv.EnvBuilder(with_pip=True).create(VENV)
        subprocess.check_call([py, "-m", "pip", "-q", "install", "--upgrade", "pip"])
        subprocess.check_call([py, "-m", "pip", "-q", "install", "aiohttp"])
    return py


def main():
    py = ensure_deps()
    # clean slate
    for f in ("detection/demo_alerts.jsonl", "detection/demo_alerts.db"):
        try:
            os.remove(os.path.join(ROOT, f))
        except OSError:
            pass
    env = dict(os.environ, SENTINEL_CONFIG="config/demo.conf.json")
    print()
    print("  SENTINEL-E — hardware-free demo")
    print("  " + "-" * 48)
    print(f"  [*] Open the dashboard:   http://localhost:{PORT}/")
    print("  [*] A simulated adversary attacks ~7s after load — watch it detect live.")
    print("  [*] Press Ctrl+C to stop.\n")
    os.chdir(ROOT)
    subprocess.call([py, "detection/server.py"], env=env)


if __name__ == "__main__":
    main()
