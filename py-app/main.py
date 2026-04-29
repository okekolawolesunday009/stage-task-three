#!/usr/bin/env python3
"""
HNG14 Stage 4 - Anomaly Detection Engine
Main entry point - starts all subsystems as threads
"""

import os
import threading
import time
import logging
import signal
import sys
import yaml
from pathlib import Path

from monitor import LogMonitor
from baseline import BaselineManager
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import UnbanManager
from notifier import SlackNotifier
from dashboard import Dashboard

# ── Structured audit logger ────────────────────────────────────────────────
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_fh = logging.FileHandler("audit.log")
_fh.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_fh)

console = logging.getLogger("main")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        config = yaml.safe_load(f)

    # Allow sensitive values to be supplied via environment variables.
    # This supports using a docker-compose env_file instead of hardcoding keys.
    if os.getenv("SLACK_WEBHOOK_URL"):
        config["slack_webhook_url"] = os.getenv("SLACK_WEBHOOK_URL")
    if os.getenv("SLACK_CHANNEL"):
        config["slack_channel"] = os.getenv("SLACK_CHANNEL")
    if os.getenv("LOG_PATH"):
        config["log_path"] = os.getenv("LOG_PATH")
    if os.getenv("DASHBOARD_PORT"):
        try:
            config["dashboard_port"] = int(os.getenv("DASHBOARD_PORT"))
        except ValueError:
            pass

    return config


def main():
    config = load_config()

    notifier   = SlackNotifier(config)
    blocker    = IPBlocker(config, notifier)
    baseline   = BaselineManager(config)
    detector   = AnomalyDetector(config, baseline, blocker, notifier)
    unbanner   = UnbanManager(config, blocker, notifier)
    monitor    = LogMonitor(config, detector, baseline)
    dashboard  = Dashboard(config, baseline, blocker, detector)

    threads = [
        threading.Thread(target=monitor.run,    daemon=True, name="monitor"),
        threading.Thread(target=baseline.run,   daemon=True, name="baseline"),
        threading.Thread(target=unbanner.run,   daemon=True, name="unbanner"),
        threading.Thread(target=dashboard.run,  daemon=True, name="dashboard"),
    ]

    def _shutdown(sig, frame):
        console.info("Shutting down detector …")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    console.info("=== Anomaly Detection Engine starting ===")
    for t in threads:
        t.start()
        console.info(f"  started thread: {t.name}")

    # Keep main thread alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
