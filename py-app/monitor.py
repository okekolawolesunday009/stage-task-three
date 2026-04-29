"""
monitor.py — Real-time Nginx access log tail + parser.

Reads the log file line-by-line as it is written (like `tail -F`),
parses each entry, and feeds structured records to the detector and
baseline manager.
"""

import io
import re
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("monitor")

# ── Regex for Nginx "combined" log format ─────────────────────────────────
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)'           # remote_addr  (real IP after set_real_ip_from)
    r'\s+\S+'                # ident (-)
    r'\s+\S+'                # auth user (-)
    r'\s+\[(?P<time>[^\]]+)\]'          # [time_local]
    r'\s+"(?P<method>\S+)'              # "METHOD
    r'\s+(?P<path>\S+)'                 # /path
    r'\s+\S+"'                          # HTTP/x.x"
    r'\s+(?P<status>\d{3})'             # status code
    r'\s+(?P<bytes>\d+|-)'              # body bytes
)

_NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


class LogRecord:
    __slots__ = ("ip", "ts", "method", "path", "status", "size")

    def __init__(self, ip, ts, method, path, status, size):
        self.ip     = ip
        self.ts     = ts        # float (epoch)
        self.method = method
        self.path   = path
        self.status = status    # int
        self.size   = size      # int


def _parse_line(line: str) -> LogRecord | None:
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], _NGINX_TIME_FMT).timestamp()
    except ValueError:
        ts = time.time()
    size = int(m["bytes"]) if m["bytes"] != "-" else 0
    return LogRecord(
        ip     = m["ip"],
        ts     = ts,
        method = m["method"],
        path   = m["path"],
        status = int(m["status"]),
        size   = size,
    )


class LogMonitor:
    """
    Continuously tails the Nginx access log.
    For every parsed line it calls:
      - baseline.record_request(record)
      - detector.process(record)
    """

    def __init__(self, config: dict, detector, baseline):
        self.log_path = Path(config["log_path"])
        self.detector = detector
        self.baseline = baseline

    # ── public ────────────────────────────────────────────────────────────
    def run(self):
        logger.info(f"Monitoring log: {self.log_path}")
        while True:
            try:
                self._tail()
            except Exception as exc:
                logger.error(f"Monitor error: {exc} — retrying in 5 s")
                time.sleep(5)

    # ── private ───────────────────────────────────────────────────────────
    def _tail(self):
        """Open the log and block-read new lines as they arrive."""
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
            # Jump to end so we don't replay old history on startup.
            # Some mounted log streams may not support seek(), so fall back.
            try:
                fh.seek(0, 2)
            except (OSError, io.UnsupportedOperation):
                logger.warning("Log stream is not seekable; reading from current position")

            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)   # ~50 ms poll — low CPU cost
                    # Handle log rotation: if file shrinks, reopen
                    try:
                        if fh.tell() > Path(self.log_path).stat().st_size:
                            logger.info("Log rotation detected — reopening")
                            return          # outer loop reopens file
                    except FileNotFoundError:
                        time.sleep(1)
                        return
                    continue

                record = _parse_line(line.strip())
                if record is None:
                    continue

                # Feed to subsystems (both are thread-safe)
                self.baseline.record_request(record)
                self.detector.process(record)
