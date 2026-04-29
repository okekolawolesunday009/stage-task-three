"""
audit.py — Structured audit trail helpers.

All events are written to audit.log in a fixed-width format so that
the file can be grepped, parsed, or tailed by operations teams.

Format examples:
  [2025-11-10 14:32:01] BANNED     203.0.113.45 | condition: z_score(4.2)  | rate: 87/60s | baseline: 3.1/s | ban: 10m
  [2025-11-10 14:42:01] UNBANNED   203.0.113.45 | duration: 10m            | status: eligible
  [2025-11-10 14:45:10] GLOBAL     anomaly      | condition: multiplier(6x) | rate: 310/s  | baseline: 52/s
  [2025-11-10 14:46:00] BASELINE   recalculated | mean: 3.20 | stddev: 0.80 | window: 30m
"""

import logging
from datetime import datetime, timezone

_audit = logging.getLogger("audit")


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log_ban(ip: str, condition: str, rate: float, mean: float, duration_min: int):
    dur = f"{duration_min}m" if duration_min > 0 else "permanent"
    _audit.info(
        f"[{_ts()}] BANNED     {ip:<20} | condition: {condition:<18} "
        f"| rate: {rate:.0f}/60s | baseline: {mean:.2f}/s | ban: {dur}"
    )


def log_unban(ip: str, duration_min: int, permanent_next: bool):
    status = "permanent_next" if permanent_next else "eligible"
    _audit.info(
        f"[{_ts()}] UNBANNED   {ip:<20} | duration: {duration_min}m"
        f"{'':>12} | status: {status}"
    )


def log_global(condition: str, rate: float, mean: float):
    _audit.info(
        f"[{_ts()}] GLOBAL     anomaly      | condition: {condition:<18} "
        f"| rate: {rate:.0f}/s  | baseline: {mean:.2f}/s"
    )


def log_baseline(mean: float, stddev: float):
    _audit.info(
        f"[{_ts()}] BASELINE   recalculated | mean: {mean:.2f} "
        f"| stddev: {stddev:.2f} | window: 30m"
    )
