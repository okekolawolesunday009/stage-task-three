"""
detector.py — Sliding-window rate tracking + anomaly detection formulas.

Sliding window implementation
──────────────────────────────
Each IP has its own collections.deque of float timestamps.  Every time a
request arrives, the current epoch time is appended.  Before computing the
current rate, all entries older than (now - window_seconds) are evicted
from the LEFT of the deque (deque.popleft is O(1)).  The window is
therefore always exactly window_seconds wide — this is a true sliding
window, NOT a fixed per-minute bucket.

The global window uses the same structure but one shared deque for ALL
requests regardless of source IP.

Anomaly conditions (both implemented; either firing is sufficient)
──────────────────────────────────────────────────────────────────
  Condition A — Z-score:  z = (rate - mean) / stddev  →  anomalous if z > threshold
  Condition B — Multiplier:  anomalous if rate > mean × threshold

Error surge adjustment
──────────────────────
If an IP's error fraction (4xx/5xx / total) over the last 60 s exceeds
baseline_error_rate × error_surge_factor, its per-IP thresholds are
lowered to make it easier to ban.
"""

import time
import logging
import threading
from collections import deque, defaultdict
from datetime import datetime, timezone

from audit import log_ban, log_global

logger = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, config: dict, baseline, blocker, notifier):
        self._config    = config
        self._baseline  = baseline
        self._blocker   = blocker
        self._notifier  = notifier

        self._ip_window_secs = config["per_ip_window_seconds"]
        self._gl_window_secs = config["global_window_seconds"]
        self._warmup_ceiling = config["warmup_hard_ceiling"]

        # Detection thresholds
        self._z_thresh  = config["zscore_threshold"]
        self._m_thresh  = config["multiplier_threshold"]
        self._ez_thresh = config["error_surge_zscore_threshold"]
        self._em_thresh = config["error_surge_multiplier_threshold"]
        self._e_factor  = config["error_surge_factor"]

        self._lock = threading.Lock()

        # Per-IP deques of timestamps (float epoch)
        self._ip_times: dict[str, deque] = defaultdict(deque)
        # Per-IP error-timestamp deques
        self._ip_errors: dict[str, deque] = defaultdict(deque)

        # Global deque of timestamps
        self._global_times: deque = deque()

        # Track already-banned IPs so we don't re-ban in the same session
        self._banned: set[str] = set()

        # Expose current rates for the dashboard
        self.current_global_rate: float = 0.0
        self.top_ips: list[tuple[str, int]] = []

    # ── public — hot path ─────────────────────────────────────────────────
    def process(self, record) -> None:
        now = time.time()
        ip  = record.ip

        with self._lock:
            # ── update per-IP sliding window ─────────────────────────────
            dq = self._ip_times[ip]
            dq.append(now)
            evict_before = now - self._ip_window_secs
            while dq and dq[0] < evict_before:
                dq.popleft()

            # ── update per-IP error window ────────────────────────────────
            if record.status >= 400:
                edq = self._ip_errors[ip]
                edq.append(now)
                while edq and edq[0] < evict_before:
                    edq.popleft()

            # ── update global sliding window ──────────────────────────────
            self._global_times.append(now)
            g_evict = now - self._gl_window_secs
            while self._global_times and self._global_times[0] < g_evict:
                self._global_times.popleft()

            ip_rate     = len(dq)
            global_rate = len(self._global_times)
            ip_errors   = len(self._ip_errors[ip])
            ip_total    = ip_rate or 1
            ip_err_rate = ip_errors / ip_total

        self.current_global_rate = global_rate
        self._update_top_ips()

        # ── warm-up hard ceiling ──────────────────────────────────────────
        if not self._baseline.is_warmed_up():
            if global_rate > self._warmup_ceiling:
                logger.warning(
                    f"[WARMUP] Global rate {global_rate}/60s exceeds hard ceiling "
                    f"{self._warmup_ceiling}/s — sending alert (no ban during warmup)"
                )
                self._notifier.send_global_alert(
                    global_rate, self._warmup_ceiling,
                    "warmup_hard_ceiling", warm_up=True
                )
            return  # no bans during warm-up

        # ── get baselines ──────────────────────────────────────────────────
        mean, stddev = self._baseline.get_effective_stats()
        baseline_err = self._baseline.baseline_error_rate

        # ── check error surge → lower thresholds ─────────────────────────
        error_surge = ip_err_rate > (baseline_err * self._e_factor) and ip_err_rate > 0.1
        z_thresh = self._ez_thresh if error_surge else self._z_thresh
        m_thresh = self._em_thresh if error_surge else self._m_thresh

        # ── per-IP anomaly detection ──────────────────────────────────────
        if ip not in self._banned:
            condition = self._check_anomaly(ip_rate, mean, stddev, z_thresh, m_thresh)
            if condition:
                self._trigger_ip_ban(ip, condition, ip_rate, mean, error_surge)

        # ── global anomaly detection ──────────────────────────────────────
        g_condition = self._check_anomaly(
            global_rate, mean, stddev, self._z_thresh, self._m_thresh
        )
        if g_condition:
            logger.warning(
                f"GLOBAL anomaly — rate={global_rate}/60s mean={mean:.2f} "
                f"condition={g_condition}"
            )
            log_global(g_condition, global_rate, mean)
            self._notifier.send_global_alert(global_rate, mean, g_condition)

    def mark_unbanned(self, ip: str):
        with self._lock:
            self._banned.discard(ip)

    # ── private ───────────────────────────────────────────────────────────
    def _check_anomaly(
        self,
        rate: float,
        mean: float,
        stddev: float,
        z_thresh: float,
        m_thresh: float,
    ) -> str | None:
        # Condition A — Z-score
        z = (rate - mean) / stddev
        if z > z_thresh:
            return f"z_score({z:.2f})"
        # Condition B — multiplier
        if rate > mean * m_thresh:
            return f"multiplier({rate/mean:.1f}x)"
        return None

    def _trigger_ip_ban(
        self,
        ip: str,
        condition: str,
        rate: float,
        mean: float,
        error_surge: bool,
    ):
        with self._lock:
            if ip in self._banned:
                return
            self._banned.add(ip)

        logger.warning(
            f"BANNED {ip} | condition={condition} | rate={rate}/60s | "
            f"mean={mean:.2f} | error_surge={error_surge}"
        )
        ban_duration = self._blocker.ban(ip)
        log_ban(ip, condition, rate, mean, ban_duration)
        self._notifier.send_ban_alert(ip, condition, rate, mean, ban_duration, error_surge)

    def _update_top_ips(self):
        now = time.time()
        evict = now - self._ip_window_secs
        with self._lock:
            counts = {
                ip: len([t for t in dq if t >= evict])
                for ip, dq in self._ip_times.items()
            }
        self.top_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
