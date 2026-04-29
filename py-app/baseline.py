"""
baseline.py — Rolling statistical baseline computation.

Design decisions
────────────────
• A 30-minute ring of per-second global request counts is kept in a
  collections.deque (maxlen = 1800 seconds).
• Every 60 seconds a background loop recomputes effective_mean and
  effective_stddev from that deque.
• 24 hourly time-slot deques (UTC) work the same way but are keyed to
  the current wall-clock hour.  A slot is used for detection only when
  it holds ≥ 5 minutes (300 data points) of history; otherwise the
  tool falls back to the global 30-minute baseline.
• Floor values prevent division-by-zero and baseline collapse on
  very quiet servers:
    effective_mean   = max(raw_mean,   2.0)
    effective_stddev = max(raw_stddev, 0.5)
"""

import math
import time
import threading
import logging
from collections import deque, defaultdict
from datetime import datetime, timezone

logger = logging.getLogger("baseline")


class BaselineManager:
    # ── construction ──────────────────────────────────────────────────────
    def __init__(self, config: dict):
        self._window_secs      = config["baseline_window_minutes"] * 60   # 1800 s
        self._recalc_interval  = config["baseline_recalc_interval"]        # 60 s
        self._mean_floor       = config["effective_mean_floor"]            # 2.0
        self._stddev_floor     = config["effective_stddev_floor"]          # 0.5
        self._slot_min_secs    = config["timeslot_min_seconds"]            # 300 s
        self._warmup_secs      = config["warmup_minutes"] * 60

        self._lock = threading.Lock()
        self._start_time = time.time()

        # Global rolling deque: each entry is a (second_bucket, count) pair.
        # We maintain one integer per second; the deque length is capped at
        # baseline_window_minutes × 60 entries.
        self._global_counts: deque[int] = deque(maxlen=self._window_secs)
        self._current_second: int = int(time.time())
        self._current_count:  int = 0

        # 24 hourly time-slot deques (same structure as global)
        self._slot_counts: list[deque[int]] = [
            deque(maxlen=self._window_secs) for _ in range(24)
        ]

        # Computed stats (written by background thread, read by detector)
        self.effective_mean:   float = self._mean_floor
        self.effective_stddev: float = self._stddev_floor

        # Per-hour stats
        self._slot_mean:   list[float] = [self._mean_floor]   * 24
        self._slot_stddev: list[float] = [self._stddev_floor] * 24
        self._slot_len:    list[int]   = [0] * 24             # data points available

        # Error tracking: per-second error counts (for baseline_error_rate)
        self._error_counts:   deque[int] = deque(maxlen=self._window_secs)
        self._current_errors: int = 0

        self.baseline_error_rate: float = 0.0   # fraction

        self._last_recalc: float = time.time()

    # ── public — called from LogMonitor (hot path) ─────────────────────────
    def record_request(self, record) -> None:
        """Called for every parsed log line."""
        now_sec = int(time.time())
        is_error = record.status >= 400

        with self._lock:
            # ── advance the per-second bucket if needed ──────────────────
            if now_sec != self._current_second:
                # flush completed seconds into the global deque
                gap = now_sec - self._current_second
                for i in range(gap):
                    sec = self._current_second + i
                    count  = self._current_count  if i == 0 else 0
                    errors = self._current_errors if i == 0 else 0
                    self._global_counts.append(count)
                    self._error_counts.append(errors)
                    # also push into the appropriate hour slot
                    hour = datetime.fromtimestamp(sec, tz=timezone.utc).hour
                    self._slot_counts[hour].append(count)

                self._current_second = now_sec
                self._current_count  = 0
                self._current_errors = 0

            self._current_count  += 1
            if is_error:
                self._current_errors += 1

    # ── public — read by detector ──────────────────────────────────────────
    def get_effective_stats(self) -> tuple[float, float]:
        """
        Return (effective_mean, effective_stddev) for the current moment.

        Uses the current hour's time-slot baseline if it has ≥ 5 min of data;
        falls back to the global 30-minute baseline otherwise.
        """
        hour = datetime.now(tz=timezone.utc).hour
        with self._lock:
            if self._slot_len[hour] >= self._slot_min_secs:
                return self._slot_mean[hour], self._slot_stddev[hour]
            return self.effective_mean, self.effective_stddev

    def is_warmed_up(self) -> bool:
        return (time.time() - self._start_time) >= self._warmup_secs

    def elapsed_seconds(self) -> float:
        return time.time() - self._start_time

    def get_global_counts_snapshot(self) -> list[int]:
        with self._lock:
            return list(self._global_counts)

    # ── background loop ───────────────────────────────────────────────────
    def run(self):
        """Recompute baseline every recalc_interval seconds."""
        while True:
            time.sleep(self._recalc_interval)
            self._recalculate()

    # ── private ───────────────────────────────────────────────────────────
    def _recalculate(self):
        with self._lock:
            counts = list(self._global_counts)
            errors = list(self._error_counts)

        # ── global stats ──────────────────────────────────────────────────
        self.effective_mean, self.effective_stddev = self._compute_stats(counts)

        # ── error rate ────────────────────────────────────────────────────
        total  = sum(counts) or 1
        err_total = sum(errors)
        self.baseline_error_rate = err_total / total

        # ── per-hour slot stats ───────────────────────────────────────────
        hour = datetime.now(tz=timezone.utc).hour
        with self._lock:
            slot_counts = list(self._slot_counts[hour])
            slot_len    = len(slot_counts)

        m, s = self._compute_stats(slot_counts)
        with self._lock:
            self._slot_mean[hour]   = m
            self._slot_stddev[hour] = s
            self._slot_len[hour]    = slot_len

        from audit import log_baseline
        log_baseline(self.effective_mean, self.effective_stddev)
        logger.debug(
            f"Baseline recalculated — mean={self.effective_mean:.2f} "
            f"stddev={self.effective_stddev:.2f} "
            f"slot_hour={hour} slot_len={slot_len}"
        )

    def _compute_stats(self, counts: list[int]) -> tuple[float, float]:
        if not counts:
            return self._mean_floor, self._stddev_floor
        n    = len(counts)
        mean = sum(counts) / n
        variance = sum((x - mean) ** 2 for x in counts) / n
        stddev = math.sqrt(variance)
        eff_mean   = max(mean,   self._mean_floor)
        eff_stddev = max(stddev, self._stddev_floor)
        return eff_mean, eff_stddev
