"""
unbanner.py — Automated unban with exponential backoff.

Runs a background sweep every unban_check_interval seconds.
For each active ban, checks if the cooldown has expired and, if so,
removes the iptables rule and fires a Slack notification.

Ban schedule (from config):
  1st ban  → 10 minutes
  2nd ban  → 30 minutes
  3rd ban  → 2 hours
  4th+ ban → permanent (manual review required)
"""

import time
import logging
import threading

from audit import log_unban

logger = logging.getLogger("unbanner")


class UnbanManager:
    def __init__(self, config: dict, blocker, notifier):
        self._blocker  = blocker
        self._notifier = notifier
        self._interval = config["unban_check_interval"]   # seconds

    # ── public ────────────────────────────────────────────────────────────
    def run(self):
        logger.info("Unban manager started")
        while True:
            time.sleep(self._interval)
            self._sweep()

    # ── private ───────────────────────────────────────────────────────────
    def _sweep(self):
        now = time.time()
        active = self._blocker.get_active_bans()

        for rec in active:
            ip        = rec["ip"]
            permanent = rec.get("permanent", False)

            if permanent:
                continue  # nothing to do — stays banned

            banned_at    = rec["banned_at"]
            duration_min = rec["duration_min"]
            expires_at   = banned_at + duration_min * 60

            if now >= expires_at:
                duration_elapsed = int((now - banned_at) / 60)
                self._blocker.unban(ip)

                # Check if next ban would be permanent
                record    = self._blocker.get_record(ip)
                ban_count = record["count"] if record else 0
                durations = self._blocker._durations
                will_be_permanent = ban_count >= len(durations)

                logger.info(
                    f"Unbanned {ip} | was banned {duration_elapsed}m | "
                    f"permanent_next={will_be_permanent}"
                )
                log_unban(ip, duration_elapsed, will_be_permanent)
                self._notifier.send_unban_alert(ip, duration_elapsed, will_be_permanent)
