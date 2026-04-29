"""
blocker.py — iptables rule management.

Applies a DROP rule for a banned IP within seconds of detection.
Tracks ban count per IP for exponential backoff durations.
All iptables calls run as subprocess so the tool doesn't need to be
setuid — run the daemon as root or with CAP_NET_ADMIN.
"""

import subprocess
import threading
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger("blocker")


class IPBlocker:
    def __init__(self, config: dict, notifier):
        self._notifier = notifier
        self._durations: list[int] = config["ban_durations_minutes"]  # [10, 30, 120]
        self._lock = threading.Lock()

        # ip → {"count": int, "banned_at": float, "duration_min": int, "permanent": bool}
        self._records: dict[str, dict] = {}

    # ── public ────────────────────────────────────────────────────────────
    def ban(self, ip: str) -> int:
        """
        Add an iptables DROP rule for ip.
        Returns the ban duration in minutes (0 = permanent).
        """
        with self._lock:
            rec = self._records.get(ip, {"count": 0})
            count = rec["count"]
            if count < len(self._durations):
                duration_min = self._durations[count]
                permanent    = False
            else:
                duration_min = 0   # permanent
                permanent    = True

            self._records[ip] = {
                "count":        count + 1,
                "banned_at":    time.time(),
                "duration_min": duration_min,
                "permanent":    permanent,
            }

        self._apply_drop(ip)
        logger.info(
            f"Banned {ip} — ban #{count+1}, duration={'permanent' if permanent else f'{duration_min}m'}"
        )
        return duration_min if not permanent else 0

    def unban(self, ip: str) -> bool:
        """
        Remove the iptables DROP rule and return True on success.
        """
        removed = self._remove_drop(ip)
        if removed:
            logger.info(f"Unbanned {ip}")
        return removed

    def get_active_bans(self) -> list[dict]:
        """
        Return list of currently active (non-expired) bans with metadata.
        """
        now = time.time()
        with self._lock:
            result = []
            for ip, rec in self._records.items():
                if rec.get("permanent"):
                    result.append({"ip": ip, **rec})
                    continue
                expires_at = rec["banned_at"] + rec["duration_min"] * 60
                if now < expires_at:
                    result.append({"ip": ip, **rec, "expires_at": expires_at})
        return result

    def get_record(self, ip: str) -> dict | None:
        with self._lock:
            return self._records.get(ip)

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._records

    @property
    def banned_count(self) -> int:
        return len(self.get_active_bans())

    # ── private ───────────────────────────────────────────────────────────
    def _apply_drop(self, ip: str):
        try:
            # Avoid duplicate rules
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode == 0:
                logger.debug(f"DROP rule already exists for {ip}")
                return
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info(f"iptables DROP added for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables ban failed for {ip}: {e.stderr.decode()}")

    def _remove_drop(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables unban failed for {ip}: {e.stderr.decode()}")
            return False
