"""
notifier.py — Slack webhook integration.

Sends structured alerts for:
  • Ban events       (IP, condition, rate, mean, duration)
  • Unban events     (IP, duration, permanent flag)
  • Global anomaly   (global rate, mean, condition)

The webhook URL is loaded from config — never hardcoded here.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger("notifier")


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class SlackNotifier:
    def __init__(self, config: dict):
        self._webhook = config["slack_webhook_url"]
        self._channel = config.get("slack_channel", "#security-alerts")

    # ── public ────────────────────────────────────────────────────────────
    def send_ban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        mean: float,
        duration_min: int,
        error_surge: bool = False,
    ):
        dur_str = f"{duration_min}m" if duration_min > 0 else "PERMANENT"
        surge_str = " ⚡ error-surge threshold applied" if error_surge else ""
        text = (
            f":no_entry: *IP BANNED* — `{ip}`\n"
            f"• Condition : `{condition}`{surge_str}\n"
            f"• Rate      : `{rate:.0f}` req/60s\n"
            f"• Baseline  : `{mean:.2f}` req/s (effective_mean)\n"
            f"• Ban dur.  : `{dur_str}`\n"
            f"• Time      : `{_now_str()}`"
        )
        self._post(text)

    def send_unban_alert(self, ip: str, duration_min: int, permanent_next: bool):
        perm_str = (
            " ⚠️ *Next violation → PERMANENT BLOCK*"
            if permanent_next
            else " ✅ Eligible to return"
        )
        text = (
            f":white_check_mark: *IP UNBANNED* — `{ip}`\n"
            f"• Was banned: `{duration_min}m`\n"
            f"• Status    :{perm_str}\n"
            f"• Time      : `{_now_str()}`"
        )
        self._post(text)

    def send_global_alert(
        self,
        global_rate: float,
        mean: float,
        condition: str,
        warm_up: bool = False,
    ):
        prefix = ":warning: *GLOBAL ANOMALY*" + (" (warm-up ceiling)" if warm_up else "")
        text = (
            f"{prefix}\n"
            f"• Condition : `{condition}`\n"
            f"• Global rate : `{global_rate:.0f}` req/60s\n"
            f"• Baseline    : `{mean:.2f}` req/s\n"
            f"• Time        : `{_now_str()}`"
        )
        self._post(text)

    # ── private ───────────────────────────────────────────────────────────
    def _post(self, text: str):
        if "YOUR/WEBHOOK" in self._webhook:
            logger.warning(f"[SLACK - not configured] {text}")
            return
        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            self._webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    logger.error(f"Slack returned {resp.status}")
        except urllib.error.URLError as e:
            logger.error(f"Slack webhook error: {e}")
