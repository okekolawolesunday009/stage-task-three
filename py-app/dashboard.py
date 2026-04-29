"""
dashboard.py — Live metrics web dashboard (updates every 3 s).

Serves a single-page HTML dashboard on dashboard_port (default 8080).
The page auto-refreshes its data via a /metrics JSON endpoint polled
by vanilla JS — no external dependencies needed on the server.

Metrics exposed:
  • Banned IP count
  • Global requests / second (current window)
  • Top 10 source IPs by request volume
  • System CPU and memory usage
  • Current effective_mean and effective_stddev
  • Time elapsed since tool startup
"""

import json
import time
import logging
import threading
import psutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import timedelta

logger = logging.getLogger("dashboard")

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Anomaly Detection Dashboard</title>
<style>
  body { font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
  h1   { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .card h3 { margin: 0 0 8px; color: #8b949e; font-size: 12px; text-transform: uppercase; }
  .card .val { font-size: 28px; font-weight: bold; color: #58a6ff; }
  .card .sub { font-size: 12px; color: #8b949e; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 12px; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-size: 12px; }
  .banned { color: #f85149; }
  .uptime { color: #3fb950; }
  #updated { font-size: 11px; color: #484f58; margin-top: 12px; }
  .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
</style>
</head>
<body>
<h1>🛡 Anomaly Detection Engine</h1>
<div class="grid" id="cards">Loading…</div>
<div class="section">
  <h3 style="color:#8b949e;font-size:12px;text-transform:uppercase;margin:0 0 12px">Top 10 Source IPs (last 60 s)</h3>
  <table><thead><tr><th>#</th><th>IP Address</th><th>Requests</th><th>Status</th></tr></thead>
  <tbody id="top-ips"></tbody></table>
</div>
<div id="updated"></div>
<script>
async function refresh() {
  try {
    const r = await fetch('/metrics');
    const d = await r.json();
    document.getElementById('cards').innerHTML = `
      <div class="card"><h3>Banned IPs</h3><div class="val banned">${d.banned_count}</div></div>
      <div class="card"><h3>Global Req/s</h3><div class="val">${d.global_rps}</div><div class="sub">over last 60 s window</div></div>
      <div class="card"><h3>Effective Mean</h3><div class="val">${d.effective_mean}</div><div class="sub">stddev ${d.effective_stddev}</div></div>
      <div class="card"><h3>CPU Usage</h3><div class="val">${d.cpu_pct}%</div></div>
      <div class="card"><h3>Memory Usage</h3><div class="val">${d.mem_pct}%</div><div class="sub">${d.mem_used_mb} MB used</div></div>
      <div class="card uptime"><h3>Uptime</h3><div class="val" style="font-size:20px">${d.uptime}</div></div>
    `;
    const tbody = document.getElementById('top-ips');
    tbody.innerHTML = d.top_ips.map((row, i) =>
      `<tr><td>${i+1}</td><td>${row[0]}</td><td>${row[1]}</td>
       <td>${row[2] ? '<span style="color:#f85149">BANNED</span>' : '—'}</td></tr>`
    ).join('');
    document.getElementById('updated').textContent = 'Last updated: ' + new Date().toISOString();
  } catch(e) { console.error(e); }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


class Dashboard:
    def __init__(self, config, baseline, blocker, detector):
        self._config   = config
        self._baseline = baseline
        self._blocker  = blocker
        self._detector = detector
        self._port     = config.get("dashboard_port", 8080)
        self._start    = time.time()

    # ── public ────────────────────────────────────────────────────────────
    def run(self):
        if self._port == 0:
            self._run_tui()
            return
        handler = self._make_handler()
        server  = HTTPServer(("0.0.0.0", self._port), handler)
        logger.info(f"Dashboard running at http://0.0.0.0:{self._port}")
        server.serve_forever()

    # ── private ───────────────────────────────────────────────────────────
    def _metrics(self) -> dict:
        mean, stddev = self._baseline.get_effective_stats()
        banned_ips   = {b["ip"] for b in self._blocker.get_active_bans()}
        top_ips      = [
            (ip, cnt, ip in banned_ips)
            for ip, cnt in self._detector.top_ips
        ]
        elapsed = int(time.time() - self._start)
        uptime  = str(timedelta(seconds=elapsed))
        mem     = psutil.virtual_memory()
        return {
            "banned_count":    len(banned_ips),
            "global_rps":      round(self._detector.current_global_rate, 1),
            "top_ips":         top_ips,
            "cpu_pct":         psutil.cpu_percent(interval=None),
            "mem_pct":         round(mem.percent, 1),
            "mem_used_mb":     round(mem.used / 1024 / 1024, 1),
            "effective_mean":  round(mean, 2),
            "effective_stddev":round(stddev, 2),
            "uptime":          uptime,
        }

    def _make_handler(self):
        dash = self  # closure

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/metrics":
                    data = json.dumps(dash._metrics()).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", len(data))
                    self.end_headers()
                    self.wfile.write(data)
                elif self.path in ("/", "/dashboard"):
                    body = _HTML.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", len(body))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass  # silence HTTP access log spam

        return Handler

    def _run_tui(self):
        """Fallback: simple terminal printout when port=0."""
        import os
        while True:
            m = self._metrics()
            os.system("clear")
            print("=== Anomaly Detection Dashboard ===")
            print(f"  Uptime        : {m['uptime']}")
            print(f"  Banned IPs    : {m['banned_count']}")
            print(f"  Global RPS    : {m['global_rps']}")
            print(f"  Effective Mean: {m['effective_mean']}  Stddev: {m['effective_stddev']}")
            print(f"  CPU: {m['cpu_pct']}%   MEM: {m['mem_pct']}%")
            print("\n  Top IPs:")
            for i, (ip, cnt, banned) in enumerate(m["top_ips"], 1):
                flag = " [BANNED]" if banned else ""
                print(f"    {i:2}. {ip:<20} {cnt} req{flag}")
            time.sleep(3)
