# HNG14 Stage 4 — Anomaly Detection Engine

> A real-time HTTP traffic anomaly detection daemon built in **Python** for Nextcloud deployments.

---

## Server Details

| Field | Value |
|-------|-------|
| Public IP | `YOUR_SERVER_IP` ← replace before submission |
| Nextcloud URL | `http://YOUR_SERVER_IP` |
| Dashboard URL | `http://YOUR_SERVER_IP:8080` |
| GitHub Repo | `https://github.com/YOUR_USERNAME/hng14-anomaly-detector` |
| Slack Channel | `#security-alerts` |

---

## Language Choice

**Python** was chosen because:
- `collections.deque` gives O(1) left-eviction — ideal for sliding windows
- `threading` module makes it easy to run monitor, baseline, unbanner and dashboard as concurrent daemons
- `subprocess` wraps `iptables` cleanly
- The standard library covers all networking needs (no framework bloat)
- Readable, easy-to-audit code satisfies the code-quality criterion

---

## Architecture

```
Nginx access.log
      │
      ▼
  monitor.py  ──── parses each line ────►  baseline.py   (rolling stats)
      │                                         │
      └──────────────────────────────────────►  detector.py  (anomaly check)
                                                    │
                              ┌─────────────────────┤
                              │                     │
                          blocker.py           notifier.py
                        (iptables ban)       (Slack webhook)
                              │
                          unbanner.py
                        (cooldown + unban)

  dashboard.py  ─── polls all of the above every 3 s ─── HTTP :8080
```

---

## Sliding Window Implementation

**Per-IP window** (`detector.py`):

Each source IP has its own `collections.deque` of float epoch timestamps.  
On every incoming request:
1. The current `time.time()` is appended to the right.
2. All entries at the **left** where `timestamp < (now - 60)` are evicted with `popleft()`.
3. `len(deque)` is the current rate.

`deque.popleft()` is O(1). The window is therefore always exactly 60 seconds wide — never a fixed bucket. A burst that started 59 seconds ago still counts; one from 61 seconds ago does not.

**Global window** uses one shared `deque` with the same eviction logic applied to every request regardless of source IP.

---

## Rolling Baseline

**`baseline.py`** maintains:

| Variable | Description |
|----------|-------------|
| `_global_counts` | `deque(maxlen=1800)` — one `int` per second for the last 30 minutes |
| `_slot_counts[h]` | 24 deques, same structure, keyed by UTC hour |
| `_error_counts`  | `deque(maxlen=1800)` for error fraction baseline |

**Every 60 seconds** the background thread calls `_recalculate()`:

```
raw_mean   = mean(global_counts[-1800:])
raw_stddev = std(global_counts[-1800:])
effective_mean   = max(raw_mean,   2.0)   # floor prevents collapse on quiet servers
effective_stddev = max(raw_stddev, 0.5)   # floor prevents division-by-zero
```

**Floor values** exist because:
- A server with 0.1 req/s mean would compute a Z-score of 500 for a burst of 50 req/s, which is technically correct but produces false positives for any slight uptick. The floor of `2.0` means the detector treats the server as if there is always at least 2 req/s of baseline activity.
- A stddev of `0.0` (perfectly flat traffic) would cause division by zero. The floor of `0.5` prevents this.

---

## Time-Aware Baseline Slots

**Time zone**: All 24 slots are keyed to **UTC hour** (`datetime.now(tz=timezone.utc).hour`).

**How fallback works**:

```python
if slot_counts[current_hour] has ≥ 300 data points (5 minutes):
    use slot baseline  ← more specific
else:
    use global 30-minute baseline  ← general fallback
```

This means on startup, the global baseline is always used. After 5 minutes of traffic in a given UTC hour the tool transparently switches to that hour's own statistics.

**Conflicting signals**: The tool does not merge signals. It uses exactly one baseline at a time — whichever is more specific and sufficiently populated. The time-slot baseline, when available, always takes precedence because it captures time-of-day traffic patterns. If a time-slot baseline shows a Z-score of 1.8 (safe) but the global shows 4.0 (anomalous), the time-slot baseline wins — preventing false positives during busy hours. The global baseline is a fallback, not a second opinion.

---

## Anomaly Detection Formula

```
# Condition A — Z-score
z = (current_rate - effective_mean) / effective_stddev
anomalous if z > 3.0

# Condition B — Multiplier
anomalous if current_rate > effective_mean × 5
```

**When each fires**:
- **Z-score** fires for volume attacks on servers with variable traffic (stddev is large enough to be meaningful).
- **Multiplier** fires when a server has very consistent near-zero baseline traffic (stddev ≈ 0.5 floor) — a sudden 10× burst reads as only Z=2.4 with a flat baseline, but `rate > mean × 5` catches it cleanly.

For most DDoS scenarios the **multiplier condition** will fire first because a true flood usually exceeds `mean × 5` before it crosses `Z > 3` on a quiet server.

---

## Warm-Up Edge Case

**What if an attack arrives in the first 10 minutes?**

During warm-up the tool collects data but applies **no IP bans**. However a **hard ceiling** of `50 req/s` (global rate) is enforced:

```python
if not baseline.is_warmed_up() and global_rate > WARMUP_HARD_CEILING:
    send_global_alert(...)   # Slack notification only
    return                   # still no ban
```

**Reasoning**: Banning IPs before a baseline exists risks banning legitimate users (a spike at startup could be legitimate first-use traffic). The hard ceiling is conservative enough (50 req/s) that it only fires for obvious floods, not organic traffic, while still alerting the operator immediately. The operator can manually review and ban if needed. After warm-up completes the statistical baseline takes over automatically.

---

## Setup Instructions (Fresh VPS → Running Stack)

### 1. Provision a VPS

Minimum specs: **2 vCPU, 2 GB RAM**, Ubuntu 22.04 LTS.  
Recommended providers: Hetzner CX21, DigitalOcean Droplet (2 CPU / 2 GB), Vultr.

### 2. SSH in and update the system

```bash
ssh root@YOUR_SERVER_IP
apt update && apt upgrade -y
```

### 3. Install Docker and Docker Compose

```bash
curl -fsSL https://get.docker.com | sh
apt install -y docker-compose-plugin python3-pip
```

### 4. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/hng14-anomaly-detector.git /opt/anomaly-detector
cd /opt/anomaly-detector
```

### 5. Configure your Slack webhook

```bash
nano detector/config.yaml
# Set slack_webhook_url to your real webhook URL
# Set SERVER_IP in docker-compose.yml or export it:
export SERVER_IP=$(curl -s ifconfig.me)
```

### 6. Create the shared Nginx log directory

```bash
mkdir -p /var/log/nginx
```

### 7. Start the Docker stack

```bash
docker compose up -d
# Verify all three containers are running:
docker compose ps
```

### 8. Install Python dependencies for the detector

```bash
pip3 install -r /opt/anomaly-detector/detector/requirements.txt
```

### 9. Install and start the detector as a systemd service

```bash
cp /opt/anomaly-detector/anomaly-detector.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable anomaly-detector
systemctl start anomaly-detector
# Check it's running:
systemctl status anomaly-detector
```

### 10. Verify everything is working

```bash
# Nextcloud accessible?
curl -I http://YOUR_SERVER_IP

# Detector processing logs?
journalctl -u anomaly-detector -f

# Dashboard up?
curl http://YOUR_SERVER_IP:8080/metrics

# iptables accessible?
iptables -L INPUT -n

# Audit log being written?
tail -f /opt/anomaly-detector/detector/audit.log
```

### 11. Generate a test ban (self-test)

```bash
# From another machine or using ab on the server itself:
ab -n 500 -c 100 http://YOUR_SERVER_IP/
# After ~10 min warmup, check:
iptables -L INPUT -n   # should show a DROP rule
# And check your Slack channel for the ban notification
```

---

## Required Screenshots

| File | Description |
|------|-------------|
| `screenshots/nextcloud-running.png` | Nextcloud login page with server IP visible |
| `screenshots/tool-running.png` | Detector daemon running and processing log lines |
| `screenshots/dashboard.png` | Live dashboard showing all metrics |
| `screenshots/ban-slack.png` | Slack ban notification |
| `screenshots/unban-slack.png` | Slack unban notification |
| `screenshots/global-alert-slack.png` | Slack global anomaly notification |
| `screenshots/iptables-banned.png` | `sudo iptables -L -n` showing a blocked IP |
| `screenshots/audit-log.png` | Audit log showing ban/unban/baseline events |
| `screenshots/baseline-graph.png` | Baseline visualisation with ≥ 2 hourly time slots |

---

## Repository Structure

```
├── detector/
│   ├── main.py          # Entry point — starts all daemon threads
│   ├── monitor.py       # Nginx log tail + line parser
│   ├── baseline.py      # Rolling 30-min baseline + 24 time slots
│   ├── detector.py      # Sliding window + anomaly detection formulas
│   ├── blocker.py       # iptables DROP rule management
│   ├── unbanner.py      # Cooldown timer + exponential backoff
│   ├── notifier.py      # Slack webhook integration
│   ├── dashboard.py     # Web dashboard (port 8080)
│   ├── audit.py         # Structured audit log helpers
│   ├── config.yaml      # All thresholds and settings
│   └── requirements.txt
├── nginx/
│   └── nginx.conf
├── docker-compose.yml
├── anomaly-detector.service
├── docs/
│   └── architecture.png
├── screenshots/
└── README.md
```
