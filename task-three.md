DevOps Task (HNG14) - Stage 4

Overview

Hey Cool Keeds! This is not a configuration task. This is an engineering task.

Congratulations! You have just been hired as a DevSecOps Engineer at HNG, a rapidly growing cloud storage company powered by Nextcloud. The platform serves users globally and is publicly accessible around the clock.

After a wave of suspicious activity, the security team has tasked you with building an anomaly detection engine that watches all incoming HTTP traffic in real time, learns what normal looks like for this specific server, and automatically responds when something deviates from that normal — whether that deviation comes from a single aggressive source or from a global spike in traffic no single IP is obviously responsible for.

You are not installing a firewall rule and calling it done. You are building a system that thinks.

> You will NOT be modifying the Nextcloud source code. All your work lives in the detection tool you build alongside the stack.

---

The Scenario

Your server will be live for a minimum of 12 hours before grading begins. During that window, your tool will be quietly learning what normal traffic looks like for your specific deployment. At some point during those 12 hours — maybe at hour 2, maybe at hour 10, maybe multiple times — we will send attack traffic at your server. Your tool must detect it and respond, regardless of when it arrives.

This means your baseline cannot be a fixed value you hardcode. It must reflect what your server's traffic actually looks like in the recent past, and it must be ready to detect deviations from the very first minutes of operation.

---

Objectives

By the end of this task, you should be able to:
- Build a real-time log analysis daemon that tracks traffic patterns as they happen
- Implement a rolling statistical baseline that adapts to your server's actual traffic
- Apply anomaly detection formulas to distinguish normal variation from genuine attacks
- Enforce automated bans at the network level via iptables
- Deliver timely, informative alerts to a Slack channel on every significant event

---

What You Are Given

A pre-built Nextcloud Docker image hosted on DockerHub:

> Image: `[DOCKERHUB_IMAGE]:[TAG]`

You must not modify or replace the image itself — build your entire stack around it as-is.

---

What You Must Provision

You are responsible for setting up your own infrastructure. This is part of the task.

Provision a Linux VPS on any cloud provider (AWS, GCP, DigitalOcean, Linode, Vultr, Hetzner, etc.) with a minimum of 2 vCPU and 2GB RAM. Deploy the provided Nextcloud stack using Docker Compose. Configure Nginx as a reverse proxy in front of Nextcloud with access logs enabled. Configure Nginx to trust and log the X-Forwarded-For header so your tool sees the real source IP of each request:

```nginx
real_ip_header     X-Forwarded-For;
real_ip_recursive  on;
set_real_ip_from   0.0.0.0/0;
```

Your log format must include at minimum: source IP, timestamp, HTTP method, request path, status code, and response size. Your server must be publicly accessible at a static IP or domain and must remain live for the full 12-hour period and throughout grading.

---

What You Must Build

You will build an anomaly detection engine — a daemon written in Python or Go that runs continuously alongside your Nextcloud stack.

> Allowed languages: Python or Go only. No other languages are accepted. Your tool must run as a long-lived process, not a cron job or one-shot script.

The tool must implement all of the following.

---

1. Real-Time Log Monitoring

Continuously tail and parse the Nginx access log. For every line, extract the source IP, timestamp, HTTP method, endpoint, status code, and response size. Your tool processes each line as it arrives — not in batches pulled on a timer.

---

2. Sliding Window Rate Tracking

Track request counts using a sliding window — not fixed per-minute buckets. Maintain two separate sliding windows:

Per-IP window: a deque of timestamps per source IP, covering the last 60 seconds. The current request rate for an IP is the number of entries in its deque after evicting timestamps older than (now - 60s).

Global window: the same structure, but counting all requests regardless of source IP.

Implement the sliding window yourself. Do not use a rate-limiting library.

---

3. Rolling Baseline

Your tool must learn what normal traffic looks like for your server and use that as the reference point for anomaly detection.

The baseline is computed from a rolling 30-minute window of per-second global request counts. Every 60 seconds, your tool recomputes:

- baseline_mean: the mean of per-second counts over the last 30 minutes
- baseline_stddev: the standard deviation of those counts
- effective_mean: max(baseline_mean, 2.0) — a hard floor to prevent instability on quiet servers
- effective_stddev: max(baseline_stddev, 0.5) — a floor to prevent division instability

Your tool enters active detection mode after a minimum warm-up period of 10 minutes. Before that, it collects data but does not enforce any bans. After 10 minutes, detection is live and the baseline continues to update every 60 seconds for as long as the tool runs.

This design means your tool is meaningful from the first 10 minutes of operation. If an attack arrives at hour 2, your baseline reflects 2 hours of real traffic on your server. If it arrives at hour 10, it reflects 10 hours. The tool adapts continuously.

You must address the following edge case in your README: what does your tool do if an attack begins before the 10-minute warm-up completes? One valid approach is to apply a hard ceiling during the warm-up period — if global rate exceeds an absolute maximum (for example, 50 req/s), flag it regardless of baseline state. Document your choice and your reasoning.

Time-Aware Baseline Slots

Your tool must also maintain separate baselines per hour of the day (24 slots: hour 0 through hour 23). Every time a per-second count is recorded, it is stored in the slot matching the current UTC hour in addition to the global rolling window. Every 60 seconds, the tool recomputes effective_mean and effective_stddev for the current hour's slot independently.

When deciding whether a current rate is anomalous, your tool uses whichever baseline is more specific and sufficiently populated:
- If the current hour's slot has at least 5 minutes of data, use the time-slot baseline
- Otherwise, fall back to the global 30-minute rolling baseline

This is the correct behavior because traffic naturally varies by time of day. A server that normally handles 200 req/s on weekday mornings and 20 req/s overnight should not fire false positives at 9 AM simply because the rate is 10× the overnight average. But an attack that drives 2000 req/s at 9 AM should still be caught — because it deviates significantly from the 9 AM baseline specifically.

Your README must document: which time zone your slots use, how you handle the first hour of a new slot before it has 5 minutes of data, and what your tool's behavior is if the time-slot baseline and global baseline produce conflicting anomaly signals.

---

4. Anomaly Detection Formula

Both conditions must be implemented. Either one firing is sufficient to trigger a response.

Condition A — Z-score:
```
z = (current_rate - effective_mean) / effective_stddev
anomalous if z > 3.0
```

Condition B — Multiplier:
```
anomalous if current_rate > effective_mean × 5
```

The multiplier exists because Z-score breaks down when the server has very consistent, near-zero baseline traffic. The multiplier catches what Z-score misses in those cases. Both must be in your code.

---

5. Error Surge as a Contributing Signal

Track the error rate per IP: the fraction of that IP's requests in the last 60 seconds that returned a 4xx or 5xx response. Also track baseline_error_rate from the same 30-minute rolling window.

If an IP's current error rate exceeds baseline_error_rate × 3, lower the anomaly threshold for that IP specifically:
- Z-score threshold drops from 3.0 to 2.0
- Multiplier threshold drops from 5× to 3×

This means an IP that is both flooding and generating errors (such as repeated failed login attempts) gets flagged faster than one doing only one of those things.

---

6. Detection Tiers and Actions

Per-IP anomaly: when an IP crosses either anomaly condition (with or without the error surge adjustment), your tool must add an iptables DROP rule for that IP and immediately send a Slack notification. The block must be applied within 10 seconds of detection.

Global anomaly: when the global request rate crosses either anomaly condition, your tool sends a Slack notification only. No IP ban is applied — a global spike may not have a single source to ban.

---

7. Automated Unban with Exponential Backoff and Slack Notification

Banned IPs are released after a configurable cooldown. The default schedule is:

- First ban: 10 minutes
- Second ban: 30 minutes
- Third ban: 2 hours
- Beyond that: permanent block until manual review

When an IP is unbanned — whether by cooldown expiry or because it has reached the permanent threshold — your tool must send a Slack notification recording which IP was released, how long it was banned, and whether it is now permanently blocked or eligible to return.

---

8. Slack Alerts

All alerts go to Slack via a webhook URL stored in your config file. Two types of events must trigger a notification:

Ban event: IP address, which condition fired (Z-score / multiplier / error-surge), current rate, effective_mean at time of detection, timestamp, ban duration assigned.

Unban event: IP address, how long it was banned, whether it is now permanently blocked, timestamp.

Global anomaly alert: current global rate, effective_mean, which condition fired, timestamp.

---

9. Live Metrics Dashboard

Your tool must expose a live dashboard — either a terminal UI or a simple web UI on a local port. It must update at least every 3 seconds and display: current banned IP count, global requests per second, top 10 source IPs by request volume in the current window, system CPU and memory usage, current effective_mean and effective_stddev values, and time elapsed since tool startup.

---

10. Logging and Audit Trail

Your tool writes a structured log of every event:

```
[2025-11-10 14:32:01] BANNED     203.0.113.45 | condition: z_score(4.2)  | rate: 87/60s | baseline: 3.1/60s | ban: 10m
[2025-11-10 14:42:01] UNBANNED   203.0.113.45 | duration: 10m            | status: eligible
[2025-11-10 14:45:10] GLOBAL     anomaly      | condition: multiplier(6x) | rate: 310/s  | baseline: 52/s
[2025-11-10 14:46:00] BASELINE   recalculated | mean: 3.2 | stddev: 0.8   | window: 30m
```

---

Repository Structure

```
├── detector/                   # Your tool — Python or Go
│   ├── main.[py|go]            # Entry point — starts the daemon
│   ├── monitor.[py|go]         # Log tail and parse logic
│   ├── baseline.[py|go]        # Rolling baseline computation
│   ├── detector.[py|go]        # Anomaly detection formulas
│   ├── blocker.[py|go]         # iptables rule management
│   ├── unbanner.[py|go]        # Cooldown and exponential backoff
│   ├── notifier.[py|go]        # Slack webhook integration
│   ├── dashboard.[py|go]       # Live metrics TUI or web UI
│   ├── config.yaml             # All thresholds, webhook URL, window sizes
│   └── requirements.txt        # Python only
├── nginx/
│   └── nginx.conf              # Your Nginx config
├── docs/
│   └── architecture.png        # Required architecture diagram
├── screenshots/
└── README.md
```

---

Required Screenshots

Include these in /screenshots and link them in your README:

1. nextcloud-running.png — Nextcloud login page in browser with your server IP visible
2. tool-running.png — Your daemon running, showing it processing log lines
3. dashboard.png — Your live dashboard showing all required metrics
4. ban-slack.png — The Slack notification your tool sent when it detected and banned an IP
5. unban-slack.png — The Slack notification your tool sent when it lifted a ban
6. global-alert-slack.png — The Slack notification for a global anomaly event
7. iptables-banned.png — Output of sudo iptables -L -n showing a blocked IP
8. audit-log.png — Your tool's own structured log showing ban, unban, and baseline recalculation events
9. baseline-graph.png — A visualisation of your baseline over time showing at least two different hourly time slots with visibly different effective_mean values, demonstrating that your tool has learned time-of-day traffic patterns (even a simple terminal plot is acceptable)

---

README Requirements

Your README must include:
- Your server's public IP (Nextcloud must be live during grading)
- Your chosen language and why
- A clear explanation of your sliding window implementation — how the deque works, what the eviction logic is
- A clear explanation of your rolling baseline — window size, recalculation interval, the floor values you apply and why
- A clear explanation of your time-aware baseline slots — which time zone, how fallback to global baseline works, and how conflicting signals are resolved
- Your anomaly detection formula — which condition you expect to fire most often for which attack type and why
- How you handle the warm-up edge case — what happens if an attack arrives in the first 10 minutes
- Your Slack webhook channel name (not the URL — keep that in config only)
- Step-by-step setup instructions from a fresh VPS to a fully running stack
- Your GitHub repo link (must be public)

---

DOs and DON'Ts

DO:
- Build your own detection logic — this is the entire point of the task
- Keep all thresholds and window sizes in a config file, not hardcoded
- Test your tool before submitting — generate some traffic yourself and confirm your tool responds
- Keep your server live for the full 12-hour learning period and throughout grading
- Comment your baseline and detection code — we will read it

DON'T:
- Don't install Fail2Ban and submit that — instant disqualification
- Don't use rate-limiting libraries (e.g. slowapi, golang.org/x/time/rate) — implement the sliding window yourself
- Don't fake the sliding window with a per-minute counter — we will check your code
- Don't hardcode thresholds as a substitute for a real baseline — your effective_mean must be computed from actual traffic
- Don't disable login or upload endpoints — legitimate users must still be able to access the app
- Don't use Kubernetes — Docker Compose on a raw VPS only
- Don't write your tool in any language other than Python or Go

---

Evaluation Criteria

Detection accuracy carries 20% of the grade. We check whether your tool detects attacks at hour 2, hour 10, and everywhere in between, and how quickly it fires after the attack begins.

Baseline quality carries 20%. We read your baseline implementation. The rolling window must be correctly computed from real traffic data, not faked. The floor values must be applied. The recalculation must fire every 60 seconds. Your 24 hourly time-slot baselines must exist and must be used when sufficiently populated — we will simulate an attack during a busy period and verify your tool compares against the correct time-slot baseline, not the flatter global average.

Blocking effectiveness carries 15%. iptables rules must be applied within 10 seconds of detection and confirmed to be in place.

Error surge detection carries 15%. We run a high-error-rate attack (many failed logins at moderate rate) and verify your tool's lowered thresholds catch it before the standard thresholds would.

Sliding window implementation carries 10%. We read your deque-based implementation and verify it is a true sliding window, not a fixed bucket.

Slack alerting carries 10%. Both ban and unban events must produce correct, informative Slack messages. We check the content, not just that something was sent.

False positive control carries 5%. Legitimate users must not be banned during or after an attack.

Code quality carries 5%. Readable, modular, configurable — we will read your code.

Automatic failure conditions: server is not live for the full 12-hour window before grading, the tool blocks nothing during a live attack, Fail2Ban or a rate-limiting library is found in the stack, the sliding window is faked, the language is not Python or Go, or Slack notifications are missing or empty.

---

Submission Process

1. Have your server live and your tool running at the announced deadline
2. Confirm Nextcloud is accessible at your public IP
3. Confirm your tool's dashboard is running and your Slack alerts are working — send yourself a test ban by generating traffic locally
4. Go to the #track-devops channel in Slack
5. Run the command: /stage-4-devops

Submit your Nextcloud public IP and your GitHub repo link (must be public). Check Thanos bot for your result after submission.

---

Deadline and Attempts

Server must be live by: [DATE TIME] WAT
Grading window opens: 12 hours after the above deadline
Submission deadline: [DATE] WAT
Attempts allowed: 3
Late submissions: Not accepted

---

> You are building something that has to be smarter than the attack it does not yet know is coming.
> The baseline is your memory. The detection formula is your judgement. The iptables rule is your reflex.
> Build all three well. You got this, Cool Keeds! @channel