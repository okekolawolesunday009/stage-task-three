Hello Cool Keeds! We heard y’all were complaining about how easy the previous tasks were. So we listened, and because we love you, we looked at everything we could throw at you, took a deep breath, and said “let’s be kind” - so we gave you an even simpler task :hehe: You are welcome!

You have just been hired as a DevSecOps Engineer at HNG’s cloud.ng. A rapidly growing cloud storage company, which is part of HNG’s businesses. Powered by Nextcloud. The platform serves users globally and is publicly accessible around the clock. After a wave of suspicious activity, your boss Mark Essien just tasked you with something. Your job is to build an anomaly detection engine that watches all incoming HTTP traffic in real time, learns what normal looks like, and automatically responds when something deviates, whether from a single aggressive IP or a global traffic spike.
You are given a pre-built Nextcloud Docker image on DockerHub: https://hub.docker.com/r/kefaslungu/hng-nextcloud
Do not modify or replace it. All your work lives in the detection tool you build alongside it.
AIRTABLE LINK



What You Must Provision


Linux VPS (AWS, GCP, DigitalOcean, Linode, Vultr, Hetzner, etc.) — minimum 2 vCPU, 2 GB RAM
Deploy the Nextcloud stack using Docker Compose
Nginx as a reverse proxy in front of Nextcloud with JSON access logs enabled
Nginx logs must be shared via a named Docker volume called HNG-nginx-logs. Nginx writes to it, Nextcloud and your detector mount it read-only.
Nginx must be configured to trust and forward the real client IP using the X-Forwarded-For header.
Access logs must be written in JSON format to /var/log/nginx/hng-access.log. Include at minimum: source_ip, timestamp, method, path, status, response_size




What You Must Build

A daemon in Python or Go that runs continuously alongside Nextcloud — not a cron job or one-shot script.



The Scenario

You will be told when to bring your server up. Keep it live for 12 continuous hours. At some point — maybe hour 2, maybe hour 10, maybe multiple times — we will send attack traffic. Your tool must detect and respond regardless of when it arrives. The baseline cannot be a hardcoded value; it must reflect actual recent traffic.



What Your Daemon Must Do


Log Monitoring: Continuously tail and parse the Nginx access log line by line — source IP, timestamp, method, endpoint, status code, response size.
Sliding Window: Track request rates using two deque-based windows over the last 60 seconds — one per IP, one global. No rate-limiting libraries.
Rolling Baseline: Compute mean and stddev from a rolling 30-minute window of per-second counts, recalculated every 60 seconds. Maintain per-hour slots and prefer the current hour’s baseline when it has enough data.
Anomaly Detection: Flag an IP or global rate as anomalous if the z-score exceeds 3.0 or the rate is more than 5x the baseline mean — whichever fires first.
Error Surge: If an IP’s 4xx/5xx rate is 3x the baseline error rate, tighten its detection thresholds automatically.
Blocking: Per-IP anomaly — add an iptables DROP rule and send a Slack alert within 10 seconds. Global anomaly — Slack alert only.
Auto-Unban: Release bans on a backoff schedule — 10 min, 30 min, 2 hours, then permanent. Send a Slack notification on every unban.
Slack Alerts: Store the webhook URL in config. Alerts must include the condition fired, current rate, baseline, timestamp, and ban duration where applicable.
Live Metrics UI: A web dashboard that refreshes every 3 seconds or less showing banned IPs, global req/s, top 10 source IPs, CPU/memory usage, effective mean/stddev, and uptime. Must be served at a domain or subdomain — this is what you submit for grading. Nextcloud itself is accessible by IP only.
Audit Log: Write structured log entries for every ban, unban, and baseline recalculation. Format: [timestamp] ACTION ip | condition | rate | baseline | duration




Repository Structure

detector/
  main.[py|go]
  monitor.[py|go]
  baseline.[py|go]
  detector.[py|go]
  blocker.[py|go]
  unbanner.[py|go]
  notifier.[py|go]
  dashboard.[py|go]
  config.yaml
  requirements.txt (Python only)
nginx/
  nginx.conf
docs/
  architecture.png
screenshots/
README.md



Required Screenshots

1. Tool-running.png — Daemon running, processing log lines
2. Ban-slack.png — Slack ban notification
3. Unban-slack.png — Slack unban notification
4. Global-alert-slack.png — Slack global anomaly notification
5. Iptables-banned.png — sudo iptables -L -n showing a blocked IP
6. Audit-log.png — Structured log with ban, unban, and baseline recalculation events
7. Baseline-graph.png — Baseline over time showing at least two hourly slots with visibly different effective_mean values



README Requirements


Server IP and metrics dashboard URL (both live during grading)
Language choice and why
How your sliding window works — deque structure and eviction logic
How your baseline works — window size, recalculation interval, floor values
Setup instructions from a fresh VPS to a fully running stack
GitHub repo link (must be public)




Blog Post

Write a beginner-friendly blog post explaining how you built this project. Publish it on any public platform (Hashnode, Dev.to, Medium, your own site, etc.) and include the link in your README and submission form. (Emphasises on beginner-friendly)

Your post must cover: what the project does and why it matters, how the sliding window works, how the baseline learns from traffic, how the detection logic makes a decision, and how iptables is used to block an IP. Write it as if you are explaining to someone who has never worked on security tooling before. Good diagrams or code snippets are a bonus.



DOs and DON’Ts

DO:

Build your own detection logic
Keep all thresholds in a config file
Test before submitting
Comment your baseline and detection code


DON’T:

Use Fail2Ban (instant disqualification)
Use rate-limiting libraries like slowapi or golang.org/x/time/rate
Fake the sliding window with a per-minute counter
Hardcode effective_mean
Disable login or upload endpoints
Use any language other than Python or Go




Submission

Have your server live and tool running at the announced deadline, then submit using this link .
Submission deadline: 29th April, 11:59pm WAT. Late submissions not accepted

May whatever you believe in be with you in these wonderful times. Cool Keeds! :cy_fingerguns:AirtableAirtable | Everyone's app platformAirtable is a low-code platform for building collaborative apps. Customize your workflow, collaborate, and achieve ambitious outcomes. Get started for free.