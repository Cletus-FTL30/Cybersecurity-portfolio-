# Log Analyzer — ELK Stack Tools Version

Centralised log analysis using the **ELK stack** (Elasticsearch · Kibana · Filebeat) against the same logs the Python analyzer parses. Detects the same attacks — SSH brute force, web scanning, SQLi/XSS/traversal probes — visually and at scale.

## Contents

| File | Description |
|------|-------------|
| `elk_guide.md` | Step-by-step walkthrough — stack bring-up, log shipping, Discover queries, dashboards, alert rule |
| `docker-compose.yml` | One-command lab stack: single-node Elasticsearch + Kibana + Filebeat (8.13.4) |
| `filebeat.yml` | Filebeat config — system + apache modules pointed at the sample logs |
| `screenshots/` | Screenshots from Kibana Discover, the dashboard, and the alert rule |

## Workflow

1. Bring up the stack — `docker compose up -d`
2. Ship the logs with Filebeat — `docker compose run --rm filebeat setup -e`
3. Explore parsed events in Kibana Discover with KQL
4. Build dashboards (failed logins by IP, status codes over time, top paths, user agents)
5. Promote the brute-force query to an alert rule

The lab runs on Cletus-lab (Ubuntu VM, `192.168.0.240`) — all systems I own. See `elk_guide.md` for the full walkthrough.
