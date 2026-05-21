# Log Analyzer (Python)

A multi-format security log analyzer that parses Linux SSH authentication logs
and Apache/Nginx web access logs, then flags suspicious activity. Built from
scratch with the Python standard library — no external dependencies.

## Features

- **Auto-detection** of log format (SSH `auth.log` vs. web access log)
- **SSH auth analysis**
  - Brute-force source detection (failed attempts per IP over a threshold)
  - Successful login *after* a brute force burst — possible account compromise
  - Username enumeration (probing invalid/privileged accounts)
- **Web access analysis**
  - SQL injection payloads in requests
  - Cross-site scripting (XSS) payloads
  - Path traversal sequences (`../`, `/etc/passwd`, URL-encoded)
  - Known attack-tool user agents (sqlmap, nikto, gobuster, nmap, …)
  - Sensitive file access (`.env`, `.git`, `config.bak`, `wp-login`, …)
  - Directory/content scanning (404 floods from a single IP)
- **Severity scoring** (Critical / High / Medium / Low)
- **Three outputs**: console summary, dark-themed **HTML report**, and **JSON**

## Usage

```bash
# Auto-detect format and print to console
python3 log_analyzer.py -f samples/auth.log

# Web log with HTML + JSON reports
python3 log_analyzer.py -f samples/access.log -r reports/web_report.html -o reports/web.json

# Force a format and tune the detection threshold
python3 log_analyzer.py -f /var/log/auth.log -t auth -n 5
```

### Options

| Flag | Description |
|------|-------------|
| `-f, --file` | Path to the log file (required) |
| `-t, --type` | `auto` (default), `auth`, or `web` |
| `-n, --threshold` | Failed-attempt / 404 count to flag an IP (default: 10) |
| `-o, --output` | Save findings as JSON |
| `-r, --report` | Save an HTML report |

## Sample data

`samples/auth.log` and `samples/access.log` contain synthetic logs with
embedded attacks (SSH brute force + root compromise, gobuster/sqlmap scans,
XSS, path traversal, sensitive-file probes) so the analyzer has something to
detect for demos and screenshots.

```
$ python3 log_analyzer.py -f samples/auth.log
...
  [CRITICAL] Successful Login After Brute Force
             Source: 198.51.100.23
             Account 'root' authenticated after 12 failed attempts — possible account compromise
```

> All IP addresses in the samples are documentation/reserved ranges
> (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
