# Cybersecurity Portfolio - Progress

## Status Legend
- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete

---

## Project 1: Port Scanner
**Status:** [x] Complete
**Goal:** Professional-grade Python port scanner with threading, service detection, and report output.

### Python Version Tasks
- [x] Multi-threaded TCP scanner
- [x] UDP scan support
- [x] Banner/service grabbing
- [ ] OS fingerprinting hints
- [x] argparse CLI
- [x] JSON output
- [x] HTML report
- [x] Reports saved to /reports

### Nmap Tools Version Tasks
- [x] Explain network interfaces (ip a)
- [x] Step 1 — Ping sweep (find live hosts) — found gateway, personal device, VM
- [x] Fix hostname (now Cletus-lab)
- [x] Step 2 — Port scan own machine (192.168.0.240) — found ports 22, 80
- [x] Step 3 — Service detection (-sV) — OpenSSH 9.6p1, Apache 2.4.58
- [x] Step 4 — Save report (-oN) — saved to tools/scan_report.txt
- [x] Take screenshots of each step
- [x] Write explanation doc for tools/ folder (nmap_guide.md)

### Notes
- Project directory: `/home/cletus/port-scanner/`
- Main file: `scanner.py`
- Reports folder: `reports/`

---

## Project 2: Network Packet Sniffer
**Status:** [x] Complete

### Python Version Tasks
- [x] Packet capture with Scapy
- [x] TCP/UDP/ICMP/DNS protocol detection
- [x] Port numbers on TCP/UDP
- [x] DNS query extraction (domain names)
- [x] Timestamps on all output
- [x] argparse CLI (-i interface, -p protocol, -c count, -o output)
- [x] Log file output
- [x] README.md

### Wireshark Tools Version Tasks
- [x] Identify correct interface (ip a, ip route)
- [x] Start live capture on ens38
- [x] Generate traffic (ping, curl)
- [x] Apply display filters (dns, icmp, http)
- [x] Save capture.pcapng
- [x] Take 4 screenshots
- [x] Redact screenshots (programmatically redacted using Python/Pillow)
- [x] Write wireshark_guide.md
- [x] Write tools/README.md
- [x] Push to GitHub

---

## Project 3: Brute Force Tool
**Status:** [x] Complete

### Python Version Tasks
- [x] SSH brute forcing with Paramiko
- [x] FTP brute forcing with ftplib
- [x] Multi-threading support (-T flag)
- [x] argparse CLI (-t, -u, -w, -s, -p, -T, -o)
- [x] Log file output
- [x] README.md

### Hydra Tools Version Tasks
- [x] Prepare wordlist
- [x] Brute force SSH with Hydra
- [x] Brute force FTP with Hydra
- [x] Take screenshots
- [x] Write hydra_guide.md
- [x] Write tools/README.md
- [x] Push to GitHub

---

## Project 4: Directory/Subdomain Fuzzer
**Status:** [x] Complete

### Python Version Tasks
- [x] Directory fuzzing with HTTP requests
- [x] File extension discovery (.php, .bak, .txt)
- [x] Response code filtering (200, 301, 302, 403)
- [x] Multi-threading
- [x] Professional HTML report with colour-coded badges
- [x] argparse CLI (-t, -w, -e, -T, -o, -r)
- [x] README.md

### Gobuster Tools Version Tasks
- [x] Set up lab (hidden dirs + sensitive files on Apache)
- [x] Root directory scan
- [x] Subdirectory scan (found config.bak)
- [x] Take 4 screenshots (2 Gobuster + 2 HTML reports)
- [x] Write gobuster_guide.md
- [x] Write tools/README.md
- [x] Fix screenshot image links in all guides (Projects 2, 3, 4)
- [x] Push to GitHub

---

## Project 5: SQL Injection Scanner
**Status:** [x] Complete

### Python Version Tasks
- [x] Intentionally vulnerable Flask target (4 injection points: GET, POST, JSON, header)
- [x] Error-based detection with DB fingerprinting (SQLite, MySQL, MSSQL, PostgreSQL, Oracle)
- [x] Boolean-based blind detection (response size differential)
- [x] Time-based blind detection
- [x] WAF bypass payloads (comment injection, case randomisation, URL encoding)
- [x] Authentication bypass detection
- [x] Data extraction proof-of-concept (JSON API UNION dump)
- [x] CVSS 3.1 base score + vector string per finding
- [x] HTML report with business impact, vulnerable vs fixed code, remediation
- [x] JSON report output
- [x] argparse CLI (--target, --full, --url, --get-param, -o, -v)
- [x] README.md

### SQLMap Tools Version Tasks
- [x] GET parameter injection (boolean-blind confirmed)
- [x] POST form injection (authentication bypass context)
- [x] JSON API body injection (Content-Type: application/json)
- [x] Data extraction — dumped full users table via boolean-blind
- [x] WAF evasion with tamper scripts (space2comment, between, randomcase)
- [x] Write sqlmap_guide.md
- [x] Take screenshots (5 steps, 10 images total)

---

## Project 6: Log Analyzer
**Status:** [x] Complete

### Python Version Tasks
- [x] Multi-format auto-detection (SSH auth log + web access log)
- [x] SSH brute-force source detection
- [x] Successful-login-after-brute-force (compromise) detection
- [x] Username enumeration detection
- [x] Web: SQLi / XSS / path traversal payload detection
- [x] Web: malicious scanner user-agent detection
- [x] Web: sensitive file access + directory scanning detection
- [x] Severity scoring (Critical/High/Medium/Low)
- [x] Console summary + HTML report + JSON output
- [x] argparse CLI (-f, -t, -n, -o, -r)
- [x] Sample logs with embedded attacks (samples/auth.log, access.log)
- [x] README.md

### ELK / Kibana Tools Version Tasks
- [x] Write elk_guide.md (walkthrough + 3 screenshots wired in)
- [x] Write docker-compose.yml (ES + Kibana + Filebeat, single-node lab)
- [x] Write filebeat.yml (system + apache modules pointed at sample logs)
- [x] Write tools/README.md
- [x] Stand up the stack on the lab VM — `docker compose up -d` (ES healthy, Kibana up)
- [x] Ship auth + access logs with Filebeat — 62 events parsed into filebeat-*
- [x] View Kibana dashboards — used prebuilt System (SSH) + Apache (access) module dashboards
- [x] Take screenshots (Discover failed logins, SSH dashboard, Apache response codes)
- [x] Push to GitHub

**Optional future enhancement:** Kibana brute-force alert rule (Stack Management → Rules) — described in Step 4 of elk_guide.md, not built.

---

## Project 7: File Integrity Monitor
**Status:** [x] Complete (AIDE-only tools version; Tripwire dropped from scope)

### Python Version Tasks
- [x] SHA-256 baseline of a directory tree (size, perms, mtime per file)
- [x] Recursive monitoring with glob-based exclusions (`-x`)
- [x] Detect Added / Modified / Deleted / Permissions-Changed
- [x] Severity scoring (Critical/High/Medium) + non-zero exit on changes
- [x] Console summary + HTML report + JSON output
- [x] argparse subcommands (`baseline` / `check`)
- [x] Sample watched tree + baseline + demo report (simulated compromise)
- [x] README.md

### AIDE Tools Version Tasks
- [x] Write tools/README.md (AIDE overview)
- [x] Write aide_guide.md (install, init DB, simulate tamper, check)
- [x] Ran AIDE on Cletus-lab — baseline (7 entries), tamper, check caught all 4 changes (+ /opt/watched/etc dir mtime)
- [x] Screenshots in tools/screenshots/ (aide-01-init, aide-02-check, aide-03-check-detail)
- [x] Pushed to GitHub (2026-05-28)
- Tripwire dropped from scope (user decision 2026-05-28)

---

## Project 8: Password Auditor
**Status:** [x] Complete

### Python Version Tasks
- [x] Hash type identification (`identify` subcommand)
- [x] Dictionary cracking across MD5/SHA-1/SHA-256/SHA-512/NTLM (`crack`)
- [x] Brute-force cracking (`crack --brute`)
- [x] NTLM support (MD4 verified against RFC 1320 test vectors)
- [x] Password entropy / strength scoring with common-password check (`score`)
- [x] Console summary + JSON + HTML report output
- [x] argparse subcommands (`identify` / `crack` / `score`)
- [x] stdlib-only (no third-party dependencies)
- [x] README.md

### Hashcat Tools Version Tasks
- [x] Write tools/README.md + hashcat_guide.md (7 steps)
- [x] Sample hash files (md5, sha1, sha256, sha512, ntlm, pin) + wordlist.txt
- [x] Dictionary attack (MD5) — 3/3 cracked
- [x] Same attack across SHA-1 / SHA-256 / SHA-512 — SHA-256 left 1 uncracked (Exhausted)
- [x] NTLM crack (`-m 1000`) — recovered password1
- [x] Rules attack with best64.rule — 30-word list expanded to 2310 candidates
- [x] Mask / brute-force attack (`-a 3 ?d?d?d?d`) — cracked 4-digit PIN
- [x] Read results back from potfile (`--show`)
- [x] 6 screenshots in tools/screenshots/ (01-md5-dictionary … 06-show)

---

## Project 9: ARP Spoofer / Network Mapper
**Status:** [ ] Not started

---

## Project 10: Steganography Tool
**Status:** [ ] Not started

---

## Session Log
| Date | Project | What was done |
|------|---------|---------------|
| 2026-04-28 | Setup | Planned 10-project portfolio, created TODO and PROGRESS tracking |
| 2026-04-28 | Port Scanner | Built step by step — sockets, loop, threads, argparse CLI, banner grab, JSON+HTML reports |
| 2026-04-28 | Port Scanner (Nmap) | Started tools version — explained network interfaces, ran ping sweep, found 3 hosts (gateway 192.168.0.1, personal device 192.168.0.97, VM 192.168.0.240) |
| 2026-04-28 | Port Scanner (Nmap) | Completed tools version — full port scan, service detection, saved report, wrote nmap_guide.md walkthrough |
| 2026-04-30 | GitHub | Set up SSH authentication, connected repo to github.com/Cletus-FTL30/Cybersecurity-portfolio-, fixed all broken links, reorganised file structure, pushed Project 1 to main branch |
| 2026-05-03 | Packet Sniffer (Python) | Built sniffer.py with Scapy — TCP/UDP/ICMP/DNS detection, timestamps, argparse CLI, log file output |
| 2026-05-03 | Packet Sniffer (Wireshark) | Ran live capture on ens38, applied dns/icmp/http filters, saved capture.pcapng, took 4 screenshots, wrote wireshark_guide.md, pushed to GitHub |
| 2026-05-04 | Brute Force Tool (Python) | Built bruteforce.py — SSH + FTP brute forcing, multi-threading, argparse CLI, log file output |
| 2026-05-04 | Brute Force Tool (Hydra) | Ran Hydra against SSH and FTP on Cletus-lab, took 2 screenshots, wrote hydra_guide.md, pushed to GitHub |
| 2026-05-08 | Directory Fuzzer (Python) | Built fuzzer.py — directory + file fuzzing, threading, HTML report with colour-coded badges |
| 2026-05-08 | Directory Fuzzer (Gobuster) | Ran Gobuster against Apache VM, found hidden dirs + config.bak, wrote gobuster_guide.md, pushed to GitHub |
| 2026-05-08 | All guides | Fixed screenshot image links in wireshark_guide.md, hydra_guide.md, gobuster_guide.md |
| 2026-05-10 | SQL Injection Scanner | Built VulnShop target (4 injection points), Python scanner with 4 detection techniques + CVSS scoring + HTML report, ran SQLMap across all endpoints including JSON API, dumped users table, wrote sqlmap_guide.md |
| 2026-05-20 | Log Analyzer (Python) | Built log_analyzer.py — multi-format auto-detection (SSH auth + web access), brute force/compromise/enumeration/SQLi/XSS/traversal/scanner detection, severity scoring, HTML + JSON reports, sample logs with embedded attacks, README |
| 2026-05-21 | Log Analyzer (ELK) | Stood up ES + Kibana + Filebeat on Cletus-lab, shipped both sample logs (62 events parsed via system + apache modules), captured 3 Kibana screenshots, finished elk_guide.md; sanitized 2 real IPs in sample logs to RFC 5737 ranges; pushed Project 6 to GitHub as one clean commit |
| 2026-05-28 | File Integrity Monitor (Python) | Built fim.py — SHA-256 baseline + check subcommands, recursive scan with glob excludes, Added/Modified/Deleted/Permissions detection, console + HTML + JSON, non-zero exit on changes; sample watched tree + baseline + demo report from a simulated compromise; README |
| 2026-05-28 | File Integrity Monitor (AIDE) | Wrote AIDE tools guide; ran AIDE 0.18.6 on Cletus-lab against /opt/watched — baselined 7 entries, simulated tamper (web shell add, hosts delete, sshd_config edit, backup.sh chmod 777), check caught all 4 + the etc/ dir mtime change. Tripwire dropped from scope. Captured 3 screenshots; pushed Project 7 to GitHub (AIDE-only) |
| 2026-05-30 | Password Auditor (Python) | Built auditor.py (stdlib-only) — identify / crack / score subcommands, dictionary + brute-force cracking across MD5/SHA-1/SHA-256/SHA-512/NTLM, MD4 verified against RFC 1320 vectors, entropy scoring with common-password check, JSON + HTML reports, README |
| 2026-06-17 | Password Auditor (Hashcat) | Ran Hashcat 6.2.6 lab on Cletus-lab — dictionary (MD5 3/3), SHA family (SHA-256 left 1 Exhausted), NTLM (password1), best64 rules (30→2310 candidates), mask brute-force of a 4-digit PIN, potfile --show recap; captured all 6 screenshots; pushed Project 8 to GitHub |
