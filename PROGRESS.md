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
**Status:** [~] In progress — screenshots need final redaction, then push to GitHub

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
- [~] Redact screenshots (1 and 2 need more redaction — other devices' IPs visible)
- [x] Write wireshark_guide.md
- [x] Write tools/README.md
- [ ] Push to GitHub

---

## Project 3: Brute Force Tool
**Status:** [ ] Not started

---

## Project 4: Directory/Subdomain Fuzzer
**Status:** [ ] Not started

---

## Project 5: SQL Injection Scanner
**Status:** [ ] Not started

---

## Project 6: Log Analyzer
**Status:** [ ] Not started

---

## Project 7: File Integrity Monitor
**Status:** [ ] Not started

---

## Project 8: Password Auditor
**Status:** [ ] Not started

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
| 2026-05-03 | Packet Sniffer (Wireshark) | Ran live capture on ens38, applied dns/icmp/http filters, saved capture.pcapng, took 4 screenshots, wrote wireshark_guide.md — awaiting screenshot re-redaction before GitHub push |
