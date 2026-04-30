# 01 — Port Scanner

A port scanner checks which ports on a target machine are open and identifies what services are running on them.

---

## What is a Port?

Every computer has 65,535 ports. Each port handles a specific type of network traffic:
- Port 22 → SSH (remote login)
- Port 80 → HTTP (websites)
- Port 443 → HTTPS (secure websites)
- Port 3306 → MySQL (database)

A port scanner knocks on each door and reports which ones are open.

---

## Versions

### Python Version (`python/`)
Built from scratch using only Python standard library — no external packages needed.

**Features:**
- Multi-threaded TCP scanning (fast)
- Service detection
- Banner grabbing (reads service response)
- JSON and HTML report output
- CLI interface with argparse

**Usage:**
```bash
cd python/
python3 scanner.py 192.168.1.1
python3 scanner.py 192.168.1.1 -p 1-1024
python3 scanner.py 192.168.1.1 -p 1-65535 --threads 500
python3 scanner.py 192.168.1.1 -p 80,443,22 --output json
```

---

### Tools Version (`tools/`)
Using **Nmap** — the industry-standard port scanner used by security professionals worldwide.

See [`tools/nmap_guide.md`](./tools/nmap_guide.md) for full usage and commands.

---

## Concepts Covered

- TCP/IP networking
- Sockets and connections
- Multithreading
- Banner grabbing
- Service fingerprinting
- JSON and HTML report generation

---

## Legal Notice

Only scan systems you own or have explicit permission to test.
