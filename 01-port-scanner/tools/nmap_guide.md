# Port Scanning with Nmap

Nmap (Network Mapper) is the industry-standard tool for port scanning and network discovery.
This guide mirrors what our Python scanner does, using Nmap instead.

---

## Installation

```bash
# Linux
sudo apt install nmap

# Mac
brew install nmap

# Windows — download installer from https://nmap.org/download.html
```

---

## Basic Usage

### Scan default top 1000 ports
```bash
nmap 192.168.1.1
```

### Scan a specific port range
```bash
nmap -p 1-1024 192.168.1.1
```

### Scan specific ports
```bash
nmap -p 80,443,22,3306 192.168.1.1
```

### Scan all 65535 ports
```bash
nmap -p- 192.168.1.1
```

---

## Service & Version Detection

This is the equivalent of our banner grabbing feature.

```bash
nmap -sV 192.168.1.1
```

- `-sV` → probe open ports to detect service name and version number

---

## OS Detection

```bash
sudo nmap -O 192.168.1.1
```

- `-O` → attempt to identify the operating system (requires sudo)

---

## Combining Flags (Most Common Scan)

```bash
sudo nmap -sV -O -p 1-1024 192.168.1.1
```

---

## Saving Reports

```bash
# Save as normal text
nmap -oN report.txt 192.168.1.1

# Save as XML (can be imported into other tools)
nmap -oX report.xml 192.168.1.1

# Save as JSON-style grepable format
nmap -oG report.gnmap 192.168.1.1

# Save all formats at once
nmap -oA report 192.168.1.1
```

---

## Scan Your Own Machine (Safe Practice)

```bash
nmap 127.0.0.1
```

Always test on your own machine or a lab machine you have permission to scan.
Never scan networks or systems without explicit authorisation — it is illegal.

---

## Sample Output

```
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 8.9 (protocol 2.0)
80/tcp  open   http     Apache httpd 2.4.52
443/tcp open   https    Apache httpd 2.4.52
3306/tcp open  mysql    MySQL 8.0.28
```

---

## Practical Walkthrough — Lab Engagement

This is a real scan performed against a controlled lab environment (`192.168.0.240`).
All other devices on the network have been redacted — only systems I own and have permission to scan are shown.

---

### Step 1 — Ping Sweep (Host Discovery)

Find which hosts are alive on the network before scanning ports.

```bash
sudo nmap -sn 192.168.0.0/24
```

**Output (other devices redacted):**
```
Nmap scan report for _gateway (192.168.0.1)
Host is up (0.032s latency).

[devices redacted — not in scope]

Nmap scan report for Cletus-lab (192.168.0.240)
Host is up.

Nmap done: 256 IP addresses (8 hosts up) scanned in 7.67 seconds
```

**Why this matters:** You never scan blindly. Host discovery tells you what's alive so you focus your scan on valid targets. Scanning dead IPs wastes time and creates noise.

---

### Step 2 — Full Port Scan

Scan all 65535 ports on the target machine.

```bash
sudo nmap -p- 192.168.0.240
```

**Output:**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.90 seconds
```

**Why `-p-` and not default:** Nmap's default only scans the top 1000 ports. Services running on non-standard ports would be missed. A full scan ensures nothing is hidden.

---

### Step 3 — Service & Version Detection

Identify exactly what software is running on each open port.

```bash
sudo nmap -sV 192.168.0.240
```

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Why this matters:** Port numbers alone tell you the protocol. Version numbers tell you whether the software is vulnerable. An attacker searches CVE databases using exact version strings like `OpenSSH 9.6p1` or `Apache 2.4.58` to find known exploits. A defender uses the same information to prioritise patching.

---

### Step 4 — Save the Report

Always save scan output. It's your evidence, your audit trail, and your documentation.

```bash
sudo nmap -sV 192.168.0.240 -oN tools/scan_report.txt
```

The saved report is included in this repository at `tools/scan_report.txt`.

**Output formats available:**
- `-oN` — normal text (human readable)
- `-oX` — XML (importable into other tools like Metasploit)
- `-oG` — grepable format (easy to parse with shell scripts)
- `-oA` — save all three formats at once

---

### What This Tells a Defender

| Finding | Risk | Action |
|---------|------|--------|
| Port 22 open (SSH) | Medium — brute force risk if weak passwords | Enforce key-based auth, disable root login |
| Port 80 open (HTTP) | Low-Medium — unencrypted traffic | Consider HTTPS, check Apache config |
| Apache 2.4.58 | Check CVEs for this version | Keep updated, monitor security advisories |
| OpenSSH 9.6p1 | Recent version, low risk | Monitor for new advisories |

---

## Nmap vs Our Python Scanner

| Feature              | Python Scanner | Nmap         |
|----------------------|---------------|--------------|
| TCP scanning         | Yes           | Yes          |
| UDP scanning         | Yes           | Yes          |
| Banner grabbing      | Basic         | Advanced     |
| OS detection         | No            | Yes          |
| Speed                | Fast          | Faster       |
| Scripting engine     | No            | Yes (NSE)    |
| Report formats       | JSON, HTML    | TXT, XML, JSON |
| Learning value       | High          | Medium       |
