# Network Packet Sniffing with Wireshark

## Objective

Capture and analyse live network traffic on a local machine using Wireshark. Identify protocols, DNS queries, and HTTP requests using display filters.

## Environment

- **Machine:** Cletus-lab (Ubuntu VM)
- **IP:** 192.168.0.240
- **Interface:** ens38 (home network adapter)
- **Tool:** Wireshark

---

## Step 1 — Identify the Right Interface

Before capturing, confirm which interface is connected to the target network.

```bash
ip a
```

Look for the interface whose IP matches the same subnet as your gateway. Find your gateway with:

```bash
ip route | grep default
```

Output:
```
default via 192.168.0.1 dev ens38
```

`ens38` is on the `192.168.0.0/24` subnet — the same network as the router and all other devices. This is the interface to capture on.

---

## Step 2 — Start a Capture

Open Wireshark:

```bash
wireshark &
```

On the welcome screen, select **ens38** from the interface list — it will have a live traffic graph showing active traffic.

Double-click to start capturing.

📸 *Screenshot 1: Wireshark capturing live traffic on ens38*

---

## Step 3 — Generate Traffic

In a separate terminal, generate traffic to capture:

```bash
ping -c 4 google.com
curl http://example.com
```

This produces:
- DNS queries (resolving `google.com` and `example.com`)
- ICMP packets (ping requests and replies)
- HTTP traffic (the curl request)

---

## Step 4 — Apply Display Filters

Wireshark captures everything — display filters let you isolate exactly what you need.

### DNS Traffic

```
dns
```

Shows all DNS queries and responses. You can see your machine querying `192.168.0.1` (the router/DNS resolver) for `google.com` and `example.com`, and the responses with the resolved IPs.

📸 *Screenshot 2: DNS filter showing google.com and example.com lookups*

---

### ICMP Traffic (Ping)

```
icmp
```

Shows the 4 ping requests sent to Google's IP and the 4 replies. Each request/reply pair confirms end-to-end connectivity.

📸 *Screenshot 3: ICMP filter showing ping requests and replies*

---

### HTTP Traffic

```
http
```

Shows the raw HTTP GET request sent by `curl http://example.com`. Unlike HTTPS, HTTP traffic is unencrypted — Wireshark can read the full request headers and response body.

📸 *Screenshot 4: HTTP filter showing curl request to example.com*

---

## Step 5 — Save the Capture

**File → Save As** → `capture.pcapng`

The `.pcapng` format is the industry standard for packet captures. It can be shared with other analysts, loaded into tools like `tshark` or `tcpdump`, and re-analysed later.

---

## Key Wireshark Display Filters

| Filter | What it shows |
|--------|--------------|
| `dns` | All DNS queries and responses |
| `icmp` | Ping requests and replies |
| `http` | Unencrypted HTTP traffic |
| `tcp` | All TCP connections |
| `udp` | All UDP traffic |
| `ip.addr == 192.168.0.240` | Traffic to/from a specific IP |
| `tcp.port == 443` | HTTPS traffic |
| `tcp.port == 22` | SSH traffic |

---

## What This Demonstrates

- How to identify the correct network interface on a multi-adapter machine
- How to start a live packet capture in Wireshark
- How to use display filters to isolate DNS, ICMP, and HTTP traffic
- How to save a capture file for offline analysis
- The difference between encrypted (HTTPS) and unencrypted (HTTP) traffic visibility

---

> **Legal note:** Only capture traffic on networks you own or have explicit written permission to monitor. Unauthorised packet capture is illegal in most jurisdictions.
