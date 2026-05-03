# Network Packet Sniffer — Python

A command-line packet sniffer built with Scapy. Captures live network traffic, decodes TCP/UDP/ICMP/DNS packets, and saves output to a log file.

## Features

- Live packet capture on any network interface
- Protocol detection: TCP, UDP, ICMP, DNS (with domain name extraction)
- Source/destination IP and port for every packet
- Timestamps on all output
- Filter by protocol (`-p`)
- Limit capture count (`-c`)
- Save output to a log file (`-o`)

## Requirements

```
sudo apt install python3-scapy
```

## Usage

```bash
sudo python3 sniffer.py [options]
```

| Flag | Description |
|------|-------------|
| `-i` | Network interface (e.g. `eth0`, `wlan0`) |
| `-p` | Filter by protocol: `TCP`, `UDP`, `ICMP`, `DNS` |
| `-c` | Stop after N packets (default: unlimited) |
| `-o` | Save output to a log file |

## Examples

Capture all traffic:
```bash
sudo python3 sniffer.py
```

Capture DNS queries only:
```bash
sudo python3 sniffer.py -p dns
```

Capture 50 TCP packets on eth0 and save to file:
```bash
sudo python3 sniffer.py -i eth0 -p tcp -c 50 -o capture.log
```

## Sample Output

```
[14:22:26] [DNS]  192.168.0.240 --> 192.168.0.1   |  Query: google.com
[14:22:26] [TCP]  192.168.0.240:39412 --> 142.250.140.101:443
[14:22:27] [TCP]  142.250.140.101:443 --> 192.168.0.240:39412
[14:22:31] [UDP]  192.168.0.240:5353 --> 224.0.0.251:5353
[14:22:31] [ICMP] 192.168.0.240 --> 8.8.8.8
```

## How It Works

Scapy puts the network interface into promiscuous mode, meaning it reads every packet on the network segment — not just packets addressed to this machine. Each packet is passed to `process_packet()`, which:

1. Checks for an IP layer (discards non-IP traffic like ARP)
2. Identifies the protocol from the packet layers
3. For DNS: decodes the `DNSQR` layer to extract the queried domain name
4. Prints a formatted line with timestamp, protocol, IPs, and ports

> **Note:** Requires root/sudo — raw packet capture is a privileged operation.
> Only use on networks you own or have explicit permission to monitor.
