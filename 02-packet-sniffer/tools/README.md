# Network Packet Sniffer — Wireshark Tools Version

Professional packet capture walkthrough using Wireshark on a live network.

## Contents

| File | Description |
|------|-------------|
| `wireshark_guide.md` | Step-by-step walkthrough — interface selection, capture, display filters, saving |
| `capture.pcapng` | Live packet capture from Cletus-lab (ens38 interface) |
| `screenshots/` | Screenshots from each step of the walkthrough |

## Workflow

1. Identify the correct network interface (`ip a`, `ip route`)
2. Start a live capture on the target interface
3. Generate traffic (ping, curl, browse)
4. Apply display filters to isolate DNS, ICMP, HTTP
5. Save the capture as `.pcapng` for offline analysis

See `wireshark_guide.md` for the full walkthrough.
