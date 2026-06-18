# ARP Mapping & Spoofing — Tools Version

The industry-tool counterpart to the from-scratch `netmapper.py` / `arpspoof.py`.
This walkthrough uses standard tools to **map** a local network and explains how
ARP **spoofing** works — without poisoning any real device.

> **Scope:** Mapping is run for real against my own lab subnet (other people's
> devices are redacted in the screenshots). The spoofing section is explained
> and shown as commands only — no live poisoning was performed.

## Tools used

| Tool | Role |
|------|------|
| `arp-scan` | Fast ARP sweep of the local subnet |
| `netdiscover` | Active/passive ARP discovery |
| `bettercap` | Modern recon/MITM framework — used here for `net.probe` mapping |

See [arp_mapping_guide.md](./arp_mapping_guide.md) for the full step-by-step
walkthrough with screenshots.
