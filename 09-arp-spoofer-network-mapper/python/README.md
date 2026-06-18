# ARP Spoofer / Network Mapper — Python

Two from-scratch Scapy tools that show the two halves of a layer-2 attack:
first **map** a network, then understand how an attacker **poisons** it.

> **Authorised use only.** These tools operate on the local Ethernet segment.
> Only run them on a network you own or have written permission to test.

## Requirements

```bash
pip install scapy
```

Both tools send raw frames, so they need root:

```bash
sudo python3 netmapper.py ...
sudo python3 arpspoof.py ...
```

## netmapper.py — ARP host discovery

Broadcasts ARP requests across a subnet and lists every host that replies,
with its MAC address and (where known) hardware vendor. This is faster and
quieter than an ICMP/port sweep because every host on the segment must answer
ARP to function.

```bash
sudo python3 netmapper.py -r 192.168.0.0/24
sudo python3 netmapper.py -r 192.168.0.0/24 -i ens38 -o map.json
```

| Flag | Meaning |
|------|---------|
| `-r`, `--range` | Target network in CIDR (e.g. `192.168.0.0/24`) |
| `-i`, `--interface` | Interface to sweep (default: Scapy's route) |
| `-t`, `--timeout` | Seconds to wait for replies (default: 2) |
| `--oui` | Path to an IEEE `oui.txt` for full vendor names |
| `-o`, `--output` | Write results to a JSON file |

Vendor lookup uses a small built-in OUI table; point `--oui` at the IEEE
`oui.txt` to resolve every manufacturer.

## arpspoof.py — ARP cache poisoning (MITM)

Demonstrates how an attacker sits between a victim and the gateway by sending
forged ARP replies, so both sides send their traffic to the attacker instead.

**Dry-run by default** — it crafts and prints the poison packets but sends
nothing. This is the safe mode for demos and screenshots:

```bash
sudo python3 arpspoof.py -t 192.168.0.50 -g 192.168.0.1
```

To poison for real on a network you own, add `--live` (and `--forward` to
relay traffic so the victim keeps working — a true MITM):

```bash
sudo python3 arpspoof.py -t 192.168.0.50 -g 192.168.0.1 --live --forward
```

On `Ctrl+C` the tool sends correct ARP replies to **restore** both caches and
turns IP forwarding back off, leaving the network as it found it.

| Flag | Meaning |
|------|---------|
| `-t`, `--target` | Victim IP |
| `-g`, `--gateway` | Gateway IP |
| `-i`, `--interface` | Network interface |
| `--interval` | Seconds between spoof packets (default: 2) |
| `--live` | Actually transmit (omit for dry-run) |
| `--forward` | Enable kernel IP forwarding for a real MITM |

## Defensive takeaways

- **ARP has no authentication** — any host can claim any IP. That is the whole
  vulnerability; the fix is at higher layers.
- **Use static ARP entries** for critical hosts (gateway, servers).
- **Enable Dynamic ARP Inspection (DAI)** on managed switches to drop forged
  replies.
- **Encrypt in transit** — TLS/SSH mean a MITM sees ciphertext, not data.
- **Watch for duplicate-MAC / rapid ARP changes** — `arpwatch` and IDS rules
  flag exactly the packets `arpspoof.py --live` would send.
