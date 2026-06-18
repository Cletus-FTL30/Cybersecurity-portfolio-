import argparse
import json
import sys
from datetime import datetime

from scapy.all import ARP, Ether, srp, conf

# Minimal built-in OUI table (first 3 MAC octets -> vendor). A full IEEE
# oui.txt can be supplied with --oui to resolve every vendor.
BUILTIN_OUI = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "f4:f5:e8": "Google",
    "00:1b:63": "Apple",
    "ac:de:48": "Apple",
    "a4:5e:60": "Apple",
}


def load_oui(path):
    """Parse an IEEE oui.txt into a {prefix: vendor} dict, merged over builtins."""
    table = dict(BUILTIN_OUI)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if "(hex)" not in line:
                    continue
                raw, vendor = line.split("(hex)")
                prefix = raw.strip().replace("-", ":").lower()
                table[prefix] = vendor.strip()
    except OSError as exc:
        print(f"[!] Could not read OUI file {path}: {exc}", file=sys.stderr)
    return table


def vendor_for(mac, oui):
    return oui.get(mac.lower()[:8], "Unknown")


def scan(network, iface, timeout):
    """ARP-sweep a network and return discovered hosts as a list of dicts."""
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(request, iface=iface, timeout=timeout, verbose=False)

    hosts = []
    for _, reply in answered:
        hosts.append({"ip": reply.psrc, "mac": reply.hwsrc})
    hosts.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))
    return hosts


def print_table(hosts, oui):
    print(f"\n  {'IP Address':<16} {'MAC Address':<19} Vendor")
    print(f"  {'-' * 16} {'-' * 17} {'-' * 20}")
    for host in hosts:
        vendor = vendor_for(host["mac"], oui)
        host["vendor"] = vendor
        print(f"  {host['ip']:<16} {host['mac']:<19} {vendor}")
    print(f"\n[+] {len(hosts)} host(s) up.\n")


def save_json(hosts, network, path):
    report = {
        "scanned": datetime.now().isoformat(timespec="seconds"),
        "network": network,
        "host_count": len(hosts),
        "hosts": hosts,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] JSON report written to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="ARP-based network mapper: discover live hosts on a subnet."
    )
    parser.add_argument("-r", "--range", required=True,
                        help="Target network in CIDR, e.g. 192.168.0.0/24")
    parser.add_argument("-i", "--interface",
                        help="Network interface to use (default: Scapy's route)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Seconds to wait for replies (default: 2)")
    parser.add_argument("--oui", help="Path to an IEEE oui.txt for full vendor lookup")
    parser.add_argument("-o", "--output", help="Write results to a JSON file")
    args = parser.parse_args()

    oui = load_oui(args.oui) if args.oui else dict(BUILTIN_OUI)

    iface = args.interface or conf.iface
    print(f"[*] Sweeping {args.range} on {iface} ...")

    try:
        hosts = scan(args.range, args.interface, args.timeout)
    except PermissionError:
        print("[!] ARP sweeping needs root. Re-run with sudo.", file=sys.stderr)
        sys.exit(1)

    if not hosts:
        print("[!] No hosts answered. Check the range/interface.")
        return

    print_table(hosts, oui)
    if args.output:
        save_json(hosts, args.range, args.output)


if __name__ == "__main__":
    main()
