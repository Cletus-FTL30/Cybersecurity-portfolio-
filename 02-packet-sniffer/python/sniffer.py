import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

log_file = None


def log(line):
    print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]
    src = ip.src
    dst = ip.dst
    ts = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        if args.protocol and args.protocol.upper() != "DNS":
            return
        query = packet[DNSQR].qname.decode().rstrip(".")
        log(f"[{ts}] [DNS]  {src} --> {dst}  |  Query: {query}")
    elif packet.haslayer(TCP):
        if args.protocol and args.protocol.upper() != "TCP":
            return
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        log(f"[{ts}] [TCP]  {src}:{sport} --> {dst}:{dport}")
    elif packet.haslayer(UDP):
        if args.protocol and args.protocol.upper() != "UDP":
            return
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        log(f"[{ts}] [UDP]  {src}:{sport} --> {dst}:{dport}")
    elif packet.haslayer(ICMP):
        if args.protocol and args.protocol.upper() != "ICMP":
            return
        log(f"[{ts}] [ICMP] {src} --> {dst}")
    else:
        if not args.protocol:
            log(f"[{ts}] [OTHER]{src} --> {dst}")


parser = argparse.ArgumentParser(description="Network Packet Sniffer")
parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0)")
parser.add_argument("-p", "--protocol", help="Filter by protocol: TCP, UDP, ICMP, DNS")
parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
parser.add_argument("-o", "--output", help="Save output to a log file (e.g. capture.log)")
args = parser.parse_args()

if args.output:
    log_file = open(args.output, "w")
else:
    log_file = None

print("Packet Sniffer started. Press Ctrl+C to stop.\n")
if args.interface:
    print(f"  Interface : {args.interface}")
if args.protocol:
    print(f"  Protocol  : {args.protocol.upper()}")
if args.count:
    print(f"  Count     : {args.count}")
if args.output:
    print(f"  Output    : {args.output}")
print()

try:
    sniff(iface=args.interface, prn=process_packet, store=False, count=args.count)
finally:
    if log_file:
        log_file.close()
        print(f"\nCapture saved to {args.output}")
