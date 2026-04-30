#!/usr/bin/env python3

import socket
import threading
import argparse
import json
import os
from datetime import datetime

# SERVICE MAP 

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}


# BANNER GRABBING 

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            if banner:
                return banner[:200]
    except Exception:
        pass
    return None


# SERVICE DETECTION 

def get_service(port):
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return KNOWN_SERVICES.get(port, "Unknown")


# REPORT: JSON 

def save_json(report, filepath):
    """
    json.dump() converts a Python dictionary into a JSON file.
    indent=4 makes it human-readable with nice spacing.
    """
    with open(filepath, "w") as f:
        json.dump(report, f, indent=4)

    print(f"  [+] JSON report saved : {filepath}")


#  REPORT: HTML 

def save_html(report, filepath):
    """
    Build an HTML page as a string, then write it to a file.
    The browser reads this file and displays a styled table.
    """

    # Build the table rows from scan results
    # We loop through results and create one <tr> (table row) per open port
    rows = ""
    for p in report["results"]:
        banner = p["banner"] or "-"
        rows += f"""
        <tr>
            <td>{p['port']}</td>
            <td><span class="badge">{p['state']}</span></td>
            <td>{p['service']}</td>
            <td class="banner">{banner}</td>
        </tr>"""

    # If no open ports found, show a message instead of an empty table
    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:#8b949e;">No open ports found</td></tr>'

    # The full HTML page — dark themed to look like a real security tool
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Scan Report - {report['target']}</title>
    <style>
        body      {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }}
        h1        {{ color: #58a6ff; margin-bottom: 5px; }}
        .meta     {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                     padding: 15px 20px; margin-bottom: 25px; display: flex; gap: 30px; flex-wrap: wrap; }}
        .meta div {{ font-size: 14px; }}
        .meta b   {{ color: #58a6ff; }}
        table     {{ width: 100%; border-collapse: collapse; background: #161b22;
                     border-radius: 6px; overflow: hidden; }}
        th        {{ background: #21262d; padding: 12px 16px; text-align: left;
                     color: #58a6ff; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }}
        td        {{ padding: 11px 16px; border-bottom: 1px solid #21262d; font-size: 14px; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td      {{ background: #21262d; }}
        .badge    {{ background: #1a4731; color: #3fb950; padding: 3px 12px;
                     border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .banner   {{ font-family: monospace; font-size: 12px; color: #8b949e; }}
    </style>
</head>
<body>
    <h1>Port Scan Report</h1>
    <div class="meta">
        <div><b>Target</b><br>{report['target']} ({report['ip']})</div>
        <div><b>Ports Scanned</b><br>{report['ports_scanned']}</div>
        <div><b>Open Ports</b><br>{len(report['results'])}</div>
        <div><b>Scan Started</b><br>{report['scan_start']}</div>
        <div><b>Duration</b><br>{report['duration_seconds']}s</div>
    </div>
    <table>
        <thead>
            <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""

    with open(filepath, "w") as f:
        f.write(html)

    print(f"  [+] HTML report saved : {filepath}")


# CLI 

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner",
        epilog="Examples:\n  python3 scanner.py 192.168.1.1\n  python3 scanner.py 192.168.1.1 -p 1-1024 --threads 200",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports",   default="1-1024",
                        help="Port range  e.g. 1-1024 or 80,443,8080  (default: 1-1024)")
    parser.add_argument("--threads",  type=int,   default=200,
                        help="Number of threads  (default: 200)")
    parser.add_argument("--timeout",  type=float, default=0.5,
                        help="Timeout per port in seconds  (default: 0.5)")
    parser.add_argument("--output",   choices=["json", "html", "both", "none"], default="both",
                        help="Report format: json, html, both, none  (default: both)")
    return parser.parse_args()


#  PORT RANGE PARSER 
def parse_ports(port_string):
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


# SCANNER

open_ports = []
lock = threading.Lock()

def scan_port(target, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    s.close()

    if result == 0:
        service = get_service(port)
        banner  = grab_banner(target, port)

        with lock:
            open_ports.append({
                "port":    port,
                "state":   "open",
                "service": service,
                "banner":  banner
            })


# MAIN 

def main():
    args       = parse_args()
    ports      = parse_ports(args.ports)
    scan_start = datetime.now()

    print(f"\n{'='*55}")
    print(f"  Target  : {args.target}")
    print(f"  Ports   : {len(ports)} ports")
    print(f"  Threads : {args.threads}")
    print(f"  Started : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    threads = []

    for port in ports:
        t = threading.Thread(target=scan_port, args=(args.target, port, args.timeout))
        threads.append(t)
        t.start()

        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    scan_end = datetime.now()
    duration = round((scan_end - scan_start).total_seconds(), 2)
    results  = sorted(open_ports, key=lambda x: x["port"])

    # Print results to terminal 
    print(f"  {'PORT':<8} {'STATE':<12} {'SERVICE':<15} BANNER")
    print(f"  {'-'*65}")

    if results:
        for p in results:
            banner = (p["banner"] or "-")[:40]
            print(f"  {p['port']:<8} {p['state']:<12} {p['service']:<15} {banner}")
    else:
        print("  No open ports found.")

    print(f"\n  Scan complete — {len(results)} open port(s) — {duration}s\n")

    #  Save reports 
    if args.output != "none":

        # Resolve hostname to IP for the report
        try:
            ip = socket.gethostbyname(args.target)
        except Exception:
            ip = args.target

        # Build the report dictionary — this becomes the JSON file
        report = {
            "target":           args.target,
            "ip":               ip,
            "ports_scanned":    len(ports),
            "scan_start":       scan_start.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end":         scan_end.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
            "results":          results
        }

        # Create the reports folder if it doesn't exist
        os.makedirs("reports", exist_ok=True)

        # Build a filename from the target + timestamp so reports don't overwrite each other
        # e.g. scan_127_0_0_1_20260428_105233
        timestamp   = scan_start.strftime("%Y%m%d_%H%M%S")
        safe_target = args.target.replace(".", "_").replace(":", "_")
        base        = os.path.join("reports", f"scan_{safe_target}_{timestamp}")

        if args.output in ("json", "both"):
            save_json(report, base + ".json")

        if args.output in ("html", "both"):
            save_html(report, base + ".html")

    print()


if __name__ == "__main__":
    main()
