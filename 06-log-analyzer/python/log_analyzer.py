import re
import json
import argparse
from datetime import datetime
from collections import defaultdict

# Log Analyzer — multi-format security log analysis
#
# Auto-detects Linux SSH auth logs (/var/log/auth.log) and web server access
# logs (Apache/Nginx combined format), parses every line, and flags suspicious
# activity: SSH brute force, scanning, SQLi/XSS probes, path traversal,
# malicious scanner user agents and sensitive-file access.

# Regex patterns

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"

AUTH_FAILED   = re.compile(r"Failed password for (invalid user )?(\S+) from " + IP)
AUTH_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from " + IP)
AUTH_INVALID  = re.compile(r"Invalid user (\S+) from " + IP)

# Apache/Nginx combined log format
WEB_LINE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
)

# Attack signatures (web)

SQLI_SIG = re.compile(
    r"(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|--\s|/\*|\bor\b\s+\d+=\d+|sleep\(|benchmark\(|information_schema)",
    re.IGNORECASE,
)
XSS_SIG = re.compile(
    r"(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src|alert\()",
    re.IGNORECASE,
)
TRAVERSAL_SIG = re.compile(r"(\.\./|\.\.\\|/etc/passwd|c:\\windows|%2e%2e%2f|/proc/self)", re.IGNORECASE)

BAD_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|ffuf|wpscan|acunetix|nessus|hydra|metasploit|havij|fimap|netsparker|w3af)",
    re.IGNORECASE,
)
SENSITIVE_PATHS = re.compile(
    r"(/\.env|/\.git|config\.bak|/wp-admin|/wp-login|phpmyadmin|/\.aws|/\.ssh|backup\.(sql|zip|tar)|/admin\b)",
    re.IGNORECASE,
)


def log(msg):
    print(msg)


# Format detection

def detect_format(lines):
    """Sample the first lines to decide between 'auth' and 'web'."""
    for line in lines[:50]:
        if WEB_LINE.match(line):
            return "web"
        if "sshd[" in line or AUTH_FAILED.search(line) or AUTH_ACCEPTED.search(line):
            return "auth"
    return "web" if any(WEB_LINE.match(l) for l in lines[:200]) else "auth"


# Auth log analysis

def analyse_auth(lines, threshold):
    failed = defaultdict(list)        # ip -> [usernames]
    accepted = []                     # (user, ip)
    invalid_users = defaultdict(set)  # ip -> {users}
    total_failed = 0

    for line in lines:
        m = AUTH_FAILED.search(line)
        if m:
            total_failed += 1
            failed[m.group(3)].append(m.group(2))
            continue
        m = AUTH_ACCEPTED.search(line)
        if m:
            accepted.append((m.group(1), m.group(2)))
            continue
        m = AUTH_INVALID.search(line)
        if m:
            invalid_users[m.group(2)].add(m.group(1))

    findings = []

    # Brute-force sources
    for ip, users in sorted(failed.items(), key=lambda kv: len(kv[1]), reverse=True):
        count = len(users)
        if count >= threshold:
            sev = "Critical" if count >= threshold * 3 else "High"
            findings.append({
                "type": "SSH Brute Force",
                "severity": sev,
                "source": ip,
                "detail": f"{count} failed login attempts targeting {len(set(users))} username(s): "
                          f"{', '.join(sorted(set(users))[:5])}",
                "count": count,
            })

    # Successful login from an IP that also brute-forced (possible compromise)
    for user, ip in accepted:
        if ip in failed and len(failed[ip]) >= threshold:
            findings.append({
                "type": "Successful Login After Brute Force",
                "severity": "Critical",
                "source": ip,
                "detail": f"Account '{user}' authenticated from {ip} after {len(failed[ip])} "
                          f"failed attempts — possible account compromise",
                "count": 1,
            })

    # Probing for nonexistent / privileged accounts
    for ip, users in invalid_users.items():
        if len(users) >= max(3, threshold // 2):
            findings.append({
                "type": "Username Enumeration",
                "severity": "Medium",
                "source": ip,
                "detail": f"Attempts against {len(users)} invalid usernames: "
                          f"{', '.join(sorted(users)[:8])}",
                "count": len(users),
            })

    summary = {
        "format": "SSH auth log",
        "total_lines": len(lines),
        "total_failed": total_failed,
        "total_accepted": len(accepted),
        "unique_attacker_ips": len([ip for ip, u in failed.items() if len(u) >= threshold]),
    }
    return findings, summary


# Web log analysis

def analyse_web(lines, threshold):
    parsed = []
    for line in lines:
        m = WEB_LINE.match(line)
        if m:
            parsed.append({
                "ip": m.group(1), "method": m.group(3), "path": m.group(4),
                "status": int(m.group(5)), "agent": m.group(8),
            })

    findings = []
    not_found = defaultdict(int)   # ip -> count of 404s
    seen = set()                   # de-dupe (ip, type)

    def add(ftype, sev, ip, detail):
        key = (ftype, ip)
        if key in seen:
            return
        seen.add(key)
        findings.append({"type": ftype, "severity": sev, "source": ip,
                         "detail": detail, "count": 1})

    for r in parsed:
        path, ip, agent = r["path"], r["ip"], r["agent"]

        if r["status"] == 404:
            not_found[ip] += 1

        if SQLI_SIG.search(path):
            add("SQL Injection Attempt", "Critical", ip, f"Malicious payload in request: {path[:120]}")
        if XSS_SIG.search(path):
            add("Cross-Site Scripting (XSS) Attempt", "High", ip, f"Script payload in request: {path[:120]}")
        if TRAVERSAL_SIG.search(path):
            add("Path Traversal Attempt", "High", ip, f"Traversal sequence in request: {path[:120]}")
        if BAD_AGENTS.search(agent):
            add("Malicious Scanner", "High", ip, f"Known attack tool user-agent: {agent[:120]}")
        if SENSITIVE_PATHS.search(path):
            add("Sensitive File Access", "Medium", ip, f"Request for sensitive resource: {path[:120]}")

    # Directory/content scanning — many 404s from one IP
    for ip, count in sorted(not_found.items(), key=lambda kv: kv[1], reverse=True):
        if count >= threshold:
            sev = "High" if count >= threshold * 2 else "Medium"
            add("Directory / Content Scanning", sev, ip,
                f"{count} requests resulted in 404 Not Found — likely automated content discovery")

    summary = {
        "format": "Web access log",
        "total_lines": len(lines),
        "total_requests": len(parsed),
        "total_404": sum(not_found.values()),
        "unique_source_ips": len({r["ip"] for r in parsed}),
    }
    return findings, summary


# Reporting

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def print_console(findings, summary):
    log("")
    log("=" * 64)
    log(f"  LOG ANALYSIS — {summary['format']}")
    log("=" * 64)
    for k, v in summary.items():
        if k == "format":
            continue
        log(f"  {k.replace('_', ' ').title():<24}: {v}")
    log("-" * 64)

    if not findings:
        log("  No suspicious activity detected.")
        log("=" * 64)
        return

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    log(f"  {len(findings)} FINDING(S):\n")
    for f in findings:
        log(f"  [{f['severity'].upper():<8}] {f['type']}")
        log(f"             Source: {f['source']}")
        log(f"             {f['detail']}")
        log("")
    log("=" * 64)


def generate_report(findings, summary, report_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("Critical", "High", "Medium", "Low")}

    rows = ""
    for f in findings:
        sev = f["severity"].lower()
        rows += f"""
        <tr>
            <td><span class="badge badge-{sev}">{f['severity']}</span></td>
            <td>{f['type']}</td>
            <td class="mono">{f['source']}</td>
            <td>{f['detail']}</td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:#22c55e;">No suspicious activity detected.</td></tr>'

    meta_rows = "".join(
        f'<div class="meta-item"><div class="meta-label">{k.replace("_"," ").title()}</div>'
        f'<div class="meta-value">{v}</div></div>'
        for k, v in summary.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Log Analysis Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 40px 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #1e2530; }}
        .header-icon {{ width: 48px; height: 48px; background: #3b82f6; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }}
        .header h1 {{ font-size: 24px; font-weight: 700; color: #f1f5f9; }}
        .header p {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .stat-card {{ background: #1a1f2e; border: 1px solid #1e2530; border-radius: 12px; padding: 20px; }}
        .stat-card .label {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-card .value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .stat-card.critical .value {{ color: #ef4444; }}
        .stat-card.high .value     {{ color: #f97316; }}
        .stat-card.medium .value   {{ color: #f59e0b; }}
        .stat-card.total .value    {{ color: #3b82f6; }}
        .meta {{ background: #1a1f2e; border: 1px solid #1e2530; border-radius: 12px; padding: 16px 20px; margin-bottom: 32px; display: flex; gap: 32px; flex-wrap: wrap; }}
        .meta-item .meta-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-item .meta-value {{ font-size: 14px; color: #cbd5e1; margin-top: 3px; font-family: monospace; }}
        .table-wrapper {{ background: #1a1f2e; border: 1px solid #1e2530; border-radius: 12px; overflow: hidden; }}
        .table-header {{ padding: 16px 20px; border-bottom: 1px solid #1e2530; font-size: 14px; font-weight: 600; color: #94a3b8; }}
        table {{ width: 100%; border-collapse: collapse; }}
        thead th {{ background: #151922; padding: 12px 20px; text-align: left; font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
        tbody td {{ padding: 14px 20px; border-bottom: 1px solid #1e2530; font-size: 14px; vertical-align: top; }}
        tbody tr:last-child td {{ border-bottom: none; }}
        tbody tr:hover {{ background: #1e2530; }}
        .mono {{ font-family: monospace; color: #60a5fa; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
        .badge-critical {{ background: #450a0a; color: #f87171; border: 1px solid #991b1b; }}
        .badge-high     {{ background: #431407; color: #fb923c; border: 1px solid #9a3412; }}
        .badge-medium   {{ background: #451a03; color: #fbbf24; border: 1px solid #92400e; }}
        .badge-low      {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #334155; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-icon">&#128220;</div>
        <div>
            <h1>Log Analysis Report</h1>
            <p>{summary['format']} &mdash; security event analysis</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card total"><div class="label">Total Findings</div><div class="value">{len(findings)}</div></div>
        <div class="stat-card critical"><div class="label">Critical</div><div class="value">{counts['Critical']}</div></div>
        <div class="stat-card high"><div class="label">High</div><div class="value">{counts['High']}</div></div>
        <div class="stat-card medium"><div class="label">Medium</div><div class="value">{counts['Medium']}</div></div>
    </div>

    <div class="meta">{meta_rows}
        <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">{timestamp}</div></div>
    </div>

    <div class="table-wrapper">
        <div class="table-header">Detected Security Events</div>
        <table>
            <thead><tr><th>Severity</th><th>Type</th><th>Source</th><th>Detail</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>

    <div class="footer">Generated by Log Analyzer &mdash; Cybersecurity Portfolio</div>
</div>
</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html)
    log(f"[*] HTML report saved to {report_path}")


# CLI

def main():
    parser = argparse.ArgumentParser(description="Multi-format security Log Analyzer")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file")
    parser.add_argument("-t", "--type", choices=["auto", "auth", "web"], default="auto",
                        help="Log type (default: auto-detect)")
    parser.add_argument("-n", "--threshold", type=int, default=10,
                        help="Failed-attempt / 404 threshold for flagging an IP (default: 10)")
    parser.add_argument("-o", "--output", help="Save findings to a JSON file")
    parser.add_argument("-r", "--report", help="Save HTML report (e.g. report.html)")
    args = parser.parse_args()

    with open(args.file, "r", errors="ignore") as fh:
        lines = [ln.rstrip("\n") for ln in fh if ln.strip()]

    fmt = args.type if args.type != "auto" else detect_format(lines)
    log(f"[*] Analysing {args.file}")
    log(f"[*] Detected format: {fmt}" if args.type == "auto" else f"[*] Format: {fmt}")

    if fmt == "auth":
        findings, summary = analyse_auth(lines, args.threshold)
    else:
        findings, summary = analyse_web(lines, args.threshold)

    print_console(findings, summary)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump({"summary": summary, "findings": findings}, fh, indent=2)
        log(f"[*] JSON findings saved to {args.output}")

    if args.report:
        generate_report(findings, summary, args.report)


if __name__ == "__main__":
    main()
