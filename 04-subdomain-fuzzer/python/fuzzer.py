import requests
import argparse
import threading
import os
from datetime import datetime

found = []
print_lock = threading.Lock()
log_file = None


def log(msg):
    with print_lock:
        print(msg)
        if log_file:
            log_file.write(msg + "\n")
            log_file.flush()


def fuzz_directory(target, word, extensions):
    paths = [word] + [f"{word}.{ext}" for ext in extensions]

    for path in paths:
        url = f"{target}/{path}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            code = response.status_code
            size = len(response.content)

            if code != 404:
                ts = datetime.now().strftime("%H:%M:%S")
                label = {200: "FOUND", 301: "REDIRECT", 302: "REDIRECT", 403: "FORBIDDEN"}.get(code, "OTHER")
                msg = f"[{ts}] [{code}] [{label}] {url}  ({size} bytes)"
                log(msg)
                with print_lock:
                    found.append({"url": url, "code": code, "label": label, "size": size})
        except requests.RequestException:
            pass


def run_fuzzer(target, wordlist, extensions, threads):
    target = target.rstrip("/")
    print(f"\n[*] Target    : {target}")
    print(f"[*] Wordlist  : {wordlist}")
    print(f"[*] Extensions: {extensions if extensions else 'none'}")
    print(f"[*] Threads   : {threads}")
    print(f"[*] Started   : {datetime.now().strftime('%H:%M:%S')}\n")

    with open(wordlist, "r", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    active = []
    for word in words:
        t = threading.Thread(target=fuzz_directory, args=(target, word, extensions))
        t.start()
        active.append(t)
        if len(active) >= threads:
            for t in active:
                t.join()
            active = []
    for t in active:
        t.join()

    print(f"\n[*] Finished. {len(found)} results found.")


def generate_report(target, report_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    found_count = sum(1 for i in found if i["label"] == "FOUND")
    redirect_count = sum(1 for i in found if i["label"] == "REDIRECT")
    forbidden_count = sum(1 for i in found if i["label"] == "FORBIDDEN")

    rows = ""
    for item in found:
        badge = {
            "FOUND":    '<span class="badge badge-found">200 FOUND</span>',
            "REDIRECT": '<span class="badge badge-redirect">301 REDIRECT</span>',
            "FORBIDDEN":'<span class="badge badge-forbidden">403 FORBIDDEN</span>',
        }.get(item["label"], f'<span class="badge badge-other">{item["code"]}</span>')

        rows += f"""
        <tr>
            <td><a href="{item['url']}" target="_blank">{item['url']}</a></td>
            <td>{badge}</td>
            <td>{item['size']:,} bytes</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fuzzer Report — {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0f1117;
            color: #e2e8f0;
            padding: 40px 20px;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}

        /* Header */
        .header {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #1e2530;
        }}
        .header-icon {{
            width: 48px; height: 48px;
            background: #3b82f6;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 24px;
        }}
        .header h1 {{ font-size: 24px; font-weight: 700; color: #f1f5f9; }}
        .header p {{ font-size: 13px; color: #64748b; margin-top: 4px; }}

        /* Stat cards */
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: #1a1f2e;
            border: 1px solid #1e2530;
            border-radius: 12px;
            padding: 20px;
        }}
        .stat-card .label {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-card .value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .stat-card.total .value  {{ color: #3b82f6; }}
        .stat-card.found .value   {{ color: #22c55e; }}
        .stat-card.redirect .value {{ color: #f59e0b; }}
        .stat-card.forbidden .value {{ color: #ef4444; }}

        /* Meta info */
        .meta {{
            background: #1a1f2e;
            border: 1px solid #1e2530;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 32px;
            display: flex;
            gap: 32px;
            flex-wrap: wrap;
        }}
        .meta-item .meta-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-item .meta-value {{ font-size: 14px; color: #cbd5e1; margin-top: 3px; font-family: monospace; }}

        /* Table */
        .table-wrapper {{
            background: #1a1f2e;
            border: 1px solid #1e2530;
            border-radius: 12px;
            overflow: hidden;
        }}
        .table-header {{
            padding: 16px 20px;
            border-bottom: 1px solid #1e2530;
            font-size: 14px;
            font-weight: 600;
            color: #94a3b8;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        thead th {{
            background: #151922;
            padding: 12px 20px;
            text-align: left;
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tbody td {{ padding: 14px 20px; border-bottom: 1px solid #1e2530; font-size: 14px; }}
        tbody tr:last-child td {{ border-bottom: none; }}
        tbody tr:hover {{ background: #1e2530; }}
        a {{ color: #60a5fa; text-decoration: none; font-family: monospace; font-size: 13px; }}
        a:hover {{ text-decoration: underline; }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            font-family: monospace;
        }}
        .badge-found    {{ background: #14532d; color: #4ade80; border: 1px solid #166534; }}
        .badge-redirect {{ background: #451a03; color: #fbbf24; border: 1px solid #92400e; }}
        .badge-forbidden{{ background: #450a0a; color: #f87171; border: 1px solid #991b1b; }}
        .badge-other    {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}

        .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #334155; }}
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <div class="header-icon">&#128269;</div>
        <div>
            <h1>Directory Fuzzer Report</h1>
            <p>Web content discovery scan results</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card total">
            <div class="label">Total Found</div>
            <div class="value">{len(found)}</div>
        </div>
        <div class="stat-card found">
            <div class="label">200 Found</div>
            <div class="value">{found_count}</div>
        </div>
        <div class="stat-card redirect">
            <div class="label">301 Redirect</div>
            <div class="value">{redirect_count}</div>
        </div>
        <div class="stat-card forbidden">
            <div class="label">403 Forbidden</div>
            <div class="value">{forbidden_count}</div>
        </div>
    </div>

    <div class="meta">
        <div class="meta-item">
            <div class="meta-label">Target</div>
            <div class="meta-value">{target}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Generated</div>
            <div class="meta-value">{timestamp}</div>
        </div>
    </div>

    <div class="table-wrapper">
        <div class="table-header">Discovered URLs</div>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Size</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <div class="footer">Generated by Directory Fuzzer &mdash; Cybersecurity Portfolio</div>
</div>
</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html)
    print(f"[*] HTML report saved to {report_path}")


parser = argparse.ArgumentParser(description="Directory Fuzzer with HTML Report")
parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. http://192.168.0.240)")
parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
parser.add_argument("-e", "--extensions", default="", help="File extensions to check (e.g. php,bak,txt)")
parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads (default: 10)")
parser.add_argument("-o", "--output", help="Save output to log file")
parser.add_argument("-r", "--report", help="Save HTML report (e.g. report.html)")
args = parser.parse_args()

if args.output:
    log_file = open(args.output, "w")

extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]

try:
    run_fuzzer(args.target, args.wordlist, extensions, args.threads)
finally:
    if log_file:
        log_file.close()
        print(f"[*] Results saved to {args.output}")

if args.report:
    generate_report(args.target, args.report)
