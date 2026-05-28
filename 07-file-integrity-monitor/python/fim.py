import os
import sys
import json
import fnmatch
import hashlib
import argparse
from datetime import datetime

# File Integrity Monitor
#
# Builds a cryptographic baseline of a directory tree (SHA-256 hash plus size,
# permissions and modification time for every file) and later checks the live
# tree against that baseline to flag tampering: files that were added, modified,
# deleted, or had their permissions changed. This is how host intrusion
# detection tools (Tripwire, AIDE, OSSEC) catch attackers dropping web shells,
# backdooring binaries or editing config behind your back.

CHUNK = 65536  # read files in 64 KB chunks so large files don't blow up memory


def log(msg):
    print(msg)


# Hashing and scanning

def hash_file(path, algorithm):
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def is_excluded(rel_path, patterns):
    return any(fnmatch.fnmatch(rel_path, pat) for pat in patterns)


def scan_directory(root, algorithm, excludes):
    """Walk root and return {relative_path: {hash, size, mode, mtime}}."""
    root = os.path.abspath(root)
    entries = {}
    errors = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories so we don't descend into them
        dirnames[:] = [
            d for d in dirnames
            if not is_excluded(os.path.relpath(os.path.join(dirpath, d), root), excludes)
        ]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if is_excluded(rel, excludes):
                continue
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            try:
                st = os.stat(full)
                entries[rel] = {
                    "hash": hash_file(full, algorithm),
                    "size": st.st_size,
                    "mode": oct(st.st_mode & 0o777),
                    "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                }
            except (OSError, PermissionError) as e:
                errors.append((rel, str(e)))

    return entries, errors


# Baseline

def create_baseline(args):
    excludes = list(args.exclude or [])
    # Never hash the baseline file itself if it lives inside the watched tree
    excludes.append(os.path.basename(args.baseline))

    log(f"[*] Building baseline of {os.path.abspath(args.directory)}")
    entries, errors = scan_directory(args.directory, args.algorithm, excludes)

    baseline = {
        "metadata": {
            "directory": os.path.abspath(args.directory),
            "algorithm": args.algorithm,
            "created": datetime.now().isoformat(timespec="seconds"),
            "file_count": len(entries),
            "excludes": excludes,
        },
        "files": entries,
    }

    with open(args.baseline, "w") as fh:
        json.dump(baseline, fh, indent=2, sort_keys=True)

    log(f"[+] Baseline written to {args.baseline}")
    log(f"[+] {len(entries)} file(s) recorded using {args.algorithm.upper()}")
    for rel, err in errors:
        log(f"[!] Skipped {rel}: {err}")


# Check

def compare(baseline, current):
    """Diff two {path: meta} maps into a list of change findings."""
    findings = []
    base_files, cur_files = baseline["files"], current

    base_set, cur_set = set(base_files), set(cur_files)

    for rel in sorted(cur_set - base_set):
        findings.append({
            "change": "Added",
            "severity": "High",
            "path": rel,
            "detail": f"New file not present in baseline ({cur_files[rel]['size']} bytes)",
        })

    for rel in sorted(base_set - cur_set):
        findings.append({
            "change": "Deleted",
            "severity": "High",
            "path": rel,
            "detail": "File in baseline is missing from the live tree",
        })

    for rel in sorted(base_set & cur_set):
        b, c = base_files[rel], cur_files[rel]
        if b["hash"] != c["hash"]:
            findings.append({
                "change": "Modified",
                "severity": "Critical",
                "path": rel,
                "detail": f"Contents changed — hash {b['hash'][:12]}… → {c['hash'][:12]}… "
                          f"(size {b['size']} → {c['size']} bytes)",
            })
        elif b["mode"] != c["mode"]:
            findings.append({
                "change": "Permissions Changed",
                "severity": "Medium",
                "path": rel,
                "detail": f"Mode changed {b['mode']} → {c['mode']} (contents unchanged)",
            })

    return findings


def run_check(args):
    if not os.path.exists(args.baseline):
        log(f"[!] Baseline file not found: {args.baseline}")
        log("    Run 'fim.py baseline' first to create one.")
        sys.exit(1)

    with open(args.baseline) as fh:
        baseline = json.load(fh)

    directory = args.directory or baseline["metadata"]["directory"]
    algorithm = baseline["metadata"].get("algorithm", "sha256")
    excludes = baseline["metadata"].get("excludes", [])

    log(f"[*] Checking {os.path.abspath(directory)} against {args.baseline}")
    current, errors = scan_directory(directory, algorithm, excludes)

    findings = compare(baseline, current)

    summary = {
        "directory": os.path.abspath(directory),
        "algorithm": algorithm.upper(),
        "baseline_files": baseline["metadata"]["file_count"],
        "current_files": len(current),
        "changes_detected": len(findings),
    }

    print_console(findings, summary, errors)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump({"summary": summary, "findings": findings}, fh, indent=2)
        log(f"[*] JSON report saved to {args.output}")

    if args.report:
        generate_html(findings, summary, args.report)

    # Non-zero exit when integrity is broken, so this can gate a cron job / CI
    sys.exit(1 if findings else 0)


# Reporting

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
CHANGE_ORDER = {"Modified": 0, "Added": 1, "Deleted": 2, "Permissions Changed": 3}


def print_console(findings, summary, errors):
    log("")
    log("=" * 64)
    log("  FILE INTEGRITY CHECK")
    log("=" * 64)
    for k, v in summary.items():
        log(f"  {k.replace('_', ' ').title():<20}: {v}")
    log("-" * 64)

    if not findings:
        log("  No changes detected — integrity intact.")
        log("=" * 64)
        for rel, err in errors:
            log(f"[!] Skipped {rel}: {err}")
        return

    findings.sort(key=lambda f: (CHANGE_ORDER.get(f["change"], 9), f["path"]))
    log(f"  {len(findings)} CHANGE(S) DETECTED:\n")
    for f in findings:
        log(f"  [{f['change'].upper()}]")
        log(f"      Path:     {f['path']}")
        log(f"      Severity: {f['severity']}")
        log(f"      {f['detail']}")
        log("")
    log("=" * 64)
    for rel, err in errors:
        log(f"[!] Skipped {rel}: {err}")


def generate_html(findings, summary, report_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = sorted(findings, key=lambda f: (CHANGE_ORDER.get(f["change"], 9), f["path"]))

    counts = {c: sum(1 for f in findings if f["change"] == c)
              for c in ("Modified", "Added", "Deleted", "Permissions Changed")}

    rows = ""
    for f in findings:
        cls = f["change"].split()[0].lower()  # modified / added / deleted / permissions
        rows += f"""
        <tr>
            <td><span class="badge badge-{cls}">{f['change']}</span></td>
            <td class="mono">{f['path']}</td>
            <td>{f['severity']}</td>
            <td>{f['detail']}</td>
        </tr>"""
    if not rows:
        rows = ('<tr><td colspan="4" style="text-align:center;color:#22c55e;">'
                'No changes detected — integrity intact.</td></tr>')

    meta_rows = "".join(
        f'<div class="meta-item"><div class="meta-label">{k.replace("_"," ").title()}</div>'
        f'<div class="meta-value">{v}</div></div>'
        for k, v in summary.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Integrity Report</title>
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
        .stat-card.modified .value    {{ color: #ef4444; }}
        .stat-card.added .value       {{ color: #f97316; }}
        .stat-card.deleted .value     {{ color: #f59e0b; }}
        .stat-card.total .value       {{ color: #3b82f6; }}
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
        .badge-modified    {{ background: #450a0a; color: #f87171; border: 1px solid #991b1b; }}
        .badge-added       {{ background: #431407; color: #fb923c; border: 1px solid #9a3412; }}
        .badge-deleted     {{ background: #451a03; color: #fbbf24; border: 1px solid #92400e; }}
        .badge-permissions {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #334155; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-icon">&#128737;</div>
        <div>
            <h1>File Integrity Report</h1>
            <p>Baseline vs. live tree &mdash; tamper detection</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card total"><div class="label">Total Changes</div><div class="value">{len(findings)}</div></div>
        <div class="stat-card modified"><div class="label">Modified</div><div class="value">{counts['Modified']}</div></div>
        <div class="stat-card added"><div class="label">Added</div><div class="value">{counts['Added']}</div></div>
        <div class="stat-card deleted"><div class="label">Deleted</div><div class="value">{counts['Deleted']}</div></div>
    </div>

    <div class="meta">{meta_rows}
        <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">{timestamp}</div></div>
    </div>

    <div class="table-wrapper">
        <div class="table-header">Detected Changes</div>
        <table>
            <thead><tr><th>Change</th><th>Path</th><th>Severity</th><th>Detail</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>

    <div class="footer">Generated by File Integrity Monitor &mdash; Cybersecurity Portfolio</div>
</div>
</body>
</html>"""

    with open(report_path, "w") as fh:
        fh.write(html)
    log(f"[*] HTML report saved to {report_path}")


# CLI

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — hash a directory tree and detect tampering")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-b", "--baseline", default="baseline.json",
                        help="Baseline file path (default: baseline.json)")

    p_base = sub.add_parser("baseline", parents=[common],
                            help="Create a baseline snapshot of a directory")
    p_base.add_argument("-d", "--directory", required=True, help="Directory to baseline")
    p_base.add_argument("-a", "--algorithm", default="sha256",
                        choices=["sha256", "sha1", "md5"], help="Hash algorithm (default: sha256)")
    p_base.add_argument("-x", "--exclude", action="append",
                        help="Glob pattern to exclude (repeatable, e.g. '*.log')")
    p_base.set_defaults(func=create_baseline)

    p_check = sub.add_parser("check", parents=[common],
                             help="Check a directory against an existing baseline")
    p_check.add_argument("-d", "--directory",
                         help="Directory to check (default: the one stored in the baseline)")
    p_check.add_argument("-o", "--output", help="Save findings to a JSON file")
    p_check.add_argument("-r", "--report", help="Save an HTML report (e.g. report.html)")
    p_check.set_defaults(func=run_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
