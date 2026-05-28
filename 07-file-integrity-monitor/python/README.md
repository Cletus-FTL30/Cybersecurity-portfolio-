# File Integrity Monitor (Python)

A host-based file integrity monitor that builds a cryptographic baseline of a
directory tree and later detects tampering — files that were **added**,
**modified**, **deleted**, or had their **permissions changed**. This is the
core idea behind host intrusion detection tools like Tripwire and AIDE: catch
an attacker dropping a web shell, backdooring a binary, or quietly editing a
config. Built from scratch with the Python standard library — no external
dependencies.

## How it works

1. **Baseline** — recursively walk a directory, compute a SHA-256 hash of every
   file along with its size, permissions and modification time, and save it all
   to a JSON baseline.
2. **Check** — re-scan the same tree and diff it against the baseline. Any
   difference is reported as a finding with a severity and exit code you can
   gate a cron job or CI step on.

## Features

- **SHA-256 baseline** (also `sha1` / `md5`) of an entire directory tree
- **Recursive monitoring** with glob-based exclusions (`*.log`, `cache/*`, …)
- **Four change types**
  - **Modified** (Critical) — file contents changed (hash mismatch)
  - **Added** (High) — file not present in the baseline
  - **Deleted** (High) — baseline file missing from the live tree
  - **Permissions Changed** (Medium) — mode changed, contents intact
- **Three outputs**: console summary, dark-themed **HTML report**, and **JSON**
- **Exit code 1 when changes are found** — drop it in `cron` and alert on failure
- Symlinks skipped; unreadable files reported, not fatal

## Usage

```bash
# 1. Create a baseline of a directory
python3 fim.py baseline -d samples/watched -b samples/baseline.json

# 2. Later, check the tree against that baseline
python3 fim.py check -d samples/watched -b samples/baseline.json

# Save HTML + JSON reports
python3 fim.py check -d samples/watched -b samples/baseline.json \
    -r reports/fim_report.html -o reports/fim.json

# Exclude noisy paths from the baseline (repeatable)
python3 fim.py baseline -d /etc -b /var/lib/fim/etc.json -x '*.log' -x '*.cache'

# Monitor a real system path on a schedule (cron)
0 * * * * /usr/bin/python3 /opt/fim/fim.py check -b /var/lib/fim/etc.json || \
    mail -s "FIM alert on $(hostname)" me@example.com < /dev/null
```

`check` reuses the directory, algorithm and exclusions stored in the baseline,
so `-d` is optional once a baseline exists.

### Commands & options

**`baseline`** — create a snapshot

| Flag | Description |
|------|-------------|
| `-d, --directory` | Directory to baseline (required) |
| `-b, --baseline` | Baseline output file (default: `baseline.json`) |
| `-a, --algorithm` | `sha256` (default), `sha1`, or `md5` |
| `-x, --exclude` | Glob pattern to skip (repeatable) |

**`check`** — compare against a baseline

| Flag | Description |
|------|-------------|
| `-b, --baseline` | Baseline file to compare against (default: `baseline.json`) |
| `-d, --directory` | Directory to check (default: the one stored in the baseline) |
| `-o, --output` | Save findings as JSON |
| `-r, --report` | Save an HTML report |

## Sample data & demo

`samples/watched/` is a small mock system tree (`etc/passwd`, `etc/sshd_config`,
`etc/hosts`, `bin/backup.sh`) to baseline and tamper with. Walk the full demo:

```bash
# 1. Baseline the pristine tree
python3 fim.py baseline -d samples/watched -b samples/baseline.json

# 2. Simulate a compromise
sed -i 's/PermitRootLogin no/PermitRootLogin yes/' samples/watched/etc/sshd_config
echo '<?php system($_GET["c"]); ?>' > samples/watched/etc/.shell.php
rm samples/watched/etc/hosts
chmod 777 samples/watched/bin/backup.sh

# 3. Detect the changes
python3 fim.py check -d samples/watched -b samples/baseline.json -r reports/fim_report.html
```

The check flags all four, one per change type:

- `etc/sshd_config` re-enables `PermitRootLogin` → **Modified (Critical)**
- web shell dropped at `etc/.shell.php` → **Added (High)**
- `etc/hosts` removed → **Deleted (High)**
- `bin/backup.sh` made world-writable → **Permissions Changed (Medium)**

```
  [MODIFIED]
      Path:     etc/sshd_config
      Severity: Critical
      Contents changed — hash d364daa2088d… → 244026f97866… (size 120 → 121 bytes)
```

> `samples/baseline.json` and `reports/` are gitignored — they're regenerable
> artifacts, and the baseline is host-specific (Git only preserves the
> executable bit, so commit a baseline and a clone could false-flag a
> permission change). Run the commands above to produce them locally.
