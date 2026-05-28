# File Integrity Monitor — Tools Version (AIDE & Tripwire)

The same job the Python `fim.py` does — baseline a directory tree and detect
tampering — using the two industry-standard host integrity tools on Linux:
**AIDE** and **Tripwire**. Both build a cryptographic database of the system's
files and report anything that changed against it.

## Contents

| File | Description |
|------|-------------|
| [`aide_guide.md`](aide_guide.md) | AIDE walkthrough — install, init the database, simulate tampering, run a check |
| [`tripwire_guide.md`](tripwire_guide.md) | Tripwire walkthrough — keys, policy, baseline DB, integrity check, reports |
| `screenshots/` | Screenshots from both tools' init and check runs |

## AIDE vs. Tripwire at a glance

| | AIDE | Tripwire |
|---|------|----------|
| Setup | `apt install aide` → `aideinit` | install → generate site/local keys → sign policy → init DB |
| Config | one `aide.conf`, rule macros per path | `twpol.txt` policy, compiled & signed to `tw.pol` |
| Database | plain (optionally signed) | cryptographically signed with the local key |
| Check | `aide --check` | `tripwire --check` (+ emailed reports) |
| Update baseline | `aide --update` | `tripwire --update` (signed) |
| Best for | quick, low-friction host monitoring | tamper-evident baselines where the DB itself must be trusted |

Both map cleanly onto the from-scratch tool: `aideinit` / `tripwire --init` is
`fim.py baseline`, and `aide --check` / `tripwire --check` is `fim.py check`.

> **Lab:** Cletus-lab (Ubuntu VM, `192.168.0.240`). All work is on a system I own.
> Screenshots live in `screenshots/`.
