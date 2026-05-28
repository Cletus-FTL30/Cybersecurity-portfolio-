# File Integrity Monitor — Tools Version (AIDE)

The same job the Python `fim.py` does — baseline a directory tree and detect
tampering — using **AIDE** (Advanced Intrusion Detection Environment), the
standard host integrity monitor on Debian/Ubuntu and RHEL. AIDE builds a
database of file hashes and attributes, then reports anything that changed
against it.

## Contents

| File | Description |
|------|-------------|
| [`aide_guide.md`](aide_guide.md) | AIDE walkthrough — install, init the database, simulate tampering, run a check |
| `screenshots/` | Screenshots from the AIDE init and check runs |

AIDE maps cleanly onto the from-scratch tool: `aide --init` is `fim.py baseline`,
and `aide --check` is `fim.py check`.

> **Lab:** Cletus-lab (Ubuntu VM, `192.168.0.240`). All work is on a system I own.
> Screenshots live in `screenshots/`.
