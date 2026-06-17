# Password Auditor — Tools Version (Hashcat)

The same job the Python `auditor.py crack` command does — recover plaintext
passwords from hashes — using **Hashcat**, the industry-standard password
recovery tool. Hashcat takes a hash, picks the right algorithm by mode number,
and runs a dictionary or mask attack against it, the same workflow the
from-scratch tool implements by hand.

## Contents

| File | Description |
|------|-------------|
| [`hashcat_guide.md`](hashcat_guide.md) | Hashcat walkthrough — modes, dictionary attack, rules, mask/brute-force, cracking NTLM, reading the potfile |
| `hashes/` | Sample hash files split by algorithm (same hashes the Python tool uses) |
| `wordlist.txt` | Small demo wordlist (copy of the Python tool's sample list) |
| `screenshots/` | Screenshots from the Hashcat runs |

Hashcat maps cleanly onto the from-scratch tool: `auditor.py crack -w` is a
Hashcat dictionary attack (`-a 0`), and `auditor.py crack --brute` is a Hashcat
mask attack (`-a 3`). Where the Python tool hard-codes a few algorithms, Hashcat
supports hundreds, selected with `-m`.

> **Lab:** Cletus-lab (Ubuntu VM, `192.168.0.240`). All hashes here are of throwaway
> demo passwords I generated myself — no real credentials. Screenshots live in `screenshots/`.
