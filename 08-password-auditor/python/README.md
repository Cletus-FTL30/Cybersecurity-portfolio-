# Password Auditor — Python

A stdlib-only password security tool with three modes: **identify** hash types, **crack** weak hashes (dictionary or brute-force), and **score** plaintext password strength.

Built as a portfolio piece to demonstrate password security fundamentals: hash recognition, attack techniques, entropy math, and policy auditing.

## Features

- **Hash identification** — auto-detects MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, and Unix crypt variants (md5_crypt, sha256_crypt, sha512_crypt) from format and length
- **Cracking engine** — dictionary attack against a wordlist, or brute-force with a configurable charset and length range
- **NTLM support** — pure-Python MD4 implementation (OpenSSL 3 disables MD4 by default), verified against RFC 1320 test vectors
- **Password strength scoring** — Shannon entropy, character-class diversity, common-password check, pattern detection (sequential / keyboard / repeated chars), 0–100 score with rating
- **Reports** — console output plus optional HTML and JSON reports
- **Zero dependencies** — Python 3 stdlib only

## Usage

### Identify a hash

```bash
# Single hash
python3 auditor.py identify 5f4dcc3b5aa765d61d8327deb882cf99

# A file of hashes (one per line)
python3 auditor.py identify samples/hashes.txt

# From stdin
echo "5f4dcc3b5aa765d61d8327deb882cf99" | python3 auditor.py identify -
```

### Crack a hash

```bash
# Dictionary attack (default)
python3 auditor.py crack samples/hashes.txt -w samples/wordlist.txt

# Force a specific algorithm (for ambiguous lengths — MD5 vs NTLM both 32 hex)
python3 auditor.py crack 5835048ce94ad0564e29a924a03510ef --type ntlm -w samples/wordlist.txt

# Brute force (lowercase + digits, length 1–4)
python3 auditor.py crack 900150983cd24fb0d6963f7d28e17f72 --brute --maxlen 3

# Generate HTML + JSON reports
python3 auditor.py crack samples/hashes.txt -w samples/wordlist.txt --html --json -o reports
```

### Score password strength

```bash
# A single password
python3 auditor.py score 'P@ssw0rd'

# A list of passwords
python3 auditor.py score samples/passwords.txt

# With reports
python3 auditor.py score samples/passwords.txt --html --json -o reports
```

## Sample data

`samples/` ships with:
- **`hashes.txt`** — 11 hashes covering MD5, SHA-1, SHA-256, SHA-512, NTLM, and bcrypt. Most crack against the wordlist; one is intentionally uncrackable.
- **`wordlist.txt`** — 30 of the most-leaked passwords from public dumps.
- **`passwords.txt`** — 12 plaintext passwords ranging from "password" to a 16-char high-entropy string, for the scoring demo.

Reports are written to `reports/` and **not committed** (`.gitignore` covers `*.json`, `*.html`, `**/reports/`).

## Scoring rubric

| Component | Max | Notes |
|---|---|---|
| Length ≥ 8 / 12 / 16 | 15 / 15 / 10 | Stacked |
| Lowercase / Uppercase / Digit / Symbol | 10 / 10 / 10 / 15 | One each |
| Shannon entropy ≥ 3.0 bits/char | 15 | Penalises low variety |
| **Penalties** | | |
| Length < 8 chars | −30 | |
| Listed in common-password set | −50 | |
| Digits only | −20 | |
| Repeated chars (3+ in a row) | −10 | `aaa`, `111` |
| Sequential / keyboard pattern | −10 | `abc`, `123`, `qwe` |

Ratings: 85+ Very Strong, 65+ Strong, 45+ Fair, 25+ Weak, else Very Weak. Score is clamped to 0–100.

## Why bcrypt isn't cracked here

The tool **detects** bcrypt (`$2a$/$2b$/$2y$`) and Unix crypt variants but doesn't crack them. They're deliberately slow KDFs with embedded salts — cracking them in pure Python without `bcrypt`/`passlib` would be a single-thread crawl that misrepresents real-world attack throughput. For bcrypt cracking, see the [Hashcat walkthrough](../tools/hashcat_guide.md) which uses GPU-accelerated attacks.

## Files

```
python/
├── auditor.py          # main tool (~350 lines, stdlib only)
├── README.md           # this file
└── samples/
    ├── hashes.txt      # mixed hash dump
    ├── wordlist.txt    # 30-entry custom wordlist
    └── passwords.txt   # plaintext for scoring demo
```

## Disclaimer

Built for authorised security testing, capture-the-flag practice, and password-policy auditing on systems you own or have permission to assess. Don't crack other people's hashes.
