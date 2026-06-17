#!/usr/bin/env python3
"""Password Auditor — identify hashes, crack weak ones, score password strength.

Three subcommands:
  identify  Detect hash type from format / length
  crack     Dictionary or brute-force attack against a hash or hash file
  score     Rate plaintext password strength (entropy + policy checks)

Stdlib only. Supports MD5, SHA-1, SHA-256, SHA-512, NTLM for cracking;
detects bcrypt, sha512_crypt, sha256_crypt, md5_crypt by format.
"""

import argparse
import hashlib
import html
import itertools
import json
import math
import re
import string
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path


HASH_SPECS = [
    # name, regex, hashlib-name or special, cracking supported?
    ("bcrypt",        re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),       None,       False),
    ("sha512_crypt",  re.compile(r"^\$6\$[^\$]{1,16}\$[./A-Za-z0-9]{86}$"),      None,       False),
    ("sha256_crypt",  re.compile(r"^\$5\$[^\$]{1,16}\$[./A-Za-z0-9]{43}$"),      None,       False),
    ("md5_crypt",     re.compile(r"^\$1\$[^\$]{1,8}\$[./A-Za-z0-9]{22}$"),       None,       False),
    ("sha512",        re.compile(r"^[a-fA-F0-9]{128}$"),                          "sha512",   True),
    ("sha256",        re.compile(r"^[a-fA-F0-9]{64}$"),                           "sha256",   True),
    ("sha1",          re.compile(r"^[a-fA-F0-9]{40}$"),                           "sha1",     True),
    # md5 and ntlm share length 32 — md5 returned first; user can pass --type ntlm
    ("md5",           re.compile(r"^[a-fA-F0-9]{32}$"),                           "md5",      True),
    ("ntlm",          re.compile(r"^[a-fA-F0-9]{32}$"),                           "ntlm",     True),
]

# Small built-in list of overused passwords (top of every leaked dump).
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "111111", "abc123",
    "password1", "iloveyou", "admin", "welcome", "monkey", "letmein",
    "dragon", "master", "login", "princess", "qwerty123", "sunshine",
    "passw0rd", "p@ssw0rd", "p@ssword", "1q2w3e4r", "qwertyuiop",
}


def hash_plaintext(plaintext: str, algo: str) -> str:
    """Return the lowercase hex digest of plaintext under the given algorithm."""
    if algo == "ntlm":
        return md4(plaintext.encode("utf-16-le")).hex()
    return hashlib.new(algo, plaintext.encode("utf-8")).hexdigest()


def md4(message: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320) — OpenSSL 3 disables MD4 by default, and NTLM needs it."""
    mask = 0xFFFFFFFF
    def lrot(x, n): return ((x << n) | (x >> (32 - n))) & mask

    orig_len = len(message)
    msg = message + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64)
    msg += (orig_len * 8).to_bytes(8, "little")

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(msg), 64):
        X = [int.from_bytes(msg[i + 4 * j:i + 4 * j + 4], "little") for j in range(16)]
        a, b, c, d = A, B, C, D
        # Round 1: F(x,y,z) = (x & y) | (~x & z)
        for k, s in zip([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                        [3, 7, 11, 19] * 4):
            f = (b & c) | (~b & mask & d)
            a, d, c, b = d, c, b, lrot((a + f + X[k]) & mask, s)
        # Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z), +constant 0x5A827999
        for k, s in zip([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
                        [3, 5, 9, 13] * 4):
            g = (b & c) | (b & d) | (c & d)
            a, d, c, b = d, c, b, lrot((a + g + X[k] + 0x5A827999) & mask, s)
        # Round 3: H(x,y,z) = x ^ y ^ z, +constant 0x6ED9EBA1
        for k, s in zip([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
                        [3, 9, 11, 15] * 4):
            h = b ^ c ^ d
            a, d, c, b = d, c, b, lrot((a + h + X[k] + 0x6ED9EBA1) & mask, s)
        A, B, C, D = (A + a) & mask, (B + b) & mask, (C + c) & mask, (D + d) & mask

    return b"".join(x.to_bytes(4, "little") for x in (A, B, C, D))


def identify_hash(h: str) -> list[str]:
    """Return all hash types whose format matches h. Most specific first."""
    matches = []
    for name, pattern, _, _ in HASH_SPECS:
        if pattern.match(h):
            matches.append(name)
    return matches


def cmd_identify(args: argparse.Namespace) -> int:
    hashes = read_hash_input(args.target)
    if not hashes:
        print("[!] No hashes found in input", file=sys.stderr)
        return 1

    print(f"[*] Identifying {len(hashes)} hash(es)\n")
    for h in hashes:
        matches = identify_hash(h)
        if not matches:
            print(f"  {short(h):<70}  UNKNOWN")
            continue
        primary = matches[0]
        extra = f"  (also matches: {', '.join(matches[1:])})" if len(matches) > 1 else ""
        print(f"  {short(h):<70}  {primary}{extra}")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    hashes = read_hash_input(args.target)
    if not hashes:
        print("[!] No hashes found in input", file=sys.stderr)
        return 1

    results = []
    for h in hashes:
        algo = args.type or pick_crackable_type(h)
        if not algo:
            results.append({"hash": h, "type": None, "plaintext": None,
                            "status": "unsupported", "elapsed_s": 0.0, "attempts": 0})
            print(f"[-] {short(h)} — no crackable type detected (use --type)")
            continue

        print(f"[*] Cracking {short(h)} as {algo} ...")
        start = time.time()
        if args.brute:
            plaintext, attempts = brute_force(h, algo, args.charset, args.minlen, args.maxlen)
        else:
            plaintext, attempts = dictionary_attack(h, algo, Path(args.wordlist))
        elapsed = time.time() - start

        if plaintext is not None:
            print(f"[+] CRACKED  {short(h)}  =>  {plaintext}   ({attempts} attempts, {elapsed:.2f}s)")
            status = "cracked"
        else:
            print(f"[-] NOT FOUND  {short(h)}   ({attempts} attempts, {elapsed:.2f}s)")
            status = "not_found"

        results.append({"hash": h, "type": algo, "plaintext": plaintext,
                        "status": status, "elapsed_s": round(elapsed, 3), "attempts": attempts})

    write_reports(args, "crack", results)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    if args.target == "-" or Path(args.target).exists():
        passwords = read_lines(args.target)
    else:
        passwords = [args.target]
    if not passwords:
        print("[!] No passwords found", file=sys.stderr)
        return 1

    print(f"[*] Scoring {len(passwords)} password(s)\n")
    results = []
    for pw in passwords:
        s = score_password(pw)
        results.append({"password": pw, **s})
        print(f"  {pw!r:<30} score={s['score']:>3}/100  {s['rating']:<12}  entropy={s['entropy_bits']:.1f} bits")
        if s["issues"]:
            for issue in s["issues"]:
                print(f"      - {issue}")

    write_reports(args, "score", results)
    return 0


def dictionary_attack(target: str, algo: str, wordlist: Path) -> tuple[str | None, int]:
    """Try each line of the wordlist; return (plaintext, attempts) or (None, attempts)."""
    target = target.lower()
    attempts = 0
    if not wordlist.exists():
        print(f"[!] Wordlist not found: {wordlist}", file=sys.stderr)
        return None, 0
    with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            attempts += 1
            if hash_plaintext(candidate, algo) == target:
                return candidate, attempts
    return None, attempts


def brute_force(target: str, algo: str, charset: str, minlen: int, maxlen: int) -> tuple[str | None, int]:
    """Iterate every combination of charset from minlen..maxlen. Returns (plaintext, attempts)."""
    target = target.lower()
    attempts = 0
    for length in range(minlen, maxlen + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if hash_plaintext(candidate, algo) == target:
                return candidate, attempts
    return None, attempts


def score_password(pw: str) -> dict:
    """Return a strength report: score 0-100, rating, entropy bits, and issues."""
    issues = []
    length = len(pw)

    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(c in string.punctuation for c in pw): pool += len(string.punctuation)
    pool = pool or 1
    entropy_bits = length * math.log2(pool)

    score = 0
    if length >= 8:  score += 15
    if length >= 12: score += 15
    if length >= 16: score += 10
    if any(c.islower() for c in pw): score += 10
    if any(c.isupper() for c in pw): score += 10
    if any(c.isdigit() for c in pw): score += 10
    if any(c in string.punctuation for c in pw): score += 15
    if shannon_entropy(pw) >= 3.0: score += 15

    if length < 8:
        issues.append("too short (< 8 chars)")
        score -= 30
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("appears in common-password list")
        score -= 50
    if pw.isalpha():
        issues.append("letters only — no digits or symbols")
    if pw.isdigit():
        issues.append("digits only")
        score -= 20
    if re.search(r"(.)\1{2,}", pw):
        issues.append("contains 3+ repeated characters in a row")
        score -= 10
    if re.search(r"(abc|bcd|cde|def|123|234|345|456|567|678|789|qwe|wer|ert|rty|asd)", pw.lower()):
        issues.append("contains a sequential or keyboard pattern")
        score -= 10

    score = max(0, min(100, score))
    if   score >= 85: rating = "Very Strong"
    elif score >= 65: rating = "Strong"
    elif score >= 45: rating = "Fair"
    elif score >= 25: rating = "Weak"
    else:             rating = "Very Weak"

    return {
        "length": length,
        "entropy_bits": round(entropy_bits, 2),
        "score": score,
        "rating": rating,
        "issues": issues,
    }


def shannon_entropy(s: str) -> float:
    """Per-character Shannon entropy — measures variety, not strength."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def pick_crackable_type(h: str) -> str | None:
    """Return the first crackable algo name that matches h's format."""
    for name, pattern, algo, crackable in HASH_SPECS:
        if crackable and pattern.match(h):
            return name
    return None


def read_hash_input(target: str) -> list[str]:
    """Accept a single hash on the CLI, a path to a file, or '-' for stdin."""
    if target == "-":
        return [l.strip() for l in sys.stdin if l.strip()]
    p = Path(target)
    if p.exists():
        return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    return [target.strip()]


def read_lines(target: str) -> list[str]:
    if target == "-":
        return [l.rstrip("\r\n") for l in sys.stdin if l.strip()]
    p = Path(target)
    return [l.rstrip("\r\n") for l in p.read_text().splitlines() if l.strip()]


def short(h: str, n: int = 60) -> str:
    return h if len(h) <= n else h[: n - 3] + "..."


def write_reports(args: argparse.Namespace, kind: str, results: list[dict]) -> None:
    if not (args.json or args.html):
        return
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    payload = {
        "tool": "password-auditor",
        "command": kind,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "results": results,
    }
    if args.json:
        path = out_dir / f"{kind}-{ts}.json"
        path.write_text(json.dumps(payload, indent=2))
        print(f"[+] JSON report: {path}")
    if args.html:
        path = out_dir / f"{kind}-{ts}.html"
        path.write_text(render_html(kind, payload))
        print(f"[+] HTML report: {path}")


def render_html(kind: str, payload: dict) -> str:
    rows = []
    if kind == "crack":
        for r in payload["results"]:
            badge = badge_html(r["status"])
            rows.append(
                f"<tr><td><code>{html.escape(short(r['hash'], 80))}</code></td>"
                f"<td>{html.escape(r['type'] or '-')}</td>"
                f"<td>{html.escape(r['plaintext'] or '-')}</td>"
                f"<td>{badge}</td>"
                f"<td>{r['attempts']:,}</td>"
                f"<td>{r['elapsed_s']:.2f}s</td></tr>"
            )
        headers = "<th>Hash</th><th>Type</th><th>Plaintext</th><th>Status</th><th>Attempts</th><th>Time</th>"
    else:
        for r in payload["results"]:
            issues = "<br>".join(html.escape(i) for i in r["issues"]) or "-"
            rows.append(
                f"<tr><td><code>{html.escape(r['password'])}</code></td>"
                f"<td>{r['length']}</td>"
                f"<td>{r['entropy_bits']:.1f}</td>"
                f"<td>{r['score']}</td>"
                f"<td>{rating_badge(r['rating'])}</td>"
                f"<td>{issues}</td></tr>"
            )
        headers = "<th>Password</th><th>Length</th><th>Entropy (bits)</th><th>Score</th><th>Rating</th><th>Issues</th>"

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Password Auditor — {kind}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;color:#222}}
h1{{border-bottom:2px solid #333;padding-bottom:.3rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem;vertical-align:top}}
th{{background:#f4f4f4}}
code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.85rem}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:3px;color:#fff;font-size:.8rem;font-weight:600}}
.b-cracked,.b-very-strong{{background:#16a34a}}
.b-strong{{background:#65a30d}}
.b-fair{{background:#eab308;color:#000}}
.b-weak,.b-not_found{{background:#f97316}}
.b-very-weak,.b-unsupported{{background:#dc2626}}
</style></head><body>
<h1>Password Auditor — {kind}</h1>
<p><b>Generated:</b> {payload['generated_at']} &nbsp; <b>Results:</b> {len(payload['results'])}</p>
<table><thead><tr>{headers}</tr></thead><tbody>
{''.join(rows)}
</tbody></table></body></html>"""


def badge_html(status: str) -> str:
    return f'<span class="badge b-{status}">{status}</span>'


def rating_badge(rating: str) -> str:
    cls = "b-" + rating.lower().replace(" ", "-")
    return f'<span class="badge {cls}">{html.escape(rating)}</span>'


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditor", description="Password Auditor — identify, crack, score.")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("identify", help="Detect hash type from format")
    pi.add_argument("target", help="A hash, a file of hashes (one per line), or '-' for stdin")
    pi.set_defaults(func=cmd_identify)

    pc = sub.add_parser("crack", help="Dictionary or brute-force attack")
    pc.add_argument("target", help="A hash, a file of hashes, or '-' for stdin")
    pc.add_argument("-w", "--wordlist", default="samples/wordlist.txt", help="Wordlist for dictionary attack")
    pc.add_argument("--type", choices=[s[0] for s in HASH_SPECS if s[3]], help="Force hash type (skip detection)")
    pc.add_argument("--brute", action="store_true", help="Brute force instead of dictionary")
    pc.add_argument("--charset", default=string.ascii_lowercase + string.digits, help="Brute-force charset")
    pc.add_argument("--minlen", type=int, default=1, help="Brute-force minimum length")
    pc.add_argument("--maxlen", type=int, default=4, help="Brute-force maximum length")
    pc.add_argument("--json", action="store_true", help="Write a JSON report")
    pc.add_argument("--html", action="store_true", help="Write an HTML report")
    pc.add_argument("-o", "--output-dir", default="reports", help="Directory for reports")
    pc.set_defaults(func=cmd_crack)

    ps = sub.add_parser("score", help="Rate plaintext password strength")
    ps.add_argument("target", help="A password, a file of passwords (one per line), or '-' for stdin")
    ps.add_argument("--json", action="store_true", help="Write a JSON report")
    ps.add_argument("--html", action="store_true", help="Write an HTML report")
    ps.add_argument("-o", "--output-dir", default="reports", help="Directory for reports")
    ps.set_defaults(func=cmd_score)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
