# Project 5: SQL Injection Scanner

A SQL injection detection tool built from scratch in Python, demonstrated against an intentionally vulnerable lab application with a professional pentest-style report.

## What Makes This Different

Most SQL injection projects test a single form field with error-based detection. This project tests **four injection contexts** that appear in real applications:

| Context | Endpoint | Why it matters |
|---------|---------|----------------|
| GET parameter | `/search?q=` | Classic injection — most common in legacy apps |
| POST form field | `/login` | Authentication bypass — highest business impact |
| JSON API body | `/api/product` | Missed by simple scanners and many WAFs |
| HTTP header | `/track` (X-Forwarded-For) | Often overlooked; common in proxy-aware apps |

---

## Versions

### Python (`python/`)

A multi-technique scanner implementing four detection methods with CVSS 3.1 scoring and a professional HTML report.

**Detection techniques:**
- Error-based (DB error signature fingerprinting — SQLite, MySQL, MSSQL, PostgreSQL, Oracle)
- Boolean-based blind (response size differential)
- Time-based blind (response delay threshold)
- WAF bypass (obfuscated payloads: comment injection, case randomisation, URL encoding)

**After detection:**
- Data extraction proof-of-concept (confirms real impact, not just detection)
- Database fingerprinting from error signatures
- CVSS 3.1 base score + vector string per finding
- HTML report with business impact, vulnerable vs fixed code, remediation

**Usage:**
```bash
cd python/
pip install -r requirements.txt

# Full scan of all VulnShop endpoints
python3 sqli_scanner.py --target http://127.0.0.1:5000 --full -v -o reports/

# Single GET parameter
python3 sqli_scanner.py --url http://127.0.0.1:5000/search --get-param q
```

### SQLMap (`tools/`)

A professional walkthrough of SQL injection testing using SQLMap against the same lab target, covering GET/POST/JSON injection, data extraction, and WAF evasion with tamper scripts.

See [`tools/sqlmap_guide.md`](tools/sqlmap_guide.md) for the full walkthrough.

---

## Lab Target (`target/`)

An intentionally vulnerable Flask + SQLite application with four deliberately injectable endpoints.

```bash
cd target/
pip install -r requirements.txt
python3 app.py
# Runs on http://127.0.0.1:5000
```

> **Warning:** This application is intentionally insecure. Run it locally only, never expose it on a network.

---

## Skills Demonstrated

- SQL injection detection across error-based, boolean-blind, and time-based techniques
- GET parameter, POST form, JSON API body, and HTTP header injection contexts
- Database fingerprinting from error response signatures
- WAF evasion via payload obfuscation (comment injection, case randomisation, encoding)
- Data extraction proof-of-concept (confirms attacker impact)
- CVSS 3.1 base scoring applied to each finding
- Professional pentest reporting (scope, methodology, findings, business impact, remediation)
- Vulnerable vs fixed code comparison (parameterised queries)
- Intentionally vulnerable target application built in Flask/SQLite

> **Note:** Only use against applications you own or have explicit written permission to test.
