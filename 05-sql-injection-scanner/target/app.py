#!/usr/bin/env python3
"""
Intentionally vulnerable Flask application for SQL injection testing.
DO NOT deploy in production.
"""

import sqlite3
import os
from flask import Flask, request, jsonify, render_template_string, g

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS products;
            DROP TABLE IF EXISTS orders;

            CREATE TABLE users (
                id       INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role     TEXT DEFAULT 'user',
                email    TEXT
            );

            CREATE TABLE products (
                id    INTEGER PRIMARY KEY,
                name  TEXT NOT NULL,
                price REAL,
                stock INTEGER
            );

            CREATE TABLE orders (
                id         INTEGER PRIMARY KEY,
                user_id    INTEGER,
                product_id INTEGER,
                quantity   INTEGER
            );

            INSERT INTO users VALUES
                (1, 'admin',   'supersecret123', 'admin', 'admin@lab.local'),
                (2, 'alice',   'password1',      'user',  'alice@lab.local'),
                (3, 'bob',     'letmein',        'user',  'bob@lab.local'),
                (4, 'charlie', 'qwerty',         'user',  'charlie@lab.local');

            INSERT INTO products VALUES
                (1, 'Widget A', 9.99,  100),
                (2, 'Widget B', 19.99, 50),
                (3, 'Gadget X', 49.99, 25),
                (4, 'Gadget Y', 99.99, 10);

            INSERT INTO orders VALUES
                (1, 2, 1, 3),
                (2, 2, 3, 1),
                (3, 3, 2, 2);
        """)
        db.commit()

# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

BASE = """<!DOCTYPE html>
<html>
<head>
  <title>VulnShop Lab</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
    h1   { color: #c0392b; }
    h2   { color: #2c3e50; }
    nav  { margin-bottom: 20px; }
    nav a { margin-right: 15px; color: #2980b9; text-decoration: none; }
    form { background: white; padding: 20px; border-radius: 6px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 6px 0 14px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
    button { background: #2980b9; color: white; padding: 9px 18px; border: none; border-radius: 4px; cursor: pointer; }
    .result { background: white; padding: 15px; border-radius: 6px; margin: 10px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .error  { color: #c0392b; }
    .warn   { background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; }
  </style>
</head>
<body>
  <h1>VulnShop — SQL Injection Lab</h1>
  <div class="warn">&#9888; This application is intentionally vulnerable. For testing purposes only.</div>
  <nav>
    <a href="/">Home</a>
    <a href="/login">Login</a>
    <a href="/search">Product Search</a>
    <a href="/api/docs">API Docs</a>
  </nav>
  {% block content %}{% endblock %}
</body>
</html>"""

HOME_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<h2>Welcome to VulnShop</h2>
<p>This is an intentionally vulnerable lab application with four SQL injection points:</p>
<ul>
  <li><strong>/login</strong> — POST form (authentication bypass)</li>
  <li><strong>/search</strong> — GET parameter (data extraction)</li>
  <li><strong>/api/product</strong> — JSON body (API injection)</li>
  <li><strong>/track</strong> — HTTP header injection (X-Forwarded-For)</li>
</ul>
""")

LOGIN_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<h2>Login</h2>
<form method="POST" action="/login">
  <label>Username</label>
  <input type="text" name="username" placeholder="admin">
  <label>Password</label>
  <input type="password" name="password" placeholder="password">
  <button type="submit">Login</button>
</form>
{% if result %}<div class="result {% if error %}error{% endif %}">{{ result }}</div>{% endif %}
""")

SEARCH_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<h2>Product Search</h2>
<form method="GET" action="/search">
  <label>Product name</label>
  <input type="text" name="q" value="{{ query }}">
  <button type="submit">Search</button>
</form>
{% if results %}
  {% for r in results %}
    <div class="result">{{ r }}</div>
  {% endfor %}
{% endif %}
{% if error %}<div class="result error">{{ error }}</div>{% endif %}
""")

API_DOCS_TMPL = BASE.replace("{% block content %}{% endblock %}", """
<h2>API Documentation</h2>
<h3>GET /api/product?id=&lt;id&gt;</h3>
<p>Returns product details for the given ID.</p>
<h3>POST /api/product</h3>
<p>Returns product details. Body: <code>{"id": 1}</code></p>
<h3>GET /track</h3>
<p>Logs visit. Reads <code>X-Forwarded-For</code> header as client IP and stores in query.</p>
""")

# ---------------------------------------------------------------------------
# Injection point 1: POST login form
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    result = None
    error = False
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        try:
            # VULNERABLE: string interpolation
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            row = db.execute(query).fetchone()
            if row:
                result = f"Login successful — welcome {row['username']} (role: {row['role']})"
            else:
                result = "Invalid credentials."
                error = True
        except Exception as e:
            result = f"Database error: {e}"
            error = True
    return render_template_string(LOGIN_TMPL, result=result, error=error)

# ---------------------------------------------------------------------------
# Injection point 2: GET search parameter
# ---------------------------------------------------------------------------

@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    error = None
    if q:
        db = get_db()
        try:
            # VULNERABLE: string interpolation
            query = f"SELECT name, price, stock FROM products WHERE name LIKE '%{q}%'"
            rows = db.execute(query).fetchall()
            results = [f"{r['name']} — ${r['price']} ({r['stock']} in stock)" for r in rows]
            if not results:
                results = ["No products found."]
        except Exception as e:
            error = f"Database error: {e}"
    return render_template_string(SEARCH_TMPL, query=q, results=results, error=error)

# ---------------------------------------------------------------------------
# Injection point 3: JSON API body
# ---------------------------------------------------------------------------

@app.route("/api/product", methods=["GET", "POST"])
def api_product():
    db = get_db()
    if request.method == "GET":
        product_id = request.args.get("id", "1")
    else:
        data = request.get_json(silent=True) or {}
        product_id = data.get("id", "1")

    try:
        # VULNERABLE: string interpolation
        query = f"SELECT * FROM products WHERE id={product_id}"
        row = db.execute(query).fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"error": "Product not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# Injection point 4: HTTP header (X-Forwarded-For)
# ---------------------------------------------------------------------------

@app.route("/track")
def track():
    db = get_db()
    # Simulates logging the client IP from a proxy header into a query
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        # VULNERABLE: header value used directly in query
        query = f"SELECT id, username FROM users WHERE id=(SELECT user_id FROM orders WHERE id=1) AND '{client_ip}'='{ client_ip}'"
        rows = db.execute(query).fetchall()
        return jsonify({"tracked": True, "ip": client_ip, "rows": len(rows)})
    except Exception as e:
        return jsonify({"tracked": False, "ip": client_ip, "error": str(e)}), 500

# ---------------------------------------------------------------------------
# Misc routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HOME_TMPL)

@app.route("/api/docs")
def api_docs():
    return render_template_string(API_DOCS_TMPL)

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[*] Initialising database...")
    init_db()
    print("[*] VulnShop running on http://127.0.0.1:5000")
    print("[!] WARNING: Intentionally vulnerable — lab use only")
    app.run(debug=False, host="127.0.0.1", port=5000)
