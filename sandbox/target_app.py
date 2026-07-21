"""
Deliberately vulnerable Flask application for lab testing.

One genuinely exploitable endpoint per attack class:
  /login   - real SQL injection (string-concatenated query against SQLite)
  /search  - real XSS reflection (unescaped user input in HTML)
  /ping    - simulated command injection (echoes canary, no real shell)
  /fetch   - simulated SSRF (returns internal-service banner for internal URLs)
  /transfer - real CSRF (accepts state-changing POST with no token validation)

LEGAL NOTE: this application is deliberately insecure. Run it ONLY in a local,
isolated lab environment. Never expose it to a network. It exists so the agent
can crawl real HTML, fire real HTTP requests, and validate real responses --
closing the gap between MockTarget's canned strings and a production DVWA.

Usage:
    python sandbox/target_app.py        # starts on http://127.0.0.1:5001
    # then point the agent at 127.0.0.1:5001
"""
import os
import re
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = ":memory:"

# ---------- database setup ----------
def get_db():
    if not hasattr(app, '_db'):
        app._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        app._db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        app._db.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'secret123')")
        app._db.execute("INSERT OR IGNORE INTO users VALUES (2, 'testuser', 'password')")
        app._db.commit()
    return app._db

# ---------- index (recon entry point) ----------
INDEX_HTML = """<!DOCTYPE html><html><head><title>Vulnerable Lab App</title></head><body>
<h1>Vulnerable Lab Application</h1>
<p>Deliberately insecure. For authorized testing only.</p>
<ul>
  <li><a href="/login">Login</a> (SQL Injection)</li>
  <li><a href="/search">Search</a> (XSS)</li>
  <li><a href="/ping">Ping</a> (Command Injection)</li>
  <li><a href="/fetch">Fetch URL</a> (SSRF)</li>
  <li><a href="/transfer">Transfer</a> (CSRF)</li>
</ul>
</body></html>"""

@app.route("/")
def index():
    return INDEX_HTML

# ---------- SQLi: real string-concatenated query ----------
LOGIN_HTML = """<!DOCTYPE html><html><body>
<h2>Login</h2>
<form method="POST" action="/login">
  <label>Username: <input type="text" name="username"></label><br>
  <label>Password: <input type="password" name="password"></label><br>
  <button type="submit">Login</button>
</form>
{% if error %}<pre style="color:red">{{ error }}</pre>{% endif %}
{% if result %}<pre>{{ result }}</pre>{% endif %}
</body></html>"""

@app.route("/login", methods=["GET", "POST"])
def login():
    error = result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # DELIBERATELY VULNERABLE: string concatenation, not parameterized
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            rows = get_db().execute(query).fetchall()
            result = f"Query: {query}\nRows returned: {len(rows)}\n{rows}" if rows else "No match."
        except Exception as e:
            error = f"SQL Error: {e}\nQuery was: {query}"
    return render_template_string(LOGIN_HTML, error=error, result=result)

# ---------- XSS: unescaped reflection ----------
SEARCH_HTML = """<!DOCTYPE html><html><body>
<h2>Search</h2>
<form method="GET" action="/search">
  <label>Query: <input type="text" name="q"></label>
  <button type="submit">Search</button>
</form>
<div id="results">Search results for: QUERY_PLACEHOLDER</div>
</body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # DELIBERATELY VULNERABLE: raw insertion, no escaping
    return SEARCH_HTML.replace("QUERY_PLACEHOLDER", q)

# ---------- CmdInj: simulated (no real shell, echoes canary) ----------
PING_HTML = """<!DOCTYPE html><html><body>
<h2>Ping</h2>
<form method="POST" action="/ping">
  <label>Host: <input type="text" name="host"></label>
  <button type="submit">Ping</button>
</form>
{% if output %}<pre>{{ output }}</pre>{% endif %}
</body></html>"""

CANARY = "pentest_canary_12345"

@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # Simulated: detects injection metacharacters and returns command output
        # without actually executing a shell command (safe for a lab app)
        if any(c in host for c in [";", "|", "&&", "`", "$("]):
            output = f"PING {host}: uid=33(www-data) gid=33(www-data) groups=33(www-data)\n{CANARY}"
        else:
            output = f"PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.1 ms"
    return render_template_string(PING_HTML, output=output)

# ---------- SSRF: simulated (returns internal banner for internal URLs) ----------
FETCH_HTML = """<!DOCTYPE html><html><body>
<h2>Fetch URL</h2>
<form method="GET" action="/fetch">
  <label>URL: <input type="text" name="url" size="60"></label>
  <button type="submit">Fetch</button>
</form>
{% if body %}<pre>{{ body }}</pre>{% endif %}
</body></html>"""

@app.route("/fetch")
def fetch_url():
    body = None
    url = request.args.get("url", "")
    if url:
        # Simulated: no real HTTP fetch, but returns internal-service banner
        # for requests targeting internal addresses
        if any(internal in url.lower() for internal in ["127.0.0.1", "localhost", "169.254.169.254", "10.", "192.168."]):
            body = 'Response from internal service: {"instance-id": "i-0abc1234", "region": "eu-central-1", "internal service data": true}'
        else:
            body = f"Fetched external URL: {url} -> 200 OK (simulated)"
    return render_template_string(FETCH_HTML, body=body)

# ---------- CSRF: no token validation ----------
TRANSFER_HTML = """<!DOCTYPE html><html><body>
<h2>Transfer Funds</h2>
<form method="POST" action="/transfer">
  <label>To account: <input type="text" name="to_account"></label><br>
  <label>Amount: <input type="text" name="amount"></label><br>
  <button type="submit">Transfer</button>
</form>
{% if msg %}<p>{{ msg }}</p>{% endif %}
</body></html>"""

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    msg = None
    if request.method == "POST":
        # DELIBERATELY VULNERABLE: no CSRF token check
        to = request.form.get("to_account", "")
        amount = request.form.get("amount", "0")
        msg = f"Transfer of {amount} to {to} successful. Reference: TXN-{hash(to) % 100000:05d}"
    return render_template_string(TRANSFER_HTML, msg=msg)


if __name__ == "__main__":
    print("Starting DELIBERATELY VULNERABLE lab target on http://127.0.0.1:5001")
    print("For authorized testing only. Never expose to a network.")
    app.run(host="127.0.0.1", port=5001, debug=False)
