"""
secure_app.py — Hardened Flask app. Fixes all 5 vulnerabilities from vulnerable_app.py.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string, escape
import sqlite3
import os
import re
import bcrypt

app = Flask(__name__)
# [FIX 3] Secret key from environment variable, not hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

DB_PATH = "secure_users.db"

# ── Database setup ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        email TEXT
    )""")
    # [FIX 3] Credentials loaded from env vars; bcrypt-hashed passwords
    admin_pass = os.environ.get("ADMIN_PASSWORD", "ChangeMe!2024#Secure")
    hashed = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users VALUES (1,'admin',?,'admin@example.com')", (hashed,))
        alice_pass = os.environ.get("ALICE_PASSWORD", "AlicePass!99#")
        hashed2 = bcrypt.hashpw(alice_pass.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users VALUES (2,'alice',?,'alice@example.com')", (hashed2,))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

# ── [FIX 4] Strong password validation ───────────────────────────────────────
def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "Minimum 10 characters required."
    if not re.search(r"[A-Z]", password):
        return False, "Must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+]", password):
        return False, "Must contain at least one special character."
    return True, ""

# ── Templates (auto-escaping is on; no | safe filter) ────────────────────────
LOGIN_HTML = """
<h2>Secure Login</h2>
<form method="POST">
  Username: <input name="username" autocomplete="username"><br>
  Password: <input name="password" type="password" autocomplete="current-password"><br>
  <input type="submit" value="Login">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

SEARCH_HTML = """
<h2>Search Users</h2>
<form method="GET">
  Query: <input name="q" value="{{ q }}"><br>
  <input type="submit" value="Search">
</form>
<!-- [FIX 2] q auto-escaped by Jinja2 (no | safe) -->
<p>Results for: {{ q }}</p>
<ul>{% for u in results %}<li>{{ u[1] }} — {{ u[3] }}</li>{% endfor %}</ul>
<br><a href="/profile">My Profile</a> | <a href="/logout">Logout</a>
<br><br>
<form method="POST" action="/ping">
  Ping host: <input name="host" pattern="^[a-zA-Z0-9.\-]+$" title="Hostname only">
  <input type="submit" value="Ping">
</form>
"""

PROFILE_HTML = """
<h2>Profile</h2>
<p>Username: {{ user[1] }}</p>
<p>Email: {{ user[3] }}</p>
<a href="/search">Search</a> | <a href="/logout">Logout</a>
"""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # [FIX 4] Strong password validation
        valid, msg = validate_password(password)
        if not valid:
            return render_template_string(LOGIN_HTML, error=f"Password policy: {msg}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # [FIX 1] Parameterised query — no SQL injection possible
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        # [FIX 3] bcrypt comparison, no plaintext passwords
        if user and bcrypt.checkpw(password.encode(), user[2]):
            session.clear()
            session["user_id"] = user[0]
            return redirect(url_for("search"))
        error = "Invalid credentials"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    results = []
    if q:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # [FIX 1] Parameterised LIKE query
        c.execute("SELECT * FROM users WHERE username LIKE ?", (f"%{q}%",))
        results = c.fetchall()
        conn.close()
    # [FIX 2] No | safe — Jinja2 auto-escaping prevents XSS
    return render_template_string(SEARCH_HTML, q=q, results=results)


@app.route("/ping", methods=["POST"])
def ping():
    if "user_id" not in session:
        return redirect(url_for("login"))
    host = request.form.get("host", "")
    # [FIX 5] Whitelist validation — only safe hostname characters allowed
    if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", host):
        return "Invalid hostname.", 400
    # No shell=True; arguments passed as list — command injection impossible
    import subprocess
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
            timeout=5
        )
        return f"<pre>{escape(output.decode())}</pre><a href='/search'>Back</a>"
    except subprocess.CalledProcessError as e:
        return f"<pre>Ping failed: {escape(e.output.decode())}</pre><a href='/search'>Back</a>"


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],))
    user = c.fetchone()
    conn.close()
    return render_template_string(PROFILE_HTML, user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    # [FIX] debug=False in production
    app.run(debug=False)
