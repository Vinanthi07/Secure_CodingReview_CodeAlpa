"""
vulnerable_app.py — INTENTIONALLY INSECURE Flask app for educational use.
DO NOT deploy this in production. For cybersecurity training only.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = "supersecret123"

# ── [VULN 3] Hardcoded Credentials ───────────────────────────────────────────
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"
DB_PATH = "users.db"

# ── Database setup ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT
    )""")
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password1','alice@example.com')")
    conn.commit()
    conn.close()

# ── Templates ─────────────────────────────────────────────────────────────────
LOGIN_HTML = """
<h2>Login</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
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
<!-- [VULN 2] XSS: user input reflected without escaping -->
<p>Results for: {{ q | safe }}</p>
<ul>{% for u in results %}<li>{{ u[1] }} — {{ u[3] }}</li>{% endfor %}</ul>
<br><a href="/profile">My Profile</a> | <a href="/logout">Logout</a>
<br><br>
<form method="POST" action="/ping">
  Ping host: <input name="host"> <input type="submit" value="Ping">
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
        username = request.form["username"]
        password = request.form["password"]

        # [VULN 4] Weak password validation — any password ≥ 3 chars accepted for new sessions
        if len(password) < 3:
            error = "Password too short (min 3 chars)"
            return render_template_string(LOGIN_HTML, error=error)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # [VULN 1] SQL Injection — raw string formatting, no parameterisation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
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
        # [VULN 1] SQL Injection again in search
        c.execute(f"SELECT * FROM users WHERE username LIKE '%{q}%'")
        results = c.fetchall()
        conn.close()
    # [VULN 2] XSS — q passed with | safe filter, raw HTML injected into page
    return render_template_string(SEARCH_HTML, q=q, results=results)


@app.route("/ping", methods=["POST"])
def ping():
    if "user_id" not in session:
        return redirect(url_for("login"))
    host = request.form.get("host", "")
    # [VULN 5] Command Injection — user input passed directly to shell
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
    return f"<pre>{output.decode()}</pre><a href='/search'>Back</a>"


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
    app.run(debug=True)  # debug=True leaks stack traces in production
