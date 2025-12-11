import os
import base64
import hashlib
import hmac
from flask import Flask, request, redirect, url_for, render_template_string, flash, session

app = Flask(__name__)
app.secret_key = os.urandom(16)

ITERATIONS = 150000
SALT_LENGTH = 16

# Simple in-memory "database"
USERS = {}

PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Password Encryption Demo</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: #020617;
      border-radius: 12px;
      padding: 24px 32px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      max-width: 540px;
      width: 100%;
    }
    h1, h2 {
      margin-top: 0;
      color: #f9fafb;
    }
    a {
      color: #38bdf8;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-top: 10px;
    }
    label {
      font-size: 14px;
      color: #cbd5f5;
    }
    input[type="text"], input[type="password"] {
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid #334155;
      background: #020617;
      color: #e5e7eb;
    }
    button {
      margin-top: 8px;
      padding: 10px;
      border-radius: 8px;
      border: none;
      background: #38bdf8;
      color: #0f172a;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover {
      background: #0ea5e9;
    }
    .nav {
      margin-bottom: 12px;
      font-size: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .nav-links a {
      margin-right: 10px;
    }
    .flash {
      margin-bottom: 10px;
      padding: 8px 10px;
      border-radius: 6px;
      font-size: 13px;
    }
    .flash-success {
      background: rgba(22, 163, 74, 0.2);
      border: 1px solid #16a34a;
    }
    .flash-error {
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid #ef4444;
    }
    .info-box {
      margin-top: 14px;
      padding: 10px 12px;
      border-radius: 8px;
      background: #020617;
      border: 1px solid #1f2937;
      font-size: 13px;
    }
    .code {
      font-family: "Fira Code", monospace;
      font-size: 12px;
      background: #020617;
      padding: 4px 6px;
      border-radius: 4px;
      display: block;
      margin-top: 4px;
      color: #f97316;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="nav">
      <div class="nav-links">
        <a href="{{ url_for('login') }}">Login</a>
        <a href="{{ url_for('register') }}">Register</a>
      </div>
      {% if session_user %}
        <div style="font-size:12px; opacity:0.8;">
          Logged in as <strong>{{ session_user }}</strong>
        </div>
      {% endif %}
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="flash flash-{{ category }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {{ content|safe }}
  </div>
</body>
</html>
"""


def hash_password(password: str) -> str:
    """PBKDF2 hash: returns 'iterations$salt_b64$hash_b64'."""
    salt = os.urandom(SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS
    )
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(dk).decode("utf-8")
    return f"{ITERATIONS}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    try:
        iterations_str, salt_b64, hash_b64 = stored.split("$")
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        stored_hash = base64.b64decode(hash_b64.encode("utf-8"))
    except Exception:
        return False

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return hmac.compare_digest(dk, stored_hash)


@app.route("/")
def root():
    # First page = login page
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username and password are required.", "error")
        elif username in USERS:
            flash("Username already exists. Try another one.", "error")
        else:
            stored_value = hash_password(password)
            USERS[username] = stored_value
            # No hash shown here anymore. Just success, then go to login.
            flash("User registered successfully. Please log in.", "success")
            return redirect(url_for("login"))

    content = """
    <h2>Register</h2>
    <form method="post">
      <label>Username</label>
      <input type="text" name="username" required>

      <label>Password</label>
      <input type="password" name="password" required>

      <button type="submit">Create Account</button>
    </form>

    <div class="info-box">
      The password is never stored in plaintext.<br>
      A random salt is generated and PBKDF2 is applied before saving.
    </div>
    """
    return render_template_string(
        PAGE_TEMPLATE,
        content=content,
        session_user=session.get("user")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if username not in USERS:
            flash("Invalid username or password.", "error")
        else:
            stored_value = USERS[username]
            if verify_password(password, stored_value):
                # Save user in session
                session["user"] = username

                # For the explanation page: generate a simple SHA-256 hash example
                regular_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                session["regular_hash_example"] = regular_hash
                session["pbkdf2_hash_example"] = stored_value

                return redirect(url_for("secure_info"))
            else:
                flash("Invalid username or password.", "error")

    content = """
    <h2>Login</h2>
    <form method="post">
      <label>Username</label>
      <input type="text" name="username" required>

      <label>Password</label>
      <input type="password" name="password" required>

      <button type="submit">Login</button>
    </form>

    <div class="info-box">
      After a successful login, you will be taken to a page that explains exactly
      how your password was protected using PBKDF2 and why this is stronger than
      a traditional single hash.
    </div>
    """
    return render_template_string(
        PAGE_TEMPLATE,
        content=content,
        session_user=session.get("user")
    )


@app.route("/secure-info")
def secure_info():
    if "user" not in session:
        flash("Please log in to view this page.", "error")
        return redirect(url_for("login"))

    # Get saved examples from session (from the last successful login)
    regular_hash = session.get("regular_hash_example", "(example not available)")
    pbkdf2_hash = session.get("pbkdf2_hash_example", "(example not available)")

    content = f"""
    <h2>What Happened to Your Password?</h2>
    <p>
      When you registered and logged in, your password was never stored in plaintext.
      Instead, our system used <strong>PBKDF2-HMAC-SHA256</strong> with:
    </p>
    <div class="info-box">
      <ul>
        <li>A random <strong>{SALT_LENGTH}-byte salt</strong> generated per user.</li>
        <li><strong>{ITERATIONS}</strong> iterations of HMAC-SHA256 (key stretching).</li>
        <li>Final storage format:
          <span class="code">iterations$salt_b64$hash_b64</span>
        </li>
      </ul>
    </div>

    <h2>Example Using the Password You Just Logged In With</h2>
    <div class="info-box">
      <strong>Traditional hash (simple SHA-256):</strong>
      <span class="code">{regular_hash}</span>

      <strong>Our stored PBKDF2 value:</strong>
      <span class="code">{pbkdf2_hash}</span>

      <p style="margin-top:8px;">
        Notice how the PBKDF2 value is longer and includes the iteration count and salt,
        not just a single hash. Even if two users choose the same password, their PBKDF2
        values will be different because the salts are different.
      </p>
    </div>

    <h2>Why PBKDF2 Is Better Than a Traditional Hash</h2>
    <div class="info-box">
      <strong>Traditional hash (weaker approach):</strong>
      <ul>
        <li>Often just <span class="code">SHA256(password)</span>.</li>
        <li>No salt: same password → same hash for every user.</li>
        <li>Very fast to compute → very fast for attackers to brute-force.</li>
        <li>Vulnerable to precomputed <strong>rainbow table</strong> attacks.</li>
      </ul>
    </div>

    <div class="info-box">
      <strong>Our PBKDF2-based hash (stronger approach):</strong>
      <ul>
        <li>Uses a unique random salt per user, so identical passwords produce different hashes.</li>
        <li>Runs the hash function <strong>{ITERATIONS}</strong> times (key stretching),
            making each guess slow for an attacker.</li>
        <li>Even if the database is stolen, attackers must brute-force each password individually.</li>
        <li>This matches what we describe in the slides: NIST/OWASP-recommended password storage.</li>
      </ul>
    </div>

    <p>
      In short: a regular hash is like a single lock that can be picked very quickly,
      while PBKDF2 turns each password guess into a heavy, expensive operation,
      greatly slowing down brute-force attacks.
    </p>
    """
    return render_template_string(
        PAGE_TEMPLATE,
        content=content,
        session_user=session.get("user")
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
