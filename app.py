import os
import string
import secrets
import random
import sqlite3
import time
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, session, redirect
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or Fernet.generate_key()

KEY_FILE = "secret.key"

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        
        if ip not in REQUEST_HISTORY:
            REQUEST_HISTORY[ip] = []
        
        # Clean old requests (older than 60 seconds)
        REQUEST_HISTORY[ip] = [t for t in REQUEST_HISTORY[ip] if now - t < 60]
        
        # Check rate limit
        if len(REQUEST_HISTORY[ip]) >= RATE_LIMIT:
            return redirect(RICK_ROLL_URL)
        
        REQUEST_HISTORY[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting storage
REQUEST_HISTORY = {}
RATE_LIMIT = 100  # requests per minute
RICK_ROLL_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_password(password):
    return Fernet(load_key()).encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return Fernet(load_key()).decrypt(encrypted_password.encode()).decode()


def get_db():
    conn = sqlite3.connect("passwords.db")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            app      TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS generated_passwords (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    columns = [row[1] for row in conn.execute("PRAGMA table_info(passwords)").fetchall()]
    if "app" not in columns:
        conn.execute("ALTER TABLE passwords ADD COLUMN app TEXT NOT NULL DEFAULT ''")
        conn.commit()
    if "user_id" not in columns:
        conn.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")
        conn.commit()

    return conn


def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_setting(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    row = conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def require_user():
    return get_current_user()

def is_api_request():
    return request.path.startswith("/api/")


SPECIAL_CHARACTERS = "@_!?$^&*#%"

def generate_password(length=12, max_attempts=100):
    """Generate a unique password that hasn't been generated before."""
    db = get_db()
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARACTERS
    
    for attempt in range(max_attempts):
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(SPECIAL_CHARACTERS),
        ]
        while len(password) < length:
            password.append(secrets.choice(alphabet))
        random.shuffle(password)
        pwd_str = "".join(password)
        
        # Check if password already exists
        existing = db.execute(
            "SELECT id FROM generated_passwords WHERE password = ?", 
            (pwd_str,)
        ).fetchone()
        
        if not existing:
            # Store this password to prevent future repeats
            try:
                db.execute(
                    "INSERT INTO generated_passwords (password) VALUES (?)",
                    (pwd_str,)
                )
                db.commit()
                db.close()
                return pwd_str
            except:
                pass  # Duplicate, try again
    
    db.close()
    # Fallback if somehow we can't generate a unique password
    return "".join(secrets.choice(alphabet) for _ in range(length))

def check_password_strength(password):
    score = sum([
        len(password) >= 8,
        len(password) >= 12,
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password),
    ])
    return ["Very Weak", "Very Weak", "Weak", "Weak", "Medium", "Strong", "Very Strong"][score]

def get_password_suggestions(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Make your password at least 8 characters long.")
    if not any(c.islower() for c in password):
        suggestions.append("Add a lowercase letter.")
    if not any(c.isupper() for c in password):
        suggestions.append("Add an uppercase letter.")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add a digit.")
    if not any(c in string.punctuation for c in password):
        suggestions.append("Add a special character (e.g. @, !, $).")
    return suggestions


@app.route("/")
@rate_limit
def index():
    user = get_current_user()
    if not user:
        return redirect("/login")
    return send_from_directory("static", "index.html")

@app.route("/login")
@rate_limit
def login_page():
    user = get_current_user()
    if user:
        return redirect("/")
    return send_from_directory("static", "login.html")

@app.route("/rickroll")
def rickroll():
    """Redirect to rick roll for security violations."""
    return redirect(RICK_ROLL_URL)

@app.route("/api/generate", methods=["GET"])
@rate_limit
def api_generate():
    length = request.args.get("length", 12, type=int)
    length = max(8, min(64, length))          # clamp to sane range
    pwd = generate_password(length)
    return jsonify({"password": pwd, "strength": check_password_strength(pwd)})

@app.route("/api/review", methods=["POST"])
@rate_limit
def api_review():
    data = request.get_json(force=True)
    password = data.get("password", "")
    return jsonify({
        "strength":    check_password_strength(password),
        "suggestions": get_password_suggestions(password),
    })

@app.route("/api/save", methods=["POST"])
@rate_limit
def api_save():
    user = require_user()
    if not user:
        return jsonify({"error": "Login required."}), 403
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    app_name = data.get("app", "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    db = get_db()
    db.execute(
        "INSERT INTO passwords (username, password, app, user_id) VALUES (?, ?, ?, ?)",
        (username, encrypt_password(password), app_name, user["id"]),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Password saved successfully."})

@app.route("/api/passwords", methods=["GET"])
@rate_limit
def api_passwords():
    user = require_user()
    if not user:
        return jsonify({"error": "Login required."}), 403
    db = get_db()
    rows = db.execute("SELECT id, username, app, password FROM passwords WHERE user_id = ?", (user["id"],)).fetchall()
    db.close()
    results = []
    for row in rows:
        try:
            pwd = decrypt_password(row["password"])
        except Exception:
            pwd = "(unable to decrypt)"
        results.append({
            "id": row["id"],
            "username": row["username"],
            "app": row["app"],
            "password": pwd,
        })
    return jsonify(results)

@app.route("/api/signup", methods=["POST"])
@rate_limit
def api_signup():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "Email already registered."}), 400
    password_hash = generate_password_hash(password)
    db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
    db.close()
    session.permanent = False
    session["user_id"] = user_id
    return jsonify({"message": "Account created and logged in."})

@app.route("/api/login", methods=["POST"])
@rate_limit
def api_login():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    db = get_db()
    user = db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        db.close()
        return jsonify({"error": "Invalid email or password."}), 403
    session.permanent = False
    session["user_id"] = user["id"]
    db.close()
    return jsonify({"message": "Logged in successfully."})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out."})

@app.route("/api/me", methods=["GET"])
def api_me():
    user = get_current_user()
    if user:
        return jsonify({"loggedIn": True, "email": user["email"], "userId": user["id"]})
    return jsonify({"loggedIn": False, "email": None, "userId": None})

@app.route("/api/passwords/<int:entry_id>", methods=["DELETE"])
def api_delete(entry_id):
    user = require_user()
    if not user:
        return jsonify({"error": "Login required."}), 403
    db = get_db()
    db.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (entry_id, user["id"]))
    db.commit()
    db.close()
    return jsonify({"message": "Entry deleted."})

# Security error handlers - redirect to rick roll on bypass attempts
@app.errorhandler(403)
def forbidden(e):
    """Anyone trying to access forbidden resources gets rick rolled."""
    if is_api_request():
        return jsonify({"error": "Forbidden."}), 403
    return redirect(RICK_ROLL_URL)

@app.errorhandler(401)
def unauthorized(e):
    """Anyone trying unauthorized actions gets rick rolled."""
    if is_api_request():
        return jsonify({"error": "Unauthorized."}), 401
    return redirect(RICK_ROLL_URL)

@app.errorhandler(404)
def not_found(e):
    """Trying to access non-existent endpoints gets rick rolled."""
    ip = request.remote_addr
    # Log suspicious activity
    print(f"[SECURITY] Suspicious access attempt from {ip} to {request.path}")
    if is_api_request():
        return jsonify({"error": "Not found."}), 404
    return redirect(RICK_ROLL_URL)

@app.before_request
def security_checks():
    """Validate all requests for security."""
    # Check for common attack patterns
    if any(pattern in request.path.lower() for pattern in ['admin', 'config', 'debug', 'sql']):
        return redirect(RICK_ROLL_URL)
    
    # Validate request headers
    if request.method in ['POST', 'PUT', 'DELETE']:
        if request.content_length and request.content_length > 1024 * 100:  # 100KB limit
            return redirect(RICK_ROLL_URL)

if __name__ == "__main__":
    app.run(debug=True)