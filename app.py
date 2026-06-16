import os
import string
import secrets
import random
import sqlite3

from flask import Flask, request, jsonify, send_from_directory
from cryptography.fernet import Fernet

app = Flask(__name__, static_folder="static")

KEY_FILE = "secret.key"

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
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


SPECIAL_CHARACTERS = "@_!?$^&"

def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARACTERS
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIAL_CHARACTERS),
    ]
    while len(password) < length:
        password.append(secrets.choice(alphabet))
    random.shuffle(password)
    return "".join(password)

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
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = request.args.get("length", 12, type=int)
    length = max(8, min(64, length))          # clamp to sane range
    pwd = generate_password(length)
    return jsonify({"password": pwd, "strength": check_password_strength(pwd)})

@app.route("/api/review", methods=["POST"])
def api_review():
    data = request.get_json(force=True)
    password = data.get("password", "")
    return jsonify({
        "strength":    check_password_strength(password),
        "suggestions": get_password_suggestions(password),
    })

@app.route("/api/save", methods=["POST"])
def api_save():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    db = get_db()
    db.execute(
        "INSERT INTO passwords (username, password) VALUES (?, ?)",
        (username, encrypt_password(password)),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Password saved successfully."})

@app.route("/api/passwords", methods=["GET"])
def api_passwords():
    db = get_db()
    rows = db.execute("SELECT id, username, password FROM passwords").fetchall()
    db.close()
    results = []
    for row in rows:
        try:
            pwd = decrypt_password(row["password"])
        except Exception:
            pwd = "(unable to decrypt)"
        results.append({"id": row["id"], "username": row["username"], "password": pwd})
    return jsonify(results)

@app.route("/api/passwords/<int:entry_id>", methods=["DELETE"])
def api_delete(entry_id):
    db = get_db()
    db.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
    db.commit()
    db.close()
    return jsonify({"message": "Entry deleted."})

if __name__ == "__main__":
    app.run(debug=True)