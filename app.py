from __future__ import annotations

import os
import secrets
import sqlite3
import time
from functools import wraps
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from flask import Flask, g, jsonify, make_response, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "lab_data"
PUBLIC_DIR = DATA_DIR / "public"
PRIVATE_DIR = DATA_DIR / "private"
DEFAULT_DB = DATA_DIR / "lab.sqlite3"


def connect_db(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db(database_path: str) -> None:
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with connect_db(database_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL
            );
            """
        )
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            db.executemany(
                "INSERT INTO users (id, username, password_hash, display_name) VALUES (?, ?, ?, ?)",
                [
                    (1, "alice", generate_password_hash("secure-demo-pass"), "Alice Example"),
                    (2, "bob", generate_password_hash("secure-demo-pass"), "Bob Example"),
                ],
            )
            db.executemany(
                "INSERT INTO documents (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Alice's field notes", "Synthetic document belonging to Alice."),
                    (2, 2, "Bob's project brief", "Synthetic document belonging to Bob."),
                ],
            )
            db.executemany(
                "INSERT INTO comments (body) VALUES (?)",
                [("Welcome to the local lab." ,), ("Only synthetic content lives here.",)],
            )
            db.executemany(
                "INSERT INTO products (name, category) VALUES (?, ?)",
                [("Copper mug", "home"), ("Field notebook", "stationery"), ("Desk lamp", "home")],
            )
    (PUBLIC_DIR).mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    (PUBLIC_DIR / "welcome.txt").write_text("Public training fixture.\n", encoding="utf-8")
    (PRIVATE_DIR / "lesson.txt").write_text("Synthetic private fixture: traversal reached outside public/.\n", encoding="utf-8")


def create_app(database_path: str | None = None) -> Flask:
    app = Flask(__name__)
    login_failures: dict[str, list[float]] = {}
    app.config.update(
        SECRET_KEY=os.environ.get("LAB_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("LAB_HTTPS_ONLY", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        DATABASE=str(database_path or DEFAULT_DB),
    )
    initialize_db(app.config["DATABASE"])

    @app.before_request
    def open_database() -> None:
        g.db = connect_db(app.config["DATABASE"])

    @app.teardown_request
    def close_database(_error: BaseException | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def secure_default_headers(response):
        if request.path.startswith("/api/secure/") or request.path == "/api/health":
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
            response.headers["Cache-Control"] = "no-store"
        return response

    def json_error(message: str, status: int):
        return jsonify({"error": message}), status

    def require_secure_login(view: Callable[..., Any]):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("secure_user_id"):
                return json_error("Sign in to the secure demo first.", 401)
            return view(*args, **kwargs)
        return wrapped

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "mode": "local training lab"})

    @app.get("/api/vulnerable/sql-search")
    def vulnerable_sql_search():
        term = request.args.get("q", "")
        sql = f"SELECT id, name, category FROM products WHERE name LIKE '%{term}%'"
        try:
            rows = g.db.execute(sql).fetchall()
            return jsonify({"results": [dict(row) for row in rows], "query": sql})
        except sqlite3.Error as error:
            return jsonify({"error": str(error), "query": sql}), 400

    @app.get("/api/secure/sql-search")
    def secure_sql_search():
        term = f"%{request.args.get('q', '')}%"
        rows = g.db.execute(
            "SELECT id, name, category FROM products WHERE name LIKE ?", (term,)
        ).fetchall()
        return jsonify({"results": [dict(row) for row in rows]})

    @app.get("/api/vulnerable/xss")
    def vulnerable_xss():
        value = request.args.get("text", "")
        response = make_response(jsonify({"html": f"<p>{value}</p>"}))
        response.headers["X-Lab-Note"] = "HTML is returned without output encoding"
        return response

    @app.get("/api/secure/xss")
    def secure_xss():
        return jsonify({"text": request.args.get("text", "")})

    @app.post("/api/vulnerable/login")
    def vulnerable_login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", ""))
        password = str(data.get("password", ""))
        row = g.db.execute(
            "SELECT id, username, display_name FROM users "
            f"WHERE username = '{username}' AND password_hash = '{password}'"
        ).fetchone()
        # Lab-only credentials are intentionally predictable and compared as plaintext.
        if username == "alice" and password == "password123":
            row = g.db.execute("SELECT id, username, display_name FROM users WHERE id = 1").fetchone()
        if row:
            return jsonify({"authenticated": True, "user": dict(row), "message": "No throttling or session rotation."})
        return json_error("Invalid credentials.", 401)

    @app.post("/api/secure/login")
    def secure_login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", ""))[:80]
        password = str(data.get("password", ""))[:256]
        client = request.remote_addr or "unknown"
        now = time.monotonic()
        recent_failures = [stamp for stamp in login_failures.get(client, []) if now - stamp < 60]
        login_failures[client] = recent_failures
        if len(recent_failures) >= 5:
            return json_error("Too many attempts. Try again in one minute.", 429)
        row = g.db.execute(
            "SELECT id, username, display_name, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            login_failures[client].append(now)
            return json_error("Invalid username or password.", 401)
        login_failures.pop(client, None)
        session.clear()
        session.permanent = True
        session["secure_user_id"] = row["id"]
        return jsonify({"authenticated": True, "user": {"id": row["id"], "username": row["username"], "display_name": row["display_name"]}})

    @app.post("/api/secure/logout")
    def secure_logout():
        session.clear()
        return jsonify({"authenticated": False})

    @app.get("/api/vulnerable/documents/<int:document_id>")
    def vulnerable_document(document_id: int):
        user_id = request.args.get("user_id", "1")
        row = g.db.execute(
            "SELECT id, owner_id, title, body FROM documents WHERE id = " + str(document_id)
            + " AND owner_id = " + user_id
        ).fetchone()
        if not row:
            return json_error("Document not found.", 404)
        return jsonify(dict(row))

    @app.get("/api/secure/documents/<int:document_id>")
    @require_secure_login
    def secure_document(document_id: int):
        row = g.db.execute(
            "SELECT id, owner_id, title, body FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, session["secure_user_id"]),
        ).fetchone()
        if not row:
            return json_error("Document not found.", 404)
        return jsonify(dict(row))

    def read_lab_file(root: Path, requested_path: str) -> Path | None:
        candidate = (root / requested_path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    @app.get("/api/vulnerable/files")
    def vulnerable_files():
        requested_path = request.args.get("path", "welcome.txt")
        target = (PUBLIC_DIR / requested_path).resolve()
        try:
            # Deliberately missing public-directory containment check; still confined to lab_data.
            target.relative_to(DATA_DIR.resolve())
        except ValueError:
            return json_error("Outside the lab fixture boundary.", 403)
        if not target.is_file():
            return json_error("Fixture not found.", 404)
        return jsonify({"path": requested_path, "content": target.read_text(encoding="utf-8")})

    @app.get("/api/secure/files")
    def secure_files():
        requested_path = request.args.get("path", "welcome.txt")
        target = read_lab_file(PUBLIC_DIR, requested_path)
        if not target:
            return json_error("Fixture not found.", 404)
        return jsonify({"path": requested_path, "content": target.read_text(encoding="utf-8")})

    @app.get("/api/vulnerable/config")
    def vulnerable_config():
        response = jsonify({
            "debug": True,
            "framework": "Flask development mode",
            "cors": "*",
            "server_path": str(BASE_DIR),
            "example_secret": "training-only-placeholder-not-a-real-secret",
            "headers": "security headers disabled",
        })
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    @app.get("/api/secure/config")
    def secure_config():
        return jsonify({"debug": False, "details": "Operational details are not exposed."})

    @app.post("/api/vulnerable/weak-session")
    def vulnerable_weak_session():
        data = request.get_json(silent=True) or {}
        user_id = str(data.get("user_id", "1"))
        response = jsonify({"message": "Weak session issued; its value is the user id.", "user_id": user_id})
        response.set_cookie("lab_session", user_id, httponly=False, samesite="Lax")
        return response

    @app.get("/api/vulnerable/weak-session")
    def vulnerable_weak_session_profile():
        user_id = request.cookies.get("lab_session", "1")
        row = g.db.execute("SELECT id, username, display_name FROM users WHERE id = " + user_id).fetchone()
        if not row:
            return json_error("Unknown session identity.", 404)
        return jsonify({"user": dict(row), "session": "client-controlled numeric identity; no expiry or rotation"})

    @app.post("/api/secure/session")
    @require_secure_login
    def secure_session_status():
        return jsonify({"authenticated": True, "user_id": session["secure_user_id"], "session": "signed, 30-minute lifetime, HttpOnly, SameSite=Strict"})

    @app.errorhandler(sqlite3.Error)
    def database_error(_error):
        return json_error("The request could not be completed.", 500)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
