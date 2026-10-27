from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "hospital_demo.db"
LOG_PATH = BASE_DIR / "logs" / "security_events.jsonl"
INTEGRITY_PATH = BASE_DIR / "monitoring" / "file_integrity_baseline.txt"
WEBSHELL_PATH = BASE_DIR / "monitoring" / "webshell_indicators.txt"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000)
    return f"pbkdf2_sha256$200000${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, digest = stored_hash.split("$")
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    expected = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations),
    )
    return expected.hex() == digest


def get_db_connection(database_path: str | Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_database(database_path: str | Path = DB_PATH) -> None:
    database_path = Path(database_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(database_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            service TEXT NOT NULL,
            doctor TEXT NOT NULL,
            appointment_date TEXT NOT NULL,
            visit_type TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            role TEXT,
            outcome TEXT NOT NULL,
            source_ip TEXT,
            user_agent TEXT,
            request_path TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    seeded_users = {
        "patient1": {
            "password": "PatientPass!2025",
            "role": "patient",
            "full_name": "Selam Desta",
            "email": "selam.desta@waliyahospital.demo",
        },
        "patient2": {
            "password": "Care123!Patient",
            "role": "patient",
            "full_name": "Mekdes Berhe",
            "email": "mekdes.berhe@waliyahospital.demo",
        },
        "dr_abel": {
            "password": "Staff@2025",
            "role": "staff",
            "full_name": "Dr. Abel Tesfaye",
            "email": "abel.tesfaye@waliyahospital.demo",
        },
        "admin": {
            "password": "Admin@2025",
            "role": "admin",
            "full_name": "Hospital Administrator",
            "email": "admin@waliyahospital.demo",
        },
    }

    for username, details in seeded_users.items():
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, full_name, email, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    username,
                    hash_password(details["password"]),
                    details["role"],
                    details["full_name"],
                    details["email"],
                    _utc_now(),
                ),
            )

    seeded_appointments = [
        (
            "Selam Desta",
            "+251 911 111 111",
            "General Consultation",
            "Dr. Meles Worku",
            "2026-11-05",
            "In-person",
            "Follow-up for routine blood pressure review.",
            _utc_now(),
        ),
        (
            "Mekdes Berhe",
            "+251 911 222 222",
            "Pediatric Care",
            "Dr. Hana Bekele",
            "2026-11-09",
            "Telehealth",
            "Vaccination review and growth assessment.",
            _utc_now(),
        ),
        (
            "Yohannes Tadesse",
            "+251 911 333 333",
            "Cardiology",
            "Dr. Daniel Girmay",
            "2026-11-12",
            "In-person",
            "ECG review and treatment plan update.",
            _utc_now(),
        ),
    ]
    existing_count = conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0]
    if existing_count == 0:
        conn.executemany(
            "INSERT INTO appointments (patient_name, phone, service, doctor, appointment_date, visit_type, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            seeded_appointments,
        )

    conn.commit()
    conn.close()


def ensure_security_logs() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch(exist_ok=True)


def ensure_monitoring_files() -> None:
    INTEGRITY_PATH.parent.mkdir(parents=True, exist_ok=True)
    INTEGRITY_PATH.write_text(
        "# Waliya Medical Center - sample file integrity baseline\n"
        "# This is a harmless demonstration file for local monitoring only.\n"
        "app.py: sha256=demo-placeholder\n"
        "templates/index.html: sha256=demo-placeholder\n"
        "static/style.css: sha256=demo-placeholder\n",
        encoding="utf-8",
    )
    WEBSHELL_PATH.write_text(
        "# Waliya Medical Center - simulated webshell indicator review\n"
        "# This file is intentionally harmless and demonstrates monitoring output only.\n"
        "status: no_high_confidence_indicators_detected\n"
        "observed_signals: 0\n"
        "notes: safe demo environment\n",
        encoding="utf-8",
    )


def log_security_event(
    event_type: str,
    username: str | None,
    role: str | None,
    outcome: str,
    source_ip: str | None,
    request_path: str | None,
    user_agent: str | None,
    database_path: str | Path = DB_PATH,
) -> None:
    ensure_security_logs()
    payload = {
        "timestamp": _utc_now(),
        "event": event_type,
        "username": username,
        "role": role,
        "outcome": outcome,
        "source_ip": source_ip,
        "request_path": request_path,
        "user_agent": user_agent,
    }
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

    conn = get_db_connection(database_path)
    conn.execute(
        "INSERT INTO login_attempts (username, role, outcome, source_ip, user_agent, request_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, role, outcome, source_ip, user_agent, request_path, payload["timestamp"]),
    )
    conn.commit()
    conn.close()


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def normalize_text(value: str, max_length: int = 200) -> str:
    cleaned = (value or "").strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def login_required(required_role: str | None = None):
    def decorator(view_func):
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("patient_login" if required_role == "patient" else "staff_login"))
            if required_role and session.get("role") not in {required_role, "admin"}:
                return redirect(url_for("home"))
            return view_func(*args, **kwargs)

        wrapped.__name__ = view_func.__name__
        return wrapped

    return decorator


def create_app(database_path: str | Path = DB_PATH):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("DEMO_HOSPITAL_SECRET_KEY", "dev-secret-key-local-only")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["DATABASE"] = str(database_path)

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        return response

    @app.route("/")
    def home():
        conn = get_db_connection(app.config["DATABASE"])
        appointments = conn.execute(
            "SELECT patient_name, service, doctor, appointment_date, visit_type FROM appointments ORDER BY appointment_date ASC LIMIT 3"
        ).fetchall()
        conn.close()
        return render_template("index.html", appointments=appointments)

    @app.route("/services")
    def services():
        return render_template("services.html")

    @app.route("/patient-login", methods=["GET", "POST"])
    def patient_login():
        if request.method == "POST":
            username = normalize_text(request.form.get("username", ""), 60)
            password = request.form.get("password", "")
            if not username or not password:
                log_security_event(
                    "auth.login.validation_error",
                    username,
                    "patient",
                    "failure",
                    get_client_ip(),
                    request.path,
                    request.headers.get("User-Agent"),
                    database_path=app.config["DATABASE"],
                )
                return render_template("login.html", role="patient", error="Please enter both username and password.")

            conn = get_db_connection(app.config["DATABASE"])
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            conn.close()

            if user and user["role"] in {"patient", "admin"} and verify_password(password, user["password_hash"]):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                log_security_event(
                    "auth.login.success",
                    user["username"],
                    user["role"],
                    "success",
                    get_client_ip(),
                    request.path,
                    request.headers.get("User-Agent"),
                    database_path=app.config["DATABASE"],
                )
                return redirect(url_for("patient_dashboard"))

            log_security_event(
                "auth.login.failure",
                username,
                "patient",
                "failure",
                get_client_ip(),
                request.path,
                request.headers.get("User-Agent"),
                database_path=app.config["DATABASE"],
            )
            return render_template("login.html", role="patient", error="Invalid username or password.")

        return render_template("login.html", role="patient")

    @app.route("/staff-login", methods=["GET", "POST"])
    def staff_login():
        if request.method == "POST":
            username = normalize_text(request.form.get("username", ""), 60)
            password = request.form.get("password", "")
            if not username or not password:
                log_security_event(
                    "auth.login.validation_error",
                    username,
                    "staff",
                    "failure",
                    get_client_ip(),
                    request.path,
                    request.headers.get("User-Agent"),
                    database_path=app.config["DATABASE"],
                )
                return render_template("login.html", role="staff", error="Please enter both username and password.")

            conn = get_db_connection(app.config["DATABASE"])
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            conn.close()

            if user and user["role"] in {"staff", "admin"} and verify_password(password, user["password_hash"]):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                log_security_event(
                    "auth.login.success",
                    user["username"],
                    user["role"],
                    "success",
                    get_client_ip(),
                    request.path,
                    request.headers.get("User-Agent"),
                    database_path=app.config["DATABASE"],
                )
                return redirect(url_for("staff_dashboard"))

            log_security_event(
                "auth.login.failure",
                username,
                "staff",
                "failure",
                get_client_ip(),
                request.path,
                request.headers.get("User-Agent"),
                database_path=app.config["DATABASE"],
            )
            return render_template("login.html", role="staff", error="Invalid staff credentials.")

        return render_template("login.html", role="staff")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.route("/patient-dashboard")
    @login_required(required_role="patient")
    def patient_dashboard():
        conn = get_db_connection(app.config["DATABASE"])
        patient_name = session.get("full_name")
        appointments = conn.execute(
            "SELECT * FROM appointments WHERE patient_name = ? ORDER BY appointment_date ASC",
            (patient_name,),
        ).fetchall()
        conn.close()
        return render_template("patient_dashboard.html", appointments=appointments)

    @app.route("/staff-dashboard")
    @login_required(required_role="staff")
    def staff_dashboard():
        conn = get_db_connection(app.config["DATABASE"])
        recent_logins = conn.execute(
            "SELECT username, role, outcome, source_ip, request_path, created_at FROM login_attempts ORDER BY id DESC LIMIT 8"
        ).fetchall()
        appointments = conn.execute(
            "SELECT patient_name, service, doctor, appointment_date, visit_type FROM appointments ORDER BY appointment_date ASC LIMIT 10"
        ).fetchall()
        conn.close()
        return render_template("staff_dashboard.html", recent_logins=recent_logins, appointments=appointments)

    @app.route("/appointments", methods=["POST"])
    def appointments():
        patient_name = normalize_text(request.form.get("patient_name", ""), 120)
        phone = normalize_text(request.form.get("phone", ""), 40)
        service = normalize_text(request.form.get("service", ""), 120)
        doctor = normalize_text(request.form.get("doctor", ""), 120)
        appointment_date = normalize_text(request.form.get("appointment_date", ""), 20)
        visit_type = normalize_text(request.form.get("visit_type", ""), 40)
        notes = normalize_text(request.form.get("notes", ""), 500)

        if not all([patient_name, phone, service, doctor, appointment_date, visit_type]):
            return render_template("index.html", error="Please complete all required appointment fields.", appointments=[])

        conn = get_db_connection(app.config["DATABASE"])
        conn.execute(
            "INSERT INTO appointments (patient_name, phone, service, doctor, appointment_date, visit_type, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (patient_name, phone, service, doctor, appointment_date, visit_type, notes, _utc_now()),
        )
        conn.commit()
        conn.close()

        log_security_event(
            "appointment.booked",
            session.get("username"),
            session.get("role"),
            "success",
            get_client_ip(),
            "/appointments",
            request.headers.get("User-Agent"),
            database_path=app.config["DATABASE"],
        )

        return render_template("index.html", success="Your fictional appointment request has been scheduled successfully.", appointments=[])

    return app


ensure_database()
ensure_security_logs()
ensure_monitoring_files()
app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
