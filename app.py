import sqlite3
from models.ml_predictor import predict_attendance
import logging
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, Response, session as flask_session)
from datetime import datetime, timedelta
import uuid
import json
import random
import qrcode
import threading
import re
from math import radians, sin, cos, sqrt, atan2
import hashlib
import time
import os
import socket
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Geofencing Configuration ────────────────────────────────────────────────

CAMPUS_LATITUDE = 21.1342
CAMPUS_LONGITUDE = 81.6684
GEOFENCE_RADIUS_METERS = 150

# ─── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="static/templates")

# Secret key: read from environment variable in production.
# The development fallback is intentionally weak — change it before deployment.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-before-production")

app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot read the cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Mitigates CSRF on same-site navigation
# SESSION_COOKIE_SECURE is intentionally NOT set to True here so the app
# works over plain HTTP during local development.

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── DB helpers ───────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
QRCODE_DIR = os.path.join(BASE_DIR, "static", "qrcodes")
CURRENT_QR_PATH = os.path.join(QRCODE_DIR, "current_qr.png")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn




def calculate_distance_meters(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two GPS coordinates using Haversine formula.
    Returns distance in meters.
    """

    R = 6371000  # Earth radius in meters

    lat1 = radians(float(lat1))
    lat2 = radians(float(lat2))

    dlat = lat2 - lat1
    dlon = radians(float(lon2) - float(lon1))

    a = (
        sin(dlat / 2) ** 2
        + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    )

    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c


def save_current_qr_image(qr_data):
    """Generate and overwrite the single active QR image used by the dashboard."""
    os.makedirs(QRCODE_DIR, exist_ok=True)
    img = qrcode.make(qr_data)
    img.save(CURRENT_QR_PATH)
    return "static/qrcodes/current_qr.png"

def detect_browser(user_agent):
    ua = user_agent or ""

    if "Edg/" in ua:
        return "Edge"
    if "Chrome/" in ua:
        return "Chrome"
    if "Firefox/" in ua:
        return "Firefox"
    if "Safari/" in ua and "Chrome/" not in ua:
        return "Safari"
    if "OPR/" in ua:
        return "Opera"

    return "Unknown"


def detect_browser_version(user_agent):
    ua = user_agent or ""

    patterns = [
        r"Edg/([\d.]+)",
        r"Chrome/([\d.]+)",
        r"Firefox/([\d.]+)",
        r"Version/([\d.]+).*Safari"
    ]

    for pattern in patterns:
        match = re.search(pattern, ua)

        if match:
            return match.group(1)

    return None


def detect_os(user_agent):
    ua = user_agent or ""

    if "Windows" in ua:
        return "Windows"

    if "Android" in ua:
        return "Android"

    if "iPhone" in ua or "iPad" in ua:
        return "iOS"

    if "Mac OS X" in ua:
        return "macOS"

    if "Linux" in ua:
        return "Linux"

    return "Unknown"


def detect_os_version(user_agent):
    ua = user_agent or ""

    if "Windows NT 10.0" in ua:
        return "10/11"

    match = re.search(r"Android ([\d.]+)", ua)
    if match:
        return match.group(1)

    match = re.search(r"(?:iPhone OS|CPU OS) ([\d_]+)", ua)
    if match:
        return match.group(1).replace("_", ".")

    match = re.search(r"Mac OS X ([\d_\.]+)", ua)
    if match:
        return match.group(1).replace("_", ".")

    return None

def generate_device_hash(device_data):
    """
    Generate a deterministic SHA-256 hash from browser/device data.
    """

    normalized = "|".join([
        str(device_data.get("user_agent", "")),
        str(device_data.get("platform", "")),
        str(device_data.get("screen_width", "")),
        str(device_data.get("screen_height", "")),
        str(device_data.get("language", "")),
        str(device_data.get("timezone", "")),
        str(device_data.get("device_type", "")),
    ])

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

def calculate_risk_score(
    duplicate_hash,
    duplicate_ip,
    duplicate_browser,
    duplicate_device,
    duplicate_session,
    scan_to_submit_time
):
    score = 0
    reasons = []

    if duplicate_hash:
        score += 40
        reasons.append("Same device fingerprint used by another student")

    if duplicate_device:
        score += 30
        reasons.append("Same device used by multiple students")

    if duplicate_ip:
        score += 15
        reasons.append("Same IP address used by another student")

    if duplicate_browser:
        score += 10
        reasons.append("Same browser/device information detected")

    if duplicate_session:
        score += 25
        reasons.append("Same device used by another student in this session")

    # Extremely fast submission
    if scan_to_submit_time is not None:
        try:
            scan_time = float(scan_to_submit_time)

            if scan_time < 3:
                score += 20
                reasons.append("Attendance submitted unusually quickly")

        except (TypeError, ValueError):
            pass

    # Maximum risk score = 100
    score = min(score, 100)

    if score >= 60:
        label = "HIGH_RISK"
    elif score >= 30:
        label = "MEDIUM_RISK"
    else:
        label = "NORMAL"

    return score, label, reasons


def init_db():
    logger.info("Initializing database schema using %s", DB_PATH)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        class TEXT,
        section TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time TEXT,
        end_time TEXT,
        active INTEGER DEFAULT 1,
        token TEXT,
        expires_at TEXT,
        pin TEXT
    )
    """)

    cursor.execute("PRAGMA table_info(sessions)")
    columns = [row[1] for row in cursor.fetchall()]

    if "pin" not in columns:
        logger.info("sessions table is missing pin; attempting ALTER TABLE")
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN pin TEXT")
            logger.info("ALTER TABLE sessions ADD COLUMN pin TEXT succeeded")
        except sqlite3.OperationalError as exc:
            logger.exception("ALTER TABLE sessions ADD COLUMN pin TEXT failed: %s", exc)
            if "duplicate column name" not in str(exc).lower():
                raise
    else:
        logger.info("sessions table already has pin column")

    try:
        cursor.execute("ALTER TABLE sessions ADD COLUMN current_qr_version INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE sessions ADD COLUMN last_qr_generated TEXT")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    session_id INTEGER,
    timestamp TEXT,
    marked_by TEXT,
    latitude REAL,
    longitude REAL,
    gps_accuracy REAL,
    distance_from_campus REAL,
    inside_geofence INTEGER DEFAULT 0
    )
    """)

    # Add GPS columns to existing attendance table if they don't exist
    attendance_gps_columns = [
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("gps_accuracy", "REAL"),
        ("distance_from_campus", "REAL"),
        ("inside_geofence", "INTEGER DEFAULT 0")
    ]

    for column_name, column_type in attendance_gps_columns:
        try:
            cursor.execute(
                f"ALTER TABLE attendance ADD COLUMN {column_name} {column_type}"
            )
        except sqlite3.OperationalError:
            pass

    # 🔹 Teachers table — created only if it does not already exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        teacher_id TEXT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 🔹 Future ML training tables for proxy-attendance detection.
    # Kept separate from the active attendance table so the existing attendance flow remains unchanged.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attendance_id INTEGER,
        student_id TEXT,
        session_id INTEGER,
        fingerprint_hash TEXT,
        browser TEXT,
        browser_version TEXT,
        os TEXT,
        os_version TEXT,
        device_type TEXT,
        screen_width INTEGER,
        screen_height INTEGER,
        language TEXT,
        timezone TEXT,
        user_agent TEXT,
        ip_address TEXT,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attendance_features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attendance_id INTEGER,
        student_id TEXT,
        session_id INTEGER,
        qr_version INTEGER,
        pin_correct INTEGER,
        typing_time REAL,
        scan_to_submit_time REAL,
        fingerprint_hash TEXT,
        duplicate_hash INTEGER,
        duplicate_ip INTEGER,
        duplicate_browser INTEGER,
        duplicate_device INTEGER,
        duplicate_session INTEGER,
        risk_score INTEGER,
        rule_label TEXT,
        teacher_label TEXT,
        created_at TEXT
    )
    """)

    # GPS / Geofencing fields
    gps_columns = [
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("gps_accuracy", "REAL"),
        ("distance_from_campus", "REAL"),
        ("inside_geofence", "INTEGER DEFAULT 0")
    ]

    for column_name, column_type in gps_columns:
        try:
            cursor.execute(
                f"ALTER TABLE attendance_features ADD COLUMN {column_name} {column_type}"
            )
        except sqlite3.OperationalError:
            pass


    
        # ML prediction fields
    ml_columns = [
        ("ml_prediction", "INTEGER"),
        ("ml_probability", "REAL"),
        ("ml_risk_level", "TEXT")
    ]

    for column_name, column_type in ml_columns:
        try:
            cursor.execute(
                f"ALTER TABLE attendance_features ADD COLUMN {column_name} {column_type}"
            )
        except sqlite3.OperationalError:
            pass


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS qr_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        qr_version INTEGER,
        generated_at TEXT,
        expires_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS suspicious_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attendance_id INTEGER,
        student_id TEXT,
        session_id INTEGER,
        severity TEXT,
        reason TEXT,
        resolved INTEGER DEFAULT 0,
        teacher_decision TEXT,
        created_at TEXT
    )
    """)

    conn.commit()

    # 🔹 Create default dev teacher account if no teacher exists yet.
    # Credentials come from environment variables when available.
    # The plain-text password is never stored — only its hash is saved.
    cursor.execute("SELECT COUNT(*) FROM teachers")
    if cursor.fetchone()[0] == 0:
        default_username = os.environ.get("TEACHER_USERNAME", "teacher")
        default_password = os.environ.get("TEACHER_PASSWORD", "admin123")
        hashed = generate_password_hash(default_password)
        created_at = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO teachers (username, password_hash, name, created_at) VALUES (?, ?, ?, ?)",
            (default_username, hashed, "Default Teacher", created_at)
        )
        conn.commit()
        logger.info(
            "Dev teacher account created. "
            "Username: '%s'. Set TEACHER_USERNAME / TEACHER_PASSWORD env vars to override.",
            default_username
        )

    conn.close()


# ─── Authentication helpers ───────────────────────────────────────────────────

def is_teacher_logged_in():
    """Return True if the current Flask session has a valid teacher id."""
    return "teacher_id" in flask_session


def login_required(f):
    """
    Decorator that protects teacher-only routes.
    - HTML pages  → redirect to /login
    - JSON / API  → return 401 JSON {"success": false, "error": "Authentication required"}
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_teacher_logged_in():
            # Detect API requests by Accept header or endpoint convention
            wants_json = (
                request.accept_mimetypes.best == "application/json"
                or request.content_type == "application/json"
            )
            if wants_json:
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    # Already logged in → go straight to dashboard
    if is_teacher_logged_in():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM teachers WHERE username = ?", (username,))
        teacher = cursor.fetchone()
        conn.close()

        # Use a single generic message — never reveal which field was wrong
        if teacher and check_password_hash(teacher["password_hash"], password):
            flask_session.clear()
            flask_session["teacher_id"] = teacher["id"]
            flask_session["teacher_name"] = teacher["name"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    flask_session.clear()
    return redirect(url_for("login_page"))

@app.route("/label-attendance/<int:attendance_id>", methods=["POST"])
@login_required
def label_attendance(attendance_id):

    data = request.get_json(silent=True) or {}

    label = data.get("label")

    if label not in [0, 1]:
        return jsonify({
            "error": "Invalid label"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            UPDATE attendance_features
            SET teacher_label = ?
            WHERE attendance_id = ?
        """, (
            str(label),
            attendance_id
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Training label saved"
        })

    finally:
        conn.close()


@app.route("/add-teacher", methods=["POST"])
@login_required
def add_teacher():
    """Add a new teacher account. Requires an authenticated teacher session."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be JSON"}), 400

    # Extract and strip fields
    teacher_id = str(data.get("teacher_id", "") or "").strip()
    name       = str(data.get("name",       "") or "").strip()
    username   = str(data.get("username",   "") or "").strip()
    password   = str(data.get("password",   "") or "").strip()

    # Validation
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not name:
        return jsonify({"error": "Name is required"}), 400
    if len(username) > 50:
        return jsonify({"error": "Username must be 50 characters or fewer"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    password_hash = generate_password_hash(password)
    created_at    = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO teachers (teacher_id, username, password_hash, name, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (teacher_id or None, username, password_hash, name, created_at))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "A teacher with that username already exists"}), 400
    except sqlite3.Error as e:
        conn.close()
        logger.error("DB error in add_teacher: %s", e)
        return jsonify({"error": "Database error. Please try again."}), 500

    new_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "message": "Teacher added successfully ✅",
        "id": new_id,
        "teacher_id": teacher_id or None,
        "username": username,
        "name": name
    })


# ─── Teacher routes (protected) ───────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", teacher_name=flask_session.get("teacher_name", ""))


@app.route("/manage-students")
@login_required
def manage_students():
    return render_template(
        "manage_students.html",
        teacher_name=flask_session.get("teacher_name", "")
    )

@app.route("/attendance-sessions", methods=["GET"])
@login_required
def get_attendance_sessions():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                sessions.id,
                sessions.start_time,
                sessions.end_time,
                sessions.active,
                sessions.expires_at,
                COUNT(attendance.id) AS present_count
            FROM sessions
            LEFT JOIN attendance
                ON sessions.id = attendance.session_id
            GROUP BY
                sessions.id,
                sessions.start_time,
                sessions.end_time,
                sessions.active,
                sessions.expires_at
            ORDER BY sessions.id DESC
        """)

        sessions = cursor.fetchall()

        result = []

        for session_row in sessions:
            result.append({
                "id": session_row["id"],
                "start_time": session_row["start_time"],
                "end_time": session_row["end_time"],
                "active": session_row["active"],
                "expires_at": session_row["expires_at"],
                "present_count": session_row["present_count"]
            })

        return jsonify({
            "success": True,
            "sessions": result
        })

    except sqlite3.Error as e:
        logger.error(
            "Database error while fetching attendance sessions: %s",
            e
        )

        return jsonify({
            "success": False,
            "error": "Could not load attendance sessions."
        }), 500

    finally:
        conn.close()

@app.route("/attendance-session/<int:session_id>", methods=["GET"])
@login_required
def get_attendance_session_details(session_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if session exists
        cursor.execute("""
            SELECT
                id,
                start_time,
                end_time,
                active,
                expires_at
            FROM sessions
            WHERE id = ?
        """, (session_id,))

        session_row = cursor.fetchone()

        if session_row is None:
            return jsonify({
                "success": False,
                "error": "Attendance session not found."
            }), 404

        # Get students who attended this session
        cursor.execute("""
            SELECT
                attendance.student_id,
                students.name,
                students.class,
                students.section,
                attendance.timestamp,
                attendance.marked_by
            FROM attendance
            INNER JOIN students
                ON attendance.student_id = students.student_id
            WHERE attendance.session_id = ?
            ORDER BY attendance.timestamp ASC
        """, (session_id,))

        attendance_rows = cursor.fetchall()

        students = []

        for row in attendance_rows:
            students.append({
                "student_id": row["student_id"],
                "name": row["name"],
                "class": row["class"],
                "section": row["section"],
                "timestamp": row["timestamp"],
                "marked_by": row["marked_by"]
            })

        return jsonify({
            "success": True,
            "session": {
                "id": session_row["id"],
                "start_time": session_row["start_time"],
                "end_time": session_row["end_time"],
                "active": session_row["active"],
                "expires_at": session_row["expires_at"]
            },
            "present_count": len(students),
            "students": students
        })

    except sqlite3.Error as e:
        logger.error(
            "Database error while fetching attendance session %s: %s",
            session_id,
            e
        )

        return jsonify({
            "success": False,
            "error": "Could not load attendance details."
        }), 500

    finally:
        conn.close()


def generate_all_qrs(session_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT token
            FROM sessions
            WHERE id = ?
        """, (session_id,))

        session = cursor.fetchone()

        if session is None:
            return []

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        os.makedirs("static/qrcodes", exist_ok=True)

        qr_paths = []

        # Generate all 6 QR codes in advance
        for version in range(1, 7):

            qr_data = (
                f"http://{local_ip}:5000/mark"
                f"?token={session['token']}"
                f"&version={version}"
            )

            file_path = f"static/qrcodes/qr_{version}.png"

            img = qrcode.make(qr_data)
            img.save(file_path)

            qr_paths.append(file_path)

        cursor.execute("""
            UPDATE sessions
            SET current_qr_version = 1,
                last_qr_generated = ?
            WHERE id = ?
        """, (
            datetime.now().isoformat(),
            session_id
        ))

        conn.commit()

        return qr_paths

    finally:
        conn.close()


def qr_rotation_worker(session_id):
    while True:
        time.sleep(20)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT active, expires_at, current_qr_version
                FROM sessions
                WHERE id = ?
            """, (session_id,))

            session = cursor.fetchone()

            if session is None:
                break

            if session["active"] == 0:
                break

            if datetime.now() >= datetime.fromisoformat(session["expires_at"]):
                cursor.execute("""
                    UPDATE sessions
                    SET active = 0
                    WHERE id = ?
                """, (session_id,))

                conn.commit()
                break

            current_version = session["current_qr_version"]

            if current_version >= 6:
                break

            new_version = current_version + 1

            cursor.execute("""
                UPDATE sessions
                SET current_qr_version = ?,
                    last_qr_generated = ?
                WHERE id = ?
            """, (
                new_version,
                datetime.now().isoformat(),
                session_id
            ))

            conn.commit()

        except sqlite3.Error as e:
            logger.error(
                "QR rotation error for session %s: %s",
                session_id,
                e
            )

            break

        finally:
            conn.close()

@app.route("/start-session", methods=["GET"])
@login_required
def start_session():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Deactivate old sessions
        cursor.execute("UPDATE sessions SET active = 0 WHERE active = 1")

        # Create new session
        token = str(uuid.uuid4())
        start_time = datetime.now().isoformat()

        expiry_time = datetime.now() + timedelta(minutes=2)
        expires_at = expiry_time.isoformat()

        end_time= expires_at
        current_qr_version = 1
        pin = f"{random.randint(1000, 9999)}"

        cursor.execute("""
        INSERT INTO sessions (
        start_time,
        end_time,
        active,
        token,
        expires_at,
        pin,
        current_qr_version,
        last_qr_generated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
        start_time,
        end_time,
        1,
        token,
        expires_at,
        pin,
        current_qr_version,
        datetime.now().isoformat()
        ))
        conn.commit()

        session_id = cursor.lastrowid

        qr_paths = generate_all_qrs(session_id)

        threading.Thread(
            target=qr_rotation_worker,
            args=(session_id,),
            daemon=True
        ).start()


        return jsonify({
            "success": True,
            "message": "Session started ✅",
            "session_id": session_id,
            "token": token,
            "qr_code": qr_paths[0] if qr_paths else None,
            "expires_at": expiry_time.isoformat(),
            "pin": pin
        })
    finally:
        conn.close()


@app.route("/resolve-suspicious/<int:event_id>", methods=["POST"])
@login_required
def resolve_suspicious(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE suspicious_events
            SET resolved = 1,
                teacher_decision = 'reviewed'
            WHERE id = ?
        """, (event_id,))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Suspicious event resolved."
        })

    finally:
        conn.close()

@app.route("/attendance-records")
@login_required
def attendance_records():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                attendance.id,
                attendance.student_id,
                students.name,
                students.class,
                students.section,
                attendance.session_id,
                attendance.timestamp,
                attendance.marked_by
            FROM attendance
            LEFT JOIN students
                ON attendance.student_id = students.student_id
            ORDER BY attendance.timestamp DESC
        """)

        records = cursor.fetchall()

        return render_template(
            "attendance_records.html",
            records=records
        )

    finally:
        conn.close()

@app.route("/students", methods=["GET"])
@login_required
def get_students():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students")
    students = cursor.fetchall()
    conn.close()

    result = []
    for s in students:
        result.append({
            "id": s["id"],
            "student_id": s["student_id"],
            "name": s["name"],
            "class": s["class"],
            "section": s["section"]
        })
    return jsonify(result)

   
@app.route("/add-student", methods=["POST"])
@login_required
def add_student():
    # Safely parse JSON body — return 400 if body is missing or not valid JSON
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be JSON"}), 400

    # Strip whitespace from all expected text fields
    student_id    = str(data.get("student_id",    "") or "").strip()
    name          = str(data.get("name",           "") or "").strip()
    student_class = str(data.get("class",          "") or "").strip()
    section       = str(data.get("section",        "") or "").strip()

    # Validation — required fields
    if not student_id:
        return jsonify({"error": "Student ID is required"}), 400
    if not name:
        return jsonify({"error": "Student name is required"}), 400

    # Validation — length limits
    if len(student_id) > 50:
        return jsonify({"error": "Student ID must be 50 characters or fewer"}), 400
    if len(name) > 100:
        return jsonify({"error": "Student name must be 100 characters or fewer"}), 400
    if len(student_class) > 50:
        return jsonify({"error": "Class must be 50 characters or fewer"}), 400
    if len(section) > 20:
        return jsonify({"error": "Section must be 20 characters or fewer"}), 400

    # Store None for optional fields that are empty after stripping
    student_class = student_class or None
    section       = section or None

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO students (student_id, name, class, section)
            VALUES (?, ?, ?, ?)
        """, (student_id, name, student_class, section))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "A student with that ID already exists"}), 400
    except sqlite3.Error as e:
        conn.close()
        logger.error("Unexpected DB error in add_student: %s", e)
        return jsonify({"error": "Database error. Please try again."}), 500

    conn.close()
    return jsonify({"message": "Student added successfully ✅"})


@app.route("/export")
@login_required
def export_attendance():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT students.student_id, students.name, attendance.timestamp
        FROM attendance
        JOIN students ON students.student_id = attendance.student_id
    """)

    rows = cursor.fetchall()
    conn.close()

    def generate():
        yield "student_id,name,timestamp\n"
        for row in rows:
            yield f"{row['student_id']},{row['name']},{row['timestamp']}\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=attendance.csv"})


@app.route("/init-db")
@login_required
def initialize_database():
    init_db()
    return "Database initialized ✅"


@app.route("/suspicious-attendance")
@login_required
def suspicious_attendance():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                se.id,
                se.attendance_id,
                se.student_id,
                se.session_id,
                se.severity,
                se.reason,
                se.resolved,
                se.teacher_decision,
                se.created_at,
                af.risk_score
            FROM suspicious_events se
            LEFT JOIN attendance_features af
                ON se.attendance_id = af.attendance_id
            ORDER BY se.created_at DESC
        """)

        events = [dict(row) for row in cursor.fetchall()]

        return render_template(
            "suspicious_attendance.html",
            events=events
        )

    finally:
        conn.close()

@app.route("/dashboard-stats", methods=["GET"])
@login_required
def dashboard_stats():

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("SELECT COUNT(*) AS total FROM students")
        total_students = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM sessions")
        total_sessions = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM attendance")
        total_attendance = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT id, start_time, active
            FROM sessions
            ORDER BY id DESC
            LIMIT 1
        """)

        last_session = cursor.fetchone()

        return jsonify({
            "success": True,
            "total_students": total_students,
            "total_sessions": total_sessions,
            "total_attendance": total_attendance,
            "active_session": (
                last_session["active"] if last_session else 0
            ),
            "last_session": (
                last_session["start_time"] if last_session else None
            )
        })

    finally:
        conn.close()


@app.route("/scan")
@login_required
def scan():
    token = str(uuid.uuid4())
    expiry = datetime.now() + timedelta(seconds=30)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sessions (token, expires_at, active)
        VALUES (?, ?, 1)
    """, (token, expiry.isoformat()))
    conn.commit()
    conn.close()

    return redirect(f"/mark?token={token}")


# ─── Public routes ────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/student")
def student():
    return render_template("student.html")


@app.route("/mark", methods=["GET"])
def mark_page():
    token = request.args.get("token")
    version = request.args.get("version", type=int)    #lavanyaislove 

    if not token:
        return "Invalid access ❌"

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        session = cursor.fetchone()

        if not session:
            return "Invalid token ❌"

        if not session["expires_at"] or datetime.now() > datetime.fromisoformat(session["expires_at"]):
            cursor.execute("UPDATE sessions SET active = 0 WHERE id = ?", (session["id"],))
            conn.commit()
            return "Session expired ❌"

        if session["active"] == 0:
            return "Session is no longer active ❌"

        current_qr_version = session["current_qr_version"]
        if version is None or version != current_qr_version:
            return "QR Code has expired. Please scan the latest QR. ❌"

        return render_template("mark.html", token=token, version=current_qr_version)
    finally:
        conn.close()

@app.route("/mark-attendance", methods=["POST"])
def mark_attendance():
    data = request.get_json(silent=True) or {}

    student_id = str(data.get("student_id", "") or "").strip()
    token = str(data.get("token", "") or "").strip()
    version = data.get("version")

    # GPS data
    latitude = data.get("latitude")
    longitude = data.get("longitude")
    gps_accuracy = data.get("gps_accuracy")
    device_data = data.get("device_data") or {}

    if (
        not student_id
        or not token
        or version is None
        or latitude is None
        or longitude is None
        or gps_accuracy is None
        ):
          return jsonify({"error": "Student ID, QR and GPS location are required"}), 400

    try:
        latitude = float(latitude)
        longitude = float(longitude)
        gps_accuracy = float(gps_accuracy)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid GPS data"}), 400

    try:
        version = int(version)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid QR version"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # -------------------------------------------------
        # 1. Find session
        # -------------------------------------------------
        cursor.execute(
            "SELECT * FROM sessions WHERE token = ?",
            (token,)
        )
        session = cursor.fetchone()

        if not session:
            return jsonify({"error": "Invalid token"}), 400

        # -------------------------------------------------
        # 2. Check session active
        # -------------------------------------------------
        if session["active"] == 0:
            return jsonify({
                "error": "Session is no longer active"
            }), 400

        # -------------------------------------------------
        # 3. Check session expiry
        # -------------------------------------------------
        if (
            not session["expires_at"]
            or datetime.now() > datetime.fromisoformat(
                session["expires_at"]
            )
        ):
            cursor.execute(
                "UPDATE sessions SET active = 0 WHERE id = ?",
                (session["id"],)
            )
            conn.commit()

            return jsonify({
                "error": "Session has expired"
            }), 400

        # -------------------------------------------------
        # 4. Check QR version
        # -------------------------------------------------
        if version != session["current_qr_version"]:
            return jsonify({
                "error": "QR Code has expired. Please scan the latest QR."
            }), 400

        # ─── Geofence validation ───────────────────────────────────────────────

        distance_from_campus = calculate_distance_meters(
            latitude,
            longitude,
            CAMPUS_LATITUDE,
            CAMPUS_LONGITUDE
        )

        inside_geofence = distance_from_campus <= GEOFENCE_RADIUS_METERS

        if not inside_geofence:
            return jsonify({
                "error": "You are outside the allowed attendance area ❌",
                "distance": round(distance_from_campus, 2)
            }), 403

        session_id = session["id"]

        # -------------------------------------------------
        # 5. Check student exists
        # -------------------------------------------------
        cursor.execute(
            "SELECT * FROM students WHERE student_id = ?",
            (student_id,)
        )
        student = cursor.fetchone()

        if not student:
            return jsonify({
                "error": "Student not found"
            }), 404

        # -------------------------------------------------
        # 6. Prevent duplicate attendance
        # -------------------------------------------------
        cursor.execute("""
            SELECT *
            FROM attendance
            WHERE student_id = ?
            AND session_id = ?
        """, (student_id, session_id))

        if cursor.fetchone():
            return jsonify({
                "error": "Attendance already marked"
            }), 400

        # -------------------------------------------------
        # 7. Generate device fingerprint hash
        # -------------------------------------------------
        fingerprint_hash = generate_device_hash(device_data)

        # -------------------------------------------------
        # 8. Get IP address from server request
        # -------------------------------------------------
        ip_address = request.remote_addr

        # -------------------------------------------------
        # 9. Extract browser/device information
        # -------------------------------------------------
        user_agent = device_data.get("user_agent", "")
        platform = device_data.get("platform", "")
        screen_width = device_data.get("screen_width")
        screen_height = device_data.get("screen_height")
        language = device_data.get("language")
        timezone = device_data.get("timezone")
        device_type = device_data.get("device_type")

        typing_time = device_data.get("typing_time")
        scan_to_submit_time = device_data.get("scan_to_submit_time")

        browser = detect_browser(user_agent)
        browser_version = detect_browser_version(user_agent)

        os_name = detect_os(user_agent)
        os_version = detect_os_version(user_agent)

        # -------------------------------------------------
        # 10. Basic duplicate-device checks
        # -------------------------------------------------

        duplicate_hash = 0
        duplicate_ip = 0
        duplicate_browser = 0
        duplicate_device = 0
        duplicate_session = 0

        if cursor.fetchone():
            duplicate_session = 1

                # -------------------------------------------------
        # 10B. Final rule-based risk calculation
        # -------------------------------------------------

        risk_score, rule_label, risk_reasons = calculate_risk_score(
            duplicate_hash,
            duplicate_ip,
            duplicate_browser,
            duplicate_device,
            duplicate_session,
            scan_to_submit_time
        )


                # -------------------------------------------------
        # 10C. ML anti-proxy prediction
        # -------------------------------------------------

        ml_features = {
            "qr_version": version,
            "pin_correct": 1 if data.get("pin_correct") else 0,
            "typing_time": typing_time,
            "scan_to_submit_time": scan_to_submit_time,
            "duplicate_hash": duplicate_hash,
            "duplicate_ip": duplicate_ip,
            "duplicate_browser": duplicate_browser,
            "duplicate_device": duplicate_device,
            "duplicate_session": duplicate_session,
            "gps_accuracy": gps_accuracy,
            "distance_from_campus": distance_from_campus
        }

        ml_result = predict_attendance(ml_features)

        ml_prediction = ml_result["prediction"]
        ml_probability = ml_result["suspicious_probability"]
        ml_risk_level = ml_result["risk_level"]

        # Same fingerprint used by another student
        cursor.execute("""
            SELECT id, student_id
            FROM device_fingerprints
            WHERE fingerprint_hash = ?
            AND student_id != ?
            LIMIT 1
        """, (fingerprint_hash, student_id))

        if cursor.fetchone():
            duplicate_hash = 1
            duplicate_device = 1

        # Same IP used by another student
        cursor.execute("""
            SELECT id, student_id
            FROM device_fingerprints
            WHERE ip_address = ?
            AND student_id != ?
            LIMIT 1
        """, (ip_address, student_id))

        if cursor.fetchone():
            duplicate_ip = 1

        # Same browser characteristics used by another student
        cursor.execute("""
            SELECT id, student_id
            FROM device_fingerprints
            WHERE user_agent = ?
            AND platform = ?
            AND student_id != ?
            LIMIT 1
        """, (
            user_agent,
            platform,
            student_id
        ))

        if cursor.fetchone():
            duplicate_browser = 1

        # Same device/fingerprint used by multiple students
        cursor.execute("""
            SELECT id
            FROM device_fingerprints
            WHERE fingerprint_hash = ?
            AND session_id = ?
            AND student_id != ?
            LIMIT 1
        """, (
            fingerprint_hash,
            session_id,
            student_id
        ))

        if cursor.fetchone():
            duplicate_session = 1

        # -------------------------------------------------
        # 11. Mark attendance
        # -------------------------------------------------
        timestamp = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO attendance (
                student_id,
                session_id,
                timestamp,
                marked_by,
                latitude,
                longitude,
                gps_accuracy,
                distance_from_campus,
                inside_geofence
        )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            student_id,
            session_id,
            timestamp,
            "student",
            latitude,
            longitude,
            gps_accuracy,
            distance_from_campus,
            1
        ))

        attendance_id = cursor.lastrowid

        # -------------------------------------------------
        # 12. Save device fingerprint
        # -------------------------------------------------
        cursor.execute("""
            INSERT INTO device_fingerprints (
                attendance_id,
                student_id,
                session_id,
                fingerprint_hash,
                browser,
                browser_version,
                os,
                os_version,
                device_type,
                screen_width,
                screen_height,
                language,
                timezone,
                user_agent,
                ip_address,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            attendance_id,
            student_id,
            session_id,
            fingerprint_hash,
            browser,
            browser_version,
            os_name,
            os_version,
            device_type,
            screen_width,
            screen_height,
            language,
            timezone,
            user_agent,
            ip_address,
            timestamp
        ))

               # -------------------------------------------------
        # 13. Save ML features + ML prediction
        # -------------------------------------------------

        cursor.execute("""
            INSERT INTO attendance_features (
                attendance_id,
                student_id,
                session_id,
                qr_version,
                pin_correct,
                typing_time,
                scan_to_submit_time,
                fingerprint_hash,
                duplicate_hash,
                duplicate_ip,
                duplicate_browser,
                duplicate_device,
                duplicate_session,
                risk_score,
                rule_label,
                teacher_label,
                created_at,
                latitude,
                longitude,
                gps_accuracy,
                distance_from_campus,
                inside_geofence,
                ml_prediction,
                ml_probability,
                ml_risk_level
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            attendance_id,
            student_id,
            session_id,
            version,
            1 if data.get("pin_correct") else 0,
            typing_time,
            scan_to_submit_time,
            fingerprint_hash,
            duplicate_hash,
            duplicate_ip,
            duplicate_browser,
            duplicate_device,
            duplicate_session,
            risk_score,
            rule_label,
            None,
            timestamp,
            latitude,
            longitude,
            gps_accuracy,
            distance_from_campus,
            inside_geofence,
            ml_prediction,
            ml_probability,
            ml_risk_level
        ))



        if risk_score >= 30:
            reason_text = "; ".join(risk_reasons)

            cursor.execute("""
                INSERT INTO suspicious_events (
                    attendance_id,
                    student_id,
                    session_id,
                    severity,
                    reason,
                    resolved,
                    teacher_decision,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attendance_id,
                student_id,
                session_id,
                rule_label,
                reason_text,
                0,
                None,
                timestamp
            ))

                # -------------------------------------------------
        # 13B. ML suspicious event
        # -------------------------------------------------

        if ml_prediction == 1 and ml_probability >= 0.50:

            ml_reason = (
                f"ML model detected suspicious attendance "
                f"(probability={ml_probability:.2%}, "
                f"risk={ml_risk_level})"
            )

            # Avoid creating a second event if the rule engine
            # already flagged the same attendance.
            cursor.execute("""
                SELECT id
                FROM suspicious_events
                WHERE attendance_id = ?
                LIMIT 1
            """, (attendance_id,))

            existing_event = cursor.fetchone()

            if existing_event:

                cursor.execute("""
                    UPDATE suspicious_events
                    SET reason = reason || ?,
                        severity = CASE
                            WHEN severity = 'HIGH_RISK'
                            THEN severity
                            ELSE ?
                        END
                    WHERE attendance_id = ?
                """, (
                    " | " + ml_reason,
                    ml_risk_level,
                    attendance_id
                ))

            else:

                cursor.execute("""
                    INSERT INTO suspicious_events (
                        attendance_id,
                        student_id,
                        session_id,
                        severity,
                        reason,
                        resolved,
                        teacher_decision,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    attendance_id,
                    student_id,
                    session_id,
                    ml_risk_level,
                    ml_reason,
                    0,
                    None,
                    timestamp
                ))

        # -------------------------------------------------
        # 14. Save everything
        # -------------------------------------------------
        conn.commit()

        return jsonify({
            "message": "Attendance marked successfully ✅",
            "ml": {
                "prediction": ml_prediction,
                "suspicious_probability": ml_probability,
                "risk_level": ml_risk_level
            },
            "rule_engine": {
                "risk_score": risk_score,
                "rule_label": rule_label
            }
        })

    except Exception:
        conn.rollback()
        logger.exception("Error while marking attendance")

        return jsonify({
            "error": "Could not mark attendance."
        }), 500

    finally:
        conn.close()
    



# ─── Entry point ──────────────────────────────────────────────────────────────


init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )