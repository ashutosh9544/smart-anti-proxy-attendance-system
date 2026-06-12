import sqlite3
from flask import Flask, request, jsonify, render_template, redirect, Response
import datetime
from datetime import datetime, timedelta
import uuid
import qrcode
import os
import csv
import socket

app = Flask(__name__, template_folder="static/templates")

# 🔹 DB connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# 🔹 Initialize DB
def init_db():
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
    expires_at TEXT
)
""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT,
        session_id INTEGER,
        timestamp TEXT,
        marked_by TEXT
    )
    """)

    conn.commit()
    conn.close()



@app.route("/export")
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
        data = ["student_id,name,timestamp\n"]
        for row in rows:
            data.append(f"{row['student_id']},{row['name']},{row['timestamp']}\n")
        return data

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=attendance.csv"})


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/mark", methods=["GET", "POST"])
def mark_page():
    token = request.args.get("token") or request.form.get("token")

    if not token:
        return "Invalid access ❌"

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Fetch session
    cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    session = cursor.fetchone()

    if not session:
        conn.close()
        return "Invalid token ❌"

    # 🔹 Check expiry
    if not session["expires_at"] or datetime.now() > datetime.fromisoformat(session["expires_at"]):
        conn.close()
        return "Token expired ❌"

    # 🔹 Check session still active
    if session["active"] == 0:
        conn.close()
        return "Token already used ❌"

    # =========================
    # 🟢 GET → Show page
    # =========================
    if request.method == "GET":
        conn.close()
        return render_template("mark.html", token=token)

    # =========================
    # 🔵 POST → Mark attendance
    # =========================
    student_id = request.form.get("student_id")

    if not student_id:
        conn.close()
        return "Student ID required ❌"

    # 🔹 Check student exists
    cursor.execute("SELECT * FROM students WHERE student_id = ?", (student_id,))
    student = cursor.fetchone()

    if not student:
        conn.close()
        return "Student not found ❌"

    # 🔹 Check duplicate attendance
    cursor.execute("""
        SELECT * FROM attendance 
        WHERE student_id = ? AND session_id = ?
    """, (student_id, session["id"]))

    existing = cursor.fetchone()

    if existing:
        conn.close()
        return "Already marked ❌"

    # 🔹 Insert attendance
    timestamp = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO attendance (student_id, session_id, timestamp)
        VALUES (?, ?, ?)
    """, (student_id, session["id"], timestamp))

    # 🔹 One-time token use — deactivate after marking
    cursor.execute("UPDATE sessions SET active = 0 WHERE token = ?", (token,))

    conn.commit()
    conn.close()

    return "Attendance marked successfully ✅"

@app.route("/student")
def student():
    return render_template("student.html")


# 🔹 Init DB route
@app.route("/init-db")
def initialize_database():
    init_db()
    return "Database initialized ✅"

@app.route("/students", methods=["GET"])
def get_students():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM students")
    students = cursor.fetchall()

    conn.close()

    # Convert to list of dictionaries
    result = []
    for student in students:
        result.append({
            "id": student["id"],
            "student_id": student["student_id"],
            "name": student["name"],
            "class": student["class"],
            "section": student["section"]
        })

    return jsonify(result)


@app.route("/scan")
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
                                   

@app.route("/mark-attendance", methods=["POST"])
def mark_attendance():
    data = request.get_json()

    student_id = data.get("student_id")
    token = data.get("token")

    if not student_id or not token:
        return jsonify({"error": "Missing data"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Check active session
    cursor.execute("""
        SELECT * FROM sessions 
        WHERE token = ? AND active = 1
    """, (token,))
    session = cursor.fetchone()

    if not session:
        conn.close()
        return jsonify({"error": "Invalid or expired session"}), 400

    session_id = session["id"]

    # 🔹 Check student exists
    cursor.execute("""
        SELECT * FROM students WHERE student_id = ?
    """, (student_id,))
    student = cursor.fetchone()

    if not student:
        conn.close()
        return jsonify({"error": "Student not found"}), 404

    # 🔹 Check duplicate attendance
    cursor.execute("""
        SELECT * FROM attendance 
        WHERE student_id = ? AND session_id = ?
    """, (student_id, session_id))

    already_marked = cursor.fetchone()

    if already_marked:
        conn.close()
        return jsonify({"error": "Attendance already marked"}), 400

    # 🔹 Mark attendance
    timestamp = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO attendance (student_id, session_id, timestamp, marked_by)
        VALUES (?, ?, ?, ?)
    """, (student_id, session_id, timestamp, "system"))

    # 🔹 Deactivate session after marking
    cursor.execute("UPDATE sessions SET active = 0 WHERE id = ?", (session_id,))

    conn.commit()
    conn.close()

    return jsonify({"message": "Attendance marked ✅"})


@app.route("/start-session", methods=["GET"])
def start_session():
    conn = get_db_connection()
    cursor = conn.cursor()

    # deactivate old sessions
    cursor.execute("UPDATE sessions SET active = 0")

    # create new session
    token = str(uuid.uuid4())
    start_time = datetime.now().isoformat()
    expiry_time = datetime.now() + timedelta(minutes=2)

    cursor.execute("""
        INSERT INTO sessions (start_time, active, token, expires_at)
        VALUES (?, 1, ?, ?)
    """, (start_time, token, expiry_time.isoformat()))

    conn.commit()
    session_id = cursor.lastrowid
    conn.close()

    # 🔹 Get current machine IP dynamically
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    # 🔹 Create QR URL
    qr_data = f"http://{local_ip}:5000/mark?token={token}"

    # 🔹 Ensure folder exists
    os.makedirs("static/qrcodes", exist_ok=True)

    # 🔹 Generate QR
    img = qrcode.make(qr_data)

    file_path = f"static/qrcodes/session_{session_id}.png"
    img.save(file_path)

    return jsonify({
        "message": "Session started ✅",
        "session_id": session_id,
        "token": token,
        "qr_code": file_path,
        "expires_at": expiry_time.isoformat()
    })


# 🔹 ADD STUDENT ROUTE (THIS IS THE PROBLEM FIX)
@app.route("/add-student", methods=["POST"])
def add_student():
    data = request.get_json()

    student_id = data.get("student_id")
    name = data.get("name")
    student_class = data.get("class")
    section = data.get("section")

    if not student_id or not name:
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
                       INSERT INTO students (student_id, name, class, section)
                       VALUES (?, ?, ?, ?)
                       """, (student_id, name, student_class, section))
        conn.commit()
    except:
        conn.close()
        return jsonify({"error": "Student already exists"}), 400

    conn.commit()
    conn.close()

    return jsonify({"message": "Student added successfully ✅"})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0")