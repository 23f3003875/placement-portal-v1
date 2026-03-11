"""
=============================================================
  PLACEMENT PORTAL - app.py  (single backend file)
=============================================================
  Run:   python app.py
  Visit: http://127.0.0.1:5000
  Admin: admin@placement.com / admin123
=============================================================
"""

import os
import sqlite3
from datetime import date
from functools import wraps

from flask import (Flask, g, render_template, redirect,
                   url_for, flash, request, session)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# =============================================================
#  APP SETUP
# =============================================================
app = Flask(__name__)
app.secret_key = "placement_portal_secret_2024"
app.config["DATABASE"]      = os.path.join(app.root_path, "placement_portal.db")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads", "resumes")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}


# =============================================================
#  DATABASE
# =============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"],
                               detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS user (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL CHECK(role IN ('admin','company','student')),
            is_active  INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS company_profile (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES user(id),
            company_name    TEXT    NOT NULL,
            hr_contact      TEXT,
            website         TEXT,
            industry        TEXT,
            description     TEXT,
            approval_status TEXT NOT NULL DEFAULT 'pending'
                CHECK(approval_status IN ('pending','approved','rejected','blacklisted'))
        );

        CREATE TABLE IF NOT EXISTS student_profile (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL REFERENCES user(id),
            roll_number    TEXT    UNIQUE,
            branch         TEXT,
            semester       TEXT,
            cgpa           REAL,
            phone          TEXT,
            resume_file    TEXT,
            skills         TEXT,
            is_blacklisted INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS placement_drive (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id           INTEGER NOT NULL REFERENCES company_profile(id),
            job_title            TEXT    NOT NULL,
            job_description      TEXT    NOT NULL,
            eligibility_criteria TEXT,
            package              TEXT,
            location             TEXT,
            application_deadline TEXT    NOT NULL,
            status               TEXT    NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','approved','rejected','closed')),
            created_at           TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS application (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES student_profile(id),
            drive_id   INTEGER NOT NULL REFERENCES placement_drive(id),
            applied_at TEXT    DEFAULT (datetime('now')),
            status     TEXT    NOT NULL DEFAULT 'applied'
                CHECK(status IN ('applied','shortlisted','selected','rejected')),
            cover_note TEXT,
            UNIQUE(student_id, drive_id)
        );
    """)
    db.commit()

    # Seed admin if not present
    if not db.execute("SELECT id FROM user WHERE role='admin' LIMIT 1").fetchone():
        db.execute(
            "INSERT INTO user (name, email, password, role, is_active) VALUES (?,?,?,?,?)",
            ("Admin", "admin@placement.com",
             generate_password_hash("admin123"), "admin", 1),
        )
        db.commit()


# =============================================================
#  DECORATORS
# =============================================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_role") != "admin":
            flash("Admins only.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def company_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_role") != "company":
            flash("Access denied.", "danger")
            return redirect(url_for("login"))
        db = get_db()
        cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                        (session["user_id"],)).fetchone()
        if not cp or cp["approval_status"] != "approved":
            flash("Your account is pending admin approval.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_role") != "student":
            flash("Access denied.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# =============================================================
#  AUTH ROUTES
# =============================================================
@app.route("/")
def home():
    if session.get("user_id"):
        return _dashboard_redirect()
    return render_template("auth/home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return _dashboard_redirect()

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db       = get_db()
        user     = db.execute("SELECT * FROM user WHERE email=?", (email,)).fetchone()

        if not user or not check_password_hash(user["password"], password):
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html")

        if not user["is_active"]:
            flash("Your account is deactivated. Contact admin.", "danger")
            return render_template("auth/login.html")

        if user["role"] == "company":
            cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                            (user["id"],)).fetchone()
            if not cp or cp["approval_status"] != "approved":
                flash("Your company registration is pending admin approval.", "warning")
                return render_template("auth/login.html")

        session.clear()
        session["user_id"]   = user["id"]
        session["user_role"] = user["role"]
        session["user_name"] = user["name"]
        flash(f"Welcome back, {user['name']}!", "success")
        return _dashboard_redirect()

    return render_template("auth/login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return _dashboard_redirect()

    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "")
        db       = get_db()

        if not all([name, email, password, confirm, role]):
            flash("All fields are required.", "danger")
            return render_template("auth/register.html")
        if role not in ("company", "student"):
            flash("Invalid role.", "danger")
            return render_template("auth/register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("auth/register.html")
        if db.execute("SELECT id FROM user WHERE email=?", (email,)).fetchone():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html")

        cur = db.execute(
            "INSERT INTO user (name, email, password, role, is_active) VALUES (?,?,?,?,?)",
            (name, email, generate_password_hash(password), role, 1),
        )
        db.commit()
        user_id = cur.lastrowid

        if role == "company":
            company_name = request.form.get("company_name", "").strip()
            if not company_name:
                db.execute("DELETE FROM user WHERE id=?", (user_id,))
                db.commit()
                flash("Company name is required.", "danger")
                return render_template("auth/register.html")
            db.execute(
                """INSERT INTO company_profile
                   (user_id, company_name, hr_contact, website, industry, approval_status)
                   VALUES (?,?,?,?,?,'pending')""",
                (user_id,
                 company_name,
                 request.form.get("hr_contact", "").strip(),
                 request.form.get("website", "").strip(),
                 request.form.get("industry", "").strip()),
            )
            db.commit()
            flash("Registered! Please wait for admin approval before logging in.", "info")
        else:
            roll_number = request.form.get("roll_number", "").strip() or None
            if roll_number:
                if db.execute("SELECT id FROM student_profile WHERE roll_number=?",
                              (roll_number,)).fetchone():
                    db.execute("DELETE FROM user WHERE id=?", (user_id,))
                    db.commit()
                    flash("Roll number already registered.", "danger")
                    return render_template("auth/register.html")
            db.execute(
                "INSERT INTO student_profile (user_id, roll_number, branch, phone) VALUES (?,?,?,?)",
                (user_id,
                 roll_number,
                 request.form.get("branch", "").strip() or None,
                 request.form.get("phone", "").strip() or None),
            )
            db.commit()
            flash("Registered successfully! You can now log in.", "success")

        return redirect(url_for("login"))

    return render_template("auth/register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


def _dashboard_redirect():
    role = session.get("user_role")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "company":
        return redirect(url_for("company_dashboard"))
    return redirect(url_for("student_dashboard"))


# =============================================================
#  ADMIN ROUTES
# =============================================================
@app.route("/admin/")
@admin_required
def admin_dashboard():
    db = get_db()
    total_students  = db.execute("SELECT COUNT(*) FROM student_profile").fetchone()[0]
    total_companies = db.execute("SELECT COUNT(*) FROM company_profile").fetchone()[0]
    total_drives    = db.execute("SELECT COUNT(*) FROM placement_drive").fetchone()[0]
    total_apps      = db.execute("SELECT COUNT(*) FROM application").fetchone()[0]
    pending_cos     = db.execute("SELECT COUNT(*) FROM company_profile WHERE approval_status='pending'").fetchone()[0]
    pending_drives  = db.execute("SELECT COUNT(*) FROM placement_drive WHERE status='pending'").fetchone()[0]
    recent_apps = db.execute("""
        SELECT a.id, a.status, a.applied_at,
               u.name  AS student_name,
               pd.job_title, cp.company_name
        FROM application a
        JOIN student_profile sp ON a.student_id = sp.id
        JOIN user u              ON sp.user_id   = u.id
        JOIN placement_drive pd  ON a.drive_id   = pd.id
        JOIN company_profile cp  ON pd.company_id = cp.id
        ORDER BY a.applied_at DESC LIMIT 5
    """).fetchall()
    return render_template("admin/dashboard.html",
        total_students=total_students, total_companies=total_companies,
        total_drives=total_drives, total_apps=total_apps,
        pending_companies=pending_cos, pending_drives=pending_drives,
        recent_applications=recent_apps)


@app.route("/admin/companies")
@admin_required
def admin_companies():
    db = get_db()
    f  = request.args.get("status", "all")
    if f == "all":
        rows = db.execute("""
            SELECT cp.*, u.email FROM company_profile cp
            JOIN user u ON cp.user_id = u.id ORDER BY cp.id DESC""").fetchall()
    else:
        rows = db.execute("""
            SELECT cp.*, u.email FROM company_profile cp
            JOIN user u ON cp.user_id = u.id
            WHERE cp.approval_status=? ORDER BY cp.id DESC""", (f,)).fetchall()
    return render_template("admin/companies.html", companies=rows, filter_status=f)


@app.route("/admin/company/<int:cid>/approve", methods=["POST"])
@admin_required
def admin_approve_company(cid):
    db = get_db()
    c  = db.execute("SELECT * FROM company_profile WHERE id=?", (cid,)).fetchone()
    if c:
        db.execute("UPDATE company_profile SET approval_status='approved' WHERE id=?", (cid,))
        db.execute("UPDATE user SET is_active=1 WHERE id=?", (c["user_id"],))
        db.commit()
        flash("Company approved.", "success")
    return redirect(url_for("admin_companies"))


@app.route("/admin/company/<int:cid>/reject", methods=["POST"])
@admin_required
def admin_reject_company(cid):
    db = get_db()
    db.execute("UPDATE company_profile SET approval_status='rejected' WHERE id=?", (cid,))
    db.commit()
    flash("Company rejected.", "warning")
    return redirect(url_for("admin_companies"))


@app.route("/admin/company/<int:cid>/blacklist", methods=["POST"])
@admin_required
def admin_blacklist_company(cid):
    db = get_db()
    c  = db.execute("SELECT * FROM company_profile WHERE id=?", (cid,)).fetchone()
    if c:
        db.execute("UPDATE company_profile SET approval_status='blacklisted' WHERE id=?", (cid,))
        db.execute("UPDATE user SET is_active=0 WHERE id=?", (c["user_id"],))
        db.commit()
    flash("Company blacklisted.", "danger")
    return redirect(url_for("admin_companies"))


@app.route("/admin/company/<int:cid>/delete", methods=["POST"])
@admin_required
def admin_delete_company(cid):
    db = get_db()
    c  = db.execute("SELECT * FROM company_profile WHERE id=?", (cid,)).fetchone()
    if c:
        drives = db.execute("SELECT id FROM placement_drive WHERE company_id=?", (cid,)).fetchall()
        for d in drives:
            db.execute("DELETE FROM application WHERE drive_id=?", (d["id"],))
        db.execute("DELETE FROM placement_drive WHERE company_id=?", (cid,))
        db.execute("DELETE FROM company_profile WHERE id=?", (cid,))
        db.execute("DELETE FROM user WHERE id=?", (c["user_id"],))
        db.commit()
    flash("Company deleted.", "info")
    return redirect(url_for("admin_companies"))


@app.route("/admin/drives")
@admin_required
def admin_drives():
    db = get_db()
    f  = request.args.get("status", "all")
    if f == "all":
        rows = db.execute("""
            SELECT pd.*, cp.company_name,
                   (SELECT COUNT(*) FROM application WHERE drive_id=pd.id) AS app_count
            FROM placement_drive pd
            JOIN company_profile cp ON pd.company_id = cp.id
            ORDER BY pd.created_at DESC""").fetchall()
    else:
        rows = db.execute("""
            SELECT pd.*, cp.company_name,
                   (SELECT COUNT(*) FROM application WHERE drive_id=pd.id) AS app_count
            FROM placement_drive pd
            JOIN company_profile cp ON pd.company_id = cp.id
            WHERE pd.status=? ORDER BY pd.created_at DESC""", (f,)).fetchall()
    return render_template("admin/drives.html", drives=rows, filter_status=f)


@app.route("/admin/drive/<int:did>/approve", methods=["POST"])
@admin_required
def admin_approve_drive(did):
    db = get_db()
    db.execute("UPDATE placement_drive SET status='approved' WHERE id=?", (did,))
    db.commit()
    flash("Drive approved.", "success")
    return redirect(url_for("admin_drives"))


@app.route("/admin/drive/<int:did>/reject", methods=["POST"])
@admin_required
def admin_reject_drive(did):
    db = get_db()
    db.execute("UPDATE placement_drive SET status='rejected' WHERE id=?", (did,))
    db.commit()
    flash("Drive rejected.", "warning")
    return redirect(url_for("admin_drives"))


@app.route("/admin/drive/<int:did>/delete", methods=["POST"])
@admin_required
def admin_delete_drive(did):
    db = get_db()
    db.execute("DELETE FROM application WHERE drive_id=?", (did,))
    db.execute("DELETE FROM placement_drive WHERE id=?", (did,))
    db.commit()
    flash("Drive deleted.", "info")
    return redirect(url_for("admin_drives"))


@app.route("/admin/students")
@admin_required
def admin_students():
    db   = get_db()
    rows = db.execute("""
        SELECT sp.*, u.name, u.email, u.is_active
        FROM student_profile sp JOIN user u ON sp.user_id = u.id
        ORDER BY sp.id DESC""").fetchall()
    return render_template("admin/students.html", students=rows)


@app.route("/admin/student/<int:sid>/blacklist", methods=["POST"])
@admin_required
def admin_blacklist_student(sid):
    db = get_db()
    s  = db.execute("SELECT * FROM student_profile WHERE id=?", (sid,)).fetchone()
    if s:
        db.execute("UPDATE student_profile SET is_blacklisted=1 WHERE id=?", (sid,))
        db.execute("UPDATE user SET is_active=0 WHERE id=?", (s["user_id"],))
        db.commit()
    flash("Student blacklisted.", "danger")
    return redirect(url_for("admin_students"))


@app.route("/admin/student/<int:sid>/activate", methods=["POST"])
@admin_required
def admin_activate_student(sid):
    db = get_db()
    s  = db.execute("SELECT * FROM student_profile WHERE id=?", (sid,)).fetchone()
    if s:
        db.execute("UPDATE student_profile SET is_blacklisted=0 WHERE id=?", (sid,))
        db.execute("UPDATE user SET is_active=1 WHERE id=?", (s["user_id"],))
        db.commit()
    flash("Student reactivated.", "success")
    return redirect(url_for("admin_students"))


@app.route("/admin/student/<int:sid>/delete", methods=["POST"])
@admin_required
def admin_delete_student(sid):
    db = get_db()
    s  = db.execute("SELECT * FROM student_profile WHERE id=?", (sid,)).fetchone()
    if s:
        db.execute("DELETE FROM application WHERE student_id=?", (sid,))
        db.execute("DELETE FROM student_profile WHERE id=?", (sid,))
        db.execute("DELETE FROM user WHERE id=?", (s["user_id"],))
        db.commit()
    flash("Student deleted.", "info")
    return redirect(url_for("admin_students"))


@app.route("/admin/search")
@admin_required
def admin_search():
    db         = get_db()
    q          = request.args.get("q", "").strip()
    students_  = []
    companies_ = []
    if q:
        like = f"%{q}%"
        students_ = db.execute("""
            SELECT sp.*, u.name, u.email FROM student_profile sp
            JOIN user u ON sp.user_id = u.id
            WHERE u.name LIKE ? OR sp.roll_number LIKE ? OR u.email LIKE ?
        """, (like, like, like)).fetchall()
        companies_ = db.execute("""
            SELECT cp.*, u.email FROM company_profile cp
            JOIN user u ON cp.user_id = u.id
            WHERE cp.company_name LIKE ? OR u.email LIKE ?
        """, (like, like)).fetchall()
    return render_template("admin/search.html",
                           query=q, students=students_, companies=companies_)


@app.route("/admin/applications")
@admin_required
def admin_applications():
    db   = get_db()
    rows = db.execute("""
        SELECT a.id, a.status, a.applied_at,
               u.name AS student_name, sp.roll_number,
               pd.job_title, cp.company_name
        FROM application a
        JOIN student_profile sp ON a.student_id = sp.id
        JOIN user u              ON sp.user_id   = u.id
        JOIN placement_drive pd  ON a.drive_id   = pd.id
        JOIN company_profile cp  ON pd.company_id = cp.id
        ORDER BY a.applied_at DESC""").fetchall()
    return render_template("admin/applications.html", applications=rows)


# =============================================================
#  COMPANY ROUTES
# =============================================================
@app.route("/company/")
@company_required
def company_dashboard():
    db  = get_db()
    cp  = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                     (session["user_id"],)).fetchone()
    drives = db.execute(
        "SELECT * FROM placement_drive WHERE company_id=? ORDER BY created_at DESC",
        (cp["id"],)).fetchall()
    drive_stats = []
    for d in drives:
        drive_stats.append({
            "drive":       d,
            "total":       db.execute("SELECT COUNT(*) FROM application WHERE drive_id=?", (d["id"],)).fetchone()[0],
            "applied":     db.execute("SELECT COUNT(*) FROM application WHERE drive_id=? AND status='applied'", (d["id"],)).fetchone()[0],
            "shortlisted": db.execute("SELECT COUNT(*) FROM application WHERE drive_id=? AND status='shortlisted'", (d["id"],)).fetchone()[0],
            "selected":    db.execute("SELECT COUNT(*) FROM application WHERE drive_id=? AND status='selected'", (d["id"],)).fetchone()[0],
            "rejected":    db.execute("SELECT COUNT(*) FROM application WHERE drive_id=? AND status='rejected'", (d["id"],)).fetchone()[0],
        })
    return render_template("company/dashboard.html", profile=cp, drive_stats=drive_stats)


@app.route("/company/profile", methods=["GET", "POST"])
@company_required
def company_profile():
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    if request.method == "POST":
        db.execute("""UPDATE company_profile
                      SET hr_contact=?, website=?, industry=?, description=?
                      WHERE id=?""",
                   (request.form.get("hr_contact", "").strip(),
                    request.form.get("website", "").strip(),
                    request.form.get("industry", "").strip(),
                    request.form.get("description", "").strip(),
                    cp["id"]))
        new_name = request.form.get("name", session["user_name"]).strip()
        db.execute("UPDATE user SET name=? WHERE id=?", (new_name, session["user_id"]))
        db.commit()
        session["user_name"] = new_name
        flash("Profile updated.", "success")
        return redirect(url_for("company_profile"))
    return render_template("company/profile.html", profile=cp)


@app.route("/company/drive/new", methods=["GET", "POST"])
@company_required
def company_create_drive():
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    if request.method == "POST":
        job_title  = request.form.get("job_title", "").strip()
        job_desc   = request.form.get("job_description", "").strip()
        deadline_s = request.form.get("application_deadline", "")
        if not all([job_title, job_desc, deadline_s]):
            flash("Job title, description, and deadline are required.", "danger")
            return render_template("company/create_drive.html")
        try:
            dl = date.fromisoformat(deadline_s)
        except ValueError:
            flash("Invalid date format.", "danger")
            return render_template("company/create_drive.html")
        if dl < date.today():
            flash("Deadline cannot be in the past.", "danger")
            return render_template("company/create_drive.html")
        db.execute("""INSERT INTO placement_drive
                      (company_id, job_title, job_description, eligibility_criteria,
                       package, location, application_deadline, status)
                      VALUES (?,?,?,?,?,?,?,'pending')""",
                   (cp["id"], job_title, job_desc,
                    request.form.get("eligibility_criteria", "").strip(),
                    request.form.get("package", "").strip(),
                    request.form.get("location", "").strip(),
                    deadline_s))
        db.commit()
        flash("Drive submitted for admin approval.", "info")
        return redirect(url_for("company_dashboard"))
    return render_template("company/create_drive.html")


@app.route("/company/drive/<int:did>/edit", methods=["GET", "POST"])
@company_required
def company_edit_drive(did):
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    d  = db.execute("SELECT * FROM placement_drive WHERE id=?", (did,)).fetchone()
    if not d or d["company_id"] != cp["id"]:
        flash("Access denied.", "danger")
        return redirect(url_for("company_dashboard"))
    if d["status"] in ("approved", "closed"):
        flash("Cannot edit approved or closed drives.", "warning")
        return redirect(url_for("company_dashboard"))
    if request.method == "POST":
        deadline_s = request.form.get("application_deadline", "")
        try:
            date.fromisoformat(deadline_s)
        except ValueError:
            flash("Invalid date.", "danger")
            return render_template("company/edit_drive.html", drive=d)
        db.execute("""UPDATE placement_drive
                      SET job_title=?, job_description=?, eligibility_criteria=?,
                          package=?, location=?, application_deadline=?, status='pending'
                      WHERE id=?""",
                   (request.form.get("job_title", "").strip(),
                    request.form.get("job_description", "").strip(),
                    request.form.get("eligibility_criteria", "").strip(),
                    request.form.get("package", "").strip(),
                    request.form.get("location", "").strip(),
                    deadline_s, did))
        db.commit()
        flash("Drive updated and resubmitted for approval.", "success")
        return redirect(url_for("company_dashboard"))
    return render_template("company/edit_drive.html", drive=d)


@app.route("/company/drive/<int:did>/close", methods=["POST"])
@company_required
def company_close_drive(did):
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    d  = db.execute("SELECT * FROM placement_drive WHERE id=?", (did,)).fetchone()
    if d and d["company_id"] == cp["id"]:
        db.execute("UPDATE placement_drive SET status='closed' WHERE id=?", (did,))
        db.commit()
        flash("Drive closed.", "info")
    return redirect(url_for("company_dashboard"))


@app.route("/company/drive/<int:did>/delete", methods=["POST"])
@company_required
def company_delete_drive(did):
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    d  = db.execute("SELECT * FROM placement_drive WHERE id=?", (did,)).fetchone()
    if d and d["company_id"] == cp["id"]:
        if d["status"] == "approved":
            flash("Cannot delete an approved drive. Close it first.", "warning")
            return redirect(url_for("company_dashboard"))
        db.execute("DELETE FROM application WHERE drive_id=?", (did,))
        db.execute("DELETE FROM placement_drive WHERE id=?", (did,))
        db.commit()
        flash("Drive deleted.", "info")
    return redirect(url_for("company_dashboard"))


@app.route("/company/drive/<int:did>/applications")
@company_required
def company_drive_applications(did):
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    d  = db.execute("SELECT * FROM placement_drive WHERE id=?", (did,)).fetchone()
    if not d or d["company_id"] != cp["id"]:
        flash("Access denied.", "danger")
        return redirect(url_for("company_dashboard"))
    f = request.args.get("status", "all")
    if f == "all":
        apps = db.execute("""
            SELECT a.*, u.name AS student_name, u.email,
                   sp.roll_number, sp.branch, sp.cgpa, sp.skills, sp.resume_file
            FROM application a
            JOIN student_profile sp ON a.student_id = sp.id
            JOIN user u              ON sp.user_id   = u.id
            WHERE a.drive_id=? ORDER BY a.applied_at ASC""", (did,)).fetchall()
    else:
        apps = db.execute("""
            SELECT a.*, u.name AS student_name, u.email,
                   sp.roll_number, sp.branch, sp.cgpa, sp.skills, sp.resume_file
            FROM application a
            JOIN student_profile sp ON a.student_id = sp.id
            JOIN user u              ON sp.user_id   = u.id
            WHERE a.drive_id=? AND a.status=?
            ORDER BY a.applied_at ASC""", (did, f)).fetchall()
    return render_template("company/applications.html",
                           drive=d, applications=apps, filter_status=f)


@app.route("/company/application/<int:aid>/status", methods=["POST"])
@company_required
def company_update_status(aid):
    db = get_db()
    cp = db.execute("SELECT * FROM company_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    a  = db.execute("SELECT * FROM application WHERE id=?", (aid,)).fetchone()
    if not a:
        flash("Not found.", "danger")
        return redirect(url_for("company_dashboard"))
    d = db.execute("SELECT * FROM placement_drive WHERE id=?", (a["drive_id"],)).fetchone()
    if not d or d["company_id"] != cp["id"]:
        flash("Access denied.", "danger")
        return redirect(url_for("company_dashboard"))
    new_status = request.form.get("status", "")
    if new_status in ("applied", "shortlisted", "selected", "rejected"):
        db.execute("UPDATE application SET status=? WHERE id=?", (new_status, aid))
        db.commit()
        flash(f"Status updated to '{new_status}'.", "success")
    return redirect(url_for("company_drive_applications", did=a["drive_id"]))


# =============================================================
#  STUDENT ROUTES
# =============================================================
@app.route("/student/")
@student_required
def student_dashboard():
    db    = get_db()
    today = date.today().isoformat()
    sp    = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                       (session["user_id"],)).fetchone()
    available_drives = db.execute("""
        SELECT pd.*, cp.company_name FROM placement_drive pd
        JOIN company_profile cp ON pd.company_id = cp.id
        WHERE pd.status='approved' AND pd.application_deadline >= ?
        ORDER BY pd.application_deadline ASC""", (today,)).fetchall()
    my_applications = db.execute("""
        SELECT a.*, pd.job_title, cp.company_name
        FROM application a
        JOIN placement_drive pd ON a.drive_id   = pd.id
        JOIN company_profile cp ON pd.company_id = cp.id
        WHERE a.student_id=? ORDER BY a.applied_at DESC LIMIT 5""",
        (sp["id"],)).fetchall()
    applied_drive_ids = {
        r["drive_id"] for r in
        db.execute("SELECT drive_id FROM application WHERE student_id=?",
                   (sp["id"],)).fetchall()
    }
    return render_template("student/dashboard.html",
        profile=sp, available_drives=available_drives,
        my_applications=my_applications,
        applied_drive_ids=applied_drive_ids, today=today)


@app.route("/student/drives")
@student_required
def student_drives():
    db    = get_db()
    today = date.today().isoformat()
    sp    = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                       (session["user_id"],)).fetchone()
    q = request.args.get("q", "").strip()
    if q:
        rows = db.execute("""
            SELECT pd.*, cp.company_name FROM placement_drive pd
            JOIN company_profile cp ON pd.company_id = cp.id
            WHERE pd.status='approved' AND pd.job_title LIKE ?
            ORDER BY pd.application_deadline ASC""", (f"%{q}%",)).fetchall()
    else:
        rows = db.execute("""
            SELECT pd.*, cp.company_name FROM placement_drive pd
            JOIN company_profile cp ON pd.company_id = cp.id
            WHERE pd.status='approved'
            ORDER BY pd.application_deadline ASC""").fetchall()
    applied_drive_ids = {
        r["drive_id"] for r in
        db.execute("SELECT drive_id FROM application WHERE student_id=?",
                   (sp["id"],)).fetchall()
    }
    return render_template("student/drives.html",
        drives=rows, applied_drive_ids=applied_drive_ids,
        today=today, search=q)


@app.route("/student/drive/<int:did>")
@student_required
def student_drive_detail(did):
    db = get_db()
    d  = db.execute("""
        SELECT pd.*, cp.company_name, cp.website FROM placement_drive pd
        JOIN company_profile cp ON pd.company_id = cp.id
        WHERE pd.id=?""", (did,)).fetchone()
    if not d or d["status"] != "approved":
        flash("This drive is not available.", "warning")
        return redirect(url_for("student_drives"))
    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    already_applied = db.execute(
        "SELECT id FROM application WHERE student_id=? AND drive_id=?",
        (sp["id"], did)).fetchone() is not None
    return render_template("student/drive_detail.html",
        drive=d, already_applied=already_applied,
        today=date.today().isoformat())


@app.route("/student/drive/<int:did>/apply", methods=["POST"])
@student_required
def student_apply(did):
    db    = get_db()
    today = date.today().isoformat()
    sp    = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                       (session["user_id"],)).fetchone()
    d = db.execute("SELECT * FROM placement_drive WHERE id=?", (did,)).fetchone()
    if not d or d["status"] != "approved":
        flash("Drive not available.", "danger")
        return redirect(url_for("student_drives"))
    if d["application_deadline"] < today:
        flash("The application deadline has passed.", "warning")
        return redirect(url_for("student_drives"))
    if db.execute("SELECT id FROM application WHERE student_id=? AND drive_id=?",
                  (sp["id"], did)).fetchone():
        flash("You have already applied.", "warning")
        return redirect(url_for("student_drives"))
    db.execute(
        "INSERT INTO application (student_id, drive_id, status, cover_note) VALUES (?,?,'applied',?)",
        (sp["id"], did, request.form.get("cover_note", "").strip()))
    db.commit()
    flash(f"Successfully applied to '{d['job_title']}'!", "success")
    return redirect(url_for("student_applications"))


@app.route("/student/applications")
@student_required
def student_applications():
    db = get_db()
    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    apps = db.execute("""
        SELECT a.*, pd.job_title, pd.location, pd.package, pd.application_deadline,
               cp.company_name
        FROM application a
        JOIN placement_drive pd ON a.drive_id   = pd.id
        JOIN company_profile cp ON pd.company_id = cp.id
        WHERE a.student_id=? ORDER BY a.applied_at DESC""",
        (sp["id"],)).fetchall()
    return render_template("student/applications.html", applications=apps)


@app.route("/student/history")
@student_required
def student_history():
    db = get_db()
    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    placed = db.execute("""
        SELECT a.*, pd.job_title, pd.location, pd.package, cp.company_name
        FROM application a
        JOIN placement_drive pd ON a.drive_id   = pd.id
        JOIN company_profile cp ON pd.company_id = cp.id
        WHERE a.student_id=? AND a.status='selected'
        ORDER BY a.applied_at DESC""",
        (sp["id"],)).fetchall()
    return render_template("student/history.html", placements=placed)


@app.route("/student/profile", methods=["GET", "POST"])
@student_required
def student_profile():
    db = get_db()
    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    u  = db.execute("SELECT * FROM user WHERE id=?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        name   = request.form.get("name", "").strip()
        cgpa_s = request.form.get("cgpa", "").strip()
        cgpa   = None
        if cgpa_s:
            try:
                cgpa = float(cgpa_s)
                if not (0 <= cgpa <= 10):
                    flash("CGPA must be between 0 and 10.", "warning")
                    cgpa = sp["cgpa"]
            except ValueError:
                flash("Invalid CGPA value.", "warning")
                cgpa = sp["cgpa"]
        db.execute("UPDATE user SET name=? WHERE id=?", (name, session["user_id"]))
        db.execute("""UPDATE student_profile
                      SET branch=?, semester=?, phone=?, skills=?, cgpa=?
                      WHERE id=?""",
                   (request.form.get("branch", "").strip() or None,
                    request.form.get("semester", "").strip() or None,
                    request.form.get("phone", "").strip() or None,
                    request.form.get("skills", "").strip() or None,
                    cgpa, sp["id"]))
        db.commit()
        session["user_name"] = name
        flash("Profile updated.", "success")
        return redirect(url_for("student_profile"))

    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    fields    = [sp["roll_number"], sp["branch"], sp["cgpa"],
                 sp["phone"], sp["skills"], sp["resume_file"]]
    pct_filled = sum(1 for f in fields if f) + 1
    pct_value  = str((pct_filled * 100) // 7) + "%"

    return render_template("student/profile.html",
        profile=sp, user=u, pct_filled=pct_filled, pct_value=pct_value)


@app.route("/student/profile/resume", methods=["POST"])
@student_required
def student_upload_resume():
    db = get_db()
    sp = db.execute("SELECT * FROM student_profile WHERE user_id=?",
                    (session["user_id"],)).fetchone()
    if "resume" not in request.files:
        flash("No file in request.", "danger")
        return redirect(url_for("student_profile"))
    f = request.files["resume"]
    if f.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("student_profile"))
    if not allowed_file(f.filename):
        flash("Only PDF, DOC, and DOCX files are allowed.", "danger")
        return redirect(url_for("student_profile"))
    filename    = secure_filename(f.filename)
    unique_name = f"student_{sp['id']}_{filename}"
    f.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))
    db.execute("UPDATE student_profile SET resume_file=? WHERE id=?",
               (unique_name, sp["id"]))
    db.commit()
    flash("Resume uploaded successfully.", "success")
    return redirect(url_for("student_profile"))


# =============================================================
#  ENTRY POINT
# =============================================================
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)