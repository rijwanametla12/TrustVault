
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, abort, flash
)
import sqlite3
import os
import re
import uuid
import hashlib
import json
import io 
import zipfile 
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-only-change-this-secret-key"
)
# CSRF Protection
csrf = CSRFProtect(app)

# Session Security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "0") == "1"
)

# Maximum upload size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Database and Upload Paths
DATABASE = os.path.join(app.instance_path, "trustvault.db")
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")

os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed File Extensions
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg"}

# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# ==========================================
# CREATE DATABASE TABLES
# ==========================================
def create_tables():
    conn = get_db_connection()

    try:
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner'
                    CHECK(role IN ('admin', 'owner', 'viewer'))
            )
        """)

        # Update older users table if role column is missing
        columns = conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        if "role" not in column_names:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
                CHECK(role IN ('admin', 'owner', 'viewer'))
            """)

        # Documents table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,
                owner_id INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id)
                REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Document sharing table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS document_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                shared_with_user_id INTEGER NOT NULL,
                permission TEXT NOT NULL DEFAULT 'viewer'
                    CHECK(permission IN ('viewer')),
                shared_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(document_id, shared_with_user_id),
                FOREIGN KEY (document_id)
                REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY (shared_with_user_id)
                REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Audit trail table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                document_id INTEGER,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                previous_hash TEXT,
                entry_hash TEXT,
                FOREIGN KEY (user_id)
                REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (document_id)
                REFERENCES documents(id) ON DELETE SET NULL
            )
        """)

        # Migration: add hash columns to older audit_logs tables
        audit_columns = conn.execute(
            "PRAGMA table_info(audit_logs)"
        ).fetchall()

        audit_column_names = [
            column["name"] for column in audit_columns
        ]

        if "previous_hash" not in audit_column_names:
            conn.execute("""
                ALTER TABLE audit_logs
                ADD COLUMN previous_hash TEXT
            """)

        if "entry_hash" not in audit_column_names:
            conn.execute("""
                ALTER TABLE audit_logs
                ADD COLUMN entry_hash TEXT
            """)

        # Initialize hashes for older audit records that do not have them
        previous_hash = "GENESIS"

        old_logs = conn.execute("""
            SELECT id, user_id, action, document_id, details, timestamp,
                   previous_hash, entry_hash
            FROM audit_logs
            ORDER BY id ASC
        """).fetchall()

        for log in old_logs:
            if log["entry_hash"]:
                previous_hash = log["entry_hash"]
                continue

            audit_data = {
                "id": log["id"],
                "user_id": log["user_id"],
                "action": log["action"],
                "document_id": log["document_id"],
                "details": log["details"] or "",
                "timestamp": log["timestamp"],
                "previous_hash": previous_hash
            }

            audit_string = json.dumps(
                audit_data,
                sort_keys=True,
                separators=(",", ":")
            )

            entry_hash = hashlib.sha256(
                audit_string.encode("utf-8")
            ).hexdigest()

            conn.execute("""
                UPDATE audit_logs
                SET previous_hash = ?, entry_hash = ?
                WHERE id = ?
            """, (previous_hash, entry_hash, log["id"]))

            previous_hash = entry_hash

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


create_tables()

# ==========================================
# AUDIT LOG HELPER
# ==========================================
def log_action(user_id, action, document_id=None, details=""):
    conn = get_db_connection()

    try:
        # Prevent two simultaneous log entries from using the same previous hash
        conn.execute("BEGIN IMMEDIATE")

        # Get the most recent audit entry
        previous = conn.execute("""
            SELECT entry_hash
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        previous_hash = (
            previous["entry_hash"]
            if previous and previous["entry_hash"]
            else "GENESIS"
        )

        # Create timestamp
        timestamp = datetime.now().astimezone().isoformat()

        # Insert the entry first to obtain its database ID
        cursor = conn.execute("""
            INSERT INTO audit_logs (
                user_id,
                action,
                document_id,
                details,
                timestamp,
                previous_hash,
                entry_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, NULL)
        """, (
            user_id,
            action,
            document_id,
            details,
            timestamp,
            previous_hash
        ))

        entry_id = cursor.lastrowid

        # Prepare audit data for hashing
        audit_data = {
            "id": entry_id,
            "user_id": user_id,
            "action": action,
            "document_id": document_id,
            "details": details,
            "timestamp": timestamp,
            "previous_hash": previous_hash
        }

        # Generate SHA-256 hash
        audit_string = json.dumps(
            audit_data,
            sort_keys=True,
            separators=(",", ":")
        )

        entry_hash = hashlib.sha256(
            audit_string.encode("utf-8")
        ).hexdigest()

        # Save the generated hash
        conn.execute("""
            UPDATE audit_logs
            SET entry_hash = ?
            WHERE id = ?
        """, (entry_hash, entry_id))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
# ==========================================
# CURRENT USER
# ==========================================

def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    conn = get_db_connection()

    try:
        return conn.execute("""
            SELECT id, username, email, role
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

    finally:
        conn.close()

# ==========================================
# ROLE-BASED ACCESS CONTROL
# ==========================================

def role_required(*allowed_roles):
    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):
            user = current_user()

            if user is None:
                session.clear()
                return redirect(url_for("login"))

            if user["role"] not in allowed_roles:
                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# Admin can manage all documents.
# Owner can manage only their own documents.

def can_manage_document(user, document):
    return (
        user["role"] == "admin"
        or document["owner_id"] == user["id"]
    )

# ==========================================
# FILE VALIDATION
# ==========================================

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )

# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")

# ==========================================
# USER REGISTRATION
# ==========================================


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Username validation
        if not re.fullmatch(r"[A-Za-z]+", username):
            return render_template(
                "register.html",
                error="Username must contain English letters only."
            )

        # Email validation
        email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

        if not re.fullmatch(email_pattern, email):
            return render_template(
                "register.html",
                error="Please enter a valid email address."
            )

        # Password validation
        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must contain at least 8 characters."
            )

        password_hash = generate_password_hash(password)

        conn = get_db_connection()

        try:
            # Public registration always creates an Owner.
            # Never accept an Admin role from the registration form.
            conn.execute("""
                INSERT INTO users (
                    username, email, password_hash, role
                )
                VALUES (?, ?, ?, 'viewer')
            """, (username, email, password_hash))

            conn.commit()

            return render_template(
                "register.html",
                success="Registration successful! Please sign in."
            )

        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                error="This email is already registered."
            )

        finally:
            conn.close()

    return render_template("register.html")

# ==========================================
# USER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()

        try:
            user = conn.execute("""
                SELECT id, username, email, password_hash, role
                FROM users
                WHERE email = ?
            """, (email,)).fetchone()

        finally:
            conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):

            session.clear()
            session["user_id"] = user["id"]

            # Record the local login time for this session.
            login_time = datetime.now().astimezone()
            session["login_time"] = login_time.isoformat()

            log_action(
                user["id"],
                "LOGIN",
                details=(
                    "User logged in successfully at "
                    f"{login_time.strftime('%Y-%m-%d %H:%M:%S %Z')}"
                )
            )

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email address or password."
        )

    return render_template("login.html")

# ==========================================
# USER DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=user["username"],
        role=user["role"]
    )

# ==========================================
# DOCUMENT LIST WITH SEARCH
# OWNER AND ADMIN
# ==========================================

@app.route("/documents")
@role_required("owner", "admin")
def documents():

    user = current_user()
    search_query = request.args.get("q", "").strip()[:100]

    conn = get_db_connection()

    try:

        if user["role"] == "admin":

            sql = """
                SELECT d.id, d.original_filename, d.file_size,
                       d.upload_date, d.owner_id,
                       u.username AS owner_name
                FROM documents AS d
                JOIN users AS u ON u.id = d.owner_id
            """

            params = []

            if search_query:
                sql += " WHERE d.original_filename LIKE ?"
                params.append(f"%{search_query}%")

            sql += " ORDER BY d.upload_date DESC"

            rows = conn.execute(sql, params).fetchall()

        else:

            sql = """
                SELECT d.id, d.original_filename, d.file_size,
                       d.upload_date, d.owner_id,
                       u.username AS owner_name
                FROM documents AS d
                JOIN users AS u ON u.id = d.owner_id
                WHERE d.owner_id = ?
            """

            params = [user["id"]]

            if search_query:
                sql += " AND d.original_filename LIKE ?"
                params.append(f"%{search_query}%")

            sql += " ORDER BY d.upload_date DESC"

            rows = conn.execute(sql, params).fetchall()

        result = []

        for doc in rows:

            item = dict(doc)

            item["shares"] = [
                dict(share)
                for share in conn.execute("""
                    SELECT s.shared_with_user_id, u.username, u.email
                    FROM document_shares AS s
                    JOIN users AS u ON u.id = s.shared_with_user_id
                    WHERE s.document_id = ?
                    ORDER BY s.shared_date DESC
                """, (doc["id"],)).fetchall()
            ]

            result.append(item)

    finally:
        conn.close()

    return render_template(
        "documents.html",
        documents=result,
        role=user["role"],
        search_query=search_query
    )

# ==========================================
# DOCUMENT UPLOAD
# OWNER AND ADMIN
# ==========================================

@app.route("/upload", methods=["POST"])
@role_required("owner", "admin")
def upload_document():

    user = current_user()

    if not user:
        flash("Please login first.")
        return redirect(url_for("login"))

    if "document" not in request.files:
        flash("Please select a file.")
        return redirect(url_for("documents"))

    file = request.files["document"]

    if not file or file.filename == "":
        flash("No file selected.")
        return redirect(url_for("documents"))

    if not allowed_file(file.filename):
        flash("Only PDF, DOCX, PNG, JPG and JPEG files are allowed.")
        return redirect(url_for("documents"))

    original_filename = secure_filename(file.filename)

    if not original_filename:
        flash("Invalid filename.")
        return redirect(url_for("documents"))

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size == 0:
        flash("Empty files cannot be uploaded.")
        return redirect(url_for("documents"))

    if file_size > app.config["MAX_CONTENT_LENGTH"]:
        flash("File size must not exceed 5 MB.")
        return redirect(url_for("documents"))

    extension = original_filename.rsplit(".", 1)[1].lower()
    stored_filename = f"{uuid.uuid4().hex}.{extension}"
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    conn = None

    try:
        file.save(file_path)

        conn = get_db_connection()

        cursor = conn.execute("""
            INSERT INTO documents (
                original_filename,
                stored_filename,
                owner_id,
                file_size
            )
            VALUES (?, ?, ?, ?)
        """, (
            original_filename,
            stored_filename,
            user["id"],
            file_size
        ))

        document_id = cursor.lastrowid

        conn.execute("""
            INSERT INTO audit_logs (
                user_id,
                action,
                document_id,
                details
            )
            VALUES (?, ?, ?, ?)
        """, (
            user["id"],
            "UPLOAD",
            document_id,
            f"Uploaded document: {original_filename}"
        ))

        conn.commit()

        flash("Document uploaded successfully!")

    except Exception:
        if conn:
            conn.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        raise

    finally:
        if conn:
            conn.close()

    return redirect(url_for("documents"))

# ==========================================
# SECURE DOWNLOAD DOCUMENT
# OWNER, ADMIN AND AUTHORIZED VIEWER
# ==========================================

@app.route("/download/<int:document_id>")
def download_document(document_id):

    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        # Find document without granting access.
        document = conn.execute("""
            SELECT
                id,
                original_filename,
                stored_filename,
                owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        # Document does not exist.
        if document is None:

            log_action(
                user["id"],
                "DOWNLOAD_DENIED",
                None,
                f"Unauthorized attempt to access nonexistent "
                f"document ID {document_id}"
            )

            abort(404)

        # Check document ownership.
        is_owner = document["owner_id"] == user["id"]

        # Admin can access all documents.
        is_admin = user["role"] == "admin"

        # Check active sharing permission.
        share = conn.execute("""
            SELECT id
            FROM document_shares
            WHERE document_id = ?
              AND shared_with_user_id = ?
              AND permission = 'viewer'
        """, (
            document_id,
            user["id"]
        )).fetchone()

        is_authorized_viewer = (
            user["role"] == "viewer"
            and share is not None
        )

        # Deny access if none of the conditions are satisfied.
        if not (
            is_owner
            or is_admin
            or is_authorized_viewer
        ):

            log_action(
                user["id"],
                "DOWNLOAD_DENIED",
                document_id,
                (
                    f"Unauthorized download attempt for "
                    f"{document['original_filename']}. "
                    f"User ID: {user['id']}, "
                    f"Role: {user['role']}, "
                    f"Owner ID: {document['owner_id']}"
                )
            )

            abort(404)

        # Confirm the stored file exists.
        stored_filename = document["stored_filename"]
        file_path = os.path.join(
            UPLOAD_FOLDER,
            stored_filename
        )

        if not os.path.isfile(file_path):

            log_action(
                user["id"],
                "DOWNLOAD_FAILED",
                document_id,
                "Document record exists but stored file is missing."
            )

            abort(404)

        # Record successful download.
        log_action(
            user["id"],
            "DOWNLOAD",
            document_id,
            f"Successfully downloaded: {document['original_filename']}"
        )

        original_filename = document["original_filename"]

    finally:
        conn.close()

    return send_from_directory(
        UPLOAD_FOLDER,
        stored_filename,
        as_attachment=True,
        download_name=original_filename
    )


# ==========================================
# DOCUMENT DELETE
# OWNER AND ADMIN
# ==========================================

@app.route("/delete/<int:document_id>", methods=["POST"])
@role_required("owner", "admin")
def delete_document(document_id):

    user = current_user()
    conn = get_db_connection()
    file_path = None

    try:
        document = conn.execute("""
            SELECT
                id,
                original_filename,
                stored_filename,
                owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        if document is None or not can_manage_document(
            user, document
        ):
            abort(404)

        file_path = os.path.join(
            UPLOAD_FOLDER,
            document["stored_filename"]
        )

        filename = document["original_filename"]

        conn.execute("""
            DELETE FROM documents
            WHERE id = ?
        """, (document_id,))

        conn.commit()

    finally:
        conn.close()

    if file_path and os.path.isfile(file_path):
        os.remove(file_path)

    log_action(
        user["id"],
        "DELETE",
        details=f"Deleted document ID {document_id}: {filename}"
    )

    flash("Document deleted successfully!")

    return redirect(url_for("documents"))

# ==========================================
# SHARE DOCUMENT
# OWNER AND ADMIN
# ==========================================

@app.route("/share/<int:document_id>", methods=["POST"])
@role_required("owner", "admin")
def share_document(document_id):

    user = current_user()

    recipient_email = request.form.get(
        "email", ""
    ).strip().lower()

    if not recipient_email:
        flash("Enter the email address of the user.")
        return redirect(url_for("documents"))

    conn = get_db_connection()

    try:
        document = conn.execute("""
            SELECT
                id,
                original_filename,
                owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        if document is None or not can_manage_document(
            user, document
        ):
            abort(404)

        recipient = conn.execute("""
            SELECT id, username, email
            FROM users
            WHERE email = ?
        """, (recipient_email,)).fetchone()

        if recipient is None:
            flash("No registered user found with that email.")
            return redirect(url_for("documents"))

        if recipient["id"] == user["id"]:
            flash("You cannot share a document with yourself.")
            return redirect(url_for("documents"))

        cursor = conn.execute("""
            INSERT INTO document_shares (
                document_id,
                shared_with_user_id
            )
            VALUES (?, ?)
            ON CONFLICT(document_id, shared_with_user_id)
            DO NOTHING
        """, (
            document_id,
            recipient["id"]
        ))

        conn.commit()

        already_shared = cursor.rowcount == 0

    finally:
        conn.close()

    if already_shared:
        flash("This document is already shared with that user.")

    else:
        log_action(
            user["id"],
            "SHARE",
            document_id,
            f"Shared {document['original_filename']} "
            f"with {recipient['username']} ({recipient['email']})"
        )

        flash("Document shared successfully with viewer access.")

    return redirect(url_for("documents"))

# ==========================================
# REVOKE DOCUMENT ACCESS
# OWNER AND ADMIN
# ==========================================

@app.route(
    "/revoke-share/<int:document_id>/<int:user_id>",
    methods=["POST"]
)
@role_required("owner", "admin")

def revoke_document_share(document_id, user_id):

    user = current_user()

    conn = get_db_connection()

    try:
        # Start one transaction for revocation and audit logging.
        conn.execute("BEGIN IMMEDIATE")

        document = conn.execute("""
            SELECT id, original_filename, owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        if document is None or not can_manage_document(user, document):
            conn.rollback()
            abort(404)

        recipient = conn.execute("""
            SELECT username, email
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        # Remove the recipient's access.
        cursor = conn.execute("""
            DELETE FROM document_shares
            WHERE document_id = ?
            AND shared_with_user_id = ?
        """, (document_id, user_id))

        revoked = cursor.rowcount > 0

        if revoked:
            recipient_label = (
                recipient["email"] if recipient else str(user_id)
            )

            # Save the audit event in the same transaction.
            conn.execute("""
                INSERT INTO audit_logs (
                    user_id, action, document_id, details
                )
                VALUES (?, ?, ?, ?)
            """, (
                user["id"],
                "REVOKE",
                document_id,
                (
                    f"Revoked access to {document['original_filename']} "
                    f"for {recipient_label}"
                )
            ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if revoked:
        flash("Document access revoked successfully.")
    else:
        flash("No sharing access was found for this user.")

    return redirect(url_for("documents"))

# ==========================================
# VIEW DOCUMENTS SHARED WITH ME
# ALL LOGGED-IN USERS
# ==========================================

@app.route("/shared-documents")
def shared_documents():

    user = current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        shared_list = conn.execute("""
            SELECT
                d.id,
                d.original_filename,
                d.file_size,
                d.upload_date,
                u.username AS owner_name,
                s.permission,
                s.shared_date
            FROM document_shares AS s
            JOIN documents AS d
                ON d.id = s.document_id
            JOIN users AS u
                ON u.id = d.owner_id
            WHERE s.shared_with_user_id = ?
            ORDER BY s.shared_date DESC
        """, (user["id"],)).fetchall()

    finally:
        conn.close()

    return render_template(
        "shared_documents.html",
        documents=shared_list
    )

# ==========================================
# ADMIN-ONLY AUDIT LOGS
# ==========================================

@app.route("/audit-logs")
@role_required("admin")
def audit_logs():

    conn = get_db_connection()

    try:
        logs = conn.execute("""
            SELECT
                audit_logs.id,
                users.username,
                audit_logs.action,
                audit_logs.document_id,
                audit_logs.details,
                audit_logs.timestamp
            FROM audit_logs
            LEFT JOIN users
                ON audit_logs.user_id = users.id
            ORDER BY
                audit_logs.timestamp DESC,
                audit_logs.id DESC
        """).fetchall()

    finally:
        conn.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )

# ==========================================
# FILE SIZE ERROR
# ==========================================

@app.errorhandler(413)
def file_too_large(error):

    return (
        "File too large. Maximum allowed size is 5 MB.",
        413
    )

# ==========================================
# ACCESS DENIED
# ==========================================

@app.errorhandler(403)
def access_denied(error):

    return """
        <h1>403 - Access Denied</h1>
        <p>You do not have permission to access this page.</p>
        <a href="/dashboard">Return to Dashboard</a>
    """, 403

# ==========================================
# LOGOUT WITH SESSION DURATION
# ==========================================

@app.route("/logout")
def logout():

    user_id = session.get("user_id")

    if user_id is not None:

        logout_time = datetime.now().astimezone()
        login_time_text = session.get("login_time")
        duration_text = "Not available"

        if login_time_text:
            try:
                login_time = datetime.fromisoformat(login_time_text)

                duration_seconds = max(
                    0,
                    int((logout_time - login_time).total_seconds())
                )

                hours, remainder = divmod(duration_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)

                duration_text = (
                    f"{hours} hours, {minutes} minutes, {seconds} seconds"
                )

            except (TypeError, ValueError):
                duration_text = "Could not calculate session duration"

        log_action(
            user_id,
            "LOGOUT",
            details=(
                f"Logout time: {logout_time.strftime('%Y-%m-%d %H:%M:%S %Z')}; "
                f"Login time: {login_time_text or 'Not available'}; "
                f"Session duration: {duration_text}"
            )
        )

    session.clear()

    return redirect(url_for("login"))

# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":
    # Debug mode is only for local development.
    app.run(debug=True)
