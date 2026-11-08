
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

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

# Secret Key — required from environment
SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable must be set."
    )

app.secret_key = SECRET_KEY

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
DATABASE = os.path.join(
    app.instance_path,
    "trustvault.db"
)

UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "uploads"
)

os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed File Extensions
ALLOWED_EXTENSIONS = {
    "pdf",
    "docx",
    "png",
    "jpg",
    "jpeg"
}
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
        # ==========================================
        # USERS TABLE
        # ==========================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer'
                    CHECK(role IN ('admin', 'owner', 'viewer'))
            )
        """)

        # Check existing users table
        columns = conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        # Add role column if it does not exist
        if "role" not in column_names:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'
                CHECK(role IN ('admin', 'owner', 'viewer'))
            """)

        # ==========================================
        # ONE-TIME EXISTING USER ROLE MIGRATION
        # ==========================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_migrations (
                migration_key TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("BEGIN IMMEDIATE")

        migration = conn.execute("""
            SELECT migration_key
            FROM app_migrations
            WHERE migration_key = 'initial_role_assignment_v1'
        """).fetchone()

        if migration is None:

            existing_users = conn.execute("""
                SELECT id
                FROM users
                ORDER BY id ASC
            """).fetchall()

            for index, account in enumerate(existing_users):

                if index == 0:
                    assigned_role = "admin"

                elif index == 1:
                    assigned_role = "owner"

                else:
                    assigned_role = "viewer"

                conn.execute("""
                    UPDATE users
                    SET role = ?
                    WHERE id = ?
                """, (
                    assigned_role,
                    account["id"]
                ))

            conn.execute("""
                INSERT INTO app_migrations (migration_key)
                VALUES ('initial_role_assignment_v1')
            """)

        conn.commit()

        # ==========================================
        # DOCUMENTS TABLE
        # ==========================================

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

        # ==========================================
        # DOCUMENT SHARING TABLE
        # ==========================================

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

        # ==========================================
        # AUDIT LOGS TABLE
        # ==========================================

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

        # Check audit table columns
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

        # Add chain identifiers
        chain_id_added = "chain_id" not in audit_column_names

        if chain_id_added:
            conn.execute("""
                ALTER TABLE audit_logs
                ADD COLUMN chain_id INTEGER NOT NULL DEFAULT 1
            """)

        # ==========================================
        # REMOVE MUTABLE AUDIT FOREIGN KEYS
        # ==========================================

        foreign_keys = conn.execute(
            "PRAGMA foreign_key_list(audit_logs)"
        ).fetchall()

        if foreign_keys:

            conn.commit()

            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("BEGIN IMMEDIATE")

            conn.execute("""
                CREATE TABLE audit_logs_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    document_id INTEGER,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    previous_hash TEXT,
                    entry_hash TEXT,
                    chain_id INTEGER NOT NULL DEFAULT 1
                )
            """)

            conn.execute("""
                INSERT INTO audit_logs_new
                    (id, user_id, action, document_id, details, timestamp,
                     previous_hash, entry_hash, chain_id)
                SELECT id, user_id, action, document_id, details, timestamp,
                       previous_hash, entry_hash, chain_id
                FROM audit_logs
                ORDER BY id
            """)

            conn.execute("DROP TABLE audit_logs")

            conn.execute(
                "ALTER TABLE audit_logs_new RENAME TO audit_logs"
            )

            conn.commit()

            conn.execute("PRAGMA foreign_keys = ON")

        # ==========================================
        # AUDIT CHAIN STATE
        # ==========================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                active_chain_id INTEGER NOT NULL
            )
        """)

        existing_count = conn.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]

        initial_active_chain = (
            2 if chain_id_added and existing_count else 1
        )

        conn.execute("""
            INSERT OR IGNORE INTO audit_chain_state
                (id, active_chain_id)
            VALUES (1, ?)
        """, (initial_active_chain,))

        # ==========================================
        # INITIALIZE OLD AUDIT LOG HASHES
        # ==========================================

        previous_hash = "GENESIS"

        old_logs = conn.execute("""
            SELECT id, user_id, action, document_id,
                   details, timestamp, previous_hash, entry_hash
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
            """, (
                previous_hash,
                entry_hash,
                log["id"]
            ))

            previous_hash = entry_hash

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# Create tables when application starts
create_tables()

# ==========================================
# AUDIT LOG HELPER
# ==========================================

def append_audit_log(conn, user_id, action, document_id=None, details=""):
    """Append an immutable, hash-chained audit entry to the active chain."""

    details = str(details or "")
    action = str(action)

    state = conn.execute("""
        SELECT active_chain_id
        FROM audit_chain_state
        WHERE id = 1
    """).fetchone()
    chain_id = state["active_chain_id"] if state else 1

    previous = conn.execute("""
        SELECT entry_hash
        FROM audit_logs
        WHERE chain_id = ?
        ORDER BY id DESC
        LIMIT 1
    """, (chain_id,)).fetchone()

    if previous:
        previous_hash = previous["entry_hash"]
        if not previous_hash:
            raise ValueError("Previous audit record has no hash.")
    else:
        previous_hash = "GENESIS"

    timestamp = datetime.now().astimezone().isoformat()

    cursor = conn.execute("""
        INSERT INTO audit_logs (
            user_id, action, document_id, details, timestamp,
            previous_hash, entry_hash, chain_id
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
    """, (
        user_id, action, document_id, details, timestamp,
        previous_hash, chain_id
    ))

    entry_id = cursor.lastrowid
    audit_data = {
        "id": entry_id,
        "user_id": user_id,
        "action": action,
        "document_id": document_id,
        "details": details,
        "timestamp": timestamp,
        "previous_hash": previous_hash
    }
    audit_string = json.dumps(
        audit_data, sort_keys=True, separators=(",", ":")
    )
    entry_hash = hashlib.sha256(audit_string.encode("utf-8")).hexdigest()

    conn.execute(
        "UPDATE audit_logs SET entry_hash = ? WHERE id = ?",
        (entry_hash, entry_id)
    )


def log_action(user_id, action, document_id=None, details=""):

    conn = get_db_connection()

    try:
        conn.execute("BEGIN IMMEDIATE")

        append_audit_log(
            conn,
            user_id,
            action,
            document_id,
            details
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def verify_audit_chain():
    """Verify every audit-chain segment and report all integrity failures."""

    conn = get_db_connection()
    try:
        logs = conn.execute("""
            SELECT id, user_id, action, document_id, details, timestamp,
                   previous_hash, entry_hash, chain_id
            FROM audit_logs
            ORDER BY chain_id ASC, id ASC
        """).fetchall()

        failures = []
        chain_ids = sorted({log["chain_id"] for log in logs})
        for chain_id in chain_ids:
            expected_previous_hash = "GENESIS"
            chain_valid = True
            for log in (item for item in logs if item["chain_id"] == chain_id):
                if log["previous_hash"] != expected_previous_hash:
                    failures.append(
                        f"Broken hash chain in segment {chain_id} "
                        f"at log ID {log['id']}"
                    )
                    chain_valid = False
                    # The next record's previous_hash may still point to this
                    # record, so continue hash checks from the stored hash.
                audit_data = {
                    "id": log["id"],
                    "user_id": log["user_id"],
                    "action": log["action"],
                    "document_id": log["document_id"],
                    "details": str(log["details"] or ""),
                    "timestamp": log["timestamp"],
                    "previous_hash": log["previous_hash"]
                }
                audit_string = json.dumps(
                    audit_data, sort_keys=True, separators=(",", ":")
                )
                calculated_hash = hashlib.sha256(
                    audit_string.encode("utf-8")
                ).hexdigest()
                if calculated_hash != log["entry_hash"]:
                    failures.append(
                        f"Integrity failure in segment {chain_id} "
                        f"at log ID {log['id']}"
                    )
                    chain_valid = False
                expected_previous_hash = log["entry_hash"]

        if failures:
            return False, "; ".join(failures)
        return True, "All audit-chain segments passed integrity verification."
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


# ==========================================
# DOCUMENT PERMISSION HELPER
# ==========================================

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
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def valid_file_content(file, extension):
    """Check whether uploaded content matches its file extension."""
    try:
        file.seek(0)
        header = file.read(16)
        file.seek(0)

        if extension == "pdf":
            return header.startswith(b"%PDF-")

        if extension == "png":
            return header.startswith(b"\x89PNG\r\n\x1a\n")

        if extension in ("jpg", "jpeg"):
            return header.startswith(b"\xff\xd8\xff")

        if extension == "docx":
            with zipfile.ZipFile(file) as archive:
                names = set(archive.namelist())

                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                )

        return False

    except (OSError, zipfile.BadZipFile, ValueError):
        return False

    finally:
        file.seek(0)


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================
# USER REGISTRATION
# PUBLIC USERS BECOME VIEWERS
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        # Username validation
        if not re.fullmatch(r"[A-Za-z]+", username):
            return render_template(
                "register.html",
                error="Username must contain English letters only."
            )

        # Email validation
        email_pattern = (
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )

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
            # Lock database during role assignment and registration
            conn.execute("BEGIN IMMEDIATE")

            # Get the highest user ID ever assigned.
            # AUTOINCREMENT preserves this value even after deletion.
            result = conn.execute("""
                SELECT COALESCE(
                    (SELECT seq
                     FROM sqlite_sequence
                     WHERE name = 'users'),
                    0
                )
            """).fetchone()

            last_registered_id = result[0]

            # Assign role according to registration order
            if last_registered_id == 0:
                assigned_role = "admin"

            elif last_registered_id == 1:
                assigned_role = "owner"

            else:
                assigned_role = "viewer"

            # Register user with automatically assigned role
            conn.execute("""
                INSERT INTO users (
                    username, email, password_hash, role
                )
                VALUES (?, ?, ?, ?)
            """, (
                username,
                email,
                password_hash,
                assigned_role
            ))

            conn.commit()

            return render_template(
                "register.html",
                success="Registration successful! Please sign in."
            )

        except sqlite3.IntegrityError:
            conn.rollback()

            return render_template(
                "register.html",
                error="This email is already registered."
            )

        except Exception:
            conn.rollback()
            app.logger.exception("User registration failed")

            return render_template(
                "register.html",
                error="Registration failed. Please try again."
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

        if not email or not password:
            return render_template(
                "login.html",
                error="Please enter your email and password."
            )

        conn = get_db_connection()

        try:
            user = conn.execute("""
                SELECT id, username, email, password_hash, role
                FROM users
                WHERE email = ?
            """, (email,)).fetchone()

        finally:
            conn.close()

        # Successful login
        if user and check_password_hash(
            user["password_hash"], password
        ):

            # Clear old session data
            session.clear()

            # Store authenticated user ID
            session["user_id"] = user["id"]

            # Record login time
            login_time = datetime.now().astimezone()
            session["login_time"] = login_time.isoformat()

            # Record successful login in audit logs
            log_action(
                user["id"],
                "LOGIN",
                details=(
                    "User logged in successfully at "
                    f"{login_time.strftime('%Y-%m-%d %H:%M:%S %Z')}"
                )
            )

            return redirect(url_for("dashboard"))

        # Record failed login attempt
        log_action(
            user["id"] if user else None,
            "LOGIN_FAILED",
            details="Invalid email address or password submitted"
        )

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
        flash("Please login first.")
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
                SELECT
                    d.id,
                    d.original_filename,
                    d.file_size,
                    d.upload_date,
                    d.owner_id,
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
                SELECT
                    d.id,
                    d.original_filename,
                    d.file_size,
                    d.upload_date,
                    d.owner_id,
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

            shares = conn.execute("""
                SELECT
                    s.shared_with_user_id,
                    u.username,
                    u.email
                FROM document_shares AS s
                JOIN users AS u
                    ON u.id = s.shared_with_user_id
                WHERE s.document_id = ?
                ORDER BY s.shared_date DESC
            """, (doc["id"],)).fetchall()

            item["shares"] = [
                dict(share) for share in shares
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
# SECURE DOCUMENT UPLOAD
# OWNER AND ADMIN ONLY
# ==========================================

@app.route("/upload", methods=["POST"])
@role_required("owner", "admin")
def upload_document():

    user = current_user()

    if user is None:
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

    # Validate that file content matches its extension
    if not valid_file_content(file, extension):
        flash("File content does not match the selected file type.")
        return redirect(url_for("documents"))

    stored_filename = f"{uuid.uuid4().hex}.{extension}"

    file_path = os.path.join(
        UPLOAD_FOLDER,
        stored_filename
    )

    conn = None

    try:
        file.save(file_path)

        conn = get_db_connection()

        conn.execute("BEGIN IMMEDIATE")

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

        append_audit_log(
            conn,
            user["id"],
            "UPLOAD",
            document_id,
            f"Uploaded document: {original_filename}"
        )

        conn.commit()

        flash("Document uploaded successfully!")

    except Exception:

        if conn:
            conn.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        app.logger.exception("Document upload failed")

        flash("Upload failed. Please try again.")

    finally:
        if conn:
            conn.close()

    return redirect(url_for("documents"))


# ==========================================
# SECURE DOCUMENT DOWNLOAD
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
        document = conn.execute("""
            SELECT id, original_filename, stored_filename, owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        if document is None:
            denied_reason = "Document does not exist"
            document_name = None
            stored_filename = None
            document_id_for_log = None

        else:
            is_owner_or_admin = (
                user["role"] == "admin"
                or document["owner_id"] == user["id"]
            )

            is_shared_viewer = conn.execute("""
                SELECT 1
                FROM document_shares
                WHERE document_id = ?
                  AND shared_with_user_id = ?
            """, (
                document_id,
                user["id"]
            )).fetchone() is not None

            if not is_owner_or_admin and not is_shared_viewer:

                denied_reason = "Unauthorized download attempt"
                document_name = document["original_filename"]
                stored_filename = None
                document_id_for_log = document_id

            else:
                denied_reason = None
                document_name = document["original_filename"]
                stored_filename = document["stored_filename"]
                document_id_for_log = document_id

    finally:
        conn.close()

    if denied_reason:

        log_action(
            user["id"],
            "DOWNLOAD_DENIED",
            document_id_for_log,
            denied_reason
        )

        abort(404)

    file_path = os.path.join(
        UPLOAD_FOLDER,
        stored_filename
    )

    if not os.path.isfile(file_path):
        abort(404)

    log_action(
        user["id"],
        "DOWNLOAD",
        document_id,
        f"Downloaded document: {document_name}"
    )

    return send_from_directory(
        UPLOAD_FOLDER,
        stored_filename,
        as_attachment=True,
        download_name=document_name
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
            SELECT id, original_filename, stored_filename, owner_id
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

        conn.execute("BEGIN IMMEDIATE")

        conn.execute("""
            DELETE FROM documents
            WHERE id = ?
        """, (document_id,))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

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
            SELECT id, original_filename, owner_id
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
            (
                f"Shared {document['original_filename']} "
                f"with {recipient['username']} ({recipient['email']})"
            )
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

    revoked = False

    try:
        conn.execute("BEGIN IMMEDIATE")

        document = conn.execute("""
            SELECT id, original_filename, owner_id
            FROM documents
            WHERE id = ?
        """, (document_id,)).fetchone()

        if document is None or not can_manage_document(
            user, document
        ):
            conn.rollback()
            abort(404)

        recipient = conn.execute("""
            SELECT username, email
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        cursor = conn.execute("""
            DELETE FROM document_shares
            WHERE document_id = ?
              AND shared_with_user_id = ?
        """, (
            document_id,
            user_id
        ))

        revoked = cursor.rowcount > 0

        if revoked:

            recipient_label = (
                recipient["email"] if recipient else str(user_id)
            )

            append_audit_log(
                conn,
                user["id"],
                "REVOKE",
                document_id,
                (
                    f"Revoked access to {document['original_filename']} "
                    f"for {recipient_label}"
                )
            )

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

@app.route("/logout", methods=["POST"])
def logout():

    user_id = session.get("user_id")

    if user_id is not None:

        logout_time = datetime.now().astimezone()

        login_time_text = session.get("login_time")

        duration_text = "Not available"

        if login_time_text:

            try:
                login_time = datetime.fromisoformat(
                    login_time_text
                )

                duration_seconds = max(
                    0,
                    int(
                        (logout_time - login_time).total_seconds()
                    )
                )

                hours, remainder = divmod(
                    duration_seconds, 3600
                )

                minutes, seconds = divmod(
                    remainder, 60
                )

                duration_text = (
                    f"{hours} hours, "
                    f"{minutes} minutes, "
                    f"{seconds} seconds"
                )

            except (TypeError, ValueError):
                duration_text = (
                    "Could not calculate session duration"
                )

        log_action(
            user_id,
            "LOGOUT",
            details=(
                f"Logout time: "
                f"{logout_time.strftime('%Y-%m-%d %H:%M:%S %Z')}; "
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
