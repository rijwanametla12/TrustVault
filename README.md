# TrustVault – Secure Document Management System

TrustVault is a secure document management and sharing application built using Python Flask. It helps users upload, manage, share, and access confidential documents with role-based permissions and audit logging.

## 1. Project Objectives

- Protect confidential documents from unauthorized access.
- Allow document owners to share documents with authorized viewers.
- Revoke document access immediately.
- Record document activities in audit logs.
- Detect changes to audit records using SHA-256 hash chaining.

## 2. Technologies Used

- Python 3.13
- Flask
- SQLite
- HTML, CSS and JavaScript
- SHA-256 hashing
- pytest
- Flask-WTF
- Werkzeug
- Gunicorn
- Supabase (dependency included; integration requires configuration)

## 3. User Roles

### Admin
- Manage documents.
- View audit logs.
- Access administrative features.

### Owner
- Upload and manage own documents.
- Share documents with other users.
- Revoke document access.

### Viewer
- View documents shared with them.
- Download authorized documents.
- Cannot upload or manage documents.

## 4. Main Features

- User registration and login.
- Role-based access control.
- Secure document upload.
- Document sharing.
- Immediate access revocation.
- Protected document downloads.
- Audit logging.
- SHA-256 hash chaining.
- Automated security tests.

## 5. Technologies and Configuration

- Database: SQLite (`instance/trustvault.db`)
- Upload directory: `uploads/`
- Maximum upload size: 5 MB
- Allowed file formats: PDF, DOCX, PNG, JPG and JPEG.
- Database tables are initialized automatically by `create_tables()`.

## 6. Installation and Setup

### Prerequisites

- Python 3.13
- Git
- Visual Studio Code (recommended)

### Clone the repository

```bash
git clone https://github.com/rijwanametla12/TrustVault.git
cd TrustVault
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate the environment (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install -r requirements.txt
```

## 7. Run the Application

```bash
python app.py
```

Open your browser:

http://127.0.0.1:5000

The application creates its database tables automatically.

**Note:** Flask debug mode is intended for local development only. Use a production configuration when deploying.

## 8. Run Security Tests

Run the automated tests:

```bash
python -m pytest -v
```

The current project test suite contains 11 security tests.

**Latest local test result: 11 tests passed.**

## 9. Project Structure

```text
TrustVault/
├── app.py
├── README.md
├── THREATS.md
├── PROMPTS.md
├── requirements.txt
├── .gitignore
├── instance/
├── uploads/
├── static/
│   └── style.css
├── templates/
│   ├── audit_logs.html
│   ├── dashboard.html
│   ├── documents.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── shared_documents.html
└── tests/
    └── test_security.py
```

**Note:** The SQLite database and uploaded documents are runtime data. They should not be committed to the public repository.

## 10. Security Considerations and Known Limitations

- Access permissions are checked before document downloads.
- Revoked users should no longer be able to download previously shared documents.
- Audit records use SHA-256 hash chaining.
- Historical audit records contain integrity failures, including records affected by earlier document or user deletions.
- A separate new audit chain has been created. Its first two records passed individual hash and linkage checks.
- Historical failures have not been silently rewritten.
- The new audit chain requires further automated verification.
- A local SQLite hash chain does not protect against an attacker who can rewrite the database and recompute the hashes.
- Production deployment requires persistent database and upload storage.
- Demo credentials should be provided separately through a secure demonstration setup. Never publish real passwords.

## 11. Deployment

**Live Application:**

https://trustvault-qp9w.onrender.com

**GitHub Repository:**

https://github.com/rijwanametla12/TrustVault

Deployment must be checked to ensure that database records and uploaded files persist across restarts.

## 12. Documentation

- `README.md` – Installation, setup and project overview.
- `THREATS.md` – Security threat model, attack paths and mitigations.
- `PROMPTS.md` – AI assistance, corrections and development history.

## 13. Future Improvements

- Stronger audit-log protection using external immutable storage.
- Improved file-content validation.
- Persistent cloud database and file storage.
- Additional automated security tests.
- Security alerts and administrative monitoring.
- Independent audit-chain verification and monitoring.
