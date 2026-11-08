
# TrustVault – Secure Document Management System

TrustVault is a secure document management and sharing application built using Python Flask. It helps users upload, manage, share, and access confidential documents through role-based permissions, protected downloads, and audit logging.

## 1. Project Objectives

- Protect confidential documents from unauthorized access.
- Allow document owners to share documents with authorized viewers.
- Revoke document access immediately.
- Record document activities in audit logs.
- Detect changes to audit records using SHA-256 hash chaining.
- Apply role-based access control during registration and document operations.

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

### Automatic Role Assignment

TrustVault assigns roles based on registration order:

1. First registered account: Admin.
2. Second registered account: Owner.
3. All remaining accounts: Viewer.

Existing accounts are assigned roles through a one-time migration based on their user ID order. New registrations receive roles automatically. Users cannot select their own role during registration.

## 4. Main Features

- User registration and login.
- Automatic role assignment.
- Role-based access control.
- Secure document upload.
- Document sharing.
- Immediate access revocation.
- Protected document downloads.
- Audit logging.
- SHA-256 hash chaining.
- CSRF protection.
- Automated security tests.

## 5. Technologies and Configuration

- Database: SQLite (`instance/trustvault.db`)
- Upload directory: `uploads/`
- Maximum upload size: 5 MB
- Allowed file formats: PDF, DOCX, PNG, JPG and JPEG.
- Database tables are initialized automatically by `create_tables()`.
- A valid `SECRET_KEY` environment variable is required before the application starts.

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

### Set the required secret key (Windows PowerShell)

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
```

This creates a temporary secret key for the current terminal session. For production, configure a stable, securely generated secret key in the hosting provider's environment variables. Never publish the secret key.

## 7. Run the Application

After setting `SECRET_KEY`, run:

```bash
python app.py
```

Open your browser:

http://127.0.0.1:5000

The application initializes its database tables automatically.

**Note:** Flask debug mode is intended for local development only. Use a production configuration when deploying.

## 8. Run Security Tests

Make sure the virtual environment is activated and `SECRET_KEY` is set in the current terminal session.

Run the automated tests:

```bash
python -m pytest tests/test_security.py -v
```

### Latest Local Test Result

**16 security tests passed.**

The tests cover:

- PDF file validation.
- Audit-log tampering detection.
- CSRF protection.
- Unauthorized download recording.
- Admin-only audit-log access.
- Owner document permissions.
- Viewer access restrictions.
- Document sharing and revocation.
- Automatic registration role assignment.

The test result was obtained locally. It does not independently certify the security of the deployed application.

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

**Note:** The SQLite database and uploaded documents are runtime data. They should not be committed to the repository.

## 10. Security Considerations and Known Limitations

- Access permissions are checked before document downloads.
- Revoked users should no longer be able to download previously shared documents.
- Audit records use SHA-256 hash chaining.
- Historical audit-chain segment 1 contains 32 integrity failures across its 122 records during local verification.
- Historical failures have not been silently rewritten.
- A separate audit-chain segment 2 contains 36 records and passed individual hash and linkage checks during local verification.
- The overall local audit-chain verification still reports failure because of the historical failures in segment 1.
- These verification results are from the local SQLite database and do not establish the integrity status of the deployed Render database.
- A local SQLite hash chain cannot prevent an attacker with database write access from rewriting the database and recalculating the hashes.
- Production deployment requires persistent database and upload storage.
- Demo credentials should be provided separately through a secure demonstration setup. Never publish real passwords.

## 11. Deployment

**Live Application:**

https://trustvault-qp9w.onrender.com

**GitHub Repository:**

https://github.com/rijwanametla12/TrustVault

The application is deployed on Render using Gunicorn.

**Deployment limitation:** The current Render Free deployment does not have verified persistent storage configured. SQLite database records and uploaded files may be lost after a restart, redeployment, or instance replacement. Persistent storage is required for reliable production use.

The production `SECRET_KEY` must be configured securely as an environment variable on Render.

## 12. Documentation

- `README.md` – Project overview, installation, setup and usage.
- `THREATS.md` – Security threat model, attack paths, mitigations and limitations.
- `PROMPTS.md` – AI assistance, corrections and development history.

## 13. Future Improvements

- Stronger audit-log protection using external immutable storage.
- Improved file-content validation.
- Persistent cloud database and file storage.
- Additional automated security tests.
- Security alerts and administrative monitoring.
- Independent audit-chain verification and monitoring.
- Backup and recovery support.
