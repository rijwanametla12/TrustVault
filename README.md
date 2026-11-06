# TrustVault - Secure Document Management System

TrustVault is a secure document management and sharing application built using Python Flask. It helps users upload, manage, share, and access documents with role-based permissions and audit logging.

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
- HTML
- CSS
- JavaScript
- SHA-256 Hashing
- Python unittest

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
- SHA-256 hash chaining for audit integrity.
- Automated security tests.

## 5. Project Structure

```text
TrustVault/
│
├── app.py
├── README.md
├── THREATS.md
├── PROMPTS.md
│
├── instance/
│   └── trustvault.db
│
├── static/
│   └── style.css
│
├── templates/
│   ├── audit_logs.html
│   ├── dashboard.html
│   ├── documents.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── shared_documents.html
│
├── tests/
│   └── test_security.py
│
└── uploads/