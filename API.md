# TrustVault – API and Role-Based Authorization Documentation

## 1. Overview

TrustVault is a Python Flask application that uses browser-facing HTTP routes, Flask sessions, and server-side role-based authorization.

**Important:** The current application does not expose a separate JSON REST API. This document describes its implemented browser routes and authorization rules.

## 2. User Roles

| Role | Permissions |
|---|---|
| Admin | Manage documents and view audit logs |
| Owner | Upload, manage, share, and revoke access to own documents |
| Viewer | View and download documents explicitly shared with them |

### Automatic Role Assignment

- First registered account: Admin
- Second registered account: Owner
- Remaining accounts: Viewer

Users cannot choose their own role during registration.

## 3. Authentication

Protected routes require an authenticated Flask session.

- Registration creates an account.
- Login verifies the user's email and password.
- Passwords are stored using Werkzeug password hashing.
- Logout clears the user session.
- State-changing forms use CSRF protection.

## 4. HTTP Route Documentation

| HTTP Method | Endpoint | Access | Description |
|---|---|---|---|
| GET | `/` | Public | Displays the home page. |
| GET, POST | `/register` | Public | Displays registration form and creates an account with an automatically assigned role. |
| GET, POST | `/login` | Public | Displays login form and authenticates users. |
| GET | `/dashboard` | Authenticated users | Displays the user's dashboard. |
| GET | `/documents` | Admin, Owner | Displays all documents for Admin and own documents for Owner. |
| POST | `/upload` | Admin, Owner | Uploads an authorized document. |
| GET | `/download/<document_id>` | Admin, Owner, authorized Viewer | Downloads a document after checking current access permissions. |
| POST | `/delete/<document_id>` | Admin, document Owner | Deletes an authorized document. |
| POST | `/share/<document_id>` | Admin, document Owner | Shares a document with a registered user using Viewer access. |
| POST | `/revoke-share/<document_id>/<user_id>` | Admin, document Owner | Revokes an existing sharing permission. |
| POST | `/ai/suggest/<document_id>` | Authorized document manager | Requests an AI-generated permission suggestion. |
| POST | `/ai/suggestions/<suggestion_id>/approve` | Admin, document Owner | Approves a pending AI permission suggestion. |
| POST | `/ai/suggestions/<suggestion_id>/reject` | Admin, document Owner | Rejects a pending AI permission suggestion. |
| GET | `/shared-documents` | Authenticated users | Displays documents shared with the current user. |
| GET | `/audit-logs` | Admin | Displays audit events. |
| POST | `/logout` | Authenticated users | Records logout and clears the session. |

## 5. Authorization Rules

### Document Download

Before downloading, the application checks whether the signed-in user is:

- The document owner.
- An Admin.
- A user with an active sharing permission.

Unauthorized or missing documents are denied.

### Document Sharing

Only the document Owner or Admin can share a document.

The recipient must already have a registered account. The current sharing permission is Viewer-only.

### AI-Powered Permission Review

TrustVault integrates Google Gemini to generate AI-powered document permission suggestions.

The workflow is:

1. An authorized document manager requests an AI permission suggestion.
2. Gemini analyzes available document metadata and recipient context.
3. The system generates a permission recommendation.
4. The recommendation remains pending until reviewed.
5. An Admin or document Owner can approve or reject the suggestion.
6. Access is granted only after approval.

**Important:** AI does not automatically grant document access. Human approval is required before an AI-generated suggestion can grant access.

### Access Revocation

Only the document Owner or Admin can revoke sharing access.

After revocation, the application checks permissions again on future download requests. A previously shared URL does not preserve access.

### Document Deletion

Only the document Owner or Admin can delete a document.

### Audit Logs

Only Admin users can view the audit-log page.

## 6. Security Controls

- Server-side role checks.
- Ownership verification.
- Active sharing-permission verification.
- CSRF protection for state-changing forms.
- Werkzeug password hashing.
- File extension and content-signature validation.
- Maximum upload size of 5 MB.
- SHA-256 audit hash chaining.
- Required SECRET_KEY environment variable.
- Secure session cookie configuration for production.
- Human approval for AI-generated permission suggestions.

## 7. Audit Events

The application records security-relevant events, including:

- LOGIN
- LOGOUT
- UPLOAD
- DOWNLOAD
- DOWNLOAD_DENIED
- SHARE
- REVOKE
- DELETE
- AI permission suggestion approval and rejection events.

Audit records use SHA-256 hash chaining.

Historical audit-chain integrity failures remain unresolved and are documented in `THREATS.md`.

## 8. Known API Limitations

- No separate JSON REST API is currently implemented.
- No API tokens or external API authentication.
- AI permission suggestions depend on a valid Gemini API key and service availability.
- AI-generated suggestions require human review and approval.
- No external-link sharing.
- No document versioning or recovery.
- Persistent cloud database and file storage are not verified.

## 9. Security Test Execution

Run the automated tests using:

```bash
python -m pytest tests/test_security.py -v
```

The latest reported local test result was 16 passed.

This result does not certify every possible security scenario or production deployment.

## 10. Deployment

Live application:

https://trustvault-qp9w.onrender.com

GitHub repository:

https://github.com/rijwanametla12/TrustVault
