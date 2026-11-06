# TrustVault - Threat Model

## 1. Project Overview

TrustVault is a secure document management and sharing application. It protects confidential documents from unauthorized access and maintains an audit trail of document activities.

## 2. Assets to Protect

- User accounts and passwords
- Uploaded confidential documents
- Document ownership information
- Document sharing permissions
- Audit logs
- User sessions

## 3. Threats and Attack Scenarios

### Threat 1: Unauthorized Document Access

**Attack:** A user attempts to access another user's document by changing the document ID in the URL.

**Mitigation:**
- Check authentication on every protected request.
- Verify document ownership or active sharing permission on the server.
- Return an error when access is not authorized.

### Threat 2: Unauthorized Document Sharing

**Attack:** A Viewer attempts to share a confidential document with another user.

**Mitigation:**
- Only Admins and authorized Owners can share documents.
- Server-side role checks enforce permissions.

### Threat 3: Access After Revocation

**Attack:** A previously authorized Viewer attempts to download a document after their access has been revoked.

**Mitigation:**
- Remove the sharing permission from the database.
- Check current permissions on every download request.
- Deny future access after revocation.

### Threat 4: Audit Log Tampering

**Attack:** An attacker attempts to modify audit records to hide document activity.

**Mitigation:**
- Generate SHA-256 hashes for audit entries.
- Link entries using previous hashes.
- Verify hashes to detect changes.

**Limitation:** Hash chains can detect tampering but cannot prevent an attacker with direct database access from changing the entire chain.

### Threat 5: Unauthorized File Upload

**Attack:** A Viewer attempts to upload a document without permission.

**Mitigation:**
- Restrict upload access using server-side role checks.
- Allow only configured file extensions.
- Enforce a maximum upload size.

### Threat 6: Password Exposure

**Attack:** An attacker obtains stored password information.

**Mitigation:**
- Store passwords using Werkzeug password hashing.
- Never store plain-text passwords.

### Threat 7: Session Misuse

**Attack:** An attacker attempts to misuse an authenticated session.

**Mitigation:**
- Use HTTP-only session cookies.
- Configure SameSite cookie protection.
- Clear the session during logout.

## 4. Security Testing

TrustVault includes automated security tests for:

- Unauthorized document access
- Viewer upload restrictions
- Viewer sharing restrictions
- Viewer revocation restrictions
- Audit log tampering detection

Current test result: 11 automated tests passed.

## 5. Accepted Risks and Limitations

- The application currently uses SQLite for database storage.
- The local development server is not suitable for production.
- Hash chaining detects changes but does not provide independent tamper-proof storage.
- Additional production security measures are required before handling real confidential documents.

## 6. Future Improvements

- Add CSRF protection.
- Validate uploaded file content and MIME types.
- Use secure production deployment settings.
- Store audit logs in independently protected storage.
- Add security monitoring and alerts.