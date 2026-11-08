# TrustVault – Security Threat Model

## 1. Project Overview

TrustVault is a secure document management and sharing application built using Python Flask. It protects confidential documents through authentication, role-based access control, document permissions and audit logging.

## 2. Assets to Protect

- User accounts and passwords
- Uploaded confidential documents
- Document ownership information
- Document sharing permissions
- Audit logs and integrity information
- User sessions and authentication data

## 3. Threats and Attack Scenarios

### Threat 1: Unauthorized Document Access

**Attack:** A user attempts to access another user's document by changing the document ID in a URL.

**Mitigations:**
- Check authentication on protected requests.
- Verify document ownership or active sharing permission on the server.
- Deny requests without authorization.
- Test direct URL access by unauthorized users.

### Threat 2: Unauthorized Document Sharing

**Attack:** A Viewer attempts to share a confidential document with another user.

**Mitigations:**
- Restrict sharing to authorized roles.
- Enforce permissions through server-side checks.
- Test unauthorized sharing attempts.

### Threat 3: Access After Revocation

**Attack:** A previously authorized Viewer attempts to download a document after their access has been revoked.

**Mitigations:**
- Remove the sharing permission from the database.
- Check current permissions on every download request.
- Deny future access after revocation.
- Test previously shared direct download URLs after revocation.

### Threat 4: Audit Log Tampering

**Attack:** An attacker attempts to modify audit records to hide document activity.

**Mitigations:**
- Generate SHA-256 hashes for audit entries.
- Link entries using previous hashes.
- Verify stored hashes against calculated hashes.
- Preserve historical integrity failures instead of silently recalculating old hashes.

**Known issue:** Historical audit records contain integrity failures. Some records may have been changed when document or user records were deleted because the database uses `ON DELETE SET NULL` for audit-log foreign keys.

A separate new audit chain was created. Its first two records passed individual hash verification and chain-linkage checks.

**Limitations:**
- The historical chain still has unresolved integrity failures.
- The new chain has only been tested with two records.
- Hash chaining alone cannot prevent an attacker with direct database access from modifying records and recalculating hashes.
- Independent immutable audit storage is a future improvement.

### Threat 5: Unauthorized File Upload

**Attack:** A Viewer attempts to upload a document without permission.

**Mitigations:**
- Restrict uploads through server-side role checks.
- Configure allowed file extensions.
- Enforce a maximum upload size of 5 MB.

**Remaining risk:** File-content and MIME-signature validation require further verification.

### Threat 6: Password Exposure

**Attack:** An attacker obtains stored password information.

**Mitigations:**
- Use Werkzeug password hashing.
- Avoid storing plain-text passwords.

### Threat 7: Session Misuse

**Attack:** An attacker attempts to misuse an authenticated session.

**Mitigations:**
- Configure HTTP-only session cookies.
- Configure SameSite cookie protection.
- Use secure cookie settings in production.
- Clear sessions during logout.
- Protect state-changing requests with CSRF tokens.

## 4. Security Testing

The current automated test suite contains 11 tests covering:

- Unauthorized document access
- Viewer download restrictions
- Denied download logging
- Authorized shared document downloads
- Revoked access
- Viewer upload restrictions
- Viewer sharing restrictions
- Viewer deletion and revocation restrictions
- Unauthorized document deletion
- Audit tampering detection

**Latest local test result: 11 tests passed.**

These tests do not establish that every possible attack is prevented.

## 5. Accepted Risks and Limitations

- SQLite is currently used for database storage.
- Production deployment requires persistent database and upload storage.
- Historical audit records have unresolved integrity failures.
- The new audit chain has only undergone initial verification.
- Hash chaining is not independently tamper-proof.
- File-content validation requires further testing.
- Additional security hardening is required before handling real confidential documents.

## 6. Future Improvements

- Preserve immutable user and document identifiers in audit records.
- Add independent, append-only audit storage.
- Validate actual uploaded file content and MIME signatures.
- Improve production deployment security.
- Add security monitoring and alerts.
- Expand automated authorization and audit-integrity tests.
