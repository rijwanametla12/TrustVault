
# TrustVault – Security Threat Model

## 1. Project Overview

TrustVault is a secure document management and sharing application built using Python Flask. It protects confidential documents through authentication, role-based access control, document permissions, protected downloads, and audit logging.

## 2. Assets to Protect

- User accounts and passwords.
- Uploaded confidential documents.
- Document ownership information.
- Document sharing permissions.
- Audit logs and integrity information.
- User sessions and authentication data.
- Application secret keys and configuration.

## 3. Threats and Attack Scenarios

### Threat 1: Unauthorized Document Access

**Attack:** A user attempts to access another user's document by changing the document ID in a URL.

**Mitigations:**
- Check authentication on protected requests.
- Verify document ownership or active sharing permission on the server.
- Deny requests without authorization.
- Record unauthorized download attempts in audit logs.
- Test direct URL access by unauthorized users.

**Verification:** Automated tests cover unauthorized document downloads. Live testing also confirmed that a Viewer cannot access the protected documents page.

### Threat 2: Unauthorized Document Sharing

**Attack:** A Viewer attempts to share a confidential document with another user.

**Mitigations:**
- Restrict sharing to authorized roles.
- Enforce permissions through server-side checks.
- Reject unauthorized sharing attempts.
- Test unauthorized sharing attempts.

**Verification:** Viewer sharing restrictions are included in the automated security tests.

### Threat 3: Access After Revocation

**Attack:** A previously authorized Viewer attempts to download a document after their access has been revoked.

**Mitigations:**
- Remove the sharing permission from the database.
- Check current permissions on every download request.
- Deny future access after revocation.
- Record revocation activity in the audit log.
- Test previously shared direct download URLs after revocation.

**Verification:** Live testing confirmed that after the Owner revoked access, the Viewer could no longer see the shared document. The old download URL returned 404.

### Threat 4: Audit Log Tampering

**Attack:** An attacker attempts to modify audit records to hide document activity.

**Mitigations:**
- Generate SHA-256 hashes for audit entries.
- Link entries using previous hashes.
- Verify stored hashes against calculated hashes.
- Test whether changes to audit records are detected.
- Preserve historical integrity failures instead of silently recalculating old hashes.

**Known Issue:**

Historical audit records contain integrity failures. The audit table uses `ON DELETE SET NULL` for both `user_id` and `document_id`. Deleting related users or documents can change values included in previously calculated audit hashes.

**Local Verification Results:**

- Audit-chain segment 1 contains 122 records.
- Segment 1 has 32 reported integrity failures.
- Audit-chain segment 2 contains 36 records.
- All 36 records in segment 2 passed individual hash and previous-hash linkage checks during local verification.
- Overall local verification still reports failure because historical failures in segment 1 remain.

**Limitations:**

- Historical integrity failures remain unresolved.
- Verification results are from the local SQLite database, not the deployed Render database.
- Hash chaining alone cannot prevent an attacker with direct database access from modifying records and recalculating hashes.
- Independent immutable audit storage is a future improvement.

### Threat 5: Unauthorized File Upload

**Attack:** A Viewer attempts to upload a document without permission.

**Mitigations:**
- Restrict uploads through server-side role checks.
- Configure allowed file extensions.
- Enforce a maximum upload size of 5 MB.
- Validate uploaded file content.

**Remaining Risk:** Further verification of file-content and MIME-signature validation is required.

### Threat 6: Password Exposure

**Attack:** An attacker obtains stored password information.

**Mitigations:**
- Use Werkzeug password hashing.
- Avoid storing plain-text passwords.
- Apply password validation during registration.

**Remaining Risk:** Additional password-policy and login rate-limiting improvements may be required.

### Threat 7: Session Misuse

**Attack:** An attacker attempts to misuse an authenticated session.

**Mitigations:**
- Configure HTTP-only session cookies.
- Configure SameSite cookie protection.
- Use secure cookie settings in production.
- Clear sessions during logout.
- Protect state-changing requests with CSRF tokens.
- Require a securely configured SECRET_KEY environment variable.

**Correction:** The previous hard-coded development fallback secret key was removed. The application now raises an error if `SECRET_KEY` is missing.

### Threat 8: Privilege Escalation During Registration

**Attack:** A new user attempts to register with an Admin or Owner role by manipulating registration data.

**Mitigations:**
- Assign roles on the server.
- Ignore client-supplied role values.
- Assign the first registered account as Admin.
- Assign the second registered account as Owner.
- Assign all subsequent accounts as Viewer.
- Use a one-time migration to assign roles to existing accounts in registration order.

**Verification:** Automated registration tests confirmed the expected role assignment for the first, second, third, and fourth accounts.

## 4. Security Testing

The current automated test suite contains 16 tests covering:

- PDF file validation.
- Audit-log tampering detection.
- CSRF protection.
- Unauthorized download logging.
- Admin-only audit-log access.
- Owner document permissions.
- Viewer download restrictions.
- Authorized shared document downloads.
- Revoked access.
- Viewer upload restrictions.
- Viewer sharing restrictions.
- Viewer deletion restrictions.
- Viewer revocation restrictions.
- Unauthorized document deletion.
- Automatic registration role assignment.

**Latest Local Test Result: 16 tests passed.**

Command used:

```bash
python -m pytest tests/test_security.py -v
```

Additional syntax verification:

```bash
python -m py_compile app.py tests/test_security.py
```

These tests provide evidence for the tested scenarios but do not establish that every possible attack is prevented.

## 5. Live Application Verification

The deployed application was manually tested using separate Admin, Owner, and Viewer accounts.

Verified workflows:

- Admin could access audit logs.
- Owner could upload a document.
- Viewer could not access the protected documents page.
- Owner could share a document with a Viewer.
- Viewer could see and download the shared document.
- Owner could revoke sharing access.
- Viewer could no longer see or download the document after revocation.
- Relevant activity events appeared in the Admin audit-log page.

**Live Application:**

https://trustvault-qp9w.onrender.com

**GitHub Repository:**

https://github.com/rijwanametla12/TrustVault

Live functional testing does not independently establish the integrity of the deployed audit chain.

## 6. Accepted Risks and Limitations

- SQLite is currently used for database storage.
- Persistent database and upload storage have not been verified for the current Render Free deployment.
- Database records and uploaded files may be lost after a restart, redeployment, or instance replacement.
- Historical audit records have unresolved integrity failures.
- The new audit chain passed local verification for 36 records, but historical failures remain.
- Hash chaining is not independently tamper-proof.
- File-content validation requires further testing.
- Login rate limiting and additional monitoring require improvement.
- Production use with real confidential documents requires further security hardening.

## 7. Future Improvements

- Preserve immutable user and document identifiers in audit records.
- Add independent, append-only audit storage.
- Validate actual uploaded file content and MIME signatures.
- Add login rate limiting and account-protection controls.
- Configure persistent cloud database and file storage.
- Add security monitoring and alerts.
- Expand automated authorization and audit-integrity tests.
- Implement reliable backup and recovery support.
- Conduct an independent security review before production use.
