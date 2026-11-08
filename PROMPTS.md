
# TrustVault – AI Prompt Log

This file records how AI assistance was used during TrustVault development. AI suggestions were reviewed, corrected, and tested by the developer. The developer remained responsible for implementation and verification.

## Entry 1 – Document Authorization

**Date:** 2026-11-06

**Prompt / Task:** Help implement server-side authorization so users cannot download documents belonging to other users without permission.

**AI Output:** Suggested checking the current user's role, document ownership, and active sharing permission on every download request.

**Errors Found:** Earlier access tests were not sufficient to prove that every user was correctly restricted.

**Human Review and Correction:** Updated the download route to check authorization before sending a file. Unauthorized attempts are recorded in the audit log and return a 404 response.

**Verification:** Tested owner access, shared viewer downloads, unauthorized viewer downloads, and revoked access.

## Entry 2 – Immediate Access Revocation

**Date:** 2026-11-06

**Prompt / Task:** Help make document-sharing revocation effective immediately.

**AI Output:** Suggested removing the sharing permission from the database and checking permissions on every download request.

**Errors Found:** The audit event and permission deletion needed to be handled safely together.

**Human Review and Correction:** Updated the revoke route to use a database transaction. It deletes the sharing record and inserts the REVOKE audit event in the same transaction.

**Verification:** Tested revocation and confirmed that the previously shared document was no longer available to the viewer. An old download URL returned 404.

## Entry 3 – Audit Log Integrity

**Date:** 2026-11-06

**Prompt / Task:** Help implement SHA-256 hash chaining for TrustVault audit logs.

**AI Output:** Suggested linking each audit entry to the previous entry using a SHA-256 hash and verifying entries to detect changes.

**Errors Found:** Existing audit records needed to be handled when introducing hash chaining.

**Human Review and Correction:** Added hash-generation and verification logic. Added a test that changes an audit record and checks that the calculated hash does not match the stored hash.

**Limitation:** Hash chaining can detect tampering but cannot prevent an attacker with sufficient database access from changing the entire chain and recalculating hashes.

**Verification:** The automated audit-tampering test passed.

## Entry 4 – Viewer Role Restrictions

**Date:** 2026-11-06

**Prompt / Task:** Help ensure that Viewer users cannot upload documents or perform Owner/Admin actions.

**AI Output:** Suggested enforcing role restrictions on the server rather than relying only on hidden interface buttons.

**Errors Found:** Role restrictions needed automated tests to verify that unauthorized actions were rejected.

**Human Review and Correction:** Reviewed server-side route protections and added security tests for Viewer restrictions.

**Verification:** Tests confirmed that viewers cannot upload documents, delete documents, share documents, or revoke sharing permissions without authorization.

## Entry 5 – Automated Security Testing

**Date:** 2026-11-06 to 2026-11-08

**Prompt / Task:** Help create automated security tests for document authorization, sharing, revocation, audit integrity, and registration roles.

**AI Output:** Suggested using pytest and Flask's test client to test security behavior.

**Errors Found:** An initial test command failed because the test file was inside the tests folder, not the project root. The earlier documentation also contained an outdated test count.

**Human Review and Correction:** Corrected the test execution path and expanded the test suite to include registration role assignment.

**Verification:** Ran:

```bash
python -m pytest tests/test_security.py -v
```

Latest local result: **16 tests passed.**

The test suite includes file validation, audit tampering detection, CSRF protection, authorization, sharing, revocation, and role assignment.

## Entry 6 – Historical Audit Integrity Investigation

**Date:** 2026-11-08

**Prompt / Task:** Investigate why TrustVault's audit-chain verification reported integrity failures in historical records.

**AI Output:** Suggested inspecting the audit-table foreign keys, hash-generation function, and verification function to identify why stored hashes no longer matched calculated hashes.

**Errors Found:** The audit table used ON DELETE SET NULL for both user_id and document_id. Deleting related users or documents could change values included in previously calculated audit hashes.

**Human Review and Correction:** Inspected the database schema and confirmed the foreign-key behavior. Created database and application backups before testing a separate audit-chain implementation. Preserved historical records without silently recalculating their hashes.

**Local Verification Results:**

- Audit-chain segment 1 contained 122 records and reported 32 integrity failures.
- Audit-chain segment 2 contained 36 records.
- Independently checked the hashes and previous-hash links in segment 2.
- All 36 records in segment 2 passed local verification.
- Overall verification still reports failure because historical failures in segment 1 remain.

**Known Limitation:** These results are from the local SQLite database. They do not establish the integrity status of the deployed Render database. Historical failures remain unresolved.

## Entry 7 – Automatic Registration Role Assignment

**Date:** 2026-11-08

**Prompt / Task:** Implement automatic account roles based on registration order: first account Admin, second account Owner, and all remaining accounts Viewer.

**AI Output:** Suggested assigning roles during registration and migrating existing accounts in registration order.

**Errors Found:** An earlier bootstrap-admin approach attempted to promote a username during application startup. Render logs indicated that the username was not found or was not unique. The startup-time approach was therefore unreliable.

**Human Review and Correction:** Removed the bootstrap-admin promotion approach. Implemented a one-time migration for existing users and assigned roles automatically during new registration. Registration ignores any client-supplied role.

**Verification:** Added registration tests confirming that the first account receives Admin, the second receives Owner, and subsequent accounts receive Viewer.

**Latest Result:** The registration role-assignment test passed as part of the 16-test local suite.

## Entry 8 – Secret Key Security Correction

**Date:** 2026-11-08

**Prompt / Task:** Review the Flask secret-key configuration and improve application security.

**AI Output:** Suggested using a securely generated secret key from an environment variable.

**Errors Found:** The earlier application configuration included a hard-coded development fallback secret key. This could allow insecure deployment if the environment variable was missing.

**Human Review and Correction:** Removed the hard-coded fallback. The application now requires the SECRET_KEY environment variable and raises a RuntimeError if it is missing.

**Verification:** Set a temporary secret key in the local PowerShell session and reran the security tests. All 16 tests passed.

**Deployment Note:** A stable secret key must be configured in the Render environment variables. The actual secret value must never be committed to GitHub or published in documentation.

## Entry 9 – Git Repository and Deployment Security

**Date:** 2026-11-08

**Prompt / Task:** Review repository hygiene and prevent local databases, uploaded documents, backup files, and secrets from being committed.

**AI Output:** Suggested updating .gitignore to exclude sensitive runtime files and unnecessary local artifacts.

**Human Review and Correction:** Updated .gitignore to exclude environment files, SQLite runtime data, uploaded documents, archives, backup Python files, caches, and temporary files.

**Verification:** Committed and pushed the security changes to GitHub.

**Commit:** `2800340` – Require secure secret key and protect project files.

**Deployment Verification:** Render showed commit `2800340` as Live.

## Entry 10 – Live Application Testing

**Date:** 2026-11-08

**Prompt / Task:** Verify the deployed TrustVault application's main role-based document-sharing workflow.

**Human Verification:**

- Confirmed the Admin account could access the audit logs.
- Confirmed the Owner account could upload documents.
- Confirmed the Viewer account could not access the protected documents page.
- Confirmed the Owner could share a document with a Viewer.
- Confirmed the Viewer could see and download the shared document.
- Confirmed the Owner could revoke access.
- Confirmed the revoked Viewer could no longer see or download the document.
- Confirmed relevant activity events appeared in the Admin audit-log page.

**Known Limitation:** Live functional testing does not independently verify the integrity of the deployed audit chain or guarantee persistent storage.

## AI Usage Statement

AI assistance was used for coding guidance, debugging, security suggestions, test-case development, and documentation.

The developer reviewed suggestions, identified errors, made corrections, implemented changes, and tested the application. AI-generated suggestions were not accepted without review.

The latest automated test result was 16 tests passed locally. Live application tests confirmed the main registration, role-based access, document-sharing, download, and revocation workflows.

Known limitations, historical audit failures, and deployment storage constraints are documented honestly. AI assistance does not replace independent security auditing or production verification.
