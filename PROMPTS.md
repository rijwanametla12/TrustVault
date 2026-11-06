# TrustVault - AI Prompt Log

This file records how AI assistance was used during TrustVault development. All suggestions were reviewed and tested by the developer.

## Entry 1 - Document Authorization

**Date:** 2026-11-06

**Prompt / Task:** Help implement server-side authorization so users cannot download documents belonging to other users without permission.

**AI Output:** Suggested checking the current user's role, document ownership, and active sharing permission on every download request.

**Errors Found:** Earlier access tests were not sufficient to prove that every user was correctly restricted.

**Human Review and Correction:** Updated the download route to check authorization before sending a file. Unauthorized attempts are recorded in the audit log and return a 404 response.

**Commit:** Pending.

## Entry 2 - Immediate Access Revocation

**Date:** 2026-11-06

**Prompt / Task:** Help make document-sharing revocation effective immediately.

**AI Output:** Suggested removing the sharing permission from the database and checking permissions on every download request.

**Errors Found:** The audit event and permission deletion needed to be handled safely together.

**Human Review and Correction:** Updated the revoke route to use a database transaction. It deletes the sharing record and inserts the REVOKE audit event in the same transaction.

**Commit:** Pending.

## Entry 3 - Audit Log Integrity

**Date:** 2026-11-06

**Prompt / Task:** Help implement SHA-256 hash chaining for TrustVault audit logs.

**AI Output:** Suggested linking each audit entry to the previous entry using a SHA-256 hash and verifying entries to detect changes.

**Errors Found:** Existing audit records needed to be handled when introducing hash chaining.

**Human Review and Correction:** Added hash-generation and verification logic. Added a test that changes an audit record and checks that the calculated hash does not match the stored hash.

**Limitation:** Hash chaining can detect tampering but cannot prevent an attacker with sufficient database access from changing the entire chain.

**Commit:** Pending.

## Entry 4 - Viewer Role Restrictions

**Date:** 2026-11-06

**Prompt / Task:** Help ensure that Viewer users cannot upload documents or perform Owner/Admin actions.

**AI Output:** Suggested enforcing role restrictions on the server rather than relying only on hidden interface buttons.

**Errors Found:** Role restrictions needed automated tests to verify that unauthorized actions were rejected.

**Human Review and Correction:** Added security tests for Viewer restrictions and reviewed the server-side route protections.

**Commit:** Pending.

## Entry 5 - Automated Security Testing

**Date:** 2026-11-06

**Prompt / Task:** Help create automated security tests for document authorization, sharing, revocation, and audit integrity.

**AI Output:** Suggested using Python unittest and Flask's test client to test security behavior.

**Errors Found:** An initial test command failed because the test file was inside the tests folder, not the project root.

**Human Review and Correction:** Corrected the test execution path and ran the test suite successfully. The latest run reported 11 tests passed.

**Commit:** Pending.

---

## AI Usage Statement

AI assistance was used for coding guidance, debugging, security suggestions, and test-case development. The developer reviewed the suggestions, made corrections, and tested the application. AI-generated suggestions were not accepted without review.
