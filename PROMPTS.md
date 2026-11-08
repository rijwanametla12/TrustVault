# TrustVault – AI Prompt Log

This file records how AI assistance was used during TrustVault development. AI suggestions were reviewed, corrected, and tested by the developer. The developer remained responsible for implementation and verification.

## Entry 1 – Document Authorization

**Date:** 2026-11-06

**Prompt / Task:** Help implement server-side authorization so users cannot download documents belonging to other users without permission.

**AI Output:** Suggested checking the current user's role, document ownership, and active sharing permission on every download request.

**Errors Found:** Earlier access tests were not sufficient to prove that every user was correctly restricted.

**Human Review and Correction:** Updated the download route to check authorization before sending a file. Unauthorized attempts are recorded in the audit log and return a 404 response.

**Commit:** Pending verification.

## Entry 2 – Immediate Access Revocation

**Date:** 2026-11-06

**Prompt / Task:** Help make document-sharing revocation effective immediately.

**AI Output:** Suggested removing the sharing permission from the database and checking permissions on every download request.

**Errors Found:** The audit event and permission deletion needed to be handled safely together.

**Human Review and Correction:** Updated the revoke route to use a database transaction. It deletes the sharing record and inserts the REVOKE audit event in the same transaction.

**Commit:** Pending verification.

## Entry 3 – Audit Log Integrity

**Date:** 2026-11-06

**Prompt / Task:** Help implement SHA-256 hash chaining for TrustVault audit logs.

**AI Output:** Suggested linking each audit entry to the previous entry using a SHA-256 hash and verifying entries to detect changes.

**Errors Found:** Existing audit records needed to be handled when introducing hash chaining.

**Human Review and Correction:** Added hash-generation and verification logic. Added a test that changes an audit record and checks that the calculated hash does not match the stored hash.

**Limitation:** Hash chaining can detect tampering but cannot prevent an attacker with sufficient database access from changing the entire chain.

**Commit:** Pending verification.

## Entry 4 – Viewer Role Restrictions

**Date:** 2026-11-06

**Prompt / Task:** Help ensure that Viewer users cannot upload documents or perform Owner/Admin actions.

**AI Output:** Suggested enforcing role restrictions on the server rather than relying only on hidden interface buttons.

**Errors Found:** Role restrictions needed automated tests to verify that unauthorized actions were rejected.

**Human Review and Correction:** Added security tests for Viewer restrictions and reviewed the server-side route protections.

**Commit:** Pending verification.

## Entry 5 – Automated Security Testing

**Date:** 2026-11-06

**Prompt / Task:** Help create automated security tests for document authorization, sharing, revocation, and audit integrity.

**AI Output:** Suggested using pytest and Flask's test client to test security behavior.

**Errors Found:** An initial test command failed because the test file was inside the tests folder, not the project root.

**Human Review and Correction:** Corrected the test execution path and ran the test suite successfully. The latest local run reported 11 tests passed.

**Commit:** Pending verification.

## Entry 6 – Historical Audit Integrity Investigation

**Date:** 2026-11-08

**Prompt / Task:** Investigate why TrustVault's audit-chain verification reported integrity failures in historical records.

**AI Output:** Suggested inspecting the audit-table foreign keys, hash-generation function, and verification function to identify why stored hashes no longer matched calculated hashes.

**Errors Found:** The audit table used ON DELETE SET NULL for both user_id and document_id. Deleting related users or documents could change values included in previously calculated audit hashes. Historical verification reported failures at multiple record IDs.

**Human Review and Correction:** Inspected the database schema and confirmed the foreign-key behavior. Created database and application backups before testing a separate audit-chain implementation. Preserved historical records without silently recalculating their hashes.

**Testing:** Created a new audit-chain segment with two records. Independently checked both record hashes and confirmed that the second record's previous hash matched the first record's entry hash. Both checks passed.

**Known Limitation:** Historical integrity failures remain unresolved. The new chain has only undergone initial testing and requires further automated verification.

**Commit:** Pending verification.

---

## AI Usage Statement

AI assistance was used for coding guidance, debugging, security suggestions, and test-case development. The developer reviewed suggestions, made corrections, and tested the application. AI-generated suggestions were not accepted without review.

All test results and implementation claims represent the development state at the time they were recorded. Commit references will be added after the corresponding Git commits are verified.