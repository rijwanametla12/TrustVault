
import os
import sys
import tempfile
import unittest
import hashlib
import json

# Find the main TrustVault project folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import app as trustvault_app


class TrustVaultSecurityTests(unittest.TestCase):

    def setUp(self):
        # Save original application settings
        self.original_database = trustvault_app.DATABASE
        self.original_upload_folder = trustvault_app.UPLOAD_FOLDER
        self.original_testing = trustvault_app.app.config.get("TESTING")
        self.original_csrf = trustvault_app.app.config.get(
            "WTF_CSRF_ENABLED", True
        )

        # Create a separate temporary database for testing
        self.temp_dir = tempfile.TemporaryDirectory()

        trustvault_app.DATABASE = os.path.join(
            self.temp_dir.name, "test.db"
        )

        trustvault_app.UPLOAD_FOLDER = os.path.join(
            self.temp_dir.name, "uploads"
        )

        os.makedirs(trustvault_app.UPLOAD_FOLDER)

        # Test configuration
        trustvault_app.app.config["TESTING"] = True

        # Disable CSRF only for automated tests.
        # CSRF remains enabled in the real application.
        trustvault_app.app.config["WTF_CSRF_ENABLED"] = False

        self.client = trustvault_app.app.test_client()

        # Create test database tables
        trustvault_app.create_tables()

        conn = trustvault_app.get_db_connection()

        try:
            # Create test users
            cursor = conn.execute("""
                INSERT INTO users
                (username, email, password_hash, role)
                VALUES ('owner1', 'owner1@test.com', 'test', 'owner')
            """)
            self.owner1_id = cursor.lastrowid

            cursor = conn.execute("""
                INSERT INTO users
                (username, email, password_hash, role)
                VALUES ('owner2', 'owner2@test.com', 'test', 'owner')
            """)
            self.owner2_id = cursor.lastrowid

            cursor = conn.execute("""
                INSERT INTO users
                (username, email, password_hash, role)
                VALUES ('viewer1', 'viewer1@test.com', 'test', 'viewer')
            """)
            self.viewer_id = cursor.lastrowid

            # Create a document owned by owner1
            cursor = conn.execute("""
                INSERT INTO documents
                (original_filename, stored_filename, owner_id, file_size)
                VALUES ('secret.pdf', 'test-secret.pdf', ?, 12)
            """, (self.owner1_id,))

            self.document_id = cursor.lastrowid

            conn.commit()

        finally:
            conn.close()

        # Create a sample document file
        with open(
            os.path.join(
                trustvault_app.UPLOAD_FOLDER,
                "test-secret.pdf"
            ),
            "wb"
        ) as file:
            file.write(b"Test document")

    def tearDown(self):
        # Restore the original application settings
        trustvault_app.DATABASE = self.original_database
        trustvault_app.UPLOAD_FOLDER = self.original_upload_folder

        trustvault_app.app.config["TESTING"] = self.original_testing
        trustvault_app.app.config["WTF_CSRF_ENABLED"] = self.original_csrf

        # Remove temporary test database and files
        self.temp_dir.cleanup()

    def login_as(self, user_id):
        # Simulate a logged-in user
        with self.client.session_transaction() as session:
            session["user_id"] = user_id

    # Test 1: Owner cannot download another owner's document
    def test_owner_cannot_download_another_owners_document(self):
        self.login_as(self.owner2_id)

        response = self.client.get(
            f"/download/{self.document_id}"
        )

        self.assertEqual(response.status_code, 404)

    # Test 2: Viewer cannot download an unshared document
    def test_viewer_cannot_download_unshared_document(self):
        self.login_as(self.viewer_id)

        response = self.client.get(
            f"/download/{self.document_id}"
        )

        self.assertEqual(response.status_code, 404)

    # Test 3: Denied download must be recorded
    def test_denied_download_is_recorded(self):
        self.login_as(self.viewer_id)

        self.client.get(
            f"/download/{self.document_id}"
        )

        conn = trustvault_app.get_db_connection()

        try:
            log = conn.execute("""
                SELECT action
                FROM audit_logs
                WHERE user_id = ?
                  AND document_id = ?
                  AND action = 'DOWNLOAD_DENIED'
            """, (self.viewer_id, self.document_id)).fetchone()

        finally:
            conn.close()

        self.assertIsNotNone(log)

    # Test 4: Authorized viewer can download
    def test_shared_viewer_can_download_document(self):
        conn = trustvault_app.get_db_connection()

        try:
            conn.execute("""
                INSERT INTO document_shares
                (document_id, shared_with_user_id, permission)
                VALUES (?, ?, 'viewer')
            """, (self.document_id, self.viewer_id))

            conn.commit()

        finally:
            conn.close()

        self.login_as(self.viewer_id)

        response = self.client.get(
            f"/download/{self.document_id}"
        )

        self.assertEqual(response.status_code, 200)

    # Test 5: Revoked viewer cannot download
    def test_revoked_viewer_cannot_download_document(self):
        conn = trustvault_app.get_db_connection()

        try:
            conn.execute("""
                INSERT INTO document_shares
                (document_id, shared_with_user_id, permission)
                VALUES (?, ?, 'viewer')
            """, (self.document_id, self.viewer_id))

            conn.commit()

            conn.execute("""
                DELETE FROM document_shares
                WHERE document_id = ?
                  AND shared_with_user_id = ?
            """, (self.document_id, self.viewer_id))

            conn.commit()

        finally:
            conn.close()

        self.login_as(self.viewer_id)

        response = self.client.get(
            f"/download/{self.document_id}"
        )

        self.assertEqual(response.status_code, 404)

    # Test 6: Viewer cannot upload documents
    def test_viewer_cannot_upload_document(self):
        self.login_as(self.viewer_id)

        response = self.client.post(
            "/upload",
            data={},
            follow_redirects=False
        )

        self.assertIn(response.status_code, (302, 403, 404))

    # Test 7: Viewer cannot share documents
    def test_viewer_cannot_share_document(self):
        self.login_as(self.viewer_id)

        response = self.client.post(
            f"/share/{self.document_id}",
            data={"email": "owner2@test.com"},
            follow_redirects=False
        )

        self.assertIn(response.status_code, (302, 403, 404))

        conn = trustvault_app.get_db_connection()

        try:
            share = conn.execute("""
                SELECT id
                FROM document_shares
                WHERE document_id = ?
                  AND shared_with_user_id = ?
            """, (self.document_id, self.owner2_id)).fetchone()

        finally:
            conn.close()

        self.assertIsNone(share)

    # Test 8: Viewer cannot delete documents
    def test_viewer_cannot_delete_document(self):
        self.login_as(self.viewer_id)

        response = self.client.post(
            f"/delete/{self.document_id}",
            follow_redirects=False
        )

        self.assertIn(response.status_code, (302, 403, 404))

        conn = trustvault_app.get_db_connection()

        try:
            document = conn.execute("""
                SELECT id
                FROM documents
                WHERE id = ?
            """, (self.document_id,)).fetchone()

        finally:
            conn.close()

        self.assertIsNotNone(document)

    # Test 9: Viewer cannot revoke document access
    def test_viewer_cannot_revoke_document_access(self):
        conn = trustvault_app.get_db_connection()

        try:
            conn.execute("""
                INSERT INTO document_shares
                (document_id, shared_with_user_id, permission)
                VALUES (?, ?, 'viewer')
            """, (self.document_id, self.viewer_id))

            conn.commit()

        finally:
            conn.close()

        self.login_as(self.viewer_id)

        response = self.client.post(
            f"/revoke-share/{self.document_id}/{self.viewer_id}",
            follow_redirects=False
        )

        self.assertIn(response.status_code, (302, 403, 404))

        conn = trustvault_app.get_db_connection()

        try:
            share = conn.execute("""
                SELECT id
                FROM document_shares
                WHERE document_id = ?
                  AND shared_with_user_id = ?
            """, (self.document_id, self.viewer_id)).fetchone()

        finally:
            conn.close()

        self.assertIsNotNone(share)

    # Test 10: Owner cannot delete another owner's document
    def test_owner_cannot_delete_another_owners_document(self):
        self.login_as(self.owner2_id)

        response = self.client.post(
            f"/delete/{self.document_id}",
            follow_redirects=False
        )

        self.assertEqual(response.status_code, 404)

        conn = trustvault_app.get_db_connection()

        try:
            document = conn.execute("""
                SELECT id
                FROM documents
                WHERE id = ?
            """, (self.document_id,)).fetchone()

        finally:
            conn.close()

        self.assertIsNotNone(document)

    # Test 11: Detect tampering with audit logs
    def test_audit_log_tampering_is_detectable(self):
        trustvault_app.log_action(
            self.owner1_id,
            "TEST_EVENT",
            self.document_id,
            "Original details"
        )

        conn = trustvault_app.get_db_connection()

        try:
            # Change the audit log details manually
            conn.execute("""
                UPDATE audit_logs
                SET details = 'Tampered details'
                WHERE action = 'TEST_EVENT'
                  AND user_id = ?
            """, (self.owner1_id,))

            conn.commit()

            log = conn.execute("""
                SELECT id, user_id, action, document_id,
                       details, timestamp, previous_hash, entry_hash
                FROM audit_logs
                WHERE action = 'TEST_EVENT'
                  AND user_id = ?
                ORDER BY id DESC
                LIMIT 1
            """, (self.owner1_id,)).fetchone()

        finally:
            conn.close()

        self.assertIsNotNone(log)

        # Recalculate the expected hash using modified data
        audit_data = {
            "id": log["id"],
            "user_id": log["user_id"],
            "action": log["action"],
            "document_id": log["document_id"],
            "details": log["details"] or "",
            "timestamp": log["timestamp"],
            "previous_hash": log["previous_hash"]
        }

        audit_string = json.dumps(
            audit_data,
            sort_keys=True,
            separators=(",", ":")
        )

        calculated_hash = hashlib.sha256(
            audit_string.encode("utf-8")
        ).hexdigest()

        # Modified details must not match the original hash
        self.assertNotEqual(
            calculated_hash,
            log["entry_hash"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
