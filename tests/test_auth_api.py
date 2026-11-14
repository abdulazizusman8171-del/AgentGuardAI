import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import api
from app.storage import SQLiteTransactionTracker


class TestAuthenticationAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "test_auth.db"

        self.tracker = SQLiteTransactionTracker(database_path)
        api.tracker = self.tracker
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        self.temp_dir.cleanup()

    @patch("app.api.send_verification_email")
    def test_registration_success(self, mock_email):
        response = self.client.post(
            "/auth/register",
            json={
                "email": "builder@example.com",
                "password": "SecurePassword123!"
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        mock_email.assert_called_once()

        user = self.tracker.get_user_by_email("builder@example.com")
        self.assertIsNotNone(user)
        self.assertEqual(user["email_verified"], 0)

    @patch("app.api.send_verification_email")
    def test_duplicate_email_rejected(self, mock_email):
        payload = {
            "email": "builder@example.com",
            "password": "SecurePassword123!"
        }

        first = self.client.post("/auth/register", json=payload)
        second = self.client.post("/auth/register", json=payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        mock_email.assert_called_once()

    def test_invalid_email_rejected(self):
        response = self.client.post(
            "/auth/register",
            json={
                "email": "not-an-email",
                "password": "SecurePassword123!"
            }
        )

        self.assertEqual(response.status_code, 422)

    @patch(
        "app.api.send_verification_email",
        side_effect=RuntimeError("SMTP unavailable")
    )
    def test_email_failure_removes_unverified_account(self, mock_email):
        response = self.client.post(
            "/auth/register",
            json={
                "email": "failure@example.com",
                "password": "SecurePassword123!"
            }
        )

        self.assertEqual(response.status_code, 503)
        self.assertIsNone(
            self.tracker.get_user_by_email("failure@example.com")
        )

    @patch("app.api.send_verification_email")
    def test_email_verification_success(self, mock_email):
        self.client.post(
            "/auth/register",
            json={
                "email": "verify@example.com",
                "password": "SecurePassword123!"
            }
        )

        token = mock_email.call_args.args[1]

        response = self.client.post(
            "/auth/verify-email",
            json={"token": token}
        )

        self.assertEqual(response.status_code, 200)

        user = self.tracker.get_user_by_email("verify@example.com")
        self.assertEqual(user["email_verified"], 1)

    def test_invalid_verification_token_rejected(self):
        response = self.client.post(
            "/auth/verify-email",
            json={"token": "invalid-token-value-123456"}
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.send_verification_email")
    def test_verification_token_cannot_be_reused(self, mock_email):
        self.client.post(
            "/auth/register",
            json={
                "email": "reuse@example.com",
                "password": "SecurePassword123!"
            }
        )

        token = mock_email.call_args.args[1]

        first = self.client.post(
            "/auth/verify-email",
            json={"token": token}
        )

        second = self.client.post(
            "/auth/verify-email",
            json={"token": token}
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)


if __name__ == "__main__":
    unittest.main()

    @patch("app.api.send_approval_key_recovery_email")
    def test_approval_key_recovery_replaces_old_key(self, mock_recovery_email):
        from app.auth import hash_password, hash_token, verify_approval_key
        import os, time
        os.environ["AGENTGUARD_COOKIE_SECURE"] = "false"
        password_hash, password_salt = hash_password("RecoveryPassword123!")
        user_id = self.tracker.create_user("recover@example.com", password_hash, password_salt, int(time.time()))
        self.tracker.verify_user_email(user_id, int(time.time()))
        login = self.client.post("/auth/login", json={"email": "recover@example.com", "password": "RecoveryPassword123!"})
        self.assertEqual(login.status_code, 200)
        csrf = self.client.cookies.get("agentguard_csrf")
        headers = {"X-CSRF-Token": csrf}
        first_key_response = self.client.post("/auth/approval-key", headers=headers)
        first_key = first_key_response.json()["approval_key"]
        self.assertEqual(first_key_response.status_code, 200)

        request_response = self.client.post("/auth/approval-key/recovery", json={"email": "recover@example.com"})
        self.assertEqual(request_response.status_code, 200)
        recovery_token = mock_recovery_email.call_args.args[1]
        recovered = self.client.post("/auth/approval-key/recover", json={"token": recovery_token})
        self.assertEqual(recovered.status_code, 200)
        replacement = recovered.json()["approval_key"]
        user = self.tracker.get_user_by_id(user_id)
        self.assertFalse(verify_approval_key(first_key, user["approval_key_hash"]))
        self.assertTrue(verify_approval_key(replacement, user["approval_key_hash"]))
        reused = self.client.post("/auth/approval-key/recover", json={"token": recovery_token})
        self.assertEqual(reused.status_code, 400)
