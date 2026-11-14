import unittest
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app import api
from app.auth import hash_password, hash_token
from app.storage import SQLiteTransactionTracker


class TestLoginAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "login_test.db"

        self.tracker = SQLiteTransactionTracker(database_path)
        api.tracker = self.tracker
        api.os.environ["AGENTGUARD_COOKIE_SECURE"] = "false"
        self.client = TestClient(api.app)

        self.password = "SecurePassword123!"
        password_hash, password_salt = hash_password(self.password)

        self.user_id = self.tracker.create_user(
            "login@example.com",
            password_hash,
            password_salt,
            int(time.time())
        )

    def tearDown(self):
        self.client.close()
        self.temp_dir.cleanup()

    def verify_user(self):
        self.tracker.verify_user_email(
            self.user_id,
            int(time.time())
        )

    def test_verified_user_can_login(self):
        self.verify_user()

        response = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": self.password
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertIn(api.SESSION_COOKIE_NAME, response.cookies)

    def test_wrong_password_rejected(self):
        self.verify_user()

        response = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": "WrongPassword123!"
            }
        )

        self.assertEqual(response.status_code, 401)

    def test_unverified_user_cannot_login(self):
        response = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": self.password
            }
        )

        self.assertEqual(response.status_code, 403)

    def test_login_cookie_is_httponly(self):
        self.verify_user()

        response = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": self.password
            }
        )

        cookie = response.headers.get("set-cookie", "").lower()

        self.assertIn("httponly", cookie)
        self.assertIn("samesite=lax", cookie)

    def test_authenticated_user_can_access_me(self):
        self.verify_user()

        login = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": self.password
            }
        )

        self.assertEqual(login.status_code, 200)

        response = self.client.get("/auth/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], "login@example.com")

    def test_unauthenticated_user_cannot_access_me(self):
        response = self.client.get("/auth/me")

        self.assertEqual(response.status_code, 401)

    def test_logout_revokes_session(self):
        self.verify_user()

        login = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": self.password
            }
        )

        self.assertEqual(login.status_code, 200)

        session_token = self.client.cookies.get(api.SESSION_COOKIE_NAME)
        self.assertIsNotNone(session_token)

        logout = self.client.post("/auth/logout", headers={"X-CSRF-Token": self.client.cookies.get("agentguard_csrf")})

        self.assertEqual(logout.status_code, 200)

        session = self.tracker.get_valid_user_session(
            hash_token(session_token),
            int(time.time())
        )

        self.assertIsNone(session)

        me = self.client.get("/auth/me")
        self.assertEqual(me.status_code, 401)

    def test_expired_session_rejected(self):
        self.verify_user()

        session_token = "expired-test-session-token"
        current_time = int(time.time())

        self.tracker.create_user_session(
            self.user_id,
            hash_token(session_token),
            current_time - 100,
            current_time - 1
        )

        self.client.cookies.set(
            api.SESSION_COOKIE_NAME,
            session_token
        )

        response = self.client.get("/auth/me")

        self.assertEqual(response.status_code, 401)


    def test_logout_requires_csrf_token(self):
        self.verify_user()
        login = self.client.post("/auth/login", json={"email": "login@example.com", "password": self.password})
        self.assertEqual(login.status_code, 200)
        response = self.client.post("/auth/logout")
        self.assertEqual(response.status_code, 403)

    def test_login_rate_limit_after_five_failed_attempts(self):
        for _ in range(5):
            response = self.client.post("/auth/login", json={"email": "rate-limit@example.com", "password": "IncorrectPassword123!"})
            self.assertEqual(response.status_code, 401)
        blocked = self.client.post("/auth/login", json={"email": "rate-limit@example.com", "password": "IncorrectPassword123!"})
        self.assertEqual(blocked.status_code, 429)


    def test_password_reset_request_sends_email(self):
        self.verify_user()

        from unittest.mock import patch

        with patch("app.api.send_password_reset_email") as send_email:
            response = self.client.post(
                "/auth/password-reset/request",
                json={"email": "login@example.com"}
            )

        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once()

        token = send_email.call_args[0][1]
        record = self.tracker.get_valid_account_token(
            hash_token(token),
            "PASSWORD_RESET",
            int(time.time())
        )
        self.assertIsNotNone(record)

    def test_password_reset_success(self):
        self.verify_user()

        now = int(time.time())
        token = "test-password-reset-token-123456789"

        self.tracker.create_account_token(
            self.user_id,
            hash_token(token),
            "PASSWORD_RESET",
            now,
            now + 1800
        )

        session_token = "existing-session-token-for-reset"
        self.tracker.create_user_session(
            self.user_id,
            hash_token(session_token),
            now,
            now + 3600
        )

        response = self.client.post(
            "/auth/password-reset/complete",
            json={
                "token": token,
                "password": "NewSecurePassword456!"
            }
        )

        self.assertEqual(response.status_code, 200)

        session = self.tracker.get_valid_user_session(
            hash_token(session_token),
            int(time.time())
        )
        self.assertIsNone(session)

        login = self.client.post(
            "/auth/login",
            json={
                "email": "login@example.com",
                "password": "NewSecurePassword456!"
            }
        )
        self.assertEqual(login.status_code, 200)

    def test_password_reset_token_cannot_be_reused(self):
        self.verify_user()

        now = int(time.time())
        token = "single-use-password-reset-token-123"

        self.tracker.create_account_token(
            self.user_id,
            hash_token(token),
            "PASSWORD_RESET",
            now,
            now + 1800
        )

        payload = {
            "token": token,
            "password": "NewSecurePassword456!"
        }

        first = self.client.post(
            "/auth/password-reset/complete",
            json=payload
        )
        second = self.client.post(
            "/auth/password-reset/complete",
            json=payload
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)

    def test_expired_password_reset_token_rejected(self):
        now = int(time.time())
        token = "expired-password-reset-token-123"

        self.tracker.create_account_token(
            self.user_id,
            hash_token(token),
            "PASSWORD_RESET",
            now - 3600,
            now - 1800
        )

        response = self.client.post(
            "/auth/password-reset/complete",
            json={
                "token": token,
                "password": "NewSecurePassword456!"
            }
        )

        self.assertEqual(response.status_code, 400)
if __name__ == "__main__":
    unittest.main()
