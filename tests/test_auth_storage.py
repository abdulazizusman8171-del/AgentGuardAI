import tempfile
import unittest
from pathlib import Path

from app.storage import SQLiteTransactionTracker


class TestAuthenticationStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "auth.db"
        self.storage = SQLiteTransactionTracker(database)

        self.user_id = self.storage.create_user(
            "auth@example.com",
            "password-hash",
            "password-salt",
            1000
        )

    def tearDown(self):
        self.storage = None
        self.temp_dir.cleanup()

    def test_user_session_creation_and_validation(self):
        self.storage.create_user_session(
            self.user_id, "session-hash", 1000, 2000
        )

        session = self.storage.get_valid_user_session(
            "session-hash", 1500
        )

        self.assertIsNotNone(session)
        self.assertEqual(session["user_id"], self.user_id)

    def test_expired_session_is_rejected(self):
        self.storage.create_user_session(
            self.user_id, "expired-session", 1000, 1200
        )

        self.assertIsNone(
            self.storage.get_valid_user_session(
                "expired-session", 1200
            )
        )

    def test_revoked_session_is_rejected(self):
        self.storage.create_user_session(
            self.user_id, "revoked-session", 1000, 2000
        )

        self.assertTrue(
            self.storage.revoke_user_session(
                "revoked-session", 1100
            )
        )

        self.assertIsNone(
            self.storage.get_valid_user_session(
                "revoked-session", 1200
            )
        )

    def test_account_token_creation_and_validation(self):
        self.storage.create_account_token(
            self.user_id,
            "verification-hash",
            "EMAIL_VERIFICATION",
            1000,
            2000
        )

        token = self.storage.get_valid_account_token(
            "verification-hash",
            "EMAIL_VERIFICATION",
            1500
        )

        self.assertIsNotNone(token)
        self.assertEqual(token["user_id"], self.user_id)

    def test_expired_account_token_is_rejected(self):
        self.storage.create_account_token(
            self.user_id,
            "expired-token",
            "EMAIL_VERIFICATION",
            1000,
            1200
        )

        self.assertIsNone(
            self.storage.get_valid_account_token(
                "expired-token",
                "EMAIL_VERIFICATION",
                1200
            )
        )

    def test_consumed_account_token_cannot_be_reused(self):
        self.storage.create_account_token(
            self.user_id,
            "consumed-token",
            "EMAIL_VERIFICATION",
            1000,
            2000
        )

        self.assertTrue(
            self.storage.consume_account_token(
                "consumed-token",
                "EMAIL_VERIFICATION",
                1500
            )
        )

        self.assertFalse(
            self.storage.consume_account_token(
                "consumed-token",
                "EMAIL_VERIFICATION",
                1600
            )
        )

    def test_replacement_token_invalidates_previous_token(self):
        self.storage.create_account_token(
            self.user_id,
            "old-token",
            "APPROVAL_KEY_RECOVERY",
            1000,
            3000
        )

        self.storage.create_account_token(
            self.user_id,
            "new-token",
            "APPROVAL_KEY_RECOVERY",
            1100,
            3100
        )

        self.assertIsNone(
            self.storage.get_valid_account_token(
                "old-token",
                "APPROVAL_KEY_RECOVERY",
                1200
            )
        )

        self.assertIsNotNone(
            self.storage.get_valid_account_token(
                "new-token",
                "APPROVAL_KEY_RECOVERY",
                1200
            )
        )


    def test_atomic_email_verification_success(self):
        self.storage.create_account_token(
            self.user_id,
            "valid-verification",
            "EMAIL_VERIFICATION",
            1000,
            2000
        )

        result = self.storage.verify_email_with_token(
            "valid-verification", 1500
        )

        user = self.storage.get_user_by_id(self.user_id)

        self.assertTrue(result)
        self.assertEqual(user["email_verified"], 1)

        self.assertIsNone(
            self.storage.get_valid_account_token(
                "valid-verification",
                "EMAIL_VERIFICATION",
                1500
            )
        )

    def test_expired_email_verification_is_rejected(self):
        self.storage.create_account_token(
            self.user_id,
            "expired-verification",
            "EMAIL_VERIFICATION",
            1000,
            1200
        )

        result = self.storage.verify_email_with_token(
            "expired-verification", 1200
        )

        user = self.storage.get_user_by_id(self.user_id)

        self.assertFalse(result)
        self.assertEqual(user["email_verified"], 0)

    def test_email_verification_token_cannot_be_reused(self):
        self.storage.create_account_token(
            self.user_id,
            "single-use-verification",
            "EMAIL_VERIFICATION",
            1000,
            2000
        )

        first_result = self.storage.verify_email_with_token(
            "single-use-verification", 1500
        )

        second_result = self.storage.verify_email_with_token(
            "single-use-verification", 1600
        )

        self.assertTrue(first_result)
        self.assertFalse(second_result)

    def test_recovery_token_cannot_verify_email(self):
        self.storage.create_account_token(
            self.user_id,
            "recovery-only-token",
            "APPROVAL_KEY_RECOVERY",
            1000,
            2000
        )

        result = self.storage.verify_email_with_token(
            "recovery-only-token", 1500
        )

        user = self.storage.get_user_by_id(self.user_id)

        self.assertFalse(result)
        self.assertEqual(user["email_verified"], 0)

    def test_invalid_token_does_not_verify_account(self):
        result = self.storage.verify_email_with_token(
            "unknown-verification-token", 1500
        )

        user = self.storage.get_user_by_id(self.user_id)

        self.assertFalse(result)
        self.assertEqual(user["email_verified"], 0)

    def test_account_token_purpose_is_enforced(self):
        self.storage.create_account_token(
            self.user_id,
            "purpose-token",
            "EMAIL_VERIFICATION",
            1000,
            2000
        )

        self.assertIsNone(
            self.storage.get_valid_account_token(
                "purpose-token",
                "APPROVAL_KEY_RECOVERY",
                1500
            )
        )


if __name__ == "__main__":
    unittest.main()
