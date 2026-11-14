import tempfile
import unittest
from pathlib import Path

from app.storage import SQLiteTransactionTracker


class TestSQLiteTransactionTracker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "test.db"
        self.tracker = SQLiteTransactionTracker(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_transaction_is_not_duplicate(self):
        self.assertFalse(
            self.tracker.is_duplicate("transaction-001")
        )

    def test_processed_transaction_is_duplicate(self):
        self.tracker.mark_processed("transaction-002")

        self.assertTrue(
            self.tracker.is_duplicate("transaction-002")
        )

    def test_transaction_remains_duplicate_after_reopening(self):
        self.tracker.mark_processed("transaction-003")

        reopened_tracker = SQLiteTransactionTracker(self.database)

        self.assertTrue(
            reopened_tracker.is_duplicate("transaction-003")
        )

    def test_empty_transaction_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.mark_processed("")

    def test_non_string_transaction_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.mark_processed(123)

    def test_transaction_history(self):
        self.tracker.mark_processed("transaction-101")
        self.tracker.mark_processed("transaction-102")

        history = self.tracker.get_transaction_history()

        self.assertEqual(len(history), 2)
        self.assertEqual(
            history[0]["transaction_id"],
            "transaction-102"
        )

    def test_empty_transaction_history(self):
        history = self.tracker.get_transaction_history()

        self.assertEqual(history, [])

    def test_invalid_history_limit(self):
        with self.assertRaises(ValueError):
            self.tracker.get_transaction_history(limit=500)

    def test_invalid_approval_status(self):
        with self.assertRaises(ValueError):
            self.tracker.get_approvals(status="INVALID")

    def test_invalid_approval_limit(self):
        with self.assertRaises(ValueError):
            self.tracker.get_approvals(limit=500)

    # ==========================================
    # DEVELOPER API KEY TESTS
    # ==========================================

    def _create_verified_user(self, email):
        from app.auth import hash_password

        password_hash, password_salt = hash_password(
            "TestPassword123!"
        )
        user_id = self.tracker.create_user(
            email,
            password_hash,
            password_salt,
            1000
        )
        self.tracker.verify_user_email(user_id, 1001)
        return user_id

    def test_developer_api_key_creation_and_retrieval(self):
        user_id = self._create_verified_user("developer@example.com")
        key_hash = "a" * 64

        key_id = self.tracker.create_developer_api_key(
            user_id, "Test SDK", key_hash, "ag_live_test", 1002
        )

        self.assertGreater(key_id, 0)

        record = self.tracker.get_developer_api_key(key_hash)

        self.assertEqual(record["user_id"], user_id)
        self.assertEqual(record["name"], "Test SDK")
        self.assertEqual(record["key_hash"], key_hash)

    def test_unverified_user_cannot_create_api_key(self):
        from app.auth import hash_password

        password_hash, password_salt = hash_password(
            "TestPassword123!"
        )
        user_id = self.tracker.create_user(
            "unverified@example.com",
            password_hash,
            password_salt,
            1000
        )

        with self.assertRaises(ValueError):
            self.tracker.create_developer_api_key(
                user_id, "Test SDK", "b" * 64, "ag_live_test", 1002
            )

    def test_api_key_revocation_prevents_retrieval(self):
        user_id = self._create_verified_user("revoke@example.com")
        key_hash = "c" * 64

        key_id = self.tracker.create_developer_api_key(
            user_id, "Revocation Test", key_hash, "ag_live_test", 1002
        )

        self.assertTrue(
            self.tracker.revoke_developer_api_key(user_id, key_id, 1003)
        )
        self.assertIsNone(
            self.tracker.get_developer_api_key(key_hash)
        )

    def test_user_cannot_revoke_another_users_api_key(self):
        first_user = self._create_verified_user("first@example.com")
        second_user = self._create_verified_user("second@example.com")

        key_id = self.tracker.create_developer_api_key(
            first_user, "First Key", "d" * 64, "ag_live_test", 1002
        )

        self.assertFalse(
            self.tracker.revoke_developer_api_key(
                second_user, key_id, 1003
            )
        )
        self.assertIsNotNone(
            self.tracker.get_developer_api_key("d" * 64)
        )

    def test_api_key_usage_timestamp_updates(self):
        user_id = self._create_verified_user("usage@example.com")

        key_id = self.tracker.create_developer_api_key(
            user_id, "Usage Test", "e" * 64, "ag_live_test", 1002
        )

        self.assertTrue(
            self.tracker.update_developer_api_key_usage(key_id, 1005)
        )

        record = self.tracker.get_developer_api_key("e" * 64)
        self.assertEqual(record["last_used_at"], 1005)

    def test_api_key_list_does_not_expose_hash(self):
        user_id = self._create_verified_user("list@example.com")

        self.tracker.create_developer_api_key(
            user_id, "Listed Key", "f" * 64, "ag_live_test", 1002
        )

        records = self.tracker.list_developer_api_keys(user_id)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "Listed Key")
        self.assertNotIn("key_hash", records[0])


if __name__ == "__main__":
    unittest.main()
