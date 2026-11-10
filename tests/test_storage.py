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
if __name__ == "__main__":
    unittest.main()
