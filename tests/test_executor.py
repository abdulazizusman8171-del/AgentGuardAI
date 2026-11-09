import tempfile
import unittest
from pathlib import Path

from app.executor import SimulatedExecutor
from app.storage import SQLiteTransactionTracker


class TestSimulatedExecutor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "test.db"

        self.tracker = SQLiteTransactionTracker(database)
        self.executor = SimulatedExecutor(self.tracker)

        self.transaction = {
            "transaction_id": "test-001",
            "amount": 0.1
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_transaction_executes(self):
        report = {"decision": "ALLOW"}

        result = self.executor.execute(
            self.transaction, report
        )

        self.assertEqual(result["status"], "EXECUTED")

    def test_confirmation_is_required(self):
        report = {"decision": "REQUIRE_CONFIRMATION"}

        result = self.executor.execute(
            self.transaction, report
        )

        self.assertEqual(
            result["status"], "AWAITING_CONFIRMATION"
        )

    def test_confirmed_transaction_executes(self):
        report = {"decision": "REQUIRE_CONFIRMATION"}

        result = self.executor.execute(
            self.transaction, report, confirmed=True
        )

        self.assertEqual(result["status"], "EXECUTED")

    def test_blocked_transaction_never_executes(self):
        report = {"decision": "BLOCK"}

        result = self.executor.execute(
            self.transaction, report, confirmed=True
        )

        self.assertEqual(result["status"], "BLOCKED")

    def test_failed_execution_is_not_recorded(self):
        report = {"decision": "ALLOW"}

        result = self.executor.execute(
            self.transaction,
            report,
            simulated_success=False
        )

        self.assertEqual(result["status"], "FAILED")
        self.assertFalse(
            self.tracker.is_duplicate("test-001")
        )

    def test_successful_execution_is_recorded(self):
        report = {"decision": "ALLOW"}

        self.executor.execute(self.transaction, report)

        self.assertTrue(
            self.tracker.is_duplicate("test-001")
        )

    def test_duplicate_transaction_is_blocked(self):
        report = {"decision": "ALLOW"}

        self.executor.execute(self.transaction, report)

        result = self.executor.execute(
            self.transaction, report
        )

        self.assertEqual(result["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()