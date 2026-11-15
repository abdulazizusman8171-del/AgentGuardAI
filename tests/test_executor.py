import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from app.executor import SimulatedExecutor
from app.main import evaluate_transaction, TransactionTracker
from app.storage import SQLiteTransactionTracker


class TestSimulatedExecutor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "test.db"

        self.tracker = SQLiteTransactionTracker(database)
        self.executor = SimulatedExecutor(self.tracker)

        self.transaction = {
            "transaction_id": "test-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_report(self, transaction=None):
        transaction = transaction or self.transaction

        return evaluate_transaction(
            transaction,
            transaction_tracker=self.tracker
        )

    def test_safe_transaction_executes(self):
        report = self.make_report()

        result = self.executor.execute(self.transaction, report)

        self.assertEqual(result["status"], "EXECUTED")

    def test_confirmation_is_required(self):
        transaction = self.transaction.copy()
        transaction["recipient_known"] = False
        report = self.make_report(transaction)

        result = self.executor.execute(transaction, report)

        self.assertEqual(result["status"], "AWAITING_CONFIRMATION")

    def test_confirmed_transaction_executes(self):
        transaction = self.transaction.copy()
        transaction["recipient_known"] = False
        report = self.make_report(transaction)

        result = self.executor.execute(
            transaction,
            report,
            confirmed=True
        )

        self.assertEqual(result["status"], "EXECUTED")

    def test_blocked_transaction_never_executes(self):
        transaction = self.transaction.copy()
        transaction["amount"] = 6
        report = self.make_report(transaction)

        result = self.executor.execute(
            transaction,
            report,
            confirmed=True
        )

        self.assertEqual(result["status"], "BLOCKED")

    def test_forged_allow_report_is_rejected(self):
        forged_report = {"decision": "ALLOW"}

        with self.assertRaisesRegex(
            ValueError,
            "Security report verification failed"
        ):
            self.executor.execute(
                self.transaction,
                forged_report
            )

    def test_modified_risk_score_is_rejected(self):
        report = self.make_report()
        report["risk_score"] = 99

        with self.assertRaisesRegex(
            ValueError,
            "Security report verification failed"
        ):
            self.executor.execute(self.transaction, report)

    def test_failed_execution_is_not_recorded(self):
        report = self.make_report()

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
        report = self.make_report()

        self.executor.execute(self.transaction, report)

        self.assertTrue(
            self.tracker.is_duplicate("test-001")
        )

    def test_duplicate_transaction_is_blocked(self):
        report = self.make_report()
        self.executor.execute(self.transaction, report)

        duplicate_report = self.make_report()

        result = self.executor.execute(
            self.transaction,
            duplicate_report
        )

        self.assertEqual(result["status"], "BLOCKED")

    def test_sqlite_atomic_claim_allows_only_one_winner(self):
        transaction_id = "concurrent-test-001"

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(
                pool.map(
                    self.tracker.claim_processed,
                    [transaction_id] * 20
                )
            )

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 19)

    def test_in_memory_claim_allows_only_one_winner(self):
        tracker = TransactionTracker()

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(
                pool.map(
                    tracker.claim_processed,
                    ["memory-test-001"] * 20
                )
            )

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 19)


if __name__ == "__main__":
    unittest.main()
