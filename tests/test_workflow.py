import tempfile
import unittest
from pathlib import Path

from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow


class TestTransactionWorkflow(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "test.db"

        self.tracker = SQLiteTransactionTracker(database)
        self.workflow = TransactionWorkflow(self.tracker)

        self.transaction = {
            "transaction_id": "workflow-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_transaction_executes(self):
        result = self.workflow.process(self.transaction)

        self.assertEqual(
            result["execution_result"]["status"],
            "EXECUTED"
        )

    def test_unknown_recipient_requires_confirmation(self):
        transaction = self.transaction.copy()
        transaction["recipient_known"] = False

        result = self.workflow.process(transaction)

        self.assertEqual(
            result["execution_result"]["status"],
            "AWAITING_CONFIRMATION"
        )

    def test_confirmed_unknown_recipient_executes(self):
        transaction = self.transaction.copy()
        transaction["recipient_known"] = False

        result = self.workflow.process(
            transaction,
            confirmed=True
        )

        self.assertEqual(
            result["execution_result"]["status"],
            "EXECUTED"
        )

    def test_transaction_over_spending_limit_is_blocked(self):
        transaction = self.transaction.copy()
        transaction["amount"] = 6

        result = self.workflow.process(transaction)

        self.assertEqual(
            result["execution_result"]["status"],
            "BLOCKED"
        )

    def test_duplicate_transaction_is_blocked(self):
        self.workflow.process(self.transaction)

        result = self.workflow.process(self.transaction)

        self.assertEqual(
            result["security_report"]["decision"],
            "BLOCK"
        )

        self.assertEqual(
            result["execution_result"]["status"],
            "BLOCKED"
        )


if __name__ == "__main__":
    unittest.main()