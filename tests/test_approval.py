from abc import ABC, abstractmethod
from unittest.mock import patch
import tempfile
import unittest

from pathlib import Path

from app.storage import SQLiteTransactionTracker
from app.approval import ApprovalManager


class ApprovalProtocol(ABC):
    @abstractmethod
    def create_approval(self, transaction):
        """Persist and return a pending approval for the supplied transaction."""
        raise NotImplementedError

    @abstractmethod
    def approve_transaction(self, approval_id, transaction):
        """Validate an approval request against the expected transaction payload."""
        raise NotImplementedError

    @abstractmethod
    def consume_approval(self, approval_id, transaction):
        """Mark an approval as consumed if it is still valid and unused."""
        raise NotImplementedError


class Self(ApprovalProtocol):
    """Concrete approval protocol backed by an ApprovalManager."""

    def __init__(self, storage, approval_lifetime=300):
        self._manager = ApprovalManager(
            storage=storage,
            approval_lifetime=approval_lifetime,
        )

    def create_approval(self, transaction):
        """Create and persist a pending approval for a transaction."""
        if transaction is None:
            raise ValueError("transaction payload is required")
        if not isinstance(transaction, dict):
            raise TypeError("transaction must be a dictionary payload")
        return self._manager.create_approval(transaction)

    def approve_transaction(self, approval_id, transaction):
        """Validate the requested approval against its transaction."""
        if approval_id is None:
            raise ValueError("approval_id is required")
        if transaction is None:
            raise ValueError("transaction payload is required")
        if not isinstance(transaction, dict):
            raise TypeError("transaction must be a dictionary payload")
        return self._manager.approve_transaction(approval_id, transaction)

    def consume_approval(self, approval_id, transaction):
        """Consume an approval if it remains valid and unused."""
        if approval_id is None:
            raise ValueError("approval_id is required")
        if transaction is None:
            raise ValueError("transaction payload is required")
        if not isinstance(transaction, dict):
            raise TypeError("transaction must be a dictionary payload")
        return self._manager.consume_approval(approval_id, transaction)


class TestApprovalManager(unittest.TestCase):
    def test_expired_approval_is_rejected(self):

        with patch("app.approval.time.time", return_value=1000):
            result = self.manager.create_approval(
                self.transaction
            )

        approval_id = result["approval_id"]

        with patch("app.approval.time.time", return_value=1301):
            approval = self.manager.approve_transaction(
                approval_id,
                self.transaction
            )
            self.assertFalse(approval["approved"])
        self.assertIn("expired", approval["message"].lower())
    def test_modified_transaction_is_rejected(self):
        result = self.manager.create_approval(
            self.transaction
        )

        approval_id = result["approval_id"]

        modified_transaction = self.transaction.copy()
        modified_transaction["amount"] = 10

        approval = self.manager.approve_transaction(
            approval_id,
            modified_transaction
        )

        self.assertFalse(approval["approved"])
        self.assertIn("modified", approval["message"].lower())
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        database_path = Path(self.temp_dir.name) / "test.db"

        self.storage = SQLiteTransactionTracker(database_path)

        self.manager = ApprovalManager(
            storage=self.storage,
            approval_lifetime=300
        )

        self.transaction = {
            "transaction_id": "test-transaction-001",
            "network": "BNB",
            "amount": 1,
            "recipient": "0x1234567890123456789012345678901234567890"
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_approval(self):

        result = self.manager.create_approval(
            self.transaction
        )

        self.assertEqual(result["status"], "PENDING")
        self.assertTrue(result["approval_id"])

        saved_approval = self.storage.get_approval(
            result["approval_id"]
        )

        self.assertIsNotNone(saved_approval)
        assert saved_approval is not None
        self.assertEqual(saved_approval["status"], "PENDING")

    def test_approve_and_consume_approval(self):

        result = self.manager.create_approval(
            self.transaction
        )

        approval_id = result["approval_id"]

        approved = self.manager.approve_transaction(
            approval_id,
            self.transaction
        )

        self.assertTrue(approved["approved"])

        consumed = self.manager.consume_approval(
            approval_id,
            self.transaction
        )

        self.assertTrue(consumed["consumed"])
    def test_approval_cannot_be_reused(self):

        result = self.manager.create_approval(
            self.transaction
        )

        approval_id = result["approval_id"]

        self.manager.approve_transaction(
            approval_id,
            self.transaction
        )

        first_use = self.manager.consume_approval(
            approval_id,
            self.transaction
        )

        second_use = self.manager.consume_approval(
            approval_id,
            self.transaction
        )

        self.assertTrue(first_use["consumed"])
        self.assertFalse(second_use["consumed"])


if __name__ == "__main__":
    unittest.main()
