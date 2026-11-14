import tempfile
import unittest
from pathlib import Path

from app.storage import SQLiteTransactionTracker
from app.approval import ApprovalManager


class TestApprovalOwnership(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "ownership.db"
        self.storage = SQLiteTransactionTracker(database)
        self.manager = ApprovalManager(self.storage)

        self.user_a = self.storage.create_user(
            "usera@example.com", "hash-a", "salt-a", 1000
        )
        self.user_b = self.storage.create_user(
            "userb@example.com", "hash-b", "salt-b", 1000
        )

        self.transaction = {
            "transaction_id": "ownership-test-001",
            "network": "NEAR",
            "amount": 1
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_user_cannot_retrieve_another_users_approval(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        result = self.storage.get_approval(
            approval["approval_id"],
            owner_user_id=self.user_b
        )

        self.assertIsNone(result)

    def test_user_cannot_approve_another_users_approval(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        result = self.storage.approve_pending_approval(
            approval["approval_id"],
            1100,
            owner_user_id=self.user_b
        )

        self.assertFalse(result)

    def test_user_cannot_consume_another_users_approval(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        self.storage.approve_pending_approval(
            approval["approval_id"],
            1100,
            owner_user_id=self.user_a
        )

        result = self.storage.consume_approved_approval(
            approval["approval_id"],
            1200,
            owner_user_id=self.user_b
        )

        self.assertFalse(result)

    def test_user_can_access_own_approval(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        result = self.storage.get_approval(
            approval["approval_id"],
            owner_user_id=self.user_a
        )

        self.assertIsNotNone(result)


    def test_manager_allows_owner_to_approve(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        result = self.manager.approve_transaction(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_a
        )

        self.assertTrue(result["approved"])

    def test_manager_blocks_other_user_from_approving(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        result = self.manager.approve_transaction(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_b
        )

        self.assertFalse(result["approved"])

    def test_manager_allows_owner_to_consume(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        approved = self.manager.approve_transaction(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_a
        )
        self.assertTrue(approved["approved"])

        result = self.manager.consume_approval(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_a
        )

        self.assertTrue(result["consumed"])

    def test_manager_blocks_other_user_from_consuming(self):
        approval = self.manager.create_approval(
            self.transaction,
            owner_user_id=self.user_a
        )

        approved = self.manager.approve_transaction(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_a
        )
        self.assertTrue(approved["approved"])

        result = self.manager.consume_approval(
            approval["approval_id"],
            self.transaction,
            owner_user_id=self.user_b
        )

        self.assertFalse(result["consumed"])


if __name__ == "__main__":
    unittest.main()
