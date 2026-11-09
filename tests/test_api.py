import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import app.api as api
from app.approval import ApprovalManager
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow


class TestAgentGuardAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "api_test.db"

        self.tracker = SQLiteTransactionTracker(database)

        api.tracker = self.tracker
        api.approval_manager = ApprovalManager(
            storage=self.tracker,
            approval_lifetime=300
        )
        api.BLOCKED_RECIPIENTS = []
        api.workflow = TransactionWorkflow(
            transaction_tracker=self.tracker,
            blocked_recipients=[]
        )

        self.client = TestClient(api.app)

        self.safe_transaction = {
            "transaction_id": "api-safe-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        self.unknown_transaction = {
            "transaction_id": "api-unknown-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "recipient_known": False,
            "new_contract": False,
            "unlimited_approval": False
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_evaluate_safe_transaction(self):
        response = self.client.post(
            "/evaluate",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_evaluate_invalid_transaction(self):
        transaction = self.safe_transaction.copy()
        transaction["amount"] = "invalid"

        response = self.client.post(
            "/evaluate",
            json=transaction
        )

        self.assertEqual(response.status_code, 400)

    def test_safe_transaction_does_not_require_approval(self):
        response = self.client.post(
            "/approvals",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["approval_required"])

    def test_unknown_recipient_creates_approval(self):
        response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["approval_required"])
        self.assertEqual(
            response.json()["approval"]["status"],
            "PENDING"
        )

    def test_approval_and_transaction_execution(self):
        create_response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        approval_id = (
            create_response.json()["approval"]["approval_id"]
        )

        approve_response = self.client.post(
            f"/approvals/{approval_id}/approve",
            json=self.unknown_transaction
        )

        self.assertTrue(approve_response.json()["approved"])

        process_payload = self.unknown_transaction.copy()
        process_payload["approval_id"] = approval_id

        process_response = self.client.post(
            "/process",
            json=process_payload
        )

        self.assertEqual(process_response.status_code, 200)
        self.assertEqual(
            process_response.json()["execution_result"]["status"],
            "EXECUTED"
        )

    def test_modified_transaction_cannot_be_approved(self):
        create_response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        approval_id = (
            create_response.json()["approval"]["approval_id"]
        )

        modified_transaction = self.unknown_transaction.copy()
        modified_transaction["amount"] = 0.2

        response = self.client.post(
            f"/approvals/{approval_id}/approve",
            json=modified_transaction
        )

        self.assertFalse(response.json()["approved"])
        self.assertIn("modified", response.json()["message"].lower())

    def test_client_cannot_supply_confirmation(self):
        payload = self.safe_transaction.copy()
        payload["confirmed"] = True

        response = self.client.post(
            "/process",
            json=payload
        )

        self.assertEqual(response.status_code, 400)

    def test_unknown_recipient_waits_for_confirmation(self):
        response = self.client.post(
            "/process",
            json=self.unknown_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "AWAITING_CONFIRMATION"
        )

    def test_safe_transaction_executes(self):
        response = self.client.post(
            "/process",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "EXECUTED"
        )

    def test_duplicate_transaction_is_blocked(self):
        self.client.post(
            "/process",
            json=self.safe_transaction
        )

        response = self.client.post(
            "/process",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["security_report"]["decision"],
            "BLOCK"
        )
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "BLOCKED"
        )


if __name__ == "__main__":
    unittest.main()
