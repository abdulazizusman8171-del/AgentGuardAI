import unittest

from app.agent_gateway import AgentSecurityGateway
from app.main import TransactionTracker


class TestAgentSecurityGateway(unittest.TestCase):

    def setUp(self):
        self.tracker = TransactionTracker()
        self.gateway = AgentSecurityGateway(self.tracker)

        self.transaction = {
            "transaction_id": "agent-test-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

    def test_safe_transaction_is_permitted(self):
        result = self.gateway.inspect_transaction(self.transaction)

        self.assertEqual(result["gateway_status"], "PERMITTED")
        self.assertEqual(
            result["recommended_action"],
            "SIMULATED_EXECUTION_ELIGIBLE"
        )
        self.assertFalse(result["execution_performed"])

    def test_unknown_recipient_requires_human_approval(self):
        transaction = self.transaction.copy()
        transaction["recipient_known"] = False

        result = self.gateway.inspect_transaction(transaction)

        self.assertEqual(
            result["gateway_status"],
            "APPROVAL_REQUIRED"
        )
        self.assertTrue(result["human_approval_required"])

    def test_blocklisted_recipient_is_rejected(self):
        address = self.transaction["recipient_address"]

        gateway = AgentSecurityGateway(
            self.tracker,
            blocked_recipients=[address]
        )

        result = gateway.inspect_transaction(self.transaction)

        self.assertEqual(result["gateway_status"], "REJECTED")
        self.assertEqual(
            result["recommended_action"],
            "STOP_TRANSACTION"
        )

    def test_duplicate_transaction_is_rejected(self):
        self.tracker.mark_processed("agent-test-001")

        result = self.gateway.inspect_transaction(self.transaction)

        self.assertEqual(result["gateway_status"], "REJECTED")
        self.assertTrue(
            result["security_report"]["duplicate_transaction"]
        )

    def test_gateway_never_executes_or_broadcasts(self):
        result = self.gateway.inspect_transaction(self.transaction)

        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["transaction_signed"])
        self.assertFalse(result["transaction_broadcast"])

    def test_invalid_transaction_is_rejected(self):
        with self.assertRaises(ValueError):
            self.gateway.inspect_transaction(None)


if __name__ == "__main__":
    unittest.main()
