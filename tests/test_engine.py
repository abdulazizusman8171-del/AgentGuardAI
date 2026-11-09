import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from main import evaluate_transaction


class TestAgentGuard(unittest.TestCase):

    def test_safe_transaction(self):
        transaction = {
            "amount": 0.1,
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["decision"], "ALLOW")

    def test_suspicious_transaction(self):
        transaction = {
            "amount": 6,
            "recipient_known": False,
            "new_contract": True,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["decision"], "BLOCK")

    def test_unlimited_approval(self):
        transaction = {
            "amount": 0.1,
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": True
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["risk_score"], 40)

    def test_transaction_exceeds_spending_limit(self):
        transaction = {
            "amount": 3,
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction, max_amount=2)

        self.assertEqual(result["decision"], "BLOCK")
        self.assertTrue(result["limit_exceeded"])

    def test_transaction_within_spending_limit(self):
        transaction = {
            "amount": 1,
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction, max_amount=2)

        self.assertEqual(result["decision"], "ALLOW")
        self.assertFalse(result["limit_exceeded"])

    def test_unknown_recipient_requires_confirmation(self):
        transaction = {
            "amount": 0.1,
            "recipient_known": False,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(
            result["decision"],
            "REQUIRE_CONFIRMATION"
        )
    def test_blocklisted_recipient_is_blocked(self):
        transaction = {
            "amount": 0.1,
            "recipient_known": True,
            "recipient_address": "0xDANGER123",
            "new_contract": False,
            "unlimited_approval": False
        }

        blocked_addresses = ["0xdanger123"]

        result = evaluate_transaction(
            transaction,
            blocked_recipients=blocked_addresses
        )

        self.assertEqual(result["decision"], "BLOCK")
        self.assertTrue(result["recipient_blocklisted"])

    def test_safe_recipient_not_on_blocklist(self):
        transaction = {
            "amount": 0.1,
            "recipient_known": True,
            "recipient_address": "0xSAFE123",
            "new_contract": False,
            "unlimited_approval": False
        }

        blocked_addresses = ["0xDANGER123"]

        result = evaluate_transaction(
            transaction,
            blocked_recipients=blocked_addresses
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertFalse(result["recipient_blocklisted"])

if __name__ == "__main__":
    unittest.main()