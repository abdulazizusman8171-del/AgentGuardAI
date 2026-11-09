import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from main import evaluate_transaction


class TestAgentGuard(unittest.TestCase):

    def test_safe_transaction(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
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
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
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
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": True
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["risk_score"], 40)

    def test_transaction_exceeds_spending_limit(self):
        transaction = {
            "amount": 3,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
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
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
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
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
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
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        blocked_addresses = [
            "0x1234567890abcdef1234567890abcdef12345678"
        ]

        result = evaluate_transaction(
            transaction,
            blocked_recipients=blocked_addresses
        )

        self.assertEqual(result["decision"], "BLOCK")
        self.assertTrue(result["recipient_blocklisted"])

    def test_safe_recipient_not_on_blocklist(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0xabcdef1234567890abcdef1234567890abcdef12",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        blocked_addresses = [
            "0x1234567890abcdef1234567890abcdef12345678"
        ]

        result = evaluate_transaction(
            transaction,
            blocked_recipients=blocked_addresses
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertFalse(result["recipient_blocklisted"])

    def test_negative_amount_is_rejected(self):
        transaction = {
            "amount": -5,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

    def test_invalid_amount_format_is_rejected(self):
        transaction = {
            "amount": "abc",
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

    def test_invalid_transaction_input_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_transaction(None)

    def test_missing_amount_is_rejected(self):
        transaction = {
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

    def test_invalid_ethereum_address_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x123INVALID",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

    def test_invalid_near_account_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "near",
            "recipient_address": "INVALID ACCOUNT!",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

    def test_valid_ethereum_address(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["decision"], "ALLOW")

    def test_valid_near_account(self):
        transaction = {
            "amount": 0.1,
            "network": "near",
            "recipient_address": "alice.near",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["decision"], "ALLOW")

    def test_valid_bnb_address(self):
        transaction = {
            "amount": 0.1,
            "network": "bnb",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        result = evaluate_transaction(transaction)

        self.assertEqual(result["decision"], "ALLOW")

    def test_missing_network_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)
    def test_negative_max_amount_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }
        with self.assertRaises(ValueError):
            evaluate_transaction(transaction, max_amount=-100)
    def test_invalid_max_amount_format_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction, max_amount="abc")
    def test_boolean_max_amount_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction, max_amount=True)
    def test_non_finite_max_amount_is_rejected(self):
        transaction = {
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        for invalid_limit in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(limit=invalid_limit):
                with self.assertRaises(ValueError):
                    evaluate_transaction(transaction, max_amount=invalid_limit)
if __name__ == "__main__":
    unittest.main()
