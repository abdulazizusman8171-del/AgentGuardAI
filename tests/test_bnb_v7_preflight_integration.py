import unittest
import app.bnb_v7
from unittest.mock import patch

from app.main import evaluate_transaction


class TestBNBV7PreflightIntegration(unittest.TestCase):

    def setUp(self):
        self.transaction = {
            "amount": 0.01,
            "network": "bnb",
            "wallet_address": "0x5c29ef39a552ad27a841925302072503386539e8",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True
        }

    @patch("app.bnb_v7.bnb_v7_preflight")
    def test_successful_v7_preflight_allows_transaction(self, preflight):
        preflight.return_value = {
            "passed": True,
            "reasons": [],
            "checks": {"vault_not_paused": True}
        }

        result = evaluate_transaction(self.transaction)

        self.assertEqual(result["decision"], "ALLOW")
        self.assertIn("bnb_v7", result)
        preflight.assert_called_once()

    @patch("app.bnb_v7.bnb_v7_preflight")
    def test_failed_v7_preflight_blocks_transaction(self, preflight):
        preflight.return_value = {
            "passed": False,
            "reasons": ["V7 vault is paused."],
            "checks": {"vault_not_paused": False}
        }

        result = evaluate_transaction(self.transaction)

        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk_score"], 100)
        self.assertIn("V7 vault is paused.", result["reasons"])

    @patch("app.bnb_v7.bnb_v7_preflight")
    def test_missing_wallet_address_is_rejected(self, preflight):
        transaction = self.transaction.copy()
        transaction.pop("wallet_address")

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

        preflight.assert_not_called()

    @patch("app.bnb_v7.bnb_v7_preflight")
    def test_non_bnb_transaction_does_not_call_v7(self, preflight):
        transaction = self.transaction.copy()
        transaction["network"] = "ethereum"
        transaction.pop("wallet_address")

        result = evaluate_transaction(transaction)

        self.assertEqual(result["decision"], "ALLOW")
        self.assertNotIn("bnb_v7", result)
        preflight.assert_not_called()

    @patch("app.bnb_v7.bnb_v7_preflight")
    def test_non_native_asset_is_rejected(self, preflight):
        transaction = self.transaction.copy()
        transaction["asset"] = "USDT"

        with self.assertRaises(ValueError):
            evaluate_transaction(transaction)

        preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()

