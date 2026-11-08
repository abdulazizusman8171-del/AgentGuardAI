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


if __name__ == "__main__":
    unittest.main()