import unittest

from app.wallet_behavior_analyzer import analyze_wallet_behavior


class TestWalletBehaviorAnalyzer(unittest.TestCase):

    def make_analysis(
        self,
        tx_hash,
        account="alice.near",
        findings=None,
        failed=0,
        total=1,
        complete=True
    ):
        return {
            "analysis_type": "deterministic_near_transaction_analysis",
            "transaction_hash": tx_hash,
            "finality": "FINAL",
            "investigation_complete": complete,
            "involved_accounts": [account, "market.near"],
            "findings": findings or [],
            "receipt_summary": {
                "total": total,
                "successful": total - failed,
                "failed": failed,
                "unknown": 0,
                "unresolved": 0
            },
            "contract_interactions": [
                {"action": "FunctionCall"}
            ]
        }

    def test_basic_wallet_profile(self):
        analyses = [
            self.make_analysis("tx-1"),
            self.make_analysis("tx-2"),
            self.make_analysis("tx-3")
        ]

        result = analyze_wallet_behavior("alice.near", analyses)

        self.assertEqual(result["transaction_count"], 3)
        self.assertEqual(result["sample_status"], "SAMPLE_BASED")
        self.assertEqual(result["activity_profile"]["unique_counterparties"], 1)
        self.assertEqual(result["threat_verdict"], "NOT_DETERMINED")

    def test_small_sample_is_insufficient(self):
        result = analyze_wallet_behavior(
            "alice.near",
            [self.make_analysis("tx-1")]
        )

        self.assertEqual(result["sample_status"], "INSUFFICIENT_SAMPLE")
        self.assertEqual(result["confidence"], "LOW")

    def test_full_access_key_finding_is_counted(self):
        finding = {
            "id": "full_access_key_added",
            "severity": "HIGH",
            "title": "A full-access key was added",
            "evidence": {"public_key": "example"}
        }

        result = analyze_wallet_behavior(
            "alice.near",
            [
                self.make_analysis("tx-1", findings=[finding]),
                self.make_analysis("tx-2"),
                self.make_analysis("tx-3")
            ]
        )

        self.assertEqual(
            result["behavioural_assessment"]["risk_score"],
            25
        )
        self.assertEqual(
            result["behavioural_assessment"]["risk_level"],
            "MEDIUM"
        )

    def test_account_deletion_is_high_impact(self):
        finding = {
            "id": "account_deletion",
            "severity": "CRITICAL",
            "title": "Account deletion observed",
            "evidence": {}
        }

        result = analyze_wallet_behavior(
            "alice.near",
            [
                self.make_analysis("tx-1", findings=[finding]),
                self.make_analysis("tx-2"),
                self.make_analysis("tx-3")
            ]
        )

        self.assertEqual(
            result["behavioural_assessment"]["risk_score"],
            40
        )

    def test_repeated_receipt_failures_are_detected(self):
        analyses = [
            self.make_analysis("tx-1", failed=2, total=2),
            self.make_analysis("tx-2", failed=2, total=2),
            self.make_analysis("tx-3", failed=2, total=2)
        ]

        result = analyze_wallet_behavior("alice.near", analyses)

        ids = [
            item["finding_id"]
            for item in result["behavioural_assessment"]["findings"]
        ]

        self.assertIn("repeated_receipt_failures", ids)

    def test_unrelated_wallet_transaction_is_rejected(self):
        analysis = self.make_analysis("tx-1", account="bob.near")

        with self.assertRaises(ValueError):
            analyze_wallet_behavior("alice.near", [analysis])

    def test_duplicate_hashes_are_rejected(self):
        analysis = self.make_analysis("same-hash")

        with self.assertRaises(ValueError):
            analyze_wallet_behavior(
                "alice.near",
                [analysis, analysis]
            )

    def test_non_final_transaction_is_rejected(self):
        analysis = self.make_analysis("tx-1")
        analysis["finality"] = "EXECUTED"

        with self.assertRaises(ValueError):
            analyze_wallet_behavior("alice.near", [analysis])

    def test_incomplete_investigation_reduces_confidence(self):
        analyses = [
            self.make_analysis("tx-1"),
            self.make_analysis("tx-2", complete=False),
            self.make_analysis("tx-3")
        ]

        result = analyze_wallet_behavior("alice.near", analyses)

        self.assertEqual(result["confidence"], "LOW")
        self.assertFalse(result["investigation_complete"])

    def test_invalid_input_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_wallet_behavior("alice.near", [])

        with self.assertRaises(ValueError):
            analyze_wallet_behavior("alice.near", "invalid")


if __name__ == "__main__":
    unittest.main()
