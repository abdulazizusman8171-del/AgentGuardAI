import unittest

from app.near_transaction_analyzer import analyze_near_transaction


class TestNearTransactionAnalyzer(unittest.TestCase):

    def setUp(self):

        self.transaction = {
            "network": "mainnet",
            "transaction_hash": "ExampleTransactionHash",
            "final_execution_status": "FINAL",
            "status": {"SuccessValue": ""},
            "signer_id": "alice.near",
            "receiver_id": "market.near",
            "actions": [
                {
                    "FunctionCall": {
                        "method_name": "buy",
                        "deposit": "1000000000000000000000000",
                        "gas": 1000000000000
                    }
                }
            ],
            "receipts": [],
            "data_status": "finalized"
        }

    def test_basic_transaction_analysis(self):

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(result["confidence"], "HIGH")
        self.assertTrue(result["investigation_complete"])
        self.assertEqual(result["transaction_execution_status"], "SUCCEEDED")
        self.assertEqual(
            result["threat_verdict"],
            "NOT_DETERMINED"
        )

    def test_attached_deposit_is_detected(self):

        result = analyze_near_transaction(self.transaction)

        self.assertTrue(
            any(
                finding["id"] == "contract_call_with_deposit"
                for finding in result["findings"]
            )
        )

    def test_function_call_authorization_and_execution_sources(self):
        self.transaction["receipts"] = [{
            "receipt_id": "receipt-function-call",
            "predecessor_id": "alice.near",
            "receiver_id": "market.near",
            "actions": [{
                "FunctionCall": {
                    "method_name": "buy",
                    "deposit": "1000000000000000000000000",
                    "gas": 1000000000000
                }
            }],
            "status": "SUCCEEDED",
            "execution_status": {"SuccessValue": ""},
            "gas_burnt": 500,
            "logs": []
        }]

        result = analyze_near_transaction(self.transaction)
        interaction = next(
            item for item in result["contract_interactions"]
            if item.get("action") == "FunctionCall"
        )

        self.assertEqual(
            interaction["authorization_evidence_sources"],
            ["transaction.actions[0]"]
        )
        self.assertEqual(
            interaction["execution_evidence_sources"],
            ["receipts[0].actions[0]"]
        )
        self.assertTrue(interaction["authorization_observed"])
        self.assertTrue(interaction["execution_observed"])
        self.assertEqual(interaction["stage"], "AUTHORIZED_AND_EXECUTED")

    def test_receipt_only_function_call_evidence_sources(self):
        self.transaction["actions"] = []
        self.transaction["receipts"] = [{
            "receipt_id": "receipt-only-function-call",
            "predecessor_id": "alice.near",
            "receiver_id": "market.near",
            "actions": [{
                "FunctionCall": {
                    "method_name": "buy",
                    "deposit": "1000000000000000000000000",
                    "gas": 1000000000000
                }
            }],
            "status": "SUCCEEDED",
            "execution_status": {"SuccessValue": ""},
            "gas_burnt": 500,
            "logs": []
        }]

        result = analyze_near_transaction(self.transaction)
        interaction = next(
            item for item in result["contract_interactions"]
            if item.get("action") == "FunctionCall"
        )

        self.assertEqual(
            interaction["authorization_evidence_sources"], []
        )
        self.assertEqual(
            interaction["execution_evidence_sources"],
            ["receipts[0].actions[0]"]
        )
        self.assertFalse(interaction["authorization_observed"])
        self.assertTrue(interaction["execution_observed"])
        self.assertEqual(interaction["stage"], "RECEIPT_EXECUTION_ONLY")

    def test_full_access_key_addition_is_high_impact(self):

        self.transaction["actions"] = [
            {
                "AddKey": {
                    "public_key": "ed25519:ExampleKey",
                    "access_key": {
                        "nonce": 0,
                        "permission": "FullAccess"
                    }
                }
            }
        ]

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(
            result["assessment"],
            "HIGH_IMPACT_ACTIONS_OBSERVED"
        )

        self.assertEqual(result["findings"][0]["severity"], "HIGH")

    def test_account_deletion_is_critical_impact(self):

        self.transaction["actions"] = [
            {
                "DeleteAccount": {
                    "beneficiary_id": "bob.near"
                }
            }
        ]

        result = analyze_near_transaction(self.transaction)

        critical = [
            finding for finding in result["findings"]
            if finding["severity"] == "CRITICAL"
        ]

        self.assertEqual(len(critical), 1)

    def test_failed_receipt_is_not_called_malicious(self):

        self.transaction["receipts"] = [
            {
                "receipt_id": "receipt-1",
                "predecessor_id": "alice.near",
                "receiver_id": "market.near",
                "actions": [],
                "status": "FAILED",
                "execution_status": {
                    "Failure": {"ActionError": {}}
                },
                "gas_burnt": 500,
                "logs": ["Execution failed"]
            }
        ]

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(
            result["assessment"],
            "EXECUTION_FAILURES_OBSERVED"
        )

        self.assertEqual(
            result["threat_verdict"],
            "NOT_DETERMINED"
        )

    def test_unresolved_receipt_reduces_confidence(self):

        self.transaction["receipts"] = [
            {
                "receipt_id": "receipt-2",
                "predecessor_id": "alice.near",
                "receiver_id": "market.near",
                "actions": [],
                "status": "UNRESOLVED",
                "execution_status": None,
                "gas_burnt": None,
                "logs": []
            }
        ]

        result = analyze_near_transaction(self.transaction)

        self.assertFalse(result["investigation_complete"])
        self.assertEqual(result["confidence"], "LIMITED")

    def test_failed_and_unresolved_receipts_are_counted(self):

        self.transaction["receipts"] = [
            {
                "receipt_id": "receipt-3",
                "predecessor_id": "alice.near",
                "receiver_id": "market.near",
                "actions": [],
                "status": "FAILED",
                "execution_status": {"Failure": {}},
                "gas_burnt": 100,
                "logs": []
            },
            {
                "receipt_id": "receipt-4",
                "predecessor_id": "market.near",
                "receiver_id": "treasury.near",
                "actions": [],
                "status": "UNRESOLVED",
                "execution_status": None,
                "gas_burnt": None,
                "logs": []
            }
        ]

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(result["receipt_summary"]["failed"], 1)
        self.assertEqual(result["receipt_summary"]["unresolved"], 1)
        self.assertEqual(result["receipt_summary"]["total"], 2)

    def test_non_final_transaction_is_rejected(self):

        self.transaction["final_execution_status"] = "EXECUTED"

        with self.assertRaises(ValueError):
            analyze_near_transaction(self.transaction)

    def test_invalid_receipt_is_rejected(self):

        self.transaction["receipts"] = ["invalid"]

        with self.assertRaises(ValueError):
            analyze_near_transaction(self.transaction)


if __name__ == "__main__":
    unittest.main()
