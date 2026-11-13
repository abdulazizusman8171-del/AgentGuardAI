import unittest

from app.near_transaction_analyzer import analyze_near_transaction


class TestNearDelegateActions(unittest.TestCase):

    def setUp(self):

        self.delegate_action = {
            "Delegate": {
                "delegate_action": {
                    "sender_id": "m17216373926083755r.tg",
                    "receiver_id": "game.hot.tg",
                    "public_key": "ed25519:ExamplePublicKey",
                    "nonce": 123,
                    "max_block_height": 224709944,
                    "actions": [
                        {
                            "FunctionCall": {
                                "method_name": "l2_claim",
                                "deposit": "0",
                                "gas": 30000000000000,
                                "args": ""
                            }
                        }
                    ]
                },
                "signature": "ed25519:ExampleSignature"
            }
        }

        self.transaction = {
            "network": "mainnet",
            "transaction_hash": "ExampleHash",
            "final_execution_status": "FINAL",
            "status": {"SuccessValue": ""},
            "signer_id": "0here.tg",
            "receiver_id": "m17216373926083755r.tg",
            "actions": [self.delegate_action],
            "receipts": [],
            "data_status": "finalized"
        }

    def test_delegate_nested_function_call_is_inspected(self):

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(result["delegated_action_count"], 1)

        delegated = result["delegated_actions"][0]

        self.assertEqual(delegated["sender_id"], "m17216373926083755r.tg")
        self.assertEqual(delegated["receiver_id"], "game.hot.tg")
        self.assertEqual(
            delegated["authorized_action_types"],
            ["FunctionCall"]
        )

        interaction = next(
            item for item in result["contract_interactions"]
            if item.get("method_name") == "l2_claim"
        )

        self.assertEqual(interaction["receiver_id"], "game.hot.tg")
        self.assertTrue(interaction["authorization_observed"])
        self.assertFalse(interaction["execution_observed"])
        self.assertEqual(interaction["stage"], "AUTHORIZED_ONLY")

    def test_authorization_and_execution_are_correlated(self):

        nested_action = (
            self.delegate_action["Delegate"]
            ["delegate_action"]["actions"][0]
        )

        self.transaction["receipts"] = [{
            "receipt_id": "receipt-execution",
            "predecessor_id": "m17216373926083755r.tg",
            "receiver_id": "game.hot.tg",
            "actions": [nested_action],
            "status": "SUCCEEDED",
            "execution_status": {"SuccessValue": ""},
            "gas_burnt": 500,
            "logs": []
        }]

        result = analyze_near_transaction(self.transaction)

        matches = [
            item for item in result["contract_interactions"]
            if item.get("method_name") == "l2_claim"
        ]

        self.assertEqual(len(matches), 1)

        interaction = matches[0]

        self.assertTrue(interaction["authorization_observed"])
        self.assertTrue(interaction["execution_observed"])

        self.assertEqual(
            interaction["authorization_evidence"],
            "transaction.actions[0].delegate_action.actions[0]"
        )

        self.assertEqual(
            interaction["execution_evidence"],
            "receipts[0].actions[0]"
        )

        self.assertEqual(
            interaction["stage"],
            "AUTHORIZED_AND_EXECUTED"
        )

    def test_same_delegate_in_transaction_and_receipt_is_deduplicated(self):

        self.transaction["receipts"] = [{
            "receipt_id": "receipt-1",
            "predecessor_id": "0here.tg",
            "receiver_id": "m17216373926083755r.tg",
            "actions": [self.delegate_action],
            "status": "SUCCEEDED",
            "execution_status": {"SuccessValue": ""},
            "gas_burnt": 100,
            "logs": []
        }]

        result = analyze_near_transaction(self.transaction)

        self.assertEqual(result["delegated_action_count"], 1)
        self.assertEqual(
            len(result["delegated_actions"][0]["source_locations"]),
            2
        )

        interaction = next(
            item for item in result["contract_interactions"]
            if item.get("action") == "Delegate"
        )

        self.assertEqual(
            interaction["authorization_evidence_sources"],
            ["transaction.actions[0]"]
        )

        self.assertEqual(
            interaction["execution_evidence_sources"],
            ["receipts[0].actions[0]"]
        )

    def test_delegated_full_access_key_addition_is_detected(self):

        self.transaction["actions"][0]["Delegate"]["delegate_action"]["actions"] = [
            {
                "AddKey": {
                    "public_key": "ed25519:NewKey",
                    "access_key": {
                        "nonce": 0,
                        "permission": "FullAccess"
                    }
                }
            }
        ]

        result = analyze_near_transaction(self.transaction)

        self.assertTrue(
            any(
                finding["id"] == "full_access_key_added"
                and finding["severity"] == "HIGH"
                for finding in result["findings"]
            )
        )

    def test_delegate_sender_mismatch_is_rejected(self):

        self.transaction["receiver_id"] = "different.near"

        with self.assertRaises(ValueError):
            analyze_near_transaction(self.transaction)

    def test_nested_delegate_action_is_rejected(self):

        self.transaction["actions"][0]["Delegate"]["delegate_action"]["actions"] = [
            self.delegate_action
        ]

        with self.assertRaises(ValueError):
            analyze_near_transaction(self.transaction)


if __name__ == "__main__":
    unittest.main()
