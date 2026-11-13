import json
import unittest
from unittest.mock import patch

from app.near_client import NearRPCClient, NearRPCError


class MockResponse:

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class TestNearReceiptInvestigation(unittest.TestCase):

    def setUp(self):
        self.client = NearRPCClient()

        self.payload = {
            "result": {
                "transaction": {
                    "signer_id": "alice.near",
                    "receiver_id": "bob.near",
                    "actions": [
                        {"Transfer": {"deposit": "1000"}}
                    ]
                },
                "transaction_outcome": {
                    "block_hash": "transaction-block",
                    "outcome": {
                        "gas_burnt": 1000,
                        "tokens_burnt": "2000",
                        "logs": []
                    }
                },
                "status": {
                    "SuccessReceiptId": "receipt-success"
                },
                "final_execution_status": "FINAL",
                "receipts": [
                    {
                        "receipt_id": "receipt-success",
                        "predecessor_id": "alice.near",
                        "receiver_id": "bob.near",
                        "receipt": {
                            "Action": {
                                "actions": [
                                    {"Transfer": {"deposit": "1000"}}
                                ]
                            }
                        }
                    },
                    {
                        "receipt_id": "receipt-failed",
                        "predecessor_id": "bob.near",
                        "receiver_id": "market.near",
                        "receipt": {
                            "Action": {
                                "actions": [
                                    {
                                        "FunctionCall": {
                                            "method_name": "withdraw",
                                            "args": "",
                                            "gas": 1000000000000,
                                            "deposit": "0"
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ],
                "receipts_outcome": [
                    {
                        "id": "receipt-success",
                        "block_hash": "receipt-block-1",
                        "outcome": {
                            "executor_id": "bob.near",
                            "gas_burnt": 400,
                            "tokens_burnt": "500",
                            "logs": ["Transfer completed"],
                            "status": {"SuccessValue": ""}
                        }
                    },
                    {
                        "id": "receipt-failed",
                        "block_hash": "receipt-block-2",
                        "outcome": {
                            "executor_id": "market.near",
                            "gas_burnt": 600,
                            "tokens_burnt": "800",
                            "logs": ["Execution failed"],
                            "status": {
                                "Failure": {
                                    "ActionError": {}
                                }
                            }
                        }
                    }
                ]
            }
        }

    @patch("app.near_client.urlopen")
    def test_successful_and_failed_receipts(self, mock_urlopen):

        mock_urlopen.return_value = MockResponse(self.payload)

        result = self.client.get_transaction(
            "E" * 44,
            "alice.near"
        )

        self.assertEqual(result["receipt_count"], 2)
        self.assertEqual(result["successful_receipt_count"], 1)
        self.assertEqual(result["failed_receipt_count"], 1)
        self.assertEqual(result["unknown_receipt_count"], 0)

        self.assertEqual(
            result["receipts"][0]["status"],
            "SUCCEEDED"
        )

        self.assertEqual(
            result["receipts"][1]["status"],
            "FAILED"
        )

        self.assertEqual(
            result["receipts"][1]["receiver_id"],
            "market.near"
        )

        self.assertEqual(result["receipts"][1]["gas_burnt"], 600)

        request_body = json.loads(
            mock_urlopen.call_args.args[0].data
        )

        self.assertEqual(
            request_body["method"],
            "tx_status"
        )

    @patch("app.near_client.urlopen")
    def test_mismatched_receipt_outcomes_are_rejected(self, mock_urlopen):

        payload = json.loads(json.dumps(self.payload))

        payload["result"]["receipts_outcome"][1]["id"] = "unknown-receipt-id"

        mock_urlopen.return_value = MockResponse(payload)

        with self.assertRaises(NearRPCError):
            self.client.get_transaction(
                "E" * 44,
                "alice.near"
            )

    @patch("app.near_client.urlopen")
    def test_unresolved_receipt_is_reported(self, mock_urlopen):

        payload = json.loads(json.dumps(self.payload))

        payload["result"]["receipts_outcome"] = (
            payload["result"]["receipts_outcome"][:1]
        )

        mock_urlopen.return_value = MockResponse(payload)

        result = self.client.get_transaction(
            "E" * 44,
            "alice.near"
        )

        self.assertEqual(result["unresolved_receipt_count"], 1)
        self.assertEqual(result["unknown_receipt_count"], 0)
        self.assertEqual(result["receipts"][1]["status"], "UNRESOLVED")
        self.assertIsNone(result["receipts"][1]["execution_status"])

    @patch("app.near_client.urlopen")
    def test_non_final_transaction_is_rejected(self, mock_urlopen):

        payload = json.loads(json.dumps(self.payload))

        payload["result"]["final_execution_status"] = "EXECUTED"

        mock_urlopen.return_value = MockResponse(payload)

        with self.assertRaises(NearRPCError):
            self.client.get_transaction(
                "E" * 44,
                "alice.near"
            )


if __name__ == "__main__":
    unittest.main()
