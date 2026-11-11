import json
import unittest
from unittest.mock import patch, MagicMock

from urllib.error import URLError

from app.near_client import NearRPCClient, NearRPCError


class TestNearRPCClient(unittest.TestCase):

    def setUp(self):
        self.client = NearRPCClient("mainnet")

    def mock_response(self, data):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = (
            json.dumps(data).encode("utf-8")
        )
        return response

    def test_mainnet_endpoint(self):
        self.assertEqual(
            self.client.endpoint,
            NearRPCClient.MAINNET_URL
        )

    def test_testnet_endpoint(self):
        client = NearRPCClient("testnet")

        self.assertEqual(
            client.endpoint,
            NearRPCClient.TESTNET_URL
        )

    def test_invalid_network(self):
        with self.assertRaises(ValueError):
            NearRPCClient("invalid")

    def test_invalid_account_id(self):
        invalid_ids = [
            "",
            "a",
            "invalid account",
            "account@near"
        ]

        for account_id in invalid_ids:
            with self.subTest(account_id=account_id):
                with self.assertRaises(ValueError):
                    self.client.validate_account_id(account_id)

    def test_account_id_normalization(self):
        result = self.client.validate_account_id(" ROOT.NEAR ")

        self.assertEqual(result, "root.near")

    @patch("app.near_client.urlopen")
    def test_get_account_success(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "jsonrpc": "2.0",
            "result": {
                "amount": str(5 * 10**24),
                "locked": str(10**24),
                "storage_usage": 100,
                "code_hash": "example-code-hash",
                "block_height": 12345,
                "block_hash": "example-block-hash"
            }
        })

        result = self.client.get_account("root.near")

        self.assertEqual(result["account_id"], "root.near")
        self.assertEqual(result["balance_near"], "5")
        self.assertEqual(result["locked_near"], "1")
        self.assertEqual(result["storage_usage"], 100)
        self.assertEqual(result["block_height"], 12345)

    @patch("app.near_client.urlopen")
    def test_rpc_error(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "error": {
                "message": "Account not found"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_account("missing.near")

    @patch("app.near_client.urlopen")
    def test_missing_result(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "jsonrpc": "2.0"
        })

        with self.assertRaises(NearRPCError):
            self.client.get_account("root.near")

    @patch("app.near_client.urlopen")
    def test_invalid_account_data(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "result": {
                "amount": "invalid",
                "locked": "0",
                "storage_usage": 100,
                "code_hash": "example"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_account("root.near")

    @patch("app.near_client.urlopen")
    def test_connection_error(self, mock_urlopen):

        mock_urlopen.side_effect = URLError("Connection failed")

        with self.assertRaises(NearRPCError):
            self.client.get_account("root.near")

    def test_valid_transaction_hash(self):
        tx_hash = "E" * 44

        result = self.client.validate_transaction_hash(tx_hash)

        self.assertEqual(result, tx_hash)

    def test_invalid_transaction_hash(self):
        invalid_hashes = [
            "",
            "short",
            "invalid-hash-with-symbols!!!",
            "0" * 44
        ]

        for tx_hash in invalid_hashes:
            with self.subTest(tx_hash=tx_hash):
                with self.assertRaises(ValueError):
                    self.client.validate_transaction_hash(tx_hash)

    @patch("app.near_client.urlopen")
    def test_get_transaction_success(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "result": {
                "transaction": {
                    "signer_id": "alice.near",
                    "receiver_id": "bob.near",
                    "actions": [
                        {"Transfer": {"deposit": "1000"}}
                    ]
                },
                "transaction_outcome": {
                    "block_hash": "example-block",
                    "outcome": {
                        "gas_burnt": 100000,
                        "tokens_burnt": "5000",
                        "logs": []
                    }
                },
                "status": {"SuccessValue": ""},
                "final_execution_status": "FINAL"
            }
        })

        result = self.client.get_transaction(
            "E" * 44,
            "alice.near"
        )

        self.assertEqual(result["signer_id"], "alice.near")
        self.assertEqual(result["receiver_id"], "bob.near")
        self.assertEqual(result["gas_burnt"], 100000)
        self.assertEqual(result["final_execution_status"], "FINAL")

    @patch("app.near_client.urlopen")
    def test_transaction_rpc_error(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "error": {"message": "Transaction not found"}
        })

        with self.assertRaises(NearRPCError):
            self.client.get_transaction("E" * 44, "alice.near")

    @patch("app.near_client.urlopen")
    def test_transaction_missing_data(self, mock_urlopen):

        mock_urlopen.return_value = self.mock_response({
            "result": {}
        })

        with self.assertRaises(NearRPCError):
            self.client.get_transaction("E" * 44, "alice.near")

    @patch("app.near_client.urlopen")
    def test_transaction_invalid_sender(self, mock_urlopen):

        with self.assertRaises(ValueError):
            self.client.get_transaction("E" * 44, "invalid account")

    @patch("app.near_client.urlopen")
    def test_transaction_connection_error(self, mock_urlopen):

        mock_urlopen.side_effect = URLError("Connection failed")

        with self.assertRaises(NearRPCError):
            self.client.get_transaction("E" * 44, "alice.near")


    @patch("app.near_client.urlopen")
    def test_get_network_activity_success(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "result": {
                "header": {
                    "height": 123456,
                    "hash": "example-block-hash",
                    "timestamp_nanosec": "1700000000000000000"
                },
                "author": "validator.near",
                "chunks": [
                    {"height_included": 123456},
                    {"height_included": 123455}
                ]
            }
        })

        result = self.client.get_network_activity()

        self.assertEqual(result["block_height"], 123456)
        self.assertEqual(result["block_hash"], "example-block-hash")
        self.assertEqual(result["block_producer"], "validator.near")
        self.assertEqual(result["shard_chunk_count"], 2)
        self.assertEqual(result["included_chunk_count"], 1)
        self.assertEqual(result["data_status"], "finalized")

    @patch("app.near_client.urlopen")
    def test_network_activity_rpc_error(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "error": {"message": "Block unavailable"}
        })

        with self.assertRaises(NearRPCError):
            self.client.get_network_activity()

    @patch("app.near_client.urlopen")
    def test_network_activity_missing_data(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "result": {}
        })

        with self.assertRaises(NearRPCError):
            self.client.get_network_activity()

    @patch("app.near_client.urlopen")
    def test_network_activity_invalid_chunks(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "result": {
                "header": {
                    "height": 123456,
                    "hash": "example-block-hash",
                    "timestamp_nanosec": "1700000000000000000"
                },
                "chunks": "invalid"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_network_activity()


    @patch("app.near_client.urlopen")
    def test_get_access_keys_success(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "result": {
                "keys": [
                    {
                        "public_key": "ed25519:FullAccessExample",
                        "access_key": {
                            "nonce": 5,
                            "permission": "FullAccess"
                        }
                    },
                    {
                        "public_key": "ed25519:FunctionCallExample",
                        "access_key": {
                            "nonce": 2,
                            "permission": {
                                "FunctionCall": {
                                    "receiver_id": "market.near",
                                    "method_names": ["buy", "sell"],
                                    "allowance": "100000000000000000000"
                                }
                            }
                        }
                    }
                ],
                "block_height": 123456,
                "block_hash": "example-block"
            }
        })

        result = self.client.get_access_keys("alice.near")

        self.assertEqual(result["total_keys"], 2)
        self.assertEqual(result["full_access_keys"], 1)
        self.assertEqual(result["restricted_keys"], 1)
        self.assertEqual(result["keys"][0]["permission"], "FullAccess")
        self.assertEqual(
            result["keys"][1]["permission"],
            "FunctionCall"
        )
        self.assertEqual(
            result["keys"][1]["receiver_id"],
            "market.near"
        )
        self.assertEqual(result["data_status"], "finalized")

    @patch("app.near_client.urlopen")
    def test_get_access_keys_invalid_data(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "result": {
                "keys": [
                    {
                        "public_key": "example-key",
                        "access_key": {
                            "nonce": "invalid",
                            "permission": "FullAccess"
                        }
                    }
                ]
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("alice.near")

    @patch("app.near_client.urlopen")
    def test_get_access_keys_rpc_error(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "error": {
                "message": "Account not found"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("missing.near")


    @patch("app.near_client.urlopen")
    def test_get_access_keys_pagination(self, mock_urlopen):
        first_page_keys = [
            {
                "public_key": f"ed25519:ExampleKey{i}",
                "access_key": {
                    "nonce": i,
                    "permission": "FullAccess"
                }
            }
            for i in range(100)
        ]

        second_page_keys = [
            {
                "public_key": "ed25519:FinalKey",
                "access_key": {
                    "nonce": 101,
                    "permission": "FullAccess"
                }
            }
        ]

        mock_urlopen.side_effect = [
            self.mock_response({
                "result": {
                    "keys": first_page_keys,
                    "last_key": "ed25519:CursorKey",
                    "block_height": 123456,
                    "block_hash": "fixed-block-hash"
                }
            }),
            self.mock_response({
                "result": {
                    "keys": second_page_keys,
                    "block_height": 123456,
                    "block_hash": "fixed-block-hash"
                }
            })
        ]

        result = self.client.get_access_keys("alice.near")

        self.assertEqual(result["total_keys"], 101)
        self.assertEqual(result["pages_scanned"], 2)
        self.assertEqual(result["full_access_keys"], 101)
        self.assertFalse(result["has_more"])

        first_request = json.loads(
            mock_urlopen.call_args_list[0].args[0].data
        )
        second_request = json.loads(
            mock_urlopen.call_args_list[1].args[0].data
        )

        self.assertEqual(
            second_request["params"]["block_id"],
            "fixed-block-hash"
        )
        self.assertEqual(
            second_request["params"]["after_key"],
            "ed25519:CursorKey"
        )

    @patch("app.near_client.urlopen")
    def test_get_access_keys_repeated_cursor(self, mock_urlopen):
        response = {
            "result": {
                "keys": [],
                "last_key": "ed25519:RepeatedCursor",
                "block_height": 123456,
                "block_hash": "fixed-block-hash"
            }
        }

        mock_urlopen.side_effect = [
            self.mock_response(response),
            self.mock_response(response)
        ]

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("alice.near")

        self.assertEqual(mock_urlopen.call_count, 2)

    @patch("app.near_client.urlopen")
    def test_get_access_keys_changed_block_hash(self, mock_urlopen):
        mock_urlopen.side_effect = [
            self.mock_response({
                "result": {
                    "keys": [],
                    "last_key": "ed25519:NextCursor",
                    "block_height": 123456,
                    "block_hash": "first-block-hash"
                }
            }),
            self.mock_response({
                "result": {
                    "keys": [],
                    "block_height": 123457,
                    "block_hash": "different-block-hash"
                }
            })
        ]

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("alice.near")

        self.assertEqual(mock_urlopen.call_count, 2)

if __name__ == "__main__":
    unittest.main()
