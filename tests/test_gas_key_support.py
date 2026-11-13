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


class TestGasKeyRPC(unittest.TestCase):

    def setUp(self):
        self.client = NearRPCClient()

    @patch("app.near_client.urlopen")
    def test_gas_key_metadata_is_retrieved(self, mock_urlopen):

        mock_urlopen.return_value = MockResponse({
            "result": {
                "keys": [
                    {
                        "public_key": "ed25519:GasFullAccess",
                        "access_key": {
                            "nonce": 0,
                            "permission": {
                                "GasKeyFullAccess": {
                                    "balance": "2500000000000000000000000",
                                    "num_nonces": 4
                                }
                            }
                        }
                    },
                    {
                        "public_key": "ed25519:GasFunctionCall",
                        "access_key": {
                            "nonce": 0,
                            "permission": {
                                "GasKeyFunctionCall": {
                                    "balance": "1000000000000000000000000",
                                    "num_nonces": 2,
                                    "allowance": None,
                                    "receiver_id": "market.near",
                                    "method_names": ["buy"]
                                }
                            }
                        }
                    }
                ],
                "block_height": 123456,
                "block_hash": "gas-key-test-block"
            }
        })

        result = self.client.get_access_keys("alice.near")

        self.assertEqual(result["total_keys"], 2)

        full_key = result["keys"][0]
        function_key = result["keys"][1]

        self.assertEqual(full_key["balance_near"], "2.5")
        self.assertEqual(full_key["num_nonces"], 4)

        self.assertEqual(function_key["balance_near"], "1")
        self.assertEqual(function_key["num_nonces"], 2)
        self.assertEqual(function_key["receiver_id"], "market.near")
        self.assertEqual(function_key["allowance"], None)

    @patch("app.near_client.urlopen")
    def test_invalid_gas_key_nonce_count_is_rejected(self, mock_urlopen):

        mock_urlopen.return_value = MockResponse({
            "result": {
                "keys": [
                    {
                        "public_key": "ed25519:InvalidGasKey",
                        "access_key": {
                            "nonce": 0,
                            "permission": {
                                "GasKeyFullAccess": {
                                    "balance": "1000000000000000000000000",
                                    "num_nonces": 0
                                }
                            }
                        }
                    }
                ],
                "block_height": 123456,
                "block_hash": "gas-key-test-block"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("alice.near")

    @patch("app.near_client.urlopen")
    def test_invalid_gas_key_balance_is_rejected(self, mock_urlopen):

        mock_urlopen.return_value = MockResponse({
            "result": {
                "keys": [
                    {
                        "public_key": "ed25519:InvalidGasBalance",
                        "access_key": {
                            "nonce": 0,
                            "permission": {
                                "GasKeyFullAccess": {
                                    "balance": "invalid",
                                    "num_nonces": 2
                                }
                            }
                        }
                    }
                ],
                "block_height": 123456,
                "block_hash": "gas-key-test-block"
            }
        })

        with self.assertRaises(NearRPCError):
            self.client.get_access_keys("alice.near")


if __name__ == "__main__":
    unittest.main()
