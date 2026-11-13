import unittest

from app.access_key_analyzer import analyze_access_key


class TestGasKeyAnalyzer(unittest.TestCase):

    def test_gas_key_full_access_is_high_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:GasFullAccess",
            "permission": "GasKeyFullAccess",
            "balance_yocto": "2500000000000000000000000",
            "num_nonces": 4
        })

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["risk_score"], 90)
        self.assertEqual(result["gas_key_balance_near"], "2.5")
        self.assertEqual(result["gas_key_num_nonces"], 4)

    def test_restricted_gas_key_function_call_is_low_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:GasFunctionCall",
            "permission": "GasKeyFunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy"],
            "allowance": None,
            "balance_yocto": "1000000000000000000000000",
            "num_nonces": 2
        })

        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["risk_score"], 15)
        self.assertIsNone(result["allowance_unlimited"])
        self.assertEqual(result["gas_key_balance_near"], "1")
        self.assertEqual(result["gas_key_num_nonces"], 2)

        self.assertFalse(
            any(
                "finite gas-fee allowance" in item
                for item in result["recommendations"]
            )
        )

    def test_unrestricted_gas_key_methods_are_medium_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:GasOpenMethods",
            "permission": "GasKeyFunctionCall",
            "receiver_id": "market.near",
            "method_names": [],
            "allowance": None,
            "balance_yocto": "1000000000000000000000000",
            "num_nonces": 1
        })

        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["risk_score"], 40)

    def test_non_null_gas_key_allowance_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_access_key({
                "public_key": "ed25519:InvalidGasAllowance",
                "permission": "GasKeyFunctionCall",
                "receiver_id": "market.near",
                "method_names": ["buy"],
                "allowance": "100000000000000000000",
                "balance_yocto": "1000000000000000000000000",
                "num_nonces": 1
            })

    def test_invalid_gas_key_metadata_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_access_key({
                "public_key": "ed25519:InvalidGasMetadata",
                "permission": "GasKeyFullAccess",
                "balance_yocto": "invalid",
                "num_nonces": 2
            })

    def test_gas_key_finding_includes_balance_and_nonce_evidence(self):
        result = analyze_access_key({
            "public_key": "ed25519:GasEvidence",
            "permission": "GasKeyFunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy"],
            "allowance": None,
            "balance_yocto": "1000000000000000000000000",
            "num_nonces": 2
        })

        finding = next(
            item for item in result["findings"]
            if item["code"] == "GAS_KEY_METADATA"
        )

        self.assertEqual(finding["severity"], "INFO")
        self.assertEqual(finding["evidence"]["balance_near"], "1")
        self.assertEqual(finding["evidence"]["num_nonces"], 2)

if __name__ == "__main__":
    unittest.main()
