import unittest

from app.access_key_analyzer import analyze_access_key


class TestAccessKeyAnalyzer(unittest.TestCase):

    def test_full_access_is_high_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:FullAccessTest",
            "permission": "FullAccess"
        })

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["risk_score"], 90)

    def test_restricted_function_call_is_low_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:RestrictedTest",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy", "sell"],
            "allowance": "100000000000000000000"
        })

        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["risk_score"], 15)
        self.assertEqual(result["allowance_near"], "0.0001")

    def test_unrestricted_methods_are_medium_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:OpenMethodsTest",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": [],
            "allowance": "100000000000000000000"
        })

        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["risk_score"], 40)

    def test_unlimited_allowance_is_medium_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:UnlimitedTest",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy"],
            "allowance": None
        })

        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertTrue(result["allowance_unlimited"])

    def test_unrestricted_methods_and_allowance_are_high_risk(self):
        result = analyze_access_key({
            "public_key": "ed25519:HighRiskTest",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": [],
            "allowance": None
        })

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["risk_score"], 65)

    def test_invalid_allowance_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_access_key({
                "public_key": "ed25519:InvalidTest",
                "permission": "FunctionCall",
                "receiver_id": "market.near",
                "method_names": ["buy"],
                "allowance": "invalid"
            })

    def test_invalid_permission_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_access_key({
                "public_key": "ed25519:InvalidPermission",
                "permission": "UnknownPermission"
            })

    def test_full_access_has_structured_finding(self):
        result = analyze_access_key({
            "public_key": "ed25519:FullAccessEvidence",
            "permission": "FullAccess"
        })

        finding = next(
            item for item in result["findings"]
            if item["code"] == "FULL_ACCESS_PERMISSION"
        )

        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["evidence"]["permission"], "FullAccess")

    def test_unrestricted_methods_include_receiver_evidence(self):
        result = analyze_access_key({
            "public_key": "ed25519:OpenMethodsEvidence",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": [],
            "allowance": "100000000000000000000"
        })

        finding = next(
            item for item in result["findings"]
            if item["code"] == "UNRESTRICTED_METHODS"
        )

        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["evidence"]["receiver_id"], "market.near")
        self.assertEqual(finding["evidence"]["method_names"], [])

    def test_unlimited_allowance_has_structured_finding(self):
        result = analyze_access_key({
            "public_key": "ed25519:UnlimitedEvidence",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy"],
            "allowance": None
        })

        finding = next(
            item for item in result["findings"]
            if item["code"] == "UNLIMITED_GAS_ALLOWANCE"
        )

        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertTrue(finding["evidence"]["allowance_unlimited"])

    def test_method_allowlist_includes_method_evidence(self):
        result = analyze_access_key({
            "public_key": "ed25519:MethodEvidence",
            "permission": "FunctionCall",
            "receiver_id": "market.near",
            "method_names": ["buy", "sell"],
            "allowance": "100000000000000000000"
        })

        finding = next(
            item for item in result["findings"]
            if item["code"] == "METHOD_ALLOWLIST"
        )

        self.assertEqual(finding["evidence"]["receiver_id"], "market.near")
        self.assertEqual(finding["evidence"]["method_names"], ["buy", "sell"])
        self.assertEqual(finding["evidence"]["method_count"], 2)

if __name__ == "__main__":
    unittest.main()
