import unittest

from app.security_intelligence import generate_security_insights


class TestSecurityIntelligence(unittest.TestCase):

    def test_unlimited_approval_is_critical(self):
        report = {
            "risk_score": 40,
            "decision": "REQUIRE_CONFIRMATION",
            "reasons": ["Unlimited token approval detected"]
        }

        result = generate_security_insights(report)

        self.assertEqual(result["findings"][0]["severity"], "CRITICAL")
        self.assertTrue(result["recommendations"])

    def test_blocked_recipient_is_critical(self):
        report = {
            "risk_score": 0,
            "decision": "BLOCK",
            "reasons": [
                "Recipient is on the dangerous address blocklist"
            ]
        }

        result = generate_security_insights(report)

        self.assertEqual(result["findings"][0]["severity"], "CRITICAL")

    def test_unknown_recipient_is_medium(self):
        report = {
            "risk_score": 25,
            "decision": "REQUIRE_CONFIRMATION",
            "reasons": ["Recipient is not recognized"]
        }

        result = generate_security_insights(report)

        self.assertEqual(result["findings"][0]["severity"], "MEDIUM")

    def test_block_decision_has_explanation(self):
        report = {
            "risk_score": 80,
            "decision": "BLOCK",
            "reasons": ["Large transaction amount"]
        }

        result = generate_security_insights(report)

        self.assertIn("blocked", result["summary"])

    def test_safe_transaction_has_no_findings(self):
        report = {
            "risk_score": 0,
            "decision": "ALLOW",
            "reasons": []
        }

        result = generate_security_insights(report)

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["recommendations"], [])

    def test_invalid_risk_score_is_rejected(self):
        report = {
            "risk_score": 150,
            "decision": "BLOCK",
            "reasons": []
        }

        with self.assertRaises(ValueError):
            generate_security_insights(report)


    def test_severity_counts(self):
        report = {
            "risk_score": 90,
            "decision": "BLOCK",
            "reasons": [
                "Unlimited token approval detected",
                "Large transaction amount",
                "Recipient is not recognized"
            ]
        }

        result = generate_security_insights(report)

        self.assertEqual(result["severity_counts"], {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1
        })


if __name__ == "__main__":
    unittest.main()
