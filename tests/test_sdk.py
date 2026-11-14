import io
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from agentguard import AgentGuardClient, AgentGuardError


class TestAgentGuardSDK(unittest.TestCase):

    def setUp(self):
        self.client = AgentGuardClient(api_key="ag_live_test_key")

    def test_valid_client_creation(self):
        self.assertEqual(
            self.client.base_url,
            "https://agentguardai.onrender.com"
        )

    def test_custom_url_is_supported(self):
        client = AgentGuardClient(
            base_url="http://localhost:8000/", api_key="ag_live_test_key"
        )
        self.assertEqual(client.base_url, "http://localhost:8000")

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentGuardClient(base_url="")

    def test_invalid_url_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentGuardClient(base_url="ftp://example.com")

    def test_url_without_host_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentGuardClient(base_url="https://")

    def test_url_with_credentials_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentGuardClient(
                base_url="https://user:password@example.com"
            )

    def test_invalid_timeout_is_rejected(self):
        for timeout in (0, -1, float("inf"), float("-inf"), float("nan"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    AgentGuardClient(timeout=timeout)

    def test_non_dictionary_transaction_is_rejected(self):
        with self.assertRaises(ValueError):
            self.client.inspect("invalid")

    def test_non_serializable_transaction_is_rejected(self):
        with self.assertRaises(ValueError):
            self.client.inspect({"invalid": object()})

    def test_non_finite_transaction_number_is_rejected(self):
        with self.assertRaises(ValueError):
            self.client.inspect({"amount": float("nan")})

    def test_permitted_decision(self):
        self.assertTrue(
            self.client.is_permitted(
                {"gateway_status": "PERMITTED"}
            )
        )

    def test_approval_required_decision(self):
        self.assertTrue(
            self.client.requires_approval(
                {"gateway_status": "APPROVAL_REQUIRED"}
            )
        )

    def test_rejected_decision(self):
        self.assertTrue(
            self.client.is_rejected(
                {"gateway_status": "REJECTED"}
            )
        )

    def test_decision_helpers_handle_invalid_input(self):
        for value in (None, [], "invalid", 123):
            self.assertFalse(self.client.is_permitted(value))
            self.assertFalse(self.client.requires_approval(value))
            self.assertFalse(self.client.is_rejected(value))

    @patch("agentguard.agentguard.urlopen")
    def test_successful_inspection(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = (
            b'{"gateway_status":"PERMITTED"}'
        )
        mock_urlopen.return_value.__enter__.return_value = response

        result = self.client.inspect({
            "transaction_id": "sdk-unit-test"
        })

        self.assertEqual(
            result["gateway_status"],
            "PERMITTED"
        )

    @patch("agentguard.agentguard.urlopen")
    def test_http_error_is_handled(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://example.com",
            503,
            "Service unavailable",
            None,
            io.BytesIO(b'{"detail":"Unavailable"}')
        )

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "http-error-test"})

    @patch("agentguard.agentguard.urlopen")
    def test_connection_error_is_handled(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "connection-test"})

    @patch("agentguard.agentguard.urlopen")
    def test_timeout_is_handled(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Request timed out")

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "timeout-test"})

    @patch("agentguard.agentguard.urlopen")
    def test_invalid_json_is_handled(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b"not valid json"
        mock_urlopen.return_value.__enter__.return_value = response

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "invalid-json-test"})

    @patch("agentguard.agentguard.urlopen")
    def test_invalid_utf8_is_handled(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b"\xff\xfe"
        mock_urlopen.return_value.__enter__.return_value = response

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "invalid-utf8-test"})

    @patch("agentguard.agentguard.urlopen")
    def test_non_dictionary_response_is_rejected(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b'["unexpected"]'
        mock_urlopen.return_value.__enter__.return_value = response

        with self.assertRaises(AgentGuardError):
            self.client.inspect({"transaction_id": "unexpected-test"})


if __name__ == "__main__":
    unittest.main()
