import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from fastapi.testclient import TestClient

import app.api as api
from app.approval import ApprovalManager
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow
from app.near_client import NearRPCError
from app.near_market import NearMarketError


class TestAgentGuardAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "api_test.db"

        self.tracker = SQLiteTransactionTracker(database)

        api.tracker = self.tracker
        api.approval_manager = ApprovalManager(
            storage=self.tracker,
            approval_lifetime=300
        )
        api.BLOCKED_RECIPIENTS = []
        api.workflow = TransactionWorkflow(
            transaction_tracker=self.tracker,
            blocked_recipients=[]
        )

        self.client = TestClient(api.app)

        self.safe_transaction = {
            "transaction_id": "api-safe-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
            "recipient_known": True,
            "new_contract": False,
            "unlimited_approval": False
        }

        self.unknown_transaction = {
            "transaction_id": "api-unknown-001",
            "amount": 0.1,
            "network": "ethereum",
            "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "recipient_known": False,
            "new_contract": False,
            "unlimited_approval": False
        }

    def tearDown(self):
        self.temp_dir.cleanup()
    def test_dashboard_homepage(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Dashboard", response.text)

    def test_dashboard_css(self):
        response = self.client.get("/static/styles.css")

        self.assertEqual(response.status_code, 200)
        self.assertIn("body", response.text)

    def test_dashboard_javascript(self):
        response = self.client.get("/static/app.js")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/intelligence", response.text)
    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_evaluate_safe_transaction(self):
        response = self.client.post(
            "/evaluate",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_evaluate_invalid_transaction(self):
        transaction = self.safe_transaction.copy()
        transaction["amount"] = "invalid"

        response = self.client.post(
            "/evaluate",
            json=transaction
        )

        self.assertEqual(response.status_code, 400)

    def test_safe_transaction_does_not_require_approval(self):
        response = self.client.post(
            "/approvals",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["approval_required"])

    def test_unknown_recipient_creates_approval(self):
        response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["approval_required"])
        self.assertEqual(
            response.json()["approval"]["status"],
            "PENDING"
        )

    def test_approval_and_transaction_execution(self):
        create_response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        approval_id = (
            create_response.json()["approval"]["approval_id"]
        )

        approve_response = self.client.post(
            f"/approvals/{approval_id}/approve",
            json=self.unknown_transaction
        )

        self.assertTrue(approve_response.json()["approved"])

        process_payload = self.unknown_transaction.copy()
        process_payload["approval_id"] = approval_id

        process_response = self.client.post(
            "/process",
            json=process_payload
        )

        self.assertEqual(process_response.status_code, 200)
        self.assertEqual(
            process_response.json()["execution_result"]["status"],
            "EXECUTED"
        )

    def test_modified_transaction_cannot_be_approved(self):
        create_response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        approval_id = (
            create_response.json()["approval"]["approval_id"]
        )

        modified_transaction = self.unknown_transaction.copy()
        modified_transaction["amount"] = 0.2

        response = self.client.post(
            f"/approvals/{approval_id}/approve",
            json=modified_transaction
        )

        self.assertFalse(response.json()["approved"])
        self.assertIn("modified", response.json()["message"].lower())

    def test_client_cannot_supply_confirmation(self):
        payload = self.safe_transaction.copy()
        payload["confirmed"] = True

        response = self.client.post(
            "/process",
            json=payload
        )

        self.assertEqual(response.status_code, 400)

    def test_unknown_recipient_waits_for_confirmation(self):
        response = self.client.post(
            "/process",
            json=self.unknown_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "AWAITING_CONFIRMATION"
        )

    def test_safe_transaction_executes(self):
        response = self.client.post(
            "/process",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "EXECUTED"
        )

    def test_duplicate_transaction_is_blocked(self):
        self.client.post(
            "/process",
            json=self.safe_transaction
        )

        response = self.client.post(
            "/process",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["security_report"]["decision"],
            "BLOCK"
        )
        self.assertEqual(
            response.json()["execution_result"]["status"],
            "BLOCKED"
        )

    @patch("app.api.NearRPCClient")
    def test_near_account_lookup(self, mock_client):

        mock_client.return_value.get_account.return_value = {
            "network": "mainnet",
            "account_id": "root.near",
            "balance_near": "5",
            "balance_yocto": str(5 * 10**24),
            "locked_near": "0",
            "locked_yocto": "0",
            "storage_usage": 100,
            "code_hash": "example",
            "block_height": 12345,
            "block_hash": "example-hash"
        }

        response = self.client.get(
            "/near/accounts/root.near"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(
            response.json()["data"]["balance_near"],
            "5"
        )

    @patch("app.api.NearRPCClient")
    def test_near_testnet_selection(self, mock_client):

        self.client.get(
            "/near/accounts/root.near?network=testnet"
        )

        mock_client.assert_called_once_with(
            network="testnet"
        )

    @patch("app.api.NearRPCClient")
    def test_near_invalid_account(self, mock_client):

        mock_client.return_value.get_account.side_effect = (
            ValueError("Invalid NEAR account ID")
        )

        response = self.client.get(
            "/near/accounts/invalid"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_invalid_network(self, mock_client):

        mock_client.side_effect = ValueError(
            "Network must be mainnet or testnet"
        )

        response = self.client.get(
            "/near/accounts/root.near?network=invalid"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_rpc_failure(self, mock_client):

        mock_client.return_value.get_account.side_effect = (
            NearRPCError("Unable to connect to NEAR RPC")
        )

        response = self.client.get(
            "/near/accounts/root.near"
        )

        self.assertEqual(response.status_code, 502)
    @patch("app.api.NearRPCClient")
    def test_near_transaction_lookup(self, mock_client):

        mock_client.return_value.get_transaction.return_value = {
            "network": "mainnet",
            "transaction_hash": "E" * 44,
            "final_execution_status": "FINAL",
            "status": {"SuccessValue": ""},
            "signer_id": "alice.near",
            "receiver_id": "bob.near",
            "actions": [{"Transfer": {"deposit": "1000"}}],
            "block_hash": "example-block",
            "gas_burnt": 1000,
            "tokens_burnt": "500",
            "logs": []
        }

        response = self.client.get(
            f"/near/transactions/{'E' * 44}"
            "?sender_account_id=alice.near"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(
            response.json()["data"]["signer_id"],
            "alice.near"
        )

    @patch("app.api.NearRPCClient")
    def test_near_transaction_testnet_selection(self, mock_client):

        self.client.get(
            f"/near/transactions/{'E' * 44}"
            "?sender_account_id=alice.near&network=testnet"
        )

        mock_client.assert_called_once_with(network="testnet")

    @patch("app.api.NearRPCClient")
    def test_near_transaction_invalid_hash(self, mock_client):

        mock_client.return_value.get_transaction.side_effect = (
            ValueError("Invalid NEAR transaction hash")
        )

        response = self.client.get(
            "/near/transactions/invalid"
            "?sender_account_id=alice.near"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_transaction_invalid_sender(self, mock_client):

        mock_client.return_value.get_transaction.side_effect = (
            ValueError("Invalid NEAR account ID")
        )

        response = self.client.get(
            f"/near/transactions/{'E' * 44}"
            "?sender_account_id=invalid"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_transaction_invalid_network(self, mock_client):

        mock_client.side_effect = ValueError(
            "Network must be mainnet or testnet"
        )

        response = self.client.get(
            f"/near/transactions/{'E' * 44}"
            "?sender_account_id=alice.near&network=invalid"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_transaction_rpc_failure(self, mock_client):

        mock_client.return_value.get_transaction.side_effect = (
            NearRPCError("Unable to connect to NEAR RPC")
        )

        response = self.client.get(
            f"/near/transactions/{'E' * 44}"
            "?sender_account_id=alice.near"
        )
        self.assertEqual(response.status_code, 502)
    def test_intelligence_safe_transaction(self):
        response = self.client.post(
            "/intelligence",
            json=self.safe_transaction
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertTrue(data["success"])
        self.assertEqual(
            data["intelligence"]["decision"],
            "ALLOW"
        )
        self.assertEqual(
            data["intelligence"]["findings"],
            []
        )

    def test_intelligence_unlimited_approval(self):
        transaction = self.safe_transaction.copy()
        transaction["unlimited_approval"] = True

        response = self.client.post(
            "/intelligence",
            json=transaction
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(
            data["intelligence"]["findings"][0]["severity"],
            "CRITICAL"
        )

    def test_intelligence_invalid_transaction(self):
        transaction = self.safe_transaction.copy()
        transaction["amount"] = "invalid"

        response = self.client.post(
            "/intelligence",
            json=transaction
        )
        self.assertEqual(response.status_code,400)

    def test_transaction_history_empty(self):
        response = self.client.get("/transactions/history")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(response.json()["transactions"], [])

    def test_transaction_history_after_execution(self):
        self.client.post(
            "/process",
            json=self.safe_transaction
        )

        response = self.client.get("/transactions/history")

        self.assertEqual(response.status_code, 200)

        transactions = response.json()["transactions"]

        self.assertEqual(len(transactions), 1)
        self.assertEqual(
            transactions[0]["transaction_id"],
            self.safe_transaction["transaction_id"]
        )

    def test_list_pending_approvals(self):
        self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        response = self.client.get("/approvals?status=PENDING")

        self.assertEqual(response.status_code, 200)

        approvals = response.json()["approvals"]

        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["status"], "PENDING")

    def test_filter_approved_approvals(self):
        create_response = self.client.post(
            "/approvals",
            json=self.unknown_transaction
        )

        approval_id = (
            create_response.json()["approval"]["approval_id"]
        )

        self.client.post(
            f"/approvals/{approval_id}/approve",
            json=self.unknown_transaction
        )

        response = self.client.get("/approvals?status=APPROVED")

        self.assertEqual(response.status_code, 200)

        approvals = response.json()["approvals"]

        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["status"], "APPROVED")

    def test_invalid_approval_status_filter(self):
        response = self.client.get("/approvals?status=INVALID")

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearMarketClient")
    def test_near_market_success(self, mock_client):

        mock_client.return_value.get_market_data.return_value = {
            "asset": "NEAR",
            "currency": "USD",
            "price": 2.50,
            "volume_24h": 15000000,
            "price_change_24h_percent": 4.5,
            "last_updated": "2026-11-10T12:00:00Z",
            "source": "CoinGecko"
        }

        response = self.client.get("/near/market")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(
            response.json()["data"]["price"],
            2.50
        )

    @patch("app.api.NearMarketClient")
    def test_near_market_provider_failure(self, mock_client):

        mock_client.return_value.get_market_data.side_effect = (
            NearMarketError("Market data unavailable")
        )

        response = self.client.get("/near/market")

        self.assertEqual(response.status_code, 502)

    @patch("app.api.NearMarketClient")
    def test_near_large_buys_success(self, mock_client):
        mock_client.return_value.get_large_buys.return_value = [{
            "asset": "NEAR",
            "direction": "BUY",
            "near_amount": 2000,
            "usd_value": 6000,
            "wallet": "example.near",
            "transaction_hash": "example_hash"
        }]

        response = self.client.get("/near/large-buys")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(response.json()["source"], "GeckoTerminal")
        self.assertEqual(len(response.json()["data"]), 1)

    @patch("app.api.NearMarketClient")
    def test_near_large_buys_provider_failure(self, mock_client):
        mock_client.return_value.get_large_buys.side_effect = (
            NearMarketError("Trade data unavailable")
        )

        response = self.client.get("/near/large-buys")

        self.assertEqual(response.status_code, 502)
if __name__ == "__main__":
    unittest.main()
