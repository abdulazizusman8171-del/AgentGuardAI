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
        api._near_market_cache.update({
            "data": None,
            "fetched_at": None
        })

        api._near_large_buys_cache.update({
            "data": None,
            "fetched_at": None
        })

        api.APPROVAL_API_KEY = "test-approval-secret"
        self.approval_headers = {
            "X-Approval-Key": "test-approval-secret"
        }
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
            json=self.unknown_transaction,
            headers=self.approval_headers
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
            json=modified_transaction,
            headers=self.approval_headers
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
    def test_near_access_keys_success(self, mock_client):
        mock_client.return_value.get_access_keys.return_value = {
            "network": "mainnet",
            "account_id": "alice.near",
            "total_keys": 2,
            "full_access_keys": 1,
            "restricted_keys": 1,
            "keys": [
                {
                    "public_key": "ed25519:ExampleKey",
                    "permission": "FullAccess"
                },
                {
                    "public_key": "ed25519:RestrictedKey",
                    "permission": "FunctionCall",
                    "receiver_id": "market.near",
                    "method_names": ["buy", "sell"],
                    "allowance": "100000000000000000000"
                }
            ],
            "data_status": "finalized"
        }

        response = self.client.get(
            "/near/accounts/alice.near/access-keys"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(
            response.json()["data"]["full_access_keys"],
            1
        )
        self.assertEqual(
            response.json()["data"]["restricted_keys"],
            1
        )

    @patch("app.api.NearRPCClient")
    def test_near_access_keys_invalid_account(self, mock_client):
        mock_client.return_value.get_access_keys.side_effect = (
            ValueError("Invalid NEAR account ID")
        )

        response = self.client.get(
            "/near/accounts/invalid/access-keys"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_access_keys_rpc_failure(self, mock_client):
        mock_client.return_value.get_access_keys.side_effect = (
            NearRPCError("Unable to connect to NEAR RPC")
        )

        response = self.client.get(
            "/near/accounts/alice.near/access-keys"
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
    def test_near_transaction_analysis(self, mock_client):

        mock_client.return_value.get_transaction.return_value = {
            "network": "mainnet",
            "transaction_hash": "E" * 44,
            "final_execution_status": "FINAL",
            "status": {"SuccessValue": ""},
            "signer_id": "alice.near",
            "receiver_id": "market.near",
            "actions": [
                {
                    "DeployContract": {
                        "code": "example"
                    }
                }
            ],
            "receipts": [],
            "data_status": "finalized"
        }

        response = self.client.get(
            f"/near/transactions/{'E' * 44}/analysis"
            "?sender_account_id=alice.near"
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()["data"]

        self.assertEqual(
            data["assessment"],
            "HIGH_IMPACT_ACTIONS_OBSERVED"
        )

        self.assertEqual(
            data["threat_verdict"],
            "NOT_DETERMINED"
        )

        self.assertEqual(
            data["findings"][0]["id"],
            "contract_deployment"
        )

        mock_client.return_value.get_transaction.assert_called_once_with(
            "E" * 44,
            "alice.near"
        )

    @patch("app.api.NearRPCClient")
    def test_near_transaction_analysis_rpc_failure(self, mock_client):

        mock_client.return_value.get_transaction.side_effect = (
            NearRPCError("Unable to connect to NEAR RPC")
        )

        response = self.client.get(
            f"/near/transactions/{'E' * 44}/analysis"
            "?sender_account_id=alice.near"
        )

        self.assertEqual(response.status_code, 502)


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

        response = self.client.get("/approvals?status=PENDING", headers=self.approval_headers)

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
            json=self.unknown_transaction,
            headers=self.approval_headers
        )

        response = self.client.get("/approvals?status=APPROVED", headers=self.approval_headers)

        self.assertEqual(response.status_code, 200)

        approvals = response.json()["approvals"]

        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["status"], "APPROVED")

    def test_approval_list_rejects_missing_and_wrong_keys(self):
        missing = self.client.get("/approvals")
        wrong = self.client.get(
            "/approvals",
            headers={"X-Approval-Key": "incorrect-key"}
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)

    def test_approval_action_rejects_missing_and_wrong_keys(self):
        missing = self.client.post(
            "/approvals/test-id/approve",
            json=self.unknown_transaction
        )
        wrong = self.client.post(
            "/approvals/test-id/approve",
            json=self.unknown_transaction,
            headers={"X-Approval-Key": "incorrect-key"}
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)

    def test_approval_routes_fail_when_key_is_not_configured(self):
        with patch.object(api, "APPROVAL_API_KEY", None):
            list_response = self.client.get("/approvals")
            action_response = self.client.post(
                "/approvals/test-id/approve",
                json=self.unknown_transaction
            )

        self.assertEqual(list_response.status_code, 503)
        self.assertEqual(action_response.status_code, 503)
    def test_invalid_approval_status_filter(self):
        response = self.client.get("/approvals?status=INVALID", headers=self.approval_headers)

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
    def test_near_market_uses_fresh_cache(self, mock_client):
        cached_data = {
            "asset": "NEAR",
            "currency": "USD",
            "price": 2.50,
            "source": "CoinGecko"
        }

        api._near_market_cache.update({
            "data": cached_data,
            "fetched_at": api.time.monotonic()
        })

        response = self.client.get("/near/market")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["price"], 2.50)
        mock_client.assert_not_called()

    @patch("app.api.NearMarketClient")
    def test_near_market_uses_stale_cache_on_provider_failure(self, mock_client):
        cached_data = {
            "asset": "NEAR",
            "currency": "USD",
            "price": 2.50,
            "source": "CoinGecko"
        }

        api._near_market_cache.update({
            "data": cached_data,
            "fetched_at": api.time.monotonic() - 120
        })

        mock_client.return_value.get_market_data.side_effect = (
            NearMarketError("Market API HTTP error: 429")
        )

        response = self.client.get("/near/market")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["price"], 2.50)

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


    @patch("app.api.NearMarketClient")
    def test_near_large_buys_uses_fresh_cache(self, mock_client):
        cached_data = [{
            "asset": "NEAR",
            "direction": "BUY",
            "near_amount": 100,
            "usd_value": 300,
            "wallet": "cached.near",
            "transaction_hash": "cached_hash"
        }]

        api._near_large_buys_cache.update({
            "data": cached_data,
            "fetched_at": api.time.monotonic()
        })

        response = self.client.get("/near/large-buys")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], cached_data)
        mock_client.assert_not_called()

    @patch("app.api.NearMarketClient")
    def test_near_large_buys_uses_stale_cache_on_provider_failure(self, mock_client):
        cached_data = [{
            "asset": "NEAR",
            "direction": "BUY",
            "near_amount": 100,
            "usd_value": 300,
            "wallet": "cached.near",
            "transaction_hash": "cached_hash"
        }]

        api._near_large_buys_cache.update({
            "data": cached_data,
            "fetched_at": api.time.monotonic() - 120
        })

        mock_client.return_value.get_large_buys.side_effect = (
            NearMarketError("Trade data unavailable")
        )

        response = self.client.get("/near/large-buys")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], cached_data)

    @patch("app.api.NearMarketClient")
    def test_near_large_buys_caches_empty_results(self, mock_client):
        api._near_large_buys_cache.update({
            "data": [],
            "fetched_at": api.time.monotonic()
        })

        response = self.client.get("/near/large-buys")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], [])
        mock_client.assert_not_called()

    @patch("app.api.NearRPCClient")
    def test_near_network_activity_success(self, mock_client):
        mock_client.return_value.get_network_activity.return_value = {
            "network": "mainnet",
            "block_height": 123456,
            "block_hash": "example-block-hash",
            "block_producer": "validator.near",
            "block_timestamp": "2023-11-14T22:13:20+00:00",
            "shard_chunk_count": 2,
            "included_chunk_count": 1,
            "data_status": "finalized"
        }

        response = self.client.get("/near/network-activity")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(
            response.json()["data"]["block_height"],
            123456
        )

    @patch("app.api.NearRPCClient")
    def test_near_network_activity_testnet(self, mock_client):
        self.client.get("/near/network-activity?network=testnet")

        mock_client.assert_called_once_with(network="testnet")

    @patch("app.api.NearRPCClient")
    def test_near_network_activity_invalid_network(self, mock_client):
        mock_client.side_effect = ValueError(
            "Network must be mainnet or testnet"
        )

        response = self.client.get(
            "/near/network-activity?network=invalid"
        )

        self.assertEqual(response.status_code, 400)

    @patch("app.api.NearRPCClient")
    def test_near_network_activity_rpc_failure(self, mock_client):
        mock_client.return_value.get_network_activity.side_effect = (
            NearRPCError("Unable to connect to NEAR RPC")
        )

        response = self.client.get("/near/network-activity")

        self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
