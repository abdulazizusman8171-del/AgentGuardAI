import json
import os
import re
from decimal import Decimal
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class NearRPCError(Exception):
    """Raised when a NEAR RPC request fails."""


class NearRPCClient:

    MAINNET_URL = "https://rpc.mainnet.fastnear.com"
    TESTNET_URL = "https://rpc.testnet.fastnear.com"

    def __init__(self, network="mainnet", timeout=15):

        if network not in ("mainnet", "testnet"):
            raise ValueError("Network must be mainnet or testnet")

        self.network = network
        self.timeout = timeout

        if network == "mainnet":
          self.endpoint = os.getenv(
        "NEAR_MAINNET_RPC_URL",
        self.MAINNET_URL
    )
        else:
         self.endpoint = os.getenv(
        "NEAR_TESTNET_RPC_URL",
        self.TESTNET_URL
    )

    def validate_account_id(self, account_id):

        if not isinstance(account_id, str):
            raise ValueError("NEAR account ID must be text")

        account_id = account_id.strip().lower()

        if not 2 <= len(account_id) <= 64:
            raise ValueError("NEAR account ID must be 2-64 characters")

        if not re.fullmatch(
            r"[a-z0-9]+(?:[-_.][a-z0-9]+)*",
            account_id
        ):
            raise ValueError("Invalid NEAR account ID")

        return account_id

    def validate_transaction_hash(self, tx_hash):

        if not isinstance(tx_hash, str):
            raise ValueError("Transaction hash must be text")

        tx_hash = tx_hash.strip()

        if not re.fullmatch(
            r"[1-9A-HJ-NP-Za-km-z]{32,50}",
            tx_hash
        ):
            raise ValueError("Invalid NEAR transaction hash")

        return tx_hash
    def _rpc(self, method, params):

        payload = {
            "jsonrpc": "2.0",
            "id": "agentguardai",
            "method": method,
            "params": params
        }

        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urlopen(
                request,
                timeout=self.timeout
            ) as response:

                result = json.loads(
                    response.read().decode("utf-8")
                )

        except HTTPError as error:
            raise NearRPCError(
                f"NEAR RPC HTTP error: {error.code}"
            ) from error

        except (URLError, TimeoutError, OSError) as error:
            raise NearRPCError(
                "Unable to connect to NEAR RPC"
            ) from error

        except json.JSONDecodeError as error:
            raise NearRPCError(
                "Invalid JSON response from NEAR RPC"
            ) from error

        if "error" in result:
            raise NearRPCError(
                str(result["error"])
            )

        if "result" not in result:
            raise NearRPCError(
                "NEAR RPC response has no result"
            )

        return result["result"]


    def get_network_activity(self):
        """Return verified information about the latest finalized NEAR block."""

        result = self._rpc(
            "block",
            {"finality": "final"}
        )

        try:
            header = result["header"]
            chunks = result["chunks"]

            height = int(header["height"])
            block_hash = header["hash"]
            timestamp_ns = int(header["timestamp_nanosec"])

            if height < 0 or timestamp_ns < 0:
                raise ValueError("Invalid block values")

            if not isinstance(chunks, list):
                raise ValueError("Invalid block chunks")

            block_time = datetime.fromtimestamp(
                timestamp_ns / 1_000_000_000,
                tz=timezone.utc
            )

            included_chunks = sum(
                1
                for chunk in chunks
                if int(chunk["height_included"]) == height
            )

        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise NearRPCError(
                "Invalid finalized block data returned by NEAR"
            ) from error

        return {
            "network": self.network,
            "block_height": height,
            "block_hash": block_hash,
            "block_producer": result.get("author"),
            "block_timestamp": block_time.isoformat(),
            "shard_chunk_count": len(chunks),
            "included_chunk_count": included_chunks,
            "data_status": "finalized"
        }

    def get_account(self, account_id):

        account_id = self.validate_account_id(account_id)

        result = self._rpc(
            "query",
            {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id
            }
        )

        try:
            amount = int(result["amount"])
            locked = int(result["locked"])
            storage_usage = int(result["storage_usage"])

            if min(amount, locked, storage_usage) < 0:
               raise ValueError("Negative account data")

        except (KeyError, TypeError, ValueError) as error:
            raise NearRPCError(
                "Invalid account data returned by NEAR"
            ) from error

        return {
            "network": self.network,
            "account_id": account_id,
            "balance_yocto": str(amount),
            "balance_near": str(
                Decimal(amount) / Decimal(10**24)
            ),
            "locked_yocto": str(locked),
            "locked_near": str(
                Decimal(locked) / Decimal(10**24)
            ),
            "storage_usage": storage_usage,
            "code_hash": result["code_hash"],
            "block_height": result.get("block_height"),
            "block_hash": result.get("block_hash")
        }
    def get_transaction(self, tx_hash, sender_account_id):

        tx_hash = self.validate_transaction_hash(tx_hash)

        sender_account_id = self.validate_account_id(
            sender_account_id
        )

        result = self._rpc(
            "tx",
            {
                "tx_hash": tx_hash,
                "sender_account_id": sender_account_id,
                "wait_until": "FINAL"
            }
        )

        try:
            transaction = result["transaction"]
            transaction_outcome = result["transaction_outcome"]
            outcome = transaction_outcome["outcome"]

            signer_id = transaction["signer_id"]
            receiver_id = transaction["receiver_id"]
            actions = transaction["actions"]
            status = result["status"]
            gas_burnt = int(outcome["gas_burnt"])

            if not isinstance(actions, list):
                raise ValueError("Invalid transaction actions")

            if gas_burnt < 0:
                raise ValueError("Invalid gas usage")

        except (KeyError, TypeError, ValueError) as error:
            raise NearRPCError(
                "Invalid transaction data returned by NEAR"
            ) from error

        return {
            "network": self.network,
            "transaction_hash": tx_hash,
            "final_execution_status": result.get(
                "final_execution_status"
            ),
            "status": status,
            "signer_id": signer_id,
            "receiver_id": receiver_id,
            "actions": actions,
            "block_hash": transaction_outcome.get("block_hash"),
            "gas_burnt": gas_burnt,
            "tokens_burnt": outcome.get("tokens_burnt"),
            "logs": outcome.get("logs", [])
        }