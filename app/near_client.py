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
    def get_access_keys(self, account_id):
        """Return all finalized public access-key permissions for a NEAR account."""

        account_id = self.validate_account_id(account_id)

        keys = []
        cursors = set()
        page_count = 0
        block_height = None
        block_hash = None
        after_key = None

        try:
            while True:
                page_count += 1

                if page_count > 1000:
                    raise ValueError("Access-key pagination limit exceeded")

                params = {
                    "request_type": "view_access_key_list",
                    "account_id": account_id,
                    "limit": 100
                }

                if after_key is None:
                    params["finality"] = "final"
                else:
                    params["block_id"] = block_hash or block_height
                    params["after_key"] = after_key

                result = self._rpc("query", params)

                if not isinstance(result, dict):
                    raise ValueError("Invalid access-key response")

                if page_count == 1:
                    block_height = result.get("block_height")
                    block_hash = result.get("block_hash")
                else:
                    if (
                        result.get("block_hash") is not None
                        and block_hash is not None
                        and result["block_hash"] != block_hash
                    ):
                        raise ValueError("Access-key snapshot changed")

                raw_keys = result["keys"]

                if not isinstance(raw_keys, list):
                    raise ValueError("Invalid access-key list")

                for item in raw_keys:
                    public_key = item["public_key"]
                    access_key = item["access_key"]
                    permission = access_key["permission"]

                    if not isinstance(public_key, str) or not public_key:
                        raise ValueError("Invalid public key")

                    if not isinstance(access_key, dict):
                        raise ValueError("Invalid access key")

                    nonce = int(access_key["nonce"])

                    if nonce < 0:
                        raise ValueError("Invalid access-key nonce")

                    receiver_id = None
                    method_names = []
                    allowance = None

                    if permission == "FullAccess":
                        permission_type = "FullAccess"

                    elif isinstance(permission, dict) and len(permission) == 1:
                        permission_type = next(iter(permission))

                        if permission_type not in (
                            "FunctionCall",
                            "GasKeyFullAccess",
                            "GasKeyFunctionCall"
                        ):
                            raise ValueError("Unknown access-key permission")

                        details = permission[permission_type]

                        if permission_type in (
                            "FunctionCall",
                            "GasKeyFunctionCall"
                        ):
                            receiver_id = self.validate_account_id(
                                details["receiver_id"]
                            )
                            method_names = details["method_names"]
                            allowance = details.get("allowance")

                            if not isinstance(method_names, list):
                                raise ValueError("Invalid method names")

                            if not all(
                                isinstance(name, str)
                                for name in method_names
                            ):
                                raise ValueError("Invalid method name")

                    else:
                        raise ValueError("Invalid access-key permission")

                    keys.append({
                        "public_key": public_key,
                        "nonce": nonce,
                        "permission": permission_type,
                        "receiver_id": receiver_id,
                        "method_names": method_names,
                        "allowance": allowance
                    })

                cursor = result.get("last_key")

                if not cursor:
                    break

                if not isinstance(cursor, str) or cursor in cursors:
                    raise ValueError("Invalid or repeated pagination cursor")

                if not block_hash and block_height is None:
                    raise ValueError("Missing block reference for pagination")

                cursors.add(cursor)
                after_key = cursor

        except (KeyError, TypeError, ValueError) as error:
            raise NearRPCError(
                "Invalid access-key data returned by NEAR"
            ) from error

        full_access_count = sum(
            1 for key in keys
            if key["permission"] in (
                "FullAccess",
                "GasKeyFullAccess"
            )
        )

        return {
            "network": self.network,
            "account_id": account_id,
            "total_keys": len(keys),
            "full_access_keys": full_access_count,
            "restricted_keys": len(keys) - full_access_count,
            "keys": keys,
            "has_more": False,
            "pages_scanned": page_count,
            "block_height": block_height,
            "block_hash": block_hash,
            "data_status": "finalized"
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
