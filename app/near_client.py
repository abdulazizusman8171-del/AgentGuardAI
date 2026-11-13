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

                    gas_key_balance_yocto = None
                    gas_key_num_nonces = None

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

                        if not isinstance(details, dict):
                            raise ValueError("Invalid permission details")

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

                            if (
                                permission_type == "GasKeyFunctionCall"
                                and allowance is not None
                            ):
                                raise ValueError(
                                    "GasKeyFunctionCall allowance must be None"
                                )

                        if permission_type in (
                            "GasKeyFullAccess",
                            "GasKeyFunctionCall"
                        ):
                            raw_balance = details.get("balance")

                            if (
                                not isinstance(raw_balance, str)
                                or not re.fullmatch(
                                    r"(0|[1-9][0-9]*)",
                                    raw_balance
                                )
                            ):
                                raise ValueError("Invalid Gas Key balance")

                            gas_key_balance_yocto = int(raw_balance)

                            gas_key_num_nonces = details.get("num_nonces")

                            if (
                                type(gas_key_num_nonces) is not int
                                or not 1 <= gas_key_num_nonces <= 1024
                            ):
                                raise ValueError("Invalid Gas Key nonce count")

                    else:
                        raise ValueError("Invalid access-key permission")

                    key_record = {
                        "public_key": public_key,
                        "nonce": nonce,
                        "permission": permission_type,
                        "receiver_id": receiver_id,
                        "method_names": method_names,
                        "allowance": allowance
                    }

                    if gas_key_balance_yocto is not None:
                        key_record.update({
                            "balance_yocto": str(gas_key_balance_yocto),
                            "balance_near": str(
                                Decimal(gas_key_balance_yocto) / Decimal(10**24)
                            ),
                            "num_nonces": gas_key_num_nonces
                        })

                    keys.append(key_record)

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
        """Retrieve a finalized NEAR transaction and its receipt outcomes."""

        tx_hash = self.validate_transaction_hash(tx_hash)
        sender_account_id = self.validate_account_id(sender_account_id)

        result = self._rpc(
            "tx_status",
            {
                "tx_hash": tx_hash,
                "sender_account_id": sender_account_id,
                "wait_until": "FINAL"
            }
        )

        try:
            transaction = result["transaction"]
            transaction_outcome = result["transaction_outcome"]
            tx_outcome = transaction_outcome["outcome"]

            signer_id = transaction["signer_id"]
            receiver_id = transaction["receiver_id"]
            actions = transaction["actions"]

            final_execution_status = result["final_execution_status"]
            transaction_status = result["status"]

            if final_execution_status != "FINAL":
                raise ValueError("Transaction has not reached FINAL status")

            if not isinstance(signer_id, str) or not signer_id:
                raise ValueError("Invalid transaction signer")

            if not isinstance(receiver_id, str) or not receiver_id:
                raise ValueError("Invalid transaction receiver")

            if not isinstance(actions, list):
                raise ValueError("Invalid transaction actions")

            gas_burnt = tx_outcome["gas_burnt"]

            if (
                isinstance(gas_burnt, bool)
                or not isinstance(gas_burnt, int)
                or gas_burnt < 0
            ):
                raise ValueError("Invalid transaction gas usage")

            transaction_logs = tx_outcome.get("logs", [])

            if (
                not isinstance(transaction_logs, list)
                or not all(isinstance(log, str) for log in transaction_logs)
            ):
                raise ValueError("Invalid transaction logs")

            receipts = result["receipts"]
            receipt_outcomes = result["receipts_outcome"]

            if not isinstance(receipts, list):
                raise ValueError("Invalid receipt list")

            if not isinstance(receipt_outcomes, list):
                raise ValueError("Invalid receipt outcomes")

            receipt_outcomes_by_id = {}

            for item in receipt_outcomes:
                if not isinstance(item, dict):
                    raise ValueError("Invalid receipt outcome record")

                receipt_id = item.get("id")
                outcome = item.get("outcome")

                if not isinstance(receipt_id, str) or not receipt_id:
                    raise ValueError("Invalid receipt outcome ID")

                if receipt_id in receipt_outcomes_by_id:
                    raise ValueError("Duplicate receipt outcome ID")

                if not isinstance(outcome, dict):
                    raise ValueError("Invalid receipt execution outcome")

                receipt_gas = outcome.get("gas_burnt")

                if (
                    isinstance(receipt_gas, bool)
                    or not isinstance(receipt_gas, int)
                    or receipt_gas < 0
                ):
                    raise ValueError("Invalid receipt gas usage")

                logs = outcome.get("logs", [])

                if (
                    not isinstance(logs, list)
                    or not all(isinstance(log, str) for log in logs)
                ):
                    raise ValueError("Invalid receipt logs")

                status = outcome.get("status")

                if not isinstance(status, (dict, str)):
                    raise ValueError("Invalid receipt execution status")

                receipt_outcomes_by_id[receipt_id] = outcome

            receipt_records = []
            receipt_ids = set()

            for receipt in receipts:

                if not isinstance(receipt, dict):
                    raise ValueError("Invalid receipt record")

                receipt_id = receipt.get("receipt_id")
                predecessor_id = receipt.get("predecessor_id")
                receipt_receiver = receipt.get("receiver_id")
                receipt_data = receipt.get("receipt")

                if not isinstance(receipt_id, str) or not receipt_id:
                    raise ValueError("Invalid receipt ID")

                if receipt_id in receipt_ids:
                    raise ValueError("Duplicate receipt ID")

                if not isinstance(predecessor_id, str) or not predecessor_id:
                    raise ValueError("Invalid receipt predecessor")

                if not isinstance(receipt_receiver, str) or not receipt_receiver:
                    raise ValueError("Invalid receipt receiver")

                if not isinstance(receipt_data, dict) or len(receipt_data) != 1:
                    raise ValueError("Invalid receipt payload")

                receipt_type, receipt_body = next(iter(receipt_data.items()))

                if receipt_type not in ("Action", "Data"):
                    raise ValueError("Unsupported receipt type")

                if not isinstance(receipt_body, dict):
                    raise ValueError("Invalid receipt body")

                if receipt_type == "Action":
                    receipt_actions = receipt_body.get("actions")

                    if not isinstance(receipt_actions, list):
                        raise ValueError("Invalid receipt actions")
                else:
                    receipt_actions = []

                receipt_ids.add(receipt_id)
                outcome = receipt_outcomes_by_id.get(receipt_id)

                if outcome is None:
                    status_label = "UNRESOLVED"
                    receipt_status = None
                    executor_id = None
                    outcome_block_hash = None
                    receipt_gas = None
                    receipt_tokens_burnt = None
                    receipt_logs = []

                else:
                    receipt_status = outcome["status"]

                    if (
                        isinstance(receipt_status, dict)
                        and "Failure" in receipt_status
                    ):
                        status_label = "FAILED"
                    elif (
                        isinstance(receipt_status, dict)
                        and any(
                            key.startswith("Success")
                            for key in receipt_status
                        )
                    ):
                        status_label = "SUCCEEDED"
                    else:
                        status_label = "UNKNOWN"

                    executor_id = outcome.get("executor_id")
                    outcome_block_hash = next(
                        (
                            item.get("block_hash")
                            for item in receipt_outcomes
                            if item.get("id") == receipt_id
                        ),
                        None
                    )
                    receipt_gas = outcome["gas_burnt"]
                    receipt_tokens_burnt = outcome.get("tokens_burnt")
                    receipt_logs = outcome.get("logs", [])

                receipt_records.append({
                    "receipt_id": receipt_id,
                    "receipt_type": receipt_type,
                    "predecessor_id": predecessor_id,
                    "receiver_id": receipt_receiver,
                    "actions": receipt_actions,
                    "status": status_label,
                    "execution_status": receipt_status,
                    "executor_id": executor_id,
                    "block_hash": outcome_block_hash,
                    "gas_burnt": receipt_gas,
                    "tokens_burnt": receipt_tokens_burnt,
                    "logs": receipt_logs
                })

            if not set(receipt_outcomes_by_id).issubset(receipt_ids):
                raise ValueError("Execution outcome references an unknown receipt")

        except (KeyError, TypeError, ValueError, StopIteration) as error:
            raise NearRPCError(
                "Invalid finalized transaction or receipt data returned by NEAR"
            ) from error

        failed_receipts = sum(
            receipt["status"] == "FAILED"
            for receipt in receipt_records
        )

        successful_receipts = sum(
            receipt["status"] == "SUCCEEDED"
            for receipt in receipt_records
        )

        unknown_receipts = sum(
            receipt["status"] == "UNKNOWN"
            for receipt in receipt_records
        )

        unresolved_receipts = sum(
            receipt["status"] == "UNRESOLVED"
            for receipt in receipt_records
        )

        return {
            "network": self.network,
            "transaction_hash": tx_hash,
            "final_execution_status": final_execution_status,
            "status": transaction_status,
            "signer_id": signer_id,
            "receiver_id": receiver_id,
            "actions": actions,
            "block_hash": transaction_outcome.get("block_hash"),
            "gas_burnt": gas_burnt,
            "tokens_burnt": tx_outcome.get("tokens_burnt"),
            "logs": transaction_logs,
            "receipt_count": len(receipt_records),
            "successful_receipt_count": successful_receipts,
            "failed_receipt_count": failed_receipts,
            "unresolved_receipt_count": unresolved_receipts,
            "unknown_receipt_count": unknown_receipts,
            "receipts": receipt_records,
            "data_status": "finalized"
        }
