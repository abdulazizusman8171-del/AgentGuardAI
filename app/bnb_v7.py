import json
import os
import re
from decimal import Decimal
from pathlib import Path

import httpx
from eth_abi import decode, encode
from eth_hash.auto import keccak
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/bnb", tags=["BNB V7"])

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ABI_DIR = Path(__file__).resolve().parent / "abi"

DEFAULT_RPC = "https://data-seed-prebsc-1-s1.binance.org:8545"
EXPECTED_CHAIN_ID = 97
ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")


def rpc_request(method, params=None):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or [],
        "id": 1
    }

    try:
        response = httpx.post(
            os.getenv("BNB_TESTNET_RPC_URL", DEFAULT_RPC),
            json=payload,
            timeout=12
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            raise HTTPException(
                status_code=502,
                detail="BNB Testnet RPC returned an error."
            )

        return result.get("result")

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to communicate with BNB Testnet."
        ) from exc


def check_network():
    chain_id = int(rpc_request("eth_chainId"), 16)

    if chain_id != EXPECTED_CHAIN_ID:
        raise HTTPException(
            status_code=503,
            detail="Connected network is not BNB Smart Chain Testnet."
        )

    return chain_id


def validate_address(address):
    if not isinstance(address, str) or not ADDRESS_PATTERN.fullmatch(address):
        raise HTTPException(
            status_code=400,
            detail="Invalid Ethereum-compatible address."
        )
    return address


def load_deployment():
    try:
        with open(PROJECT_ROOT / "v7-testnet-deployment.json", "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="V7 deployment configuration could not be loaded."
        ) from exc


def load_abi(filename):
    try:
        with open(ABI_DIR / filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Contract ABI configuration could not be loaded."
        ) from exc


def function_call(address, signature, input_types=None, input_values=None, output_types=None):
    validate_address(address)

    input_types = input_types or []
    input_values = input_values or []
    output_types = output_types or []

    selector = keccak(signature.encode())[:4].hex()
    arguments = encode(input_types, input_values).hex() if input_types else ""
    calldata = "0x" + selector + arguments

    result = rpc_request(
        "eth_call",
        [{"to": address, "data": calldata}, "latest"]
    )

    if not output_types:
        return None

    try:
        return decode(output_types, bytes.fromhex(result[2:]))
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to decode response for {signature}."
        ) from exc


def contract_exists(address):
    code = rpc_request("eth_getCode", [address, "latest"])

    if not code or code == "0x":
        raise HTTPException(
            status_code=404,
            detail="No deployed contract found at this address."
        )

    return True


def to_bnb(wei_value):
    return format(
        Decimal(int(wei_value)) / Decimal(10**18),
        "f"
    )


@router.get("/health")
def bnb_health():
    chain_id = check_network()
    block_number = int(rpc_request("eth_blockNumber"), 16)

    return {
        "status": "connected",
        "network": "BNB Smart Chain Testnet",
        "chain_id": chain_id,
        "latest_block": block_number,
        "read_only": True
    }


@router.get("/factory")
def factory_status(wallet: str | None = Query(default=None)):
    chain_id = check_network()
    deployment = load_deployment()
    factory_address = validate_address(deployment["factoryAddress"])

    contract_exists(factory_address)

    result = {
        "network": "BNB Smart Chain Testnet",
        "chain_id": chain_id,
        "factory_address": factory_address,
        "contract_deployed": True,
        "read_only": True
    }

    if wallet:
        wallet = validate_address(wallet)

        has_vault = function_call(
            factory_address,
            "hasVault(address)",
            ["address"],
            [wallet],
            ["bool"]
        )[0]

        vault_address = function_call(
            factory_address,
            "getVault(address)",
            ["address"],
            [wallet],
            ["address"]
        )[0]

        result["wallet"] = wallet
        result["has_vault"] = has_vault
        result["vault_address"] = vault_address if has_vault else None

    return result


@router.get("/vault/{address}")
def vault_status(address: str):
    chain_id = check_network()
    address = validate_address(address)
    contract_exists(address)

    owner = function_call(address, "owner()", output_types=["address"])[0]
    balance = function_call(address, "getBalance()", output_types=["uint256"])[0]
    paused = function_call(address, "paused()", output_types=["bool"])[0]
    count = function_call(address, "transactionCount()", output_types=["uint256"])[0]

    return {
        "network": "BNB Smart Chain Testnet",
        "chain_id": chain_id,
        "vault_address": address,
        "owner": owner,
        "balance_wei": str(balance),
        "balance_bnb": to_bnb(balance),
        "paused": paused,
        "transaction_count": count,
        "read_only": True
    }


@router.get("/vault/{address}/security")
def vault_security(address: str):
    check_network()
    address = validate_address(address)
    contract_exists(address)

    max_transaction = function_call(
        address, "maxTransactionValue()", output_types=["uint256"]
    )[0]

    daily_limit = function_call(
        address, "dailySpendingLimit()", output_types=["uint256"]
    )[0]

    daily_spent = function_call(
        address, "getCurrentDaySpending()", output_types=["uint256"]
    )[0]

    pending_recipient = function_call(
        address, "pendingRecoveryRecipient()", output_types=["address"]
    )[0]

    recovery_ready = function_call(
        address, "recoveryReadyAt()", output_types=["uint256"]
    )[0]

    recovery_delay = function_call(
        address, "RECOVERY_DELAY()", output_types=["uint256"]
    )[0]

    return {
        "vault_address": address,
        "max_transaction_wei": str(max_transaction),
        "max_transaction_bnb": to_bnb(max_transaction),
        "daily_limit_wei": str(daily_limit),
        "daily_limit_bnb": to_bnb(daily_limit),
        "daily_spent_wei": str(daily_spent),
        "daily_spent_bnb": to_bnb(daily_spent),
        "pending_recovery_recipient": pending_recipient,
        "recovery_ready_at": recovery_ready,
        "recovery_delay_seconds": recovery_delay,
        "read_only": True
    }


def bnb_v7_preflight(amount_bnb):
    """
    Read-only BNB V7 pre-execution security checks.
    Returns on-chain limits and whether the proposed amount is permitted.
    Does not sign or execute transactions.
    """
    try:
        amount = Decimal(str(amount_bnb))

        if not amount.is_finite() or amount < 0:
            raise ValueError("Transaction amount must be a finite, non-negative number.")

        amount_wei_decimal = amount * Decimal(10**18)

        if amount_wei_decimal != amount_wei_decimal.to_integral_value():
            raise ValueError("Transaction amount has more precision than wei supports.")

        amount_wei = int(amount_wei_decimal)

        chain_id = check_network()
        deployment = load_deployment()
        vault_address = validate_address(deployment["vaultAddress"])

        contract_exists(vault_address)

        paused = function_call(
            vault_address, "paused()", output_types=["bool"]
        )[0]

        max_transaction = function_call(
            vault_address, "maxTransactionValue()", output_types=["uint256"]
        )[0]

        daily_limit = function_call(
            vault_address, "dailySpendingLimit()", output_types=["uint256"]
        )[0]

        daily_spent = function_call(
            vault_address, "getCurrentDaySpending()", output_types=["uint256"]
        )[0]

        pending_recipient = function_call(
            vault_address, "pendingRecoveryRecipient()", output_types=["address"]
        )[0]

        recovery_ready = function_call(
            vault_address, "recoveryReadyAt()", output_types=["uint256"]
        )[0]

        zero_address = "0x0000000000000000000000000000000000000000"
        recovery_pending = (
            pending_recipient.lower() != zero_address
            or int(recovery_ready) > 0
        )

        remaining_daily = max(0, int(daily_limit) - int(daily_spent))

        checks = {
            "network_verified": chain_id == EXPECTED_CHAIN_ID,
            "vault_not_paused": not paused,
            "no_pending_recovery": not recovery_pending,
            "within_transaction_limit": amount_wei <= int(max_transaction),
            "within_daily_limit": (
                amount_wei <= remaining_daily
            )
        }

        reasons = []

        if paused:
            reasons.append("V7 vault is paused.")

        if recovery_pending:
            reasons.append("V7 vault has a pending recovery process.")

        if amount_wei > int(max_transaction):
            reasons.append("Transaction exceeds the V7 maximum transaction limit.")

        if amount_wei > remaining_daily:
            reasons.append("Transaction exceeds the remaining V7 daily spending allowance.")

        return {
            "network": "BNB Smart Chain Testnet",
            "chain_id": chain_id,
            "vault_address": vault_address,
            "amount_wei": str(amount_wei),
            "max_transaction_wei": str(max_transaction),
            "daily_limit_wei": str(daily_limit),
            "daily_spent_wei": str(daily_spent),
            "remaining_daily_wei": str(remaining_daily),
            "paused": paused,
            "recovery_pending": recovery_pending,
            "checks": checks,
            "passed": all(checks.values()),
            "reasons": reasons,
            "read_only": True
        }

    except HTTPException:
        raise
    except ValueError:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="BNB V7 pre-execution security checks could not be completed."
        ) from exc
