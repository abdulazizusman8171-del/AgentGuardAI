import math
import re
def validate_recipient_address(network, address):

    if not isinstance(address, str):
        raise ValueError("Recipient address must be text")

    address = address.strip()

    if network == "near":
        if not re.fullmatch(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*", address):
            raise ValueError("Invalid NEAR account ID")

        if not 2 <= len(address) <= 64:
            raise ValueError("NEAR account ID must be 2-64 characters")

    elif network in ("ethereum", "bnb"):
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
            raise ValueError("Invalid EVM wallet address")

    else:
        raise ValueError("Unsupported blockchain network")

    return True

def evaluate_transaction(
    transaction,
    max_amount=2,
    blocked_recipients=None
):
    risk_score = 0
    if not isinstance(transaction, dict):
        raise ValueError("Transaction must be a dictionary")
        # Validate spending limit
    if isinstance(max_amount, bool) or not isinstance(max_amount, (int, float)):
        raise ValueError("Maximum amount must be a number")

    if not math.isfinite(max_amount):
        raise ValueError("Maximum amount must be finite")

    if max_amount < 0:
        raise ValueError("Maximum amount cannot be negative")

    if "amount" not in transaction:
        raise ValueError("Transaction amount is required")

    reasons = []
    amount = transaction.get("amount", 0)

    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("Transaction amount must be a number")

    if not math.isfinite(amount):
        raise ValueError("Transaction amount must be finite")

    if amount < 0:
        raise ValueError("Transaction amount cannot be negative")

    security_flags = [
        "recipient_known",
        "new_contract",
        "unlimited_approval"
    ]

    for flag in security_flags:
        if flag in transaction and type(transaction[flag]) is not bool:
            raise ValueError(f"{flag} must be True or False")

    recipient_known = transaction.get("recipient_known", False)
    recipient_address = transaction.get("recipient_address", "")
    if "network" not in transaction:
        raise ValueError("Blockchain network is required")

    network = transaction["network"]

    if not isinstance(network, str):
        raise ValueError("Network must be text")

    network = network.strip().lower()

    if not recipient_address:
        raise ValueError("Recipient address is required")

    validate_recipient_address(network, recipient_address)

    new_contract = transaction.get("new_contract", False)
    unlimited_approval = transaction.get("unlimited_approval", False)

    # Prepare blocked address list
    blocked_addresses = {
        address.strip().lower()
        for address in (blocked_recipients or [])
        if isinstance(address, str)
    }

    # Check recipient address
    normalized_address = (
        recipient_address.strip().lower()
        if isinstance(recipient_address, str)
        else ""
    )

    recipient_blocklisted = (
        normalized_address in blocked_addresses
        and normalized_address != ""
    )

    # Rule 1: Spending limit
    limit_exceeded = amount > max_amount

    if limit_exceeded:
        reasons.append("Transaction exceeds configured spending limit")

    # Rule 2: Large transaction
    if amount >= 5:
        risk_score += 35
        reasons.append("Large transaction amount")

    elif amount >= 1:
        risk_score += 15
        reasons.append("Moderate transaction amount")

    # Rule 3: Unknown recipient
    if not recipient_known:
        risk_score += 25
        reasons.append("Recipient is not recognized")

    # Rule 4: New smart contract
    if new_contract:
        risk_score += 20
        reasons.append("Interaction with a new contract")

    # Rule 5: Unlimited token approval
    if unlimited_approval:
        risk_score += 40
        reasons.append("Unlimited token approval detected")

    # Rule 6: Dangerous recipient
    if recipient_blocklisted:
        reasons.append("Recipient is on the dangerous address blocklist")

    risk_score = min(risk_score, 100)

    # Final decision
    if recipient_blocklisted:
        decision = "BLOCK"

    elif risk_score >= 60 or limit_exceeded:
        decision = "BLOCK"

    elif not recipient_known:
        decision = "REQUIRE_CONFIRMATION"

    else:
        decision = "ALLOW"

    return {
        "risk_score": risk_score,
        "decision": decision,
        "reasons": reasons,
        "max_amount": max_amount,
        "limit_exceeded": limit_exceeded,
        "recipient_blocklisted": recipient_blocklisted
    }


if __name__ == "__main__":

    sample_transaction = {
        "amount": 6,
        "recipient_known": False,
        "recipient_address": "0x1234567890abcdef",
        "new_contract": True,
        "unlimited_approval": False
    }

    dangerous_addresses = [
        "0x1234567890abcdef"
    ]

    result = evaluate_transaction(
        sample_transaction,
        blocked_recipients=dangerous_addresses
    )

    print("AGENTGUARD AI SECURITY REPORT")
    print("-----------------------------")
    print("Risk Score:", result["risk_score"])
    print("Decision:", result["decision"])
    print("Reasons:", result["reasons"])