import math
import re


# ==========================================
# TRANSACTION TRACKER
# ==========================================

class TransactionTracker:

    def __init__(self):
        self.processed_ids = set()

    def is_duplicate(self, transaction_id):
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("Transaction ID must be non-empty text")

        return transaction_id.strip() in self.processed_ids

    def mark_processed(self, transaction_id):
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("Transaction ID must be non-empty text")

        self.processed_ids.add(transaction_id.strip())


# ==========================================
# BLOCKCHAIN ADDRESS VALIDATION
# ==========================================

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


# ==========================================
# MAIN SECURITY ENGINE
# ==========================================

def evaluate_transaction(
    transaction,
    max_amount=2,
    blocked_recipients=None,
    transaction_tracker=None
):

    risk_score = 0

    # Validate transaction input
    if not isinstance(transaction, dict):
        raise ValueError("Transaction must be a dictionary")

    # ======================================
    # DUPLICATE TRANSACTION DETECTION
    # ======================================

    transaction_id = transaction.get("transaction_id")
    duplicate_transaction = False

    if transaction_tracker is not None:
        if not (
            callable(getattr(transaction_tracker, "is_duplicate", None))
            and callable(getattr(transaction_tracker, "mark_processed", None))
        ):
            raise ValueError("Invalid transaction tracker")

        if transaction_id is None:
            raise ValueError(
                "Transaction ID is required when using the tracker"
            )

        duplicate_transaction = transaction_tracker.is_duplicate(
            transaction_id
        )

    elif transaction_id is not None:
        raise ValueError(
            "Transaction tracker is required when using a transaction ID"
        )

    # ======================================
    # SPENDING LIMIT VALIDATION
    # ======================================

    if isinstance(max_amount, bool) or not isinstance(max_amount, (int, float)):
        raise ValueError("Maximum amount must be a number")

    if not math.isfinite(max_amount):
        raise ValueError("Maximum amount must be finite")

    if max_amount < 0:
        raise ValueError("Maximum amount cannot be negative")

    # ======================================
    # AMOUNT VALIDATION
    # ======================================

    if "amount" not in transaction:
        raise ValueError("Transaction amount is required")

    amount = transaction["amount"]

    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("Transaction amount must be a number")

    if not math.isfinite(amount):
        raise ValueError("Transaction amount must be finite")

    if amount < 0:
        raise ValueError("Transaction amount cannot be negative")

    reasons = []

    # ======================================
    # SECURITY FLAG VALIDATION
    # ======================================

    security_flags = [
        "recipient_known",
        "new_contract",
        "unlimited_approval"
    ]

    for flag in security_flags:

        if flag in transaction and type(transaction[flag]) is not bool:
            raise ValueError(f"{flag} must be True or False")

    recipient_known = transaction.get("recipient_known", False)
    new_contract = transaction.get("new_contract", False)
    unlimited_approval = transaction.get("unlimited_approval", False)

    # ======================================
    # NETWORK VALIDATION
    # ======================================

    if "network" not in transaction:
        raise ValueError("Blockchain network is required")

    network = transaction["network"]

    if not isinstance(network, str):
        raise ValueError("Network must be text")

    network = network.strip().lower()

    # ======================================
    # RECIPIENT VALIDATION
    # ======================================

    recipient_address = transaction.get("recipient_address", "")

    if not recipient_address:
        raise ValueError("Recipient address is required")

    validate_recipient_address(network, recipient_address)

    # ======================================
    # BLOCKLIST VALIDATION
    # ======================================

    if blocked_recipients is None:
        blocked_recipients = []

    if not isinstance(blocked_recipients, list):
        raise ValueError("Blocked recipients must be a list")

    blocked_addresses = set()

    for address in blocked_recipients:

        validate_recipient_address(network, address)

        blocked_addresses.add(address.strip().lower())

    normalized_address = recipient_address.strip().lower()

    recipient_blocklisted = normalized_address in blocked_addresses

    # ======================================
    # RISK RULES
    # ======================================

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

    # ======================================
    # FINAL RISK SCORE
    # ======================================

    risk_score = min(risk_score, 100)

    # ======================================
    # FINAL SECURITY DECISION
    # ======================================

    if duplicate_transaction:

        risk_score = 100
        decision = "BLOCK"

        reasons.append("Duplicate transaction detected")

    elif recipient_blocklisted:

        decision = "BLOCK"

    elif risk_score >= 60 or limit_exceeded:

        decision = "BLOCK"

    elif unlimited_approval:

        decision = "REQUIRE_CONFIRMATION"

    elif not recipient_known:

        decision = "REQUIRE_CONFIRMATION"

    else:

        decision = "ALLOW"

    # ======================================
    # SECURITY REPORT
    # ======================================

    return {
        "risk_score": risk_score,
        "decision": decision,
        "reasons": reasons,
        "max_amount": max_amount,
        "limit_exceeded": limit_exceeded,
        "recipient_blocklisted": recipient_blocklisted,
        "duplicate_transaction": duplicate_transaction
    }


# ==========================================
# DEMONSTRATION
# ==========================================

if __name__ == "__main__":

    sample_transaction = {
        "amount": 6,
        "network": "ethereum",
        "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
        "recipient_known": False,
        "new_contract": True,
        "unlimited_approval": False
    }

    dangerous_addresses = [
        "0x1234567890abcdef1234567890abcdef12345678"
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