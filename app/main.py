def evaluate_transaction(
    transaction,
    max_amount=2,
    blocked_recipients=None
):

    risk_score = 0
    reasons = []

    amount = transaction.get("amount", 0)
    recipient_known = transaction.get("recipient_known", False)
    recipient_address = transaction.get("recipient_address", "")
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