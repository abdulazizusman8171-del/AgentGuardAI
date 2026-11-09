def evaluate_transaction(transaction, max_amount=2):

    risk_score = 0
    reasons = []

    amount = transaction.get("amount", 0)
    recipient_known = transaction.get("recipient_known", False)
    new_contract = transaction.get("new_contract", False)
    unlimited_approval = transaction.get("unlimited_approval", False)

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

    risk_score = min(risk_score, 100)

    # Final decision
    if risk_score >= 60 or limit_exceeded:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    return {
        "risk_score": risk_score,
        "decision": decision,
        "reasons": reasons,
        "max_amount": max_amount,
        "limit_exceeded": limit_exceeded
    }


if __name__ == "__main__":

    sample_transaction = {
        "amount": 6,
        "recipient_known": False,
        "new_contract": True,
        "unlimited_approval": False
    }

    result = evaluate_transaction(sample_transaction)

    print("AGENTGUARD AI SECURITY REPORT")
    print("-----------------------------")
    print("Risk Score:", result["risk_score"])
    print("Decision:", result["decision"])
    print("Reasons:", result["reasons"])