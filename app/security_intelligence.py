# ==========================================
# AGENTGUARD AI SECURITY INTELLIGENCE
# ==========================================

def generate_security_insights(security_report):

    if not isinstance(security_report, dict):
        raise ValueError("Security report must be a dictionary")

    required_fields = ["risk_score", "decision", "reasons"]

    for field in required_fields:
        if field not in security_report:
            raise ValueError(f"Missing security report field: {field}")

    risk_score = security_report["risk_score"]
    decision = security_report["decision"]
    reasons = security_report["reasons"]

    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise ValueError("Risk score must be a number")

    if not 0 <= risk_score <= 100:
        raise ValueError("Risk score must be between 0 and 100")

    if not isinstance(reasons, list):
        raise ValueError("Reasons must be a list")

    if not all(isinstance(reason, str) for reason in reasons):
        raise ValueError("Every reason must be text")

    findings = []
    recommendations = []

    security_rules = {
        "Large transaction amount": {
            "severity": "HIGH",
            "explanation": "The transaction amount is unusually large.",
            "recommendation": "Verify the amount and recipient before proceeding."
        },
        "Moderate transaction amount": {
            "severity": "MEDIUM",
            "explanation": "The transaction amount requires additional attention.",
            "recommendation": "Confirm that the amount matches your intention."
        },
        "Recipient is not recognized": {
            "severity": "MEDIUM",
            "explanation": "The recipient is not recognized by the security system.",
            "recommendation": "Verify the recipient address independently."
        },
        "Interaction with a new contract": {
            "severity": "HIGH",
            "explanation": "The transaction interacts with a new smart contract.",
            "recommendation": "Review the contract before interacting with it."
        },
        "Unlimited token approval detected": {
            "severity": "CRITICAL",
            "explanation": "Unlimited approval may allow a contract to spend your tokens.",
            "recommendation": "Avoid unlimited approval unless it is necessary and trusted."
        },
        "Recipient is on the dangerous address blocklist": {
            "severity": "CRITICAL",
            "explanation": "The recipient appears on your configured dangerous-address list.",
            "recommendation": "Do not send funds to this recipient."
        },
        "Duplicate transaction detected": {
            "severity": "CRITICAL",
            "explanation": "This transaction has already been processed.",
            "recommendation": "Do not submit the same transaction again."
        },
        "Transaction exceeds configured spending limit": {
            "severity": "HIGH",
            "explanation": "The transaction exceeds your configured spending limit.",
            "recommendation": "Review the amount and your spending policy."
        }
    }

    for reason in reasons:

        rule = security_rules.get(reason)

        if rule:
            findings.append({
                "reason": reason,
                **rule
            })

            if rule["recommendation"] not in recommendations:
                recommendations.append(rule["recommendation"])

    if decision == "BLOCK":
        summary = "The transaction has been blocked because of security risks."

    elif decision == "REQUIRE_CONFIRMATION":
        summary = "The transaction requires additional human verification."

    else:
        summary = "No blocking security condition was detected."

    return {
        "intelligence_type": "explainable_rules",
        "risk_score": risk_score,
        "decision": decision,
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations
    }