"""Evidence-based behavioural analysis for supplied finalized NEAR transactions."""

from collections import Counter


MAX_TRANSACTIONS = 20

_FINDING_WEIGHTS = {
    "full_access_key_added": 25,
    "contract_deployment": 15,
    "account_deletion": 40,
    "receipt_execution_failed": 8,
}

def analyze_wallet_behavior(account_id, transaction_analyses):
    """Build a wallet profile from supplied finalized transaction analyses.

    This function does not claim to have complete on-chain wallet history.
    """

    if not isinstance(account_id, str) or not account_id.strip():
        raise ValueError("A valid wallet account ID is required")

    account_id = account_id.strip().lower()

    if not isinstance(transaction_analyses, list):
        raise ValueError("Transaction analyses must be a list")

    if not 1 <= len(transaction_analyses) <= MAX_TRANSACTIONS:
        raise ValueError(
            f"Supply between 1 and {MAX_TRANSACTIONS} transaction analyses"
        )

    seen_hashes = set()
    counterparties = Counter()
    evidence_findings = []
    total_receipts = Counter()
    interaction_counts = Counter()
    incomplete_transactions = 0
    high_impact_count = 0
    weighted_score = 0

    for analysis in transaction_analyses:
        if not isinstance(analysis, dict):
            raise ValueError("Each transaction analysis must be an object")

        if analysis.get("analysis_type") != (
            "deterministic_near_transaction_analysis"
        ):
            raise ValueError("Unsupported transaction analysis type")

        if analysis.get("finality") != "FINAL":
            raise ValueError("Only finalized transactions are supported")

        tx_hash = analysis.get("transaction_hash")
        if not isinstance(tx_hash, str) or not tx_hash:
            raise ValueError("A valid transaction hash is required")

        if tx_hash in seen_hashes:
            raise ValueError("Duplicate transaction hashes are not allowed")
        seen_hashes.add(tx_hash)

        involved = analysis.get("involved_accounts")
        findings = analysis.get("findings")
        receipts = analysis.get("receipt_summary")
        interactions = analysis.get("contract_interactions")

        if not isinstance(involved, list) or not all(
            isinstance(item, str) for item in involved
        ):
            raise ValueError("Invalid involved-account evidence")

        if account_id not in [item.lower() for item in involved]:
            raise ValueError(
                "A supplied transaction does not involve the requested wallet"
            )

        if not isinstance(findings, list):
            raise ValueError("Invalid transaction findings")

        if not isinstance(receipts, dict):
            raise ValueError("Invalid receipt summary")

        if not isinstance(interactions, list):
            raise ValueError("Invalid contract interaction evidence")

        if analysis.get("investigation_complete") is not True:
            incomplete_transactions += 1

        for key in ("total", "successful", "failed", "unknown", "unresolved"):
            value = receipts.get(key, 0)
            if type(value) is not int or value < 0:
                raise ValueError("Invalid receipt summary values")
            total_receipts[key] += value

        for participant in involved:
            participant = participant.lower()
            if participant != account_id:
                counterparties[participant] += 1

        for interaction in interactions:
            if not isinstance(interaction, dict):
                raise ValueError("Invalid contract interaction")
            action = interaction.get("action", "UNKNOWN")
            if not isinstance(action, str):
                raise ValueError("Invalid interaction action")
            interaction_counts[action] += 1

        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Invalid finding evidence")

            finding_id = finding.get("id")
            severity = finding.get("severity")
            if not isinstance(finding_id, str) or not isinstance(severity, str):
                raise ValueError("Invalid finding identity or severity")

            if severity in ("HIGH", "CRITICAL"):
                high_impact_count += 1

            weight = _FINDING_WEIGHTS.get(finding_id, 0)
            if weight:
                weighted_score += weight
                evidence_findings.append({
                    "transaction_hash": tx_hash,
                    "finding_id": finding_id,
                    "severity": severity,
                    "title": finding.get("title", finding_id),
                    "weight": weight,
                    "evidence": finding.get("evidence", {})
                })

    transaction_count = len(transaction_analyses)
    failed = total_receipts["failed"]
    receipt_total = total_receipts["total"]

    if failed >= 3 and receipt_total and failed / receipt_total >= 0.5:
        weighted_score += 10
        evidence_findings.append({
            "transaction_hashes": sorted(seen_hashes),
            "finding_id": "repeated_receipt_failures",
            "severity": "WARNING",
            "title": "Repeated receipt execution failures observed",
            "weight": 10,
            "evidence": {
                "failed_receipts": failed,
                "total_receipts": receipt_total
            }
        })

    risk_score = min(weighted_score, 100)

    if transaction_count < 3:
        sample_status = "INSUFFICIENT_SAMPLE"
        confidence = "LOW"
    else:
        sample_status = "SAMPLE_BASED"
        confidence = "MEDIUM" if incomplete_transactions == 0 else "LOW"

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    anomalies = [
        item for item in evidence_findings
        if item["finding_id"] in (
            "full_access_key_added",
            "contract_deployment",
            "account_deletion",
            "repeated_receipt_failures"
        )
    ]

    return {
        "analysis_type": "deterministic_wallet_behavior_analysis",
        "account_id": account_id,
        "network": "NEAR",
        "sample_status": sample_status,
        "transaction_count": transaction_count,
        "confidence": confidence,
        "investigation_complete": incomplete_transactions == 0,
        "incomplete_transaction_count": incomplete_transactions,
        "activity_profile": {
            "unique_counterparties": len(counterparties),
            "counterparty_interactions": dict(
                sorted(counterparties.items())
            ),
            "contract_action_counts": dict(
                sorted(interaction_counts.items())
            ),
            "receipt_summary": dict(total_receipts),
            "high_impact_findings": high_impact_count
        },
        "behavioural_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "anomaly_count": len(anomalies),
            "findings": evidence_findings
        },
        "threat_verdict": "NOT_DETERMINED",
        "data_scope": "USER_SUPPLIED_FINALIZED_TRANSACTION_SAMPLES",
        "scope_limitations": [
            "This is not a complete wallet transaction history.",
            "Only supplied finalized transactions were investigated.",
            "No hourly or daily activity trend is inferred.",
            "Unusual activity does not establish malicious intent.",
            "The score measures observed indicators, not probability of compromise."
        ]
    }
