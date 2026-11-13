from decimal import Decimal, InvalidOperation


def _execution_status(value):
    """Convert a NEAR execution status into a consistent label."""

    if isinstance(value, dict) and len(value) == 1:
        name = next(iter(value))

        if name == "Failure":
            return "FAILED"

        if name in ("SuccessValue", "SuccessReceiptId"):
            return "SUCCEEDED"

        if name == "Unknown":
            return "UNKNOWN"

    if isinstance(value, str):
        if value in ("Started", "NotStarted", "Unknown"):
            return "UNKNOWN"

    return "UNKNOWN"


def _format_action(action):
    """Validate and unpack one NEAR action."""

    if isinstance(action, str) and action:
        return action, {}

    if not isinstance(action, dict) or len(action) != 1:
        raise ValueError("Invalid NEAR action")

    name, details = next(iter(action.items()))

    if not isinstance(name, str) or not name:
        raise ValueError("Invalid NEAR action name")

    if not isinstance(details, dict):
        raise ValueError("Invalid NEAR action details")

    return name, details


def _full_access_permission(permission):
    """Detect full-access permission in supported key structures."""

    if permission == "FullAccess":
        return True

    if isinstance(permission, dict):
        return any(
            key in ("FullAccess", "GasKeyFullAccess")
            for key in permission
        )

    return False


def _analyze_actions(actions, receiver_id, source, findings, interactions):
    """Extract observable behaviour from transaction or receipt actions."""

    for index, raw_action in enumerate(actions):

        name, details = _format_action(raw_action)

        evidence_location = f"{source}[{index}]"

        interaction = {
            "action": name,
            "receiver_id": receiver_id,
            "evidence_source": evidence_location
        }

        if name == "FunctionCall":

            method = details.get("method_name")
            deposit = details.get("deposit", "0")

            if method is not None:
                if not isinstance(method, str):
                    raise ValueError("Invalid function-call method")

                interaction["method_name"] = method

            try:
                deposit_value = Decimal(str(deposit))
            except (InvalidOperation, ValueError):
                raise ValueError("Invalid function-call deposit")

            if not deposit_value.is_finite() or deposit_value < 0:
                raise ValueError("Invalid function-call deposit")

            interaction["attached_deposit_yocto"] = str(deposit_value)

            if deposit_value > 0:
                findings.append({
                    "id": "contract_call_with_deposit",
                    "category": "VALUE_MOVEMENT",
                    "severity": "INFO",
                    "title": "Contract call includes an attached deposit",
                    "description": (
                        "The function call includes a positive attached "
                        "deposit. This records value movement, not evidence "
                        "of malicious behaviour."
                    ),
                    "evidence": {
                        "source": evidence_location,
                        "receiver_id": receiver_id,
                        "method_name": method,
                        "deposit_yocto": str(deposit_value)
                    }
                })

        elif name == "AddKey":

            access_key = details.get("access_key", {})

            if not isinstance(access_key, dict):
                raise ValueError("Invalid AddKey access-key data")

            permission = access_key.get("permission")

            if _full_access_permission(permission):
                findings.append({
                    "id": "full_access_key_added",
                    "category": "ACCOUNT_AUTHORITY_CHANGE",
                    "severity": "HIGH",
                    "title": "A full-access key was added",
                    "description": (
                        "The transaction adds a key with powerful "
                        "account-level permissions. Verify that the key "
                        "belongs to an authorized owner."
                    ),
                    "evidence": {
                        "source": evidence_location,
                        "public_key": details.get("public_key"),
                        "permission": permission
                    }
                })

            else:
                findings.append({
                    "id": "access_key_added",
                    "category": "ACCOUNT_AUTHORITY_CHANGE",
                    "severity": "INFO",
                    "title": "An access key was added",
                    "description": (
                        "The transaction adds an access key. Review its "
                        "permissions and intended purpose."
                    ),
                    "evidence": {
                        "source": evidence_location,
                        "public_key": details.get("public_key"),
                        "permission": permission
                    }
                })

        elif name == "DeleteKey":

            findings.append({
                "id": "access_key_deleted",
                "category": "ACCOUNT_AUTHORITY_CHANGE",
                "severity": "INFO",
                "title": "An access key was deleted",
                "description": (
                    "The transaction removes an access key from an account."
                ),
                "evidence": {
                    "source": evidence_location,
                    "public_key": details.get("public_key")
                }
            })

        elif name == "DeployContract":

            findings.append({
                "id": "contract_deployment",
                "category": "CONTRACT_CHANGE",
                "severity": "HIGH",
                "title": "A smart contract deployment was observed",
                "description": (
                    "Contract code was submitted for deployment. "
                    "This is a high-impact operation, but does not by "
                    "itself establish that the code is malicious."
                ),
                "evidence": {
                    "source": evidence_location,
                    "receiver_id": receiver_id
                }
            })

        elif name == "DeleteAccount":

            findings.append({
                "id": "account_deletion",
                "category": "ACCOUNT_LIFECYCLE",
                "severity": "CRITICAL",
                "title": "An account deletion action was observed",
                "description": (
                    "The transaction contains an account deletion action. "
                    "Verify that this irreversible operation was intended."
                ),
                "evidence": {
                    "source": evidence_location,
                    "receiver_id": receiver_id,
                    "beneficiary_id": details.get("beneficiary_id")
                }
            })

        elif name == "Transfer":

            deposit = details.get("deposit")

            if deposit is not None:
                if (
                    not isinstance(deposit, str)
                    or not deposit.isdigit()
                ):
                    raise ValueError("Invalid transfer deposit")

                interaction["transfer_yocto"] = deposit

        interactions.append(interaction)


def analyze_near_transaction(transaction_data):
    """
    Produce an explainable investigation from finalized NEAR RPC data.

    This is deterministic analysis, not a machine-learning prediction
    or cryptographic proof verification.
    """

    if not isinstance(transaction_data, dict):
        raise ValueError("Transaction data must be a dictionary")

    required = (
        "network",
        "transaction_hash",
        "final_execution_status",
        "status",
        "signer_id",
        "receiver_id",
        "actions",
        "receipts",
        "data_status"
    )

    for field in required:
        if field not in transaction_data:
            raise ValueError(f"Missing transaction field: {field}")

    if transaction_data["network"] not in ("mainnet", "testnet"):
        raise ValueError("Invalid NEAR network")

    if transaction_data["final_execution_status"] != "FINAL":
        raise ValueError("Transaction is not finalized")

    if transaction_data["data_status"] != "finalized":
        raise ValueError("Transaction data is not marked finalized")

    for field in ("transaction_hash", "signer_id", "receiver_id"):
        value = transaction_data[field]

        if not isinstance(value, str) or not value:
            raise ValueError(f"Invalid transaction field: {field}")

    actions = transaction_data["actions"]
    receipts = transaction_data["receipts"]

    if not isinstance(actions, list):
        raise ValueError("Transaction actions must be a list")

    if not isinstance(receipts, list):
        raise ValueError("Receipts must be a list")

    findings = []
    interactions = []

    transaction_status = _execution_status(transaction_data["status"])

    _analyze_actions(
        actions,
        transaction_data["receiver_id"],
        "transaction.actions",
        findings,
        interactions
    )

    receipt_counts = {
        "SUCCEEDED": 0,
        "FAILED": 0,
        "UNKNOWN": 0,
        "UNRESOLVED": 0
    }

    involved_accounts = {
        transaction_data["signer_id"],
        transaction_data["receiver_id"]
    }

    for index, receipt in enumerate(receipts):

        if not isinstance(receipt, dict):
            raise ValueError("Invalid receipt record")

        receipt_id = receipt.get("receipt_id")
        predecessor = receipt.get("predecessor_id")
        receiver = receipt.get("receiver_id")

        if not all(
            isinstance(value, str) and value
            for value in (receipt_id, predecessor, receiver)
        ):
            raise ValueError("Invalid receipt identity")

        status = receipt.get("status")

        if status not in receipt_counts:
            raise ValueError("Unsupported receipt execution status")

        receipt_counts[status] += 1

        involved_accounts.add(predecessor)
        involved_accounts.add(receiver)

        source = f"receipts[{index}].actions"

        receipt_actions = receipt.get("actions")

        if not isinstance(receipt_actions, list):
            raise ValueError("Invalid receipt actions")

        if receipt_actions:
            _analyze_actions(
                receipt_actions,
                receiver,
                source,
                findings,
                interactions
            )

        if status == "FAILED":
            findings.append({
                "id": "receipt_execution_failed",
                "category": "EXECUTION_FAILURE",
                "severity": "WARNING",
                "title": "A receipt execution failed",
                "description": (
                    "The receipt failed during execution. This indicates "
                    "an execution problem, not proof of malicious activity."
                ),
                "evidence": {
                    "receipt_id": receipt_id,
                    "receiver_id": receiver,
                    "execution_status": receipt.get("execution_status"),
                    "gas_burnt": receipt.get("gas_burnt"),
                    "logs": receipt.get("logs", [])
                }
            })

        elif status == "UNRESOLVED":
            findings.append({
                "id": "receipt_unresolved",
                "category": "INVESTIGATION_LIMITATION",
                "severity": "INFO",
                "title": "A receipt has no execution outcome",
                "description": (
                    "The receipt exists, but its execution outcome was not "
                    "available in the returned data."
                ),
                "evidence": {
                    "receipt_id": receipt_id,
                    "receiver_id": receiver
                }
            })

        elif status == "UNKNOWN":
            findings.append({
                "id": "receipt_status_unknown",
                "category": "INVESTIGATION_LIMITATION",
                "severity": "INFO",
                "title": "A receipt has an unknown execution status",
                "description": (
                    "The returned execution status could not be classified."
                ),
                "evidence": {
                    "receipt_id": receipt_id,
                    "receiver_id": receiver
                }
            })

    incomplete_count = (
        receipt_counts["UNKNOWN"] + receipt_counts["UNRESOLVED"]
    )

    high_impact = any(
        finding["severity"] in ("HIGH", "CRITICAL")
        for finding in findings
    )

    investigation_complete = incomplete_count == 0

    if not investigation_complete:
        assessment = "INCOMPLETE_INVESTIGATION"
        confidence = "LIMITED"
    elif high_impact:
        assessment = "HIGH_IMPACT_ACTIONS_OBSERVED"
        confidence = "HIGH"
    elif receipt_counts["FAILED"]:
        assessment = "EXECUTION_FAILURES_OBSERVED"
        confidence = "HIGH"
    else:
        assessment = "NO_HIGH_IMPACT_ACTIONS_OBSERVED"
        confidence = "HIGH"

    return {
        "analysis_type": "deterministic_near_transaction_analysis",
        "network": transaction_data["network"],
        "transaction_hash": transaction_data["transaction_hash"],
        "finality": "FINAL",
        "transaction_execution_status": transaction_status,
        "investigation_complete": investigation_complete,
        "confidence": confidence,
        "assessment": assessment,
        "threat_verdict": "NOT_DETERMINED",
        "scope_note": (
            "This report describes observable transaction and receipt "
            "behaviour. It does not prove that a transaction, account "
            "or contract is malicious or safe."
        ),
        "receipt_summary": {
            "total": len(receipts),
            "successful": receipt_counts["SUCCEEDED"],
            "failed": receipt_counts["FAILED"],
            "unknown": receipt_counts["UNKNOWN"],
            "unresolved": receipt_counts["UNRESOLVED"]
        },
        "involved_accounts": sorted(involved_accounts),
        "contract_interactions": interactions,
        "findings": findings
    }
