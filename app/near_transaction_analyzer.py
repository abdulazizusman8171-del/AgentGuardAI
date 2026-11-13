import hashlib
import json
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



def _analyze_actions(
    actions,
    receiver_id,
    source,
    findings,
    interactions,
    delegations,
    seen_delegates,
    stage
):
    """Inspect ordinary actions and NEAR Delegate Actions."""

    for index, raw_action in enumerate(actions):

        name, details = _format_action(raw_action)
        evidence_location = f"{source}[{index}]"

        if name == "Delegate":

            delegate = details.get("delegate_action")
            signature = details.get("signature")

            if not isinstance(delegate, dict):
                raise ValueError("Invalid delegate action")

            sender_id = delegate.get("sender_id")
            delegated_receiver = delegate.get("receiver_id")
            public_key = delegate.get("public_key")
            nonce = delegate.get("nonce")
            max_height = delegate.get("max_block_height")
            nested_actions = delegate.get("actions")

            if not all(
                isinstance(value, str) and value
                for value in (
                    sender_id,
                    delegated_receiver,
                    public_key,
                    signature
                )
            ):
                raise ValueError("Invalid delegated identity or signature")

            if sender_id != receiver_id:
                raise ValueError(
                    "Delegate sender does not match transaction receiver"
                )

            if type(nonce) is not int or nonce < 0:
                raise ValueError("Invalid delegate nonce")

            if type(max_height) is not int or max_height <= 0:
                raise ValueError("Invalid delegate block height")

            if not isinstance(nested_actions, list) or not nested_actions:
                raise ValueError("Invalid delegated action list")

            action_types = []

            for nested in nested_actions:
                nested_name, _ = _format_action(nested)

                if nested_name == "Delegate":
                    raise ValueError("Nested Delegate Actions are not supported")

                action_types.append(nested_name)

            fingerprint_data = json.dumps(
                {
                    "delegate_action": delegate,
                    "signature": signature
                },
                sort_keys=True,
                separators=(",", ":")
            )

            fingerprint = hashlib.sha256(
                fingerprint_data.encode("utf-8")
            ).hexdigest()

            if fingerprint in seen_delegates:

                record = seen_delegates[fingerprint]

                if evidence_location not in record["source_locations"]:
                    record["source_locations"].append(evidence_location)

            else:

                record = {
                    "sender_id": sender_id,
                    "receiver_id": delegated_receiver,
                    "public_key": public_key,
                    "nonce": nonce,
                    "max_block_height": max_height,
                    "signature_present": True,
                    "signature_scheme": signature.split(":", 1)[0],
                    "authorized_action_types": action_types,
                    "source_locations": [evidence_location]
                }

                seen_delegates[fingerprint] = record
                delegations.append(record)

                findings.append({
                    "id": "delegated_authorization_observed",
                    "category": "DELEGATED_AUTHORIZATION",
                    "severity": "INFO",
                    "title": "NEAR delegated authorization observed",
                    "description": (
                        "A signed Delegate Action authorizes another account "
                        "to submit the listed operations. Its contents are "
                        "analyzed separately. Delegation alone does not "
                        "indicate malicious activity."
                    ),
                    "evidence": {
                        "sender_id": sender_id,
                        "receiver_id": delegated_receiver,
                        "public_key": public_key,
                        "nonce": nonce,
                        "max_block_height": max_height,
                        "authorized_actions": action_types
                    }
                })

                # Inspect the operations authorized by the delegate.
                _analyze_actions(
                    nested_actions,
                    delegated_receiver,
                    evidence_location + ".delegate_action.actions",
                    findings,
                    interactions,
                    delegations,
                    seen_delegates,
                    "DELEGATED_AUTHORIZATION"
                )

            interactions.append({
                "action": "Delegate",
                "sender_id": sender_id,
                "receiver_id": delegated_receiver,
                "public_key": public_key,
                "evidence_source": evidence_location,
                "stage": stage,
                "_delegate_fingerprint": fingerprint
            })

            continue

        correlation_payload = json.dumps(
            {"receiver_id": receiver_id, "action": raw_action},
            sort_keys=True,
            separators=(",", ":")
        )

        interaction = {
            "action": name,
            "receiver_id": receiver_id,
            "evidence_source": evidence_location,
            "stage": stage,
            "_correlation_key": hashlib.sha256(
                correlation_payload.encode("utf-8")
            ).hexdigest()
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
                        "deposit. This records value movement, not proof "
                        "of malicious activity."
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
                        "The action adds a key with powerful account-level "
                        "permissions. Verify its ownership and necessity."
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
                    "description": "The action adds an access key.",
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
                "description": "The transaction removes an access key.",
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
                    "This does not establish that the code is malicious."
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
                    "Verify that this operation was intended."
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
                if not isinstance(deposit, str) or not deposit.isdigit():
                    raise ValueError("Invalid transfer deposit")

                interaction["transfer_yocto"] = deposit

        interactions.append(interaction)


def _correlate_interactions(interactions):
    """
    Match delegated authorized actions with their observed receipt actions.

    Identical actions are paired one-to-one so repeated legitimate calls
    are not accidentally collapsed into a single operation.
    """

    groups = {}
    output = []

    for position, interaction in enumerate(interactions):

        if "_delegate_fingerprint" in interaction:
            key = ("delegate", interaction["_delegate_fingerprint"])
            kind = "delegate"

        elif (
            interaction.get("_correlation_key")
            and interaction.get("stage") in (
                "DELEGATED_AUTHORIZATION",
                "RECEIPT_EXECUTION"
            )
        ):
            key = ("action", interaction["_correlation_key"])
            kind = "action"

        else:
            clean = {
                key: value
                for key, value in interaction.items()
                if not key.startswith("_")
            }
            output.append((position, clean))
            continue

        group = groups.setdefault(
            key,
            {
                "kind": kind,
                "first": position,
                "items": []
            }
        )

        group["items"].append((position, interaction))

    for group in groups.values():

        items = group["items"]

        if group["kind"] == "delegate":

            base = dict(items[0][1])

            authorization_sources = [
                item["evidence_source"]
                for _, item in items
                if item.get("stage") == "TRANSACTION"
            ]

            execution_sources = [
                item["evidence_source"]
                for _, item in items
                if item.get("stage") == "RECEIPT_EXECUTION"
            ]

            base["authorization_observed"] = bool(authorization_sources)
            base["execution_observed"] = bool(execution_sources)

            base["authorization_evidence"] = (
                authorization_sources[0]
                if authorization_sources else None
            )

            base["execution_evidence"] = (
                execution_sources[0]
                if execution_sources else None
            )

            base["evidence_source"] = (
                base["authorization_evidence"]
                or base["execution_evidence"]
            )

            if authorization_sources and execution_sources:
                base["stage"] = "AUTHORIZED_AND_EXECUTED"
            elif authorization_sources:
                base["stage"] = "AUTHORIZED_ONLY"
            else:
                base["stage"] = "RECEIPT_EXECUTION_ONLY"

            base.pop("_delegate_fingerprint", None)

            output.append((group["first"], base))
            continue

        authorization_items = [
            (position, item)
            for position, item in items
            if item.get("stage") == "DELEGATED_AUTHORIZATION"
        ]

        execution_items = [
            (position, item)
            for position, item in items
            if item.get("stage") == "RECEIPT_EXECUTION"
        ]

        for index, (position, authorized) in enumerate(authorization_items):

            executed = (
                execution_items[index][1]
                if index < len(execution_items)
                else None
            )

            merged = {
                key: value
                for key, value in authorized.items()
                if not key.startswith("_")
            }

            merged["authorization_observed"] = True
            merged["execution_observed"] = executed is not None

            merged["authorization_evidence"] = authorized["evidence_source"]
            merged["execution_evidence"] = (
                executed["evidence_source"]
                if executed is not None else None
            )

            merged["stage"] = (
                "AUTHORIZED_AND_EXECUTED"
                if executed is not None
                else "AUTHORIZED_ONLY"
            )

            output.append((position, merged))

        for position, executed in execution_items[len(authorization_items):]:

            merged = {
                key: value
                for key, value in executed.items()
                if not key.startswith("_")
            }

            merged["authorization_observed"] = False
            merged["execution_observed"] = True
            merged["authorization_evidence"] = None
            merged["execution_evidence"] = executed["evidence_source"]
            merged["stage"] = "RECEIPT_EXECUTION_ONLY"

            output.append((position, merged))

    return [
        interaction
        for _, interaction in sorted(output, key=lambda item: item[0])
    ]


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
    delegations = []
    seen_delegates = {}

    transaction_status = _execution_status(transaction_data["status"])

    _analyze_actions(
        actions,
        transaction_data["receiver_id"],
        "transaction.actions",
        findings,
        interactions,
        delegations,
        seen_delegates,
        "TRANSACTION"
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
                interactions,
                delegations,
                seen_delegates,
                "RECEIPT_EXECUTION"
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

    interactions = _correlate_interactions(interactions)

    for delegation in delegations:
        involved_accounts.add(delegation["sender_id"])
        involved_accounts.add(delegation["receiver_id"])

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
        "delegated_action_count": len(delegations),
        "delegated_actions": delegations,
        "findings": findings
    }
