from app.main import evaluate_transaction


class AgentSecurityGateway:
    """
    Inspection gateway for transactions proposed by AI agents.

    This component evaluates transactions but never executes,
    signs, broadcasts, or approves them.
    """

    def __init__(self, transaction_tracker, blocked_recipients=None):
        self.transaction_tracker = transaction_tracker
        self.blocked_recipients = (
            blocked_recipients
            if blocked_recipients is not None
            else []
        )

    def inspect_transaction(self, transaction):
        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        security_report = evaluate_transaction(
            transaction,
            transaction_tracker=self.transaction_tracker,
            blocked_recipients=self.blocked_recipients
        )

        register_inspection = getattr(
            self.transaction_tracker,
            "register_inspection",
            None
        )

        if not callable(register_inspection):
            raise ValueError("Inspection tracking is unavailable")

        transaction_id = transaction.get("transaction_id")

        security_report.setdefault("duplicate_inspection", False)

        if not register_inspection(transaction_id):
            security_report["risk_score"] = 100
            security_report["decision"] = "BLOCK"
            security_report["duplicate_inspection"] = True
            security_report["reasons"].append(
                "Duplicate inspection detected"
            )

        decision = security_report["decision"]

        if decision == "ALLOW":
            gateway_status = "PERMITTED"
            recommended_action = "SIMULATED_EXECUTION_ELIGIBLE"
            human_approval_required = False

        elif decision == "REQUIRE_CONFIRMATION":
            gateway_status = "APPROVAL_REQUIRED"
            recommended_action = "WAIT_FOR_HUMAN_APPROVAL"
            human_approval_required = True

        elif decision == "BLOCK":
            gateway_status = "REJECTED"
            recommended_action = "STOP_TRANSACTION"
            human_approval_required = False

        else:
            raise ValueError("Unknown security decision")

        return {
            "gateway": "AgentGuard AI Security Gateway",
            "inspection_only": True,
            "transaction_id": transaction.get("transaction_id"),
            "gateway_status": gateway_status,
            "recommended_action": recommended_action,
            "human_approval_required": human_approval_required,
            "security_report": security_report,
            "execution_performed": False,
            "transaction_signed": False,
            "transaction_broadcast": False
        }
