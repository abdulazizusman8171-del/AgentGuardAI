from app.main import evaluate_transaction


class SimulatedExecutor:

    def __init__(self, transaction_tracker, blocked_recipients=None):
        self.transaction_tracker = transaction_tracker
        self.blocked_recipients = (
            blocked_recipients if blocked_recipients is not None else []
        )

    def execute(
        self,
        transaction,
        security_report,
        confirmed=False,
        simulated_success=True
    ):

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        if not isinstance(security_report, dict):
            raise ValueError("Security report must be a dictionary")

        if type(confirmed) is not bool:
            raise ValueError("Confirmation must be True or False")

        if type(simulated_success) is not bool:
            raise ValueError("Execution result must be True or False")

        transaction_id = transaction.get("transaction_id")

        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("Valid transaction ID is required")

        # Independently regenerate the trusted security decision.
        trusted_report = evaluate_transaction(
            transaction,
            transaction_tracker=self.transaction_tracker,
            blocked_recipients=self.blocked_recipients
        )

        # A concurrent request may have processed this transaction
        # after the original report was generated. Always block it.
        if trusted_report.get("duplicate_transaction") is True:
            return {
                "status": "BLOCKED",
                "message": "Duplicate transaction detected."
            }

        # Reject forged, modified, or stale security reports.
        if security_report != trusted_report:
            raise ValueError("Security report verification failed")

        decision = trusted_report["decision"]

        if decision == "BLOCK":
            return {
                "status": "BLOCKED",
                "message": "Security engine blocked this transaction."
            }

        if decision == "REQUIRE_CONFIRMATION" and not confirmed:
            return {
                "status": "AWAITING_CONFIRMATION",
                "message": "User confirmation is required."
            }

        if decision not in ["ALLOW", "REQUIRE_CONFIRMATION"]:
            raise ValueError("Invalid security decision")

        # Failed simulations must not claim the transaction.
        if not simulated_success:
            return {
                "status": "FAILED",
                "message": "Simulated execution failed."
            }

        # Atomically claim the transaction.
        claim_processed = getattr(
            self.transaction_tracker,
            "claim_processed",
            None
        )

        if not callable(claim_processed):
            raise ValueError(
                "Atomic transaction protection is unavailable"
            )

        if not claim_processed(transaction_id):
            return {
                "status": "BLOCKED",
                "message": "Duplicate transaction detected."
            }

        return {
            "status": "EXECUTED",
            "message": "Simulated transaction executed successfully.",
            "transaction_id": transaction_id
        }
