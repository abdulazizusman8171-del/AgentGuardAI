class SimulatedExecutor:

    def __init__(self, transaction_tracker):
        self.transaction_tracker = transaction_tracker

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

        decision = security_report.get("decision")

        # Security rule 1: Never execute blocked transactions.

        if decision == "BLOCK":
            return {
                "status": "BLOCKED",
                "message": "Security engine blocked this transaction."
            }

        # Security rule 2: Wait for confirmation.

        if decision == "REQUIRE_CONFIRMATION" and not confirmed:
            return {
                "status": "AWAITING_CONFIRMATION",
                "message": "User confirmation is required."
            }

        # Reject unknown security decisions.

        if decision not in ["ALLOW", "REQUIRE_CONFIRMATION"]:
            raise ValueError("Invalid security decision")

        # Check for previously processed transactions.

        if self.transaction_tracker.is_duplicate(transaction_id):
            return {
                "status": "BLOCKED",
                "message": "Duplicate transaction detected."
            }

        # Simulate blockchain execution.

        if not simulated_success:
            return {
                "status": "FAILED",
                "message": "Simulated execution failed."
            }

        # Record only successful simulated executions.

        self.transaction_tracker.mark_processed(transaction_id)

        return {
            "status": "EXECUTED",
            "message": "Simulated transaction executed successfully.",
            "transaction_id": transaction_id
        }