from app.main import evaluate_transaction
from app.executor import SimulatedExecutor


class TransactionWorkflow:

    def __init__(self, transaction_tracker, blocked_recipients=None):

        self.transaction_tracker = transaction_tracker

        self.blocked_recipients = (
            blocked_recipients if blocked_recipients is not None else []
        )

        self.executor = SimulatedExecutor(transaction_tracker)

    def process(
        self,
        transaction,
        confirmed=False,
        simulated_success=True
    ):

        # Step 1: Evaluate the transaction internally.

        security_report = evaluate_transaction(
            transaction,
            transaction_tracker=self.transaction_tracker,
            blocked_recipients=self.blocked_recipients
        )

        # Step 2: Pass the internally generated report to the executor.

        execution_result = self.executor.execute(
            transaction=transaction,
            security_report=security_report,
            confirmed=confirmed,
            simulated_success=simulated_success
        )

        # Step 3: Return both security and execution results.

        return {
            "security_report": security_report,
            "execution_result": execution_result
        }