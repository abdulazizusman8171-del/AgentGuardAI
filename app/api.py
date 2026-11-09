import os
from typing import Any

from fastapi import FastAPI, HTTPException

from app.main import evaluate_transaction
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow


app = FastAPI(
    title="AgentGuard AI",
    description="Blockchain transaction security API",
    version="0.2.0"
)

tracker = SQLiteTransactionTracker()

BLOCKED_RECIPIENTS = [
    address.strip()
    for address in os.getenv(
        "AGENTGUARD_BLOCKED_RECIPIENTS", ""
    ).split(",")
    if address.strip()
]

workflow = TransactionWorkflow(
    transaction_tracker=tracker,
    blocked_recipients=BLOCKED_RECIPIENTS
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard AI",
        "version": "0.2.0"
    }


@app.post("/evaluate")
def evaluate(payload: dict[str, Any]):

    try:
        result = evaluate_transaction(
            payload,
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.post("/process")
def process_transaction(payload: dict[str, Any]):

    try:
        transaction = payload.copy()

        confirmed = transaction.pop("confirmed", False)
        simulated_success = transaction.pop(
            "simulated_success", True
        )

        if type(confirmed) is not bool:
            raise ValueError("Confirmation must be True or False")

        if type(simulated_success) is not bool:
            raise ValueError(
                "Execution result must be True or False"
            )

        result = workflow.process(
            transaction=transaction,
            confirmed=confirmed,
            simulated_success=simulated_success
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )