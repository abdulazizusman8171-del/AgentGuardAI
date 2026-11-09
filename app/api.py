import os
from typing import Any

from fastapi import FastAPI, HTTPException

from app.main import evaluate_transaction
from app.storage import SQLiteTransactionTracker


app = FastAPI(
    title="AgentGuard AI",
    description="Blockchain transaction security API",
    version="0.1.0"
)

tracker = SQLiteTransactionTracker()
BLOCKED_RECIPIENTS = [
    address.strip()
    for address in os.getenv(
        "AGENTGUARD_BLOCKED_RECIPIENTS", ""
    ).split(",")
    if address.strip()
]


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard AI",
        "version": "0.1.0"
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
