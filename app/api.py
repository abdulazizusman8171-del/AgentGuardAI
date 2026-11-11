import os
import hmac
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.main import evaluate_transaction
from app.security_intelligence import generate_security_insights
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow
from app.approval import ApprovalManager
from app.near_client import NearRPCClient, NearRPCError
from app.near_market import NearMarketClient, NearMarketError


app = FastAPI(
    title="AgentGuard AI",
    description="Blockchain transaction security API",
    version="0.3.0"
)

APPROVAL_API_KEY = os.getenv("AGENTGUARD_APPROVAL_API_KEY")


def require_approval_key(request: Request):
    if not APPROVAL_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Approval authorization is not configured."
        )

    supplied_key = request.headers.get("X-Approval-Key", "")

    if not hmac.compare_digest(supplied_key, APPROVAL_API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: valid approval key required."
        )

tracker = SQLiteTransactionTracker()

approval_manager = ApprovalManager(
    storage=tracker,
    approval_lifetime=300
)

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
BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)

templates = Jinja2Templates(
    directory=BASE_DIR / "templates"
)


@app.get("/", include_in_schema=False)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AgentGuard AI",
        "version": "0.3.0"
    }
@app.get("/near/accounts/{account_id}")
def get_near_account(
    account_id: str,
    network: str = "mainnet"
):
    try:
        client = NearRPCClient(network=network)

        account_data = client.get_account(account_id)

        return {
            "success": True,
            "data": account_data
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except NearRPCError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )
@app.get("/near/market")
def get_near_market():
    try:
        client = NearMarketClient()
        market_data = client.get_market_data()

        return {
            "success": True,
            "data": market_data
        }

    except NearMarketError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )

@app.get("/near/transactions/{tx_hash}")
def get_near_transaction(
    tx_hash: str,
    sender_account_id: str,
    network: str = "mainnet"
):
    try:
        client = NearRPCClient(network=network)

        transaction_data = client.get_transaction(
            tx_hash,
            sender_account_id
        )

        return {
            "success": True,
            "data": transaction_data
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except NearRPCError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )

@app.post("/evaluate")
def evaluate(payload: dict[str, Any]):

    try:
        return evaluate_transaction(
            payload,
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

@app.post("/intelligence")
def security_intelligence(payload: dict[str, Any]):

    try:
        security_report = evaluate_transaction(
            payload,
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

        intelligence = generate_security_insights(
            security_report
        )

        return {
            "success": True,
            "security_report": security_report,
            "intelligence": intelligence
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

@app.get("/transactions/history")
def transaction_history(
    limit: int = Query(default=50, ge=1, le=200)
):
    try:
        transactions = tracker.get_transaction_history(limit=limit)

        return {
            "success": True,
            "transactions": transactions
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/approvals")
def list_approvals(
    request: Request,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200)
):
    require_approval_key(request)

    try:
        approvals = tracker.get_approvals(
            status=status,
            limit=limit
        )

        return {
            "success": True,
            "approvals": approvals
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
@app.post("/approvals")
def create_approval(payload: dict[str, Any]):

    try:
        security_report = evaluate_transaction(
            payload,
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

        if security_report["decision"] != "REQUIRE_CONFIRMATION":
            return {
                "approval_required": False,
                "security_report": security_report,
                "message": "This transaction does not require approval."
            }

        approval = approval_manager.create_approval(payload)

        return {
            "approval_required": True,
            "security_report": security_report,
            "approval": approval
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.post("/approvals/{approval_id}/approve")
def approve_transaction(
    approval_id: str,
    payload: dict[str, Any],
    request: Request
):
    require_approval_key(request)

    try:
        return approval_manager.approve_transaction(
            approval_id,
            payload
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.post("/process")
def process_transaction(payload: dict[str, Any]):

    try:
        transaction = payload.copy()

        if "confirmed" in transaction:
            raise ValueError(
                "Client-supplied confirmation is not accepted. "
                "Use an approval ID instead."
            )

        approval_id = transaction.pop("approval_id", None)

        simulated_success = transaction.pop(
            "simulated_success", True
        )

        if type(simulated_success) is not bool:
            raise ValueError(
                "Execution result must be True or False"
            )

        security_report = evaluate_transaction(
            transaction,
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

        confirmed = False

        if security_report["decision"] == "REQUIRE_CONFIRMATION":

            if not approval_id:
                return workflow.process(
                    transaction=transaction,
                    confirmed=False,
                    simulated_success=simulated_success
                )

            approval_result = approval_manager.consume_approval(
                approval_id,
                transaction
            )

            if not approval_result["consumed"]:
                return {
                    "security_report": security_report,
                    "execution_result": {
                        "status": "APPROVAL_REJECTED",
                        "message": approval_result["message"]
                    }
                }

            confirmed = True

        elif approval_id is not None:
            raise ValueError(
                "An approval ID was supplied for a transaction "
                "that does not require confirmation."
            )

        return workflow.process(
            transaction=transaction,
            confirmed=confirmed,
            simulated_success=simulated_success
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )




@app.get("/near/large-buys")
def get_near_large_buys():
    try:
        client = NearMarketClient()
        buys = client.get_large_buys()

        return {
            "success": True,
            "data": buys,
            "source": "GeckoTerminal",
            "scope": "Ref Finance USDC/wNEAR pool"
        }

    except NearMarketError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )
