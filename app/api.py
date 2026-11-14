import os
import hmac
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Query, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.main import evaluate_transaction
from app.security_intelligence import generate_security_insights
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow
from app.approval import ApprovalManager
from app.near_client import NearRPCClient, NearRPCError
from app.near_transaction_analyzer import analyze_near_transaction
from app.access_key_analyzer import analyze_access_key
from app.near_market import NearMarketClient, NearMarketError
from app.auth import hash_password, verify_password, generate_session_token, hash_token, generate_approval_key, verify_approval_key
from app.auth_models import RegistrationRequest, EmailVerificationRequest, LoginRequest, ApprovalKeyRecoveryRequest
from app.email_service import send_verification_email, send_approval_key_recovery_email
from app.final_security import enforce_login_rate_limit, record_login_failure, new_csrf_token, require_csrf



# Shared NEAR market-data cache to reduce CoinGecko requests.
NEAR_MARKET_CACHE_TTL = 60
NEAR_MARKET_STALE_TTL = 900

_near_market_cache = {
    "data": None,
    "fetched_at": None
}
_near_market_cache_lock = Lock()

# Shared NEAR large-buy cache to reduce GeckoTerminal requests.
NEAR_LARGE_BUYS_CACHE_TTL = 60
NEAR_LARGE_BUYS_STALE_TTL = 900

_near_large_buys_cache = {
    "data": None,
    "fetched_at": None
}
_near_large_buys_cache_lock = Lock()


app = FastAPI(
    title="AgentGuard AI",
    description="Blockchain transaction security API",
    version="0.3.0"
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




@app.post("/auth/register")
def register_user(payload: RegistrationRequest):
    email = payload.email.strip().lower()

    if len(email) > 254 or not __import__("re").fullmatch(
        r"[^\s@]+@[^\s@]+\.[^\s@]+", email
    ):
        raise HTTPException(
            status_code=422,
            detail="A valid email address is required."
        )

    password_hash, password_salt = hash_password(payload.password)
    current_time = int(time.time())

    try:
        user_id = tracker.create_user(
            email,
            password_hash,
            password_salt,
            current_time
        )

        verification_token = generate_session_token()

        tracker.create_account_token(
            user_id,
            hash_token(verification_token),
            "EMAIL_VERIFICATION",
            current_time,
            current_time + 1800
        )

        send_verification_email(email, verification_token)

        return {
            "success": True,
            "message": (
                "Account created. Check your email "
                "to verify your account."
            )
        }

    except ValueError as error:
        raise HTTPException(
            status_code=409,
            detail=str(error)
        )

    except Exception:
        if "user_id" in locals():
            tracker.delete_unverified_user(user_id)

        raise HTTPException(
            status_code=503,
            detail="Registration email could not be delivered. Please try again."
        )


@app.post("/auth/verify-email")
def verify_email(payload: EmailVerificationRequest):
    current_time = int(time.time())

    try:
        verified = tracker.verify_email_with_token(
            hash_token(payload.token),
            current_time
        )

        if not verified:
            raise HTTPException(
                status_code=400,
                detail="Verification token is invalid, expired, or already used."
            )

        return {
            "success": True,
            "message": "Email verified successfully. You can now log in."
        }

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Email verification failed."
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


@app.get("/near/accounts/{account_id}/access-keys")
def get_near_access_keys(
    account_id: str,
    network: str = "mainnet"
):
    try:
        client = NearRPCClient(network=network)
        access_key_data = client.get_access_keys(account_id)

        risk_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for key in access_key_data["keys"]:
            assessment = analyze_access_key(key)
            key["risk_assessment"] = assessment
            risk_counts[assessment["risk_level"]] += 1

        access_key_data["risk_summary"] = {
            "assessed_keys": len(access_key_data["keys"]),
            "high_risk": risk_counts["HIGH"],
            "medium_risk": risk_counts["MEDIUM"],
            "low_risk": risk_counts["LOW"],
            "assessment_type": "heuristic"
        }

        return {
            "success": True,
            "data": access_key_data
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

@app.get("/near/network-activity")
def get_near_network_activity(network: str = "mainnet"):
    try:
        client = NearRPCClient(network=network)
        activity = client.get_network_activity()

        return {
            "success": True,
            "data": activity
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

def get_cached_near_market_data():
    with _near_market_cache_lock:
        now = time.monotonic()
        cached_data = _near_market_cache["data"]
        fetched_at = _near_market_cache["fetched_at"]

        # Return fresh data without contacting CoinGecko.
        if (
            cached_data is not None
            and fetched_at is not None
            and now - fetched_at < NEAR_MARKET_CACHE_TTL
        ):
            return cached_data

        try:
            market_data = NearMarketClient().get_market_data()

            _near_market_cache["data"] = market_data
            _near_market_cache["fetched_at"] = time.monotonic()

            return market_data

        except NearMarketError:
            # Use the last successful result during temporary provider failures.
            if (
                cached_data is not None
                and fetched_at is not None
                and time.monotonic() - fetched_at < NEAR_MARKET_STALE_TTL
            ):
                return cached_data

            raise


def get_cached_near_large_buys():
    with _near_large_buys_cache_lock:
        now = time.monotonic()
        cached_data = _near_large_buys_cache["data"]
        fetched_at = _near_large_buys_cache["fetched_at"]
        last_updated = _near_large_buys_cache.get("last_updated")

        if (
            cached_data is not None
            and fetched_at is not None
            and now - fetched_at < NEAR_LARGE_BUYS_CACHE_TTL
        ):
            return {
                "data": cached_data,
                "last_updated": last_updated,
                "is_stale": False
            }

        try:
            buys = NearMarketClient().get_large_buys()
            updated_at = datetime.now(timezone.utc).isoformat()

            _near_large_buys_cache["data"] = buys
            _near_large_buys_cache["fetched_at"] = time.monotonic()
            _near_large_buys_cache["last_updated"] = updated_at

            return {
                "data": buys,
                "last_updated": updated_at,
                "is_stale": False
            }

        except NearMarketError:
            if (
                cached_data is not None
                and fetched_at is not None
                and time.monotonic() - fetched_at < NEAR_LARGE_BUYS_STALE_TTL
            ):
                return {
                    "data": cached_data,
                    "last_updated": last_updated,
                    "is_stale": True
                }

            raise

@app.get("/near/market")
def get_near_market():
    try:
        market_data = get_cached_near_market_data()

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

@app.get("/near/transactions/{tx_hash}/analysis")
def analyze_near_transaction_route(
    tx_hash: str,
    sender_account_id: str,
    network: str = "mainnet"
):
    """Retrieve and analyze finalized NEAR transaction and receipt data."""

    try:
        client = NearRPCClient(network=network)

        transaction_data = client.get_transaction(
            tx_hash,
            sender_account_id
        )

        analysis = analyze_near_transaction(transaction_data)

        return {
            "success": True,
            "data": analysis
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

        tracker.record_transaction_assessment(
            payload,
            security_report,
            execution_status="NOT_EXECUTED"
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
        transactions = tracker.get_assessment_history(
            limit=limit
        )

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
def list_approvals(request: Request, status: str | None = None, limit: int = Query(default=50, ge=1, le=200)):
    user = get_authenticated_user(request)
    require_personal_approval_key(request, user)
    try:
        approvals = tracker.get_approvals(status=status, limit=limit, owner_user_id=user["id"])
        return {"success": True, "approvals": approvals}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/approvals")
def create_approval(payload: dict[str, Any], request: Request):
    security_report = evaluate_transaction(payload, transaction_tracker=tracker, blocked_recipients=BLOCKED_RECIPIENTS)
    if security_report["decision"] != "REQUIRE_CONFIRMATION":
        tracker.record_transaction_assessment(payload, security_report, execution_status="NOT_EXECUTED")
        return {"approval_required": False, "security_report": security_report, "message": "This transaction does not require approval."}
    user = get_authenticated_user(request)
    require_csrf(request)
    approval = approval_manager.create_approval(payload, owner_user_id=user["id"])
    tracker.record_transaction_assessment(payload, security_report, execution_status="AWAITING_CONFIRMATION")
    return {"approval_required": True, "security_report": security_report, "approval": approval}


@app.post("/approvals/{approval_id}/approve")
def approve_transaction(approval_id: str, payload: dict[str, Any], request: Request):
    user = get_authenticated_user(request)
    require_csrf(request)
    require_personal_approval_key(request, user)
    try:
        return approval_manager.approve_transaction(approval_id, payload, owner_user_id=user["id"])
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/process")
def process_transaction(payload: dict[str, Any], request: Request):

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
            user = get_authenticated_user(request)
            require_csrf(request)
            require_personal_approval_key(request, user)
            if not approval_id:
                tracker.record_transaction_assessment(transaction, security_report, execution_status="APPROVAL_REQUIRED")
                raise HTTPException(status_code=403, detail="An approval ID is required for confirmation-required transactions.")
            else:
                approval_result = approval_manager.consume_approval(
                    approval_id,
                    transaction,
                    owner_user_id=user["id"]
                )

                if not approval_result["consumed"]:
                    execution_result = {
                        "status": "APPROVAL_REJECTED",
                        "message": approval_result["message"]
                    }

                    tracker.record_transaction_assessment(
                        transaction,
                        security_report,
                        execution_status="APPROVAL_REJECTED"
                    )

                    return {
                        "security_report": security_report,
                        "execution_result": execution_result
                    }

                confirmed = True

                execution_result = workflow.executor.execute(
                    transaction=transaction,
                    security_report=security_report,
                    confirmed=confirmed,
                    simulated_success=simulated_success
                )

        else:

            if approval_id is not None:
                raise ValueError(
                    "An approval ID was supplied for a transaction "
                    "that does not require confirmation."
                )

            execution_result = workflow.executor.execute(
                transaction=transaction,
                security_report=security_report,
                confirmed=False,
                simulated_success=simulated_success
            )

        tracker.record_transaction_assessment(
            transaction,
            security_report,
            execution_status=execution_result["status"]
        )

        return {
            "security_report": security_report,
            "execution_result": execution_result
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/near/large-buys")
def get_near_large_buys():
    try:
        result = get_cached_near_large_buys()

        return {
            "success": True,
            "data": result["data"],
            "last_updated": result["last_updated"],
            "is_stale": result["is_stale"],
            "source": "GeckoTerminal",
            "scope": "Ref Finance USDC/wNEAR pool"
        }

    except NearMarketError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )



def require_personal_approval_key(request: Request, user: dict):
    supplied = request.headers.get("X-Approval-Key", "")
    if not verify_approval_key(supplied, user.get("approval_key_hash")):
        raise HTTPException(status_code=401, detail="A valid personal Approval Key is required.")


# ==========================================
# USER LOGIN AND SESSION AUTHENTICATION
# ==========================================

SESSION_DURATION_SECONDS = 12 * 60 * 60
SESSION_COOKIE_NAME = "agentguard_session"


def get_authenticated_user(request: Request):
    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        session = tracker.get_valid_user_session(
            hash_token(session_token),
            int(time.time())
        )
    except (ValueError, TypeError):
        session = None

    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")

    user = tracker.get_user_by_id(session["user_id"])

    if not user or not user["email_verified"]:
        raise HTTPException(status_code=401, detail="Authentication required.")

    return user


@app.post("/auth/login")
def login_user(payload: LoginRequest, response: Response, request: Request):
    enforce_login_rate_limit(request, payload.email)
    user = tracker.get_user_by_email(payload.email.strip().lower())

    if not user or not verify_password(
        payload.password,
        user["password_hash"],
        user["password_salt"]
    ):
        record_login_failure(request, payload.email)
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user["email_verified"]:
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in."
        )

    current_time = int(time.time())
    session_token = generate_session_token()

    tracker.create_user_session(
        user["id"],
        hash_token(session_token),
        current_time,
        current_time + SESSION_DURATION_SECONDS
    )

    secure_cookie = os.getenv("AGENTGUARD_COOKIE_SECURE", "true").lower() == "true"

    csrf_token = new_csrf_token()
    response.set_cookie(
        key="agentguard_csrf", value=csrf_token, max_age=SESSION_DURATION_SECONDS,
        httponly=False, secure=secure_cookie, samesite="lax", path="/"
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=SESSION_DURATION_SECONDS,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/"
    )

    return {
        "success": True,
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "email_verified": bool(user["email_verified"])
        }
    }


@app.post("/auth/logout")
def logout_user(request: Request, response: Response):
    require_csrf(request)
    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    if session_token:
        tracker.revoke_user_session(
            hash_token(session_token),
            int(time.time())
        )

    response.delete_cookie(key="agentguard_csrf", path="/", secure=os.getenv("AGENTGUARD_COOKIE_SECURE", "true").lower() == "true", samesite="lax")
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=os.getenv("AGENTGUARD_COOKIE_SECURE", "true").lower() == "true",
        samesite="lax"
    )

    return {
        "success": True,
        "message": "Logged out successfully."
    }



@app.post("/auth/approval-key")
def create_personal_approval_key(request: Request):
    user = get_authenticated_user(request)
    require_csrf(request)
    if user.get("approval_key_hash"):
        raise HTTPException(status_code=409, detail="An Approval Key already exists. Use email recovery to replace it.")
    raw_key = generate_approval_key()
    if not tracker.set_user_approval_key(user["id"], hash_token(raw_key), int(time.time())):
        raise HTTPException(status_code=400, detail="Could not create Approval Key.")
    return {"success": True, "approval_key": raw_key, "warning": "Copy this key now. It cannot be displayed again."}


@app.post("/auth/approval-key/recovery")
def request_approval_key_recovery(payload: ApprovalKeyRecoveryRequest):
    email = payload.email.strip().lower()
    user = tracker.get_user_by_email(email)
    # Always return the same response to prevent account enumeration.
    if user and user.get("email_verified"):
        now = int(time.time())
        token = generate_session_token()
        tracker.create_account_token(user["id"], hash_token(token), "APPROVAL_KEY_RECOVERY", now, now + 1800)
        try:
            send_approval_key_recovery_email(email, token)
        except Exception:
            # Do not reveal whether an account exists or mail delivery failed.
            pass
    return {"success": True, "message": "If a verified account exists, recovery instructions have been sent."}


@app.post("/auth/approval-key/recover")
def recover_approval_key(payload: EmailVerificationRequest):
    token_hash = hash_token(payload.token)
    now = int(time.time())
    token_record = tracker.get_valid_account_token(token_hash, "APPROVAL_KEY_RECOVERY", now)
    if not token_record or not tracker.consume_account_token(token_hash, "APPROVAL_KEY_RECOVERY", now):
        raise HTTPException(status_code=400, detail="Recovery token is invalid, expired, or already used.")
    raw_key = generate_approval_key()
    if not tracker.set_user_approval_key(token_record["user_id"], hash_token(raw_key), now):
        raise HTTPException(status_code=400, detail="Could not replace Approval Key.")
    tracker.revoke_all_user_sessions(token_record["user_id"], now)
    return {"success": True, "approval_key": raw_key, "warning": "Your previous key is invalid. Copy this replacement now and log in again."}


@app.get("/auth/me")
def current_user(request: Request):
    user = get_authenticated_user(request)

    return {
        "id": user["id"],
        "email": user["email"],
        "email_verified": bool(user["email_verified"])
    }

