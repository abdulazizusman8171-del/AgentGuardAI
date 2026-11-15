import os
from app.wallet_behavior_analyzer import analyze_wallet_behavior
import logging
import hmac
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Query, Response
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

logger = logging.getLogger(__name__)

from app.main import evaluate_transaction
from app.security_intelligence import generate_security_insights
from app.storage import SQLiteTransactionTracker
from app.workflow import TransactionWorkflow
from app.agent_gateway import AgentSecurityGateway
from app.approval import ApprovalManager
from app.near_client import NearRPCClient, NearRPCError
from app.near_transaction_analyzer import analyze_near_transaction
from app.access_key_analyzer import analyze_access_key
from app.near_market import NearMarketClient, NearMarketError
from app.auth import hash_password, verify_password, generate_session_token, hash_token, generate_approval_key, verify_approval_key
from app.auth_models import RegistrationRequest, EmailVerificationRequest, LoginRequest, ApprovalKeyRecoveryRequest
from app.email_service import send_verification_email, send_approval_key_recovery_email, send_password_reset_email
from app.final_security import (
    enforce_login_rate_limit,
    record_login_failure,
    new_csrf_token,
    require_csrf,
    enforce_gateway_rate_limit,
)



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




class GatewayRequestSizeLimitMiddleware:
    """Reject oversized request bodies sent to the inspection gateway."""

    MAX_BODY_BYTES = 64 * 1024

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("path") != "/agent/inspect"
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")

        if content_length:
            try:
                if int(content_length) > self.MAX_BODY_BYTES:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Gateway request body is too large."}
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."}
                )
                await response(scope, receive, send)
                return

        received_bytes = 0

        async def limited_receive():
            nonlocal received_bytes

            message = await receive()

            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))

                if received_bytes > self.MAX_BODY_BYTES:
                    raise RequestBodyTooLarge()

            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            response = JSONResponse(
                status_code=413,
                content={"detail": "Gateway request body is too large."}
            )
            await response(scope, receive, send)


class RequestBodyTooLarge(Exception):
    pass


app = FastAPI(
    title="AgentGuard AI",
    description="Blockchain transaction security API",
    version="0.3.0"
)

app.add_middleware(GatewayRequestSizeLimitMiddleware)

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

        dev_mode = os.getenv("AGENTGUARD_DEV_MODE", "false").lower() == "true"
        public_url = os.getenv("AGENTGUARD_PUBLIC_URL", "").lower()
        local_url = public_url.startswith(("http://127.0.0.1", "http://localhost"))

        if dev_mode and local_url and not os.getenv("RENDER"):
            print(
                "\n[AGENTGUARD LOCAL DEVELOPMENT] "
                "Email verification token:\n"
                f"{verification_token}\n",
                flush=True
            )
        else:
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

@app.post("/agent/inspect")
def inspect_agent_transaction(
    payload: dict[str, Any],
    request: Request
):
    """
    Inspect an AI-agent-proposed transaction without executing it.
    Requires a valid developer API key.
    """

    raw_key = request.headers.get("X-API-Key", "")

    if not isinstance(raw_key, str) or not raw_key.startswith("ag_live_"):
        raise HTTPException(
            status_code=401,
            detail="A valid AgentGuard API key is required."
        )

    try:
        supplied_hash = hash_token(raw_key)
        key_record = tracker.get_developer_api_key(supplied_hash)
    except (ValueError, TypeError):
        key_record = None

    if (
        not key_record
        or not hmac.compare_digest(key_record["key_hash"], supplied_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked AgentGuard API key."
        )

    def record_event_safely(**event):
        try:
            tracker.record_developer_api_event(**event)
        except Exception:
            # Analytics must never interrupt security inspection.
            logger.exception("Unable to record developer analytics event")

    try:
        enforce_gateway_rate_limit(request, key_record["id"])
    except HTTPException as error:
        if error.status_code == 429:
            record_event_safely(
                user_id=key_record["user_id"],
                api_key_id=key_record["id"],
                event_type="RATE_LIMIT",
                http_status=429,
                created_at=int(time.time())
            )
        raise

    if not tracker.update_developer_api_key_usage(
        key_record["id"], int(time.time())
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked AgentGuard API key."
        )

    try:
        gateway = AgentSecurityGateway(
            transaction_tracker=tracker,
            blocked_recipients=BLOCKED_RECIPIENTS
        )

        result = gateway.inspect_transaction(payload)
        security_report = result.get("security_report") or {}

        risk_score = security_report.get("risk_score")
        if type(risk_score) is not int or not 0 <= risk_score <= 100:
            risk_score = None

        record_event_safely(
            user_id=key_record["user_id"],
            api_key_id=key_record["id"],
            event_type="INSPECTION",
            gateway_status=result["gateway_status"],
            risk_score=risk_score,
            duplicate_inspection=(
                security_report.get("duplicate_inspection") is True
            ),
            http_status=200,
            created_at=int(time.time())
        )

        return result

    except ValueError as error:
        record_event_safely(
            user_id=key_record["user_id"],
            api_key_id=key_record["id"],
            event_type="INSPECTION",
            http_status=400,
            created_at=int(time.time())
        )

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


@app.post("/auth/password-reset/request")
def request_password_reset(payload: dict):
    email = payload.get("email", "")
    if not isinstance(email, str):
        email = ""
    email = email.strip().lower()

    user = tracker.get_user_by_email(email) if email else None

    # Same response for existing and unknown accounts.
    if user and user.get("email_verified"):
        now = int(time.time())
        token = generate_session_token()

        tracker.create_account_token(
            user["id"],
            hash_token(token),
            "PASSWORD_RESET",
            now,
            now + 1800
        )

        try:
            send_password_reset_email(email, token)
        except Exception:
            pass

    return {
        "success": True,
        "message": "If a verified account exists, password reset instructions have been sent."
    }


@app.post("/auth/password-reset/complete")
def complete_password_reset(payload: dict):
    token = payload.get("token")
    password = payload.get("password")

    if not isinstance(token, str) or not 20 <= len(token) <= 200:
        raise HTTPException(
            status_code=400,
            detail="Reset token is invalid or expired."
        )

    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise HTTPException(
            status_code=400,
            detail="Password must contain between 12 and 128 characters."
        )

    token_hash = hash_token(token)
    now = int(time.time())

    token_record = tracker.get_valid_account_token(
        token_hash,
        "PASSWORD_RESET",
        now
    )

    if not token_record:
        raise HTTPException(
            status_code=400,
            detail="Reset token is invalid, expired, or already used."
        )

    password_hash, password_salt = hash_password(password)

    if not tracker.consume_account_token(
        token_hash,
        "PASSWORD_RESET",
        now
    ):
        raise HTTPException(
            status_code=400,
            detail="Reset token is invalid, expired, or already used."
        )

    updated = tracker.update_user_password(
        token_record["user_id"],
        password_hash,
        password_salt,
        now
    )

    if not updated:
        raise HTTPException(
            status_code=500,
            detail="Could not update password. Request a new reset link."
        )

    tracker.revoke_all_user_sessions(token_record["user_id"], now)

    return {
        "success": True,
        "message": "Password updated successfully. Please log in again."
    }

@app.get("/auth/me")
def current_user(request: Request):
    user = get_authenticated_user(request)

    return {
        "id": user["id"],
        "email": user["email"],
        "email_verified": bool(user["email_verified"])
    }


# ==========================================
# DEVELOPER API KEY MANAGEMENT
# ==========================================

@app.post("/developer/api-keys")
def create_developer_api_key(payload: dict[str, Any], request: Request):
    user = get_authenticated_user(request)
    require_csrf(request)

    name = payload.get("name")

    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        raise HTTPException(
            status_code=422,
            detail="API key name must contain 1 to 80 characters."
        )

    raw_key = "ag_live_" + generate_session_token()
    key_hash = hash_token(raw_key)
    key_prefix = raw_key[:16]

    try:
        key_id = tracker.create_developer_api_key(
            user["id"],
            name.strip(),
            key_hash,
            key_prefix,
            int(time.time())
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    return {
        "success": True,
        "id": key_id,
        "name": name.strip(),
        "api_key": raw_key,
        "key_prefix": key_prefix,
        "warning": "Copy this API key now. It cannot be displayed again."
    }


@app.get("/developer/api-keys")
def list_developer_api_keys(request: Request):
    user = get_authenticated_user(request)

    return {
        "success": True,
        "api_keys": tracker.list_developer_api_keys(user["id"])
    }


@app.get("/developer/analytics")
def developer_api_analytics(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    api_key_id: int | None = Query(default=None, ge=1)
):
    user = get_authenticated_user(request)

    analytics = tracker.get_developer_api_analytics(
        user_id=user["id"],
        limit=limit,
        api_key_id=api_key_id
    )

    return {
        "success": True,
        "analytics": analytics
    }


@app.delete("/developer/api-keys/{key_id}")
def revoke_developer_api_key(key_id: int, request: Request):
    user = get_authenticated_user(request)
    require_csrf(request)

    revoked = tracker.revoke_developer_api_key(
        user["id"],
        key_id,
        int(time.time())
    )

    if not revoked:
        raise HTTPException(
            status_code=404,
            detail="API key not found or already revoked."
        )

    return {
        "success": True,
        "message": "API key revoked successfully."
    }




# NEAR WALLET BEHAVIOUR INTELLIGENCE
@app.post("/near/accounts/{account_id}/behavior")
def inspect_wallet_behavior(
    request: Request,
    account_id: str,
    payload: dict[str, Any],
    network: str = "mainnet"
):
    """Analyse supplied finalized NEAR transactions without executing them."""

    user = get_authenticated_user(request)

    if not isinstance(network, str) or network not in ("mainnet", "testnet"):
        raise HTTPException(
            status_code=400,
            detail="Network must be mainnet or testnet"
        )

    transactions = payload.get("transactions")

    if not isinstance(transactions, list):
        raise HTTPException(
            status_code=400,
            detail="transactions must be a list"
        )

    if not 1 <= len(transactions) <= 20:
        raise HTTPException(
            status_code=400,
            detail="Supply between 1 and 20 transactions"
        )

    try:
        client = NearRPCClient(network=network)

        # Validate the wallet being investigated.
        normalized_account_id = client.validate_account_id(account_id)

        analyses = []
        seen_hashes = set()

        for item in transactions:
            if not isinstance(item, dict):
                raise ValueError("Each transaction must be an object")

            tx_hash = item.get("transaction_hash")
            sender_account_id = item.get("sender_account_id")

            if not isinstance(tx_hash, str) or not tx_hash.strip():
                raise ValueError(
                    "Every transaction needs a transaction_hash"
                )

            if not isinstance(sender_account_id, str) or not sender_account_id.strip():
                raise ValueError(
                    "Every transaction needs a sender_account_id"
                )

            # Validate both fields before making the RPC request.
            tx_hash = client.validate_transaction_hash(tx_hash.strip())
            sender_account_id = client.validate_account_id(
                sender_account_id.strip()
            )

            if tx_hash in seen_hashes:
                raise ValueError(
                    "Duplicate transaction hashes are not allowed"
                )

            seen_hashes.add(tx_hash)

            transaction_data = client.get_transaction(
                tx_hash,
                sender_account_id
            )

            analysis = analyze_near_transaction(transaction_data)

            if analysis.get("network") != network:
                raise ValueError(
                    "Transaction network does not match request"
                )

            analyses.append(analysis)

        result = analyze_wallet_behavior(
            normalized_account_id,
            analyses
        )

        result["network"] = network
        result["inspection_only"] = True
        result["execution_performed"] = False
        result["transaction_signed"] = False
        result["transaction_broadcast"] = False

        history_id = tracker.save_wallet_behavior_report(
            normalized_account_id,
            network,
            result,
            owner_user_id=user["id"]
        )
        result["history_id"] = history_id

        return result

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except NearRPCError as exc:
        raise HTTPException(status_code=502, detail=str(exc))



# NEAR WALLET BEHAVIOUR HISTORY
@app.get("/near/accounts/{account_id}/behavior/history")
def get_wallet_behavior_history(
    request: Request,
    account_id: str,
    network: str = "mainnet",
    limit: int = Query(default=20, ge=1, le=100)
):
    user = get_authenticated_user(request)

    try:
        client = NearRPCClient(network=network)
        normalized_account_id = client.validate_account_id(account_id)

        history = tracker.get_wallet_behavior_history(
            normalized_account_id,
            network,
            limit,
            owner_user_id=user["id"]
        )

        return {
            "success": True,
            "account_id": normalized_account_id,
            "network": network,
            "count": len(history),
            "history": history
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/near/behavior/report/{report_id}")
def get_wallet_behavior_history_report(report_id: int, request: Request):
    user = get_authenticated_user(request)
    try:
        report = tracker.get_wallet_behavior_report(
            report_id,
            owner_user_id=user["id"]
        )
        if report is None:
            raise HTTPException(
                status_code=404,
                detail="Investigation report not found"
            )

        return {"success": True, "record": report}

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/near/behavior/history/compare")
def compare_wallet_behavior_reports(
    request: Request,
    first_id: int = Query(..., ge=1),
    second_id: int = Query(..., ge=1)
):
    user = get_authenticated_user(request)
    if first_id == second_id:
        raise HTTPException(
            status_code=400,
            detail="Choose two different investigation reports"
        )

    first = tracker.get_wallet_behavior_report(
        first_id,
        owner_user_id=user["id"]
    )
    second = tracker.get_wallet_behavior_report(
        second_id,
        owner_user_id=user["id"]
    )

    if first is None or second is None:
        raise HTTPException(
            status_code=404,
            detail="One or both investigation reports were not found"
        )

    if (
        first["account_id"] != second["account_id"]
        or first["network"] != second["network"]
    ):
        raise HTTPException(
            status_code=400,
            detail="Reports must belong to the same wallet and network"
        )

    return {
        "success": True,
        "comparison_scope": "TWO_SAVED_SAMPLE_BASED_INVESTIGATIONS",
        "account_id": first["account_id"],
        "network": first["network"],
        "older": {
            "id": first["id"],
            "created_at": first["created_at"],
            "risk_score": first["risk_score"],
            "risk_level": first["risk_level"],
            "threat_verdict": first["report"].get("threat_verdict", "NOT_DETERMINED"),
            "transaction_count": first["transaction_count"]
        },
        "newer": {
            "id": second["id"],
            "created_at": second["created_at"],
            "risk_score": second["risk_score"],
            "risk_level": second["risk_level"],
            "threat_verdict": second["report"].get("threat_verdict", "NOT_DETERMINED"),
            "transaction_count": second["transaction_count"]
        },
        "changes": {
            "risk_score": second["risk_score"] - first["risk_score"],
            "transaction_count": (
                second["transaction_count"] - first["transaction_count"]
            ),
            "risk_level_changed": (
                first["risk_level"] != second["risk_level"]
            ),
            "threat_verdict_changed": (
                first["report"].get("threat_verdict", "NOT_DETERMINED") !=
                second["report"].get("threat_verdict", "NOT_DETERMINED")
            )
        },
        "notice": (
            "This compares two supplied transaction samples. "
            "It does not establish continuous wallet monitoring."
        )
    }


