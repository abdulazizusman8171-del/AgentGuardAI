"""Security helpers for AgentGuard AI authenticated Approval Center."""
import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from fastapi import HTTPException, Request

_RATE_LOCK = Lock()
_LOGIN_ATTEMPTS = defaultdict(deque)
_LOGIN_WINDOW_SECONDS = 900
_LOGIN_MAX_ATTEMPTS = 5


def enforce_login_rate_limit(request: Request, email: str) -> None:
    now = time.time()
    host = request.client.host if request.client else "unknown"
    key = (host, (email or "").strip().lower())
    with _RATE_LOCK:
        attempts = _LOGIN_ATTEMPTS[key]
        while attempts and now - attempts[0] > _LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again in 15 minutes.")


def record_login_failure(request: Request, email: str) -> None:
    now = time.time()
    host = request.client.host if request.client else "unknown"
    key = (host, (email or "").strip().lower())
    with _RATE_LOCK:
        attempts = _LOGIN_ATTEMPTS[key]
        while attempts and now - attempts[0] > _LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        attempts.append(now)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def require_csrf(request: Request) -> None:
    cookie = request.cookies.get("agentguard_csrf", "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF validation failed. Refresh the page and try again.")
    origin = request.headers.get("origin")
    public_url = __import__("os").getenv("AGENTGUARD_PUBLIC_URL")
    if origin and public_url:
        expected = public_url.rstrip("/")
        if origin.rstrip("/") != expected:
            raise HTTPException(status_code=403, detail="Request origin is not allowed.")


# AgentGuard developer gateway rate limits.
_GATEWAY_ATTEMPTS = defaultdict(deque)
_GATEWAY_WINDOW_SECONDS = 60
_GATEWAY_IP_MAX_REQUESTS = 120
_GATEWAY_KEY_MAX_REQUESTS = 60


def enforce_gateway_rate_limit(request: Request, key_id: int) -> None:
    """
    Apply independent per-IP and per-developer-key sliding-window limits.

    This in-memory limiter is process-local. Production deployments with
    multiple workers should use a shared rate-limit store.
    """
    now = time.time()
    host = request.client.host if request.client else "unknown"

    keys = [
        ("gateway_ip", host),
        ("gateway_api_key", key_id),
    ]

    limits = [
        _GATEWAY_IP_MAX_REQUESTS,
        _GATEWAY_KEY_MAX_REQUESTS,
    ]

    with _RATE_LOCK:
        for key, maximum in zip(keys, limits):
            attempts = _GATEWAY_ATTEMPTS[key]

            while (
                attempts
                and now - attempts[0] >= _GATEWAY_WINDOW_SECONDS
            ):
                attempts.popleft()

            if len(attempts) >= maximum:
                raise HTTPException(
                    status_code=429,
                    detail="Gateway rate limit exceeded. Try again shortly."
                )

        for key in keys:
            _GATEWAY_ATTEMPTS[key].append(now)
