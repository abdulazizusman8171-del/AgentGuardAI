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
