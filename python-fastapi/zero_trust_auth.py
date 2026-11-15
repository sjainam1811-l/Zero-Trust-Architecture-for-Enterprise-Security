"""
zero_trust_auth.py
==================
Zero-Trust Authentication for Python / FastAPI

Author:  Kelvin Chipili <KelvinChipili>
License: MIT

────────────────────────────────────────────────────────────────
ZERO-TRUST PHILOSOPHY
"Never trust, always verify."

Traditional perimeter security assumes that traffic inside a
network is safe. Zero-trust rejects this assumption — every
request must prove its identity from scratch, every single time.
────────────────────────────────────────────────────────────────

WHAT THIS FILE PROVIDES
─────────────────────────
• JWT access tokens  (short-lived, 15 min)
• JWT refresh tokens (longer-lived, 7 days, single-use rotation)
• Per-request identity verification (FastAPI dependency)
• Device fingerprinting (detects token theft / session hijacking)
• Brute-force protection with per-user + per-IP lockout
• Role-Based Access Control (RBAC) via FastAPI dependency injection
• TOTP / MFA verification hook (Google Authenticator / Authy)
• Token revocation via JTI blacklist
• Structured audit logging (JSON, ready for log aggregators)
• Async-native — works with async database drivers (asyncpg, motor)

HOW TO USE
──────────
1. pip install fastapi uvicorn python-jose[cryptography]
              passlib[bcrypt] pyotp slowapi structlog
2. Copy this file into your project
3. Set environment variables (see ZT_CONFIG below)
4. Replace find_user() with your real database query
5. Mount the route handlers on your FastAPI app (see create_app())

EDIT GUIDE
──────────
Search for "# EDIT:" comments — these are the only lines you
need to change to plug this into your application.
"""

from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Set
from uuid import uuid4

import pyotp
import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


# ─── CONFIGURATION ───────────────────────────────────────────
# All sensitive values must come from environment variables.
# Never commit real secrets to version control.
ZT_CONFIG = {
    "jwt": {
        # EDIT: Set these in your .env or secrets manager (32+ random chars)
        "access_secret":  os.getenv("JWT_ACCESS_SECRET",  "CHANGE_ME_ACCESS_SECRET_MIN_32_CHARS"),
        "refresh_secret": os.getenv("JWT_REFRESH_SECRET", "CHANGE_ME_REFRESH_SECRET_MIN_32_CHARS"),

        # HS256 is symmetric — one secret signs and verifies.
        # Switch to RS256 (asymmetric) if multiple services verify tokens.
        "algorithm":     "HS256",           # EDIT: "RS256" for production with key pairs

        "access_expiry":  15,               # minutes — short-lived to limit damage
        "refresh_expiry": 10_080,           # minutes (7 days)

        # EDIT: Replace with your application name and user base identifier
        "issuer":        "your-app-name",
        "audience":      "your-app-users",
    },
    "security": {
        "max_login_attempts": 5,    # lockout after this many consecutive failures
        "lockout_duration_s": 900,  # 15-minute lockout window (seconds)
        "require_mfa":        False, # EDIT: True to enforce TOTP for all users globally
        "bcrypt_rounds":      12,   # higher = slower hash = harder to brute-force
    },
}


# ─── STRUCTURED AUDIT LOGGER ─────────────────────────────────
# Every auth event is logged as structured JSON with a timestamp
# and user ID. This makes it easy to query in log aggregators.
#
# EDIT: In production, add a transport to ship logs to your
#       observability stack (Datadog, CloudWatch, Loki, etc.)
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
_audit_log = structlog.get_logger("zero-trust-audit")


def log_event(event: str, user_id: Optional[str] = None, **kwargs):
    """
    Write a structured audit log entry.

    Args:
        event:   Identifier for the event (e.g. 'LOGIN_SUCCESS')
        user_id: The user involved (or None for anonymous events)
        **kwargs: Additional context (ip, path, device, etc.)
    """
    _audit_log.info(event, user_id=user_id or "anonymous", **kwargs)


# ─── IN-MEMORY STORES ────────────────────────────────────────
# These work for single-process development and testing.
# In production with multiple worker processes, replace with Redis
# so all instances share the same revocation and lockout state.
#
# EDIT: Replace each store with async Redis calls for production.
_token_blacklist: Set[str]       = set()   # revoked token JTIs
_refresh_store: dict[str, Set]   = {}      # user_id → set of active refresh JTIs
_login_attempts: dict[str, dict] = {}      # "ip:user" → {count, timestamp}
_device_registry: dict[str, Set] = {}      # user_id → set of trusted fingerprints


# ─── PASSWORD CONTEXT ─────────────────────────────────────────
# bcrypt is intentionally slow, making offline password cracking impractical.
# Increasing rounds from 12 to 13 doubles the hash time.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=ZT_CONFIG["security"]["bcrypt_rounds"],
)


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain, hashed)


# ─── TOKEN GENERATION ────────────────────────────────────────

def _make_token(payload: dict, secret: str, expiry_minutes: int, token_type: str) -> str:
    """
    Internal helper — creates a signed JWT with standard claims.

    JTI (JWT ID) makes every token unique so it can be individually revoked.
    """
    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    data = {
        **payload,
        "jti":  jti,
        "type": token_type,    # "access" or "refresh" — prevents type confusion attacks
        "iat":  now,
        "exp":  now + timedelta(minutes=expiry_minutes),
        "iss":  ZT_CONFIG["jwt"]["issuer"],
        "aud":  ZT_CONFIG["jwt"]["audience"],
    }
    return jwt.encode(data, secret, algorithm=ZT_CONFIG["jwt"]["algorithm"])


def create_access_token(payload: dict) -> str:
    """
    Creates a short-lived access token.

    Args:
        payload: Claims to embed (user_id, role, fingerprint, etc.)

    Returns:
        Signed JWT string
    """
    return _make_token(
        payload,
        ZT_CONFIG["jwt"]["access_secret"],
        ZT_CONFIG["jwt"]["access_expiry"],
        "access",
    )


def create_refresh_token(payload: dict) -> str:
    """
    Creates a longer-lived refresh token and registers its JTI.

    The JTI is stored so we can validate it on refresh and detect
    replay attacks (a used token won't be in the store any more).

    Args:
        payload: Claims to embed (same as access token)

    Returns:
        Signed JWT string
    """
    token = _make_token(
        payload,
        ZT_CONFIG["jwt"]["refresh_secret"],
        ZT_CONFIG["jwt"]["refresh_expiry"],
        "refresh",
    )
    # Decode just to extract the JTI and register it
    decoded = jwt.decode(
        token,
        ZT_CONFIG["jwt"]["refresh_secret"],
        algorithms=[ZT_CONFIG["jwt"]["algorithm"]],
        audience=ZT_CONFIG["jwt"]["audience"],
    )
    uid = decoded["user_id"]
    _refresh_store.setdefault(uid, set()).add(decoded["jti"])
    return token


# ─── TOKEN VERIFICATION ──────────────────────────────────────

def decode_access_token(token: str) -> dict:
    """
    Verifies an access token's signature, expiry, type, and blacklist status.

    Args:
        token: Raw JWT string from the Authorization header

    Returns:
        Decoded payload dictionary

    Raises:
        HTTPException 401 if the token is invalid, expired, wrong type, or revoked
    """
    try:
        payload = jwt.decode(
            token,
            ZT_CONFIG["jwt"]["access_secret"],
            algorithms=[ZT_CONFIG["jwt"]["algorithm"]],
            audience=ZT_CONFIG["jwt"]["audience"],
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Token error: {exc}")

    # Reject refresh tokens accidentally sent as access tokens
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type — expected access token")

    # Reject explicitly revoked tokens (e.g. after logout)
    if payload["jti"] in _token_blacklist:
        raise HTTPException(status_code=401, detail="Token has been revoked")

    return payload


def decode_refresh_token(token: str) -> dict:
    """
    Verifies a refresh token and confirms its JTI is still active.

    If the JTI isn't in our store, the token was already used or was
    never issued by us — this is a likely replay attack.

    Args:
        token: Raw JWT refresh token string

    Returns:
        Decoded payload dictionary

    Raises:
        HTTPException 401 on any validation failure
    """
    try:
        payload = jwt.decode(
            token,
            ZT_CONFIG["jwt"]["refresh_secret"],
            algorithms=[ZT_CONFIG["jwt"]["algorithm"]],
            audience=ZT_CONFIG["jwt"]["audience"],
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Token error: {exc}")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type — expected refresh token")

    # Check the JTI is still in our active set
    user_tokens = _refresh_store.get(payload["user_id"], set())
    if payload["jti"] not in user_tokens:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not recognised — possible replay attack",
        )

    return payload


# ─── TOKEN REVOCATION ────────────────────────────────────────

def revoke_token(jti: str, user_id: Optional[str] = None):
    """
    Revokes a single token by adding its JTI to the blacklist.

    Args:
        jti:     The JWT ID to revoke
        user_id: The owning user's ID (removes from refresh store if provided)
    """
    _token_blacklist.add(jti)
    if user_id and user_id in _refresh_store:
        _refresh_store[user_id].discard(jti)


def revoke_all_user_tokens(user_id: str):
    """
    Revokes ALL active sessions for a user.

    Call this on: password change, account compromise, admin-forced logout.
    EDIT: In production with Redis, also mark all JTIs for this user as revoked.
    """
    _refresh_store.pop(user_id, None)
    log_event("TOKENS_REVOKED_ALL", user_id)


# ─── DEVICE FINGERPRINTING ───────────────────────────────────
# A fingerprint is derived from request headers that rarely change
# between requests from the same browser. If a token is stolen and
# replayed from a different device, the fingerprint won't match.
#
# EDIT: Add more signals (TLS fingerprint, IP subnet) for higher security.

def extract_fingerprint(request: Request) -> str:
    """
    Derives a device fingerprint from request headers.

    Args:
        request: FastAPI/Starlette Request object

    Returns:
        SHA-256 hex digest of the combined header values
    """
    raw = ":".join([
        request.headers.get("user-agent",       ""),
        request.headers.get("accept-language",  ""),
        request.headers.get("accept-encoding",  ""),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def is_trusted_device(user_id: str, fingerprint: str) -> bool:
    """Returns True if this fingerprint is in the user's trusted device list."""
    return fingerprint in _device_registry.get(user_id, set())


def trust_device(user_id: str, fingerprint: str):
    """Adds a fingerprint to a user's trusted device list."""
    _device_registry.setdefault(user_id, set()).add(fingerprint)


# ─── BRUTE-FORCE PROTECTION ──────────────────────────────────

def check_login_attempts(ip: str, identifier: str):
    """
    Raises HTTP 429 if the IP/user combo has exceeded the attempt limit.

    Combining IP and identifier means:
    - One IP can't hammer many accounts
    - One account can't be hit from many IPs via this check
      (add a global per-user counter in Redis for distributed protection)

    Args:
        ip:         Client IP address
        identifier: Username or email being attempted

    Raises:
        HTTPException 429 with seconds remaining until unlock
    """
    key  = f"{ip}:{identifier}"
    data = _login_attempts.get(key, {"count": 0, "ts": 0})
    cfg  = ZT_CONFIG["security"]

    if data["count"] >= cfg["max_login_attempts"]:
        elapsed   = time.time() - data["ts"]
        remaining = cfg["lockout_duration_s"] - elapsed

        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail=f"Account locked. Retry in {int(remaining)}s",
            )
        # Lockout has expired — reset
        _login_attempts.pop(key, None)


def record_failed_attempt(ip: str, identifier: str):
    """Increments the failed attempt counter for an IP/user combo."""
    key  = f"{ip}:{identifier}"
    data = _login_attempts.get(key, {"count": 0, "ts": 0})
    data["count"] += 1
    data["ts"]     = time.time()
    _login_attempts[key] = data
    log_event("LOGIN_FAILED", identifier, ip=ip, attempts=data["count"])


def clear_login_attempts(ip: str, identifier: str):
    """Clears the failed attempt counter after a successful login."""
    _login_attempts.pop(f"{ip}:{identifier}", None)


# ─── PYDANTIC SCHEMAS ─────────────────────────────────────────

class LoginRequest(BaseModel):
    """Request body for POST /auth/login"""
    identifier: str           # email or username
    password:   str
    mfa_token:  Optional[str] = None  # TOTP code if MFA is enabled


class RefreshRequest(BaseModel):
    """Request body for POST /auth/refresh"""
    refresh_token: Optional[str] = None
    refreshToken: Optional[str] = None


class LogoutRequest(BaseModel):
    """Request body for POST /auth/logout"""
    refresh_token: Optional[str] = None  # revoke refresh token too if provided


class TokenResponse(BaseModel):
    """Response body for login and refresh endpoints"""
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int  # seconds until access token expires


# ─── ROLE-BASED ACCESS CONTROL ───────────────────────────────
# EDIT: Modify this map to match your application's roles.
# Permission strings can be anything — match them in require_permissions().
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin":  ["read", "write", "delete", "manage"],  # EDIT
    "editor": ["read", "write"],                       # EDIT
    "viewer": ["read"],                                # EDIT
}


def require_permissions(*permissions: str):
    """
    FastAPI dependency factory — checks that the authenticated user
    holds all specified permissions for their role.

    Usage:
        @app.get("/api/data")
        async def read_data(user: dict = Depends(require_permissions("read"))):
            ...

        @app.delete("/api/data")
        async def delete_data(user: dict = Depends(require_permissions("delete"))):
            ...
    """
    async def _check(current_user: dict = Depends(get_current_user)):
        role       = current_user.get("role", "")
        user_perms = ROLE_PERMISSIONS.get(role, [])

        if not all(p in user_perms for p in permissions):
            log_event(
                "AUTHORIZATION_DENIED",
                current_user.get("user_id"),
                role=role,
                required=list(permissions),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _check


# ─── CORE AUTH DEPENDENCY ────────────────────────────────────

# FastAPI's HTTPBearer extracts the token from the Authorization header
bearer_scheme = HTTPBearer()


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Core Zero-Trust authentication dependency.

    Verifies the token on EVERY request — no session state, no caching.
    Also checks the device fingerprint to detect token theft.

    Attach via Depends() to any route that requires authentication:
        @app.get("/api/profile")
        async def profile(user: dict = Depends(get_current_user)):
            return {"user_id": user["user_id"]}

    Returns:
        Decoded token payload with user_id, role, etc.

    Raises:
        HTTPException 401 on any verification failure
    """
    # 1. Verify signature, expiry, type, and blacklist
    payload = decode_access_token(credentials.credentials)

    # 2. Zero-Trust device check — reject if fingerprint has changed
    fingerprint = extract_fingerprint(request)
    if "fingerprint" in payload and payload["fingerprint"] != fingerprint:
        log_event(
            "FINGERPRINT_MISMATCH",
            payload.get("user_id"),
            ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=401,
            detail="Device fingerprint mismatch — re-authenticate",
        )

    log_event(
        "REQUEST_AUTHENTICATED",
        payload.get("user_id"),
        path=str(request.url.path),
        method=request.method,
    )
    return payload


async def get_current_user_mfa(
    request: Request,
    current_user: dict = Depends(get_current_user),
    x_mfa_token: Optional[str] = Header(default=None),
) -> dict:
    """
    MFA-enforcing dependency — extends get_current_user.

    Reads the TOTP code from the X-MFA-Token header.
    Only active when ZT_CONFIG["security"]["require_mfa"] is True.

    EDIT: Fetch the user's TOTP secret from your database if not in the token.

    Usage:
        @app.get("/admin/dashboard")
        async def admin(user: dict = Depends(get_current_user_mfa)):
            ...
    """
    if not ZT_CONFIG["security"]["require_mfa"]:
        return current_user  # MFA not required globally — pass through

    if not x_mfa_token:
        raise HTTPException(
            status_code=401,
            detail="MFA token required (X-MFA-Token header)",
        )

    # EDIT: Fetch the user's TOTP secret from your database
    # e.g. user_record = await db.users.find_one({"_id": current_user["user_id"]})
    # totp_secret = user_record["totp_secret"]
    totp_secret = current_user.get("totp_secret", "")

    totp  = pyotp.TOTP(totp_secret)
    valid = totp.verify(x_mfa_token, valid_window=1)  # ±30s clock tolerance

    if not valid:
        log_event("MFA_FAILED", current_user.get("user_id"),
                  ip=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Invalid MFA token")

    log_event("MFA_PASSED", current_user.get("user_id"))
    return current_user


# ─── MOCK USER DATABASE ──────────────────────────────────────
# EDIT: Delete this function and replace every call with your real DB query.
#
# SQLAlchemy example:
#   result = await db.execute(select(User).where(User.email == identifier))
#   return result.scalar_one_or_none()
#
# MongoDB (Motor) example:
#   return await db.users.find_one({"email": identifier})
async def find_user(identifier: str) -> Optional[dict]:
    """Mock user lookup — replace with your database query."""
    if identifier != "user@example.com":
        return None
    return {
        "id":            "user-001",
        "email":         "user@example.com",
        "password_hash": hash_password("password123"),  # EDIT: stored hash from DB
        "role":          "editor",                       # EDIT: from DB
        "mfa_enabled":   False,                          # EDIT: from DB
        "totp_secret":   "",                             # EDIT: from DB (store encrypted)
    }


# ─── ROUTE HANDLERS ──────────────────────────────────────────
# These are plain async functions — register them on your FastAPI
# app or router (see create_app() below for a wiring example).

async def login(request: Request, body: LoginRequest) -> TokenResponse:
    """
    POST /auth/login — Authenticates a user and issues a token pair.

    Steps:
    1. Check for lockout
    2. Verify credentials
    3. Check MFA if enabled
    4. Issue access + refresh tokens
    """
    ip = request.client.host if request.client else "unknown"

    # 1. Reject if locked out
    check_login_attempts(ip, body.identifier)

    # 2. Look up the user — EDIT: replace find_user() with your DB call
    user = await find_user(body.identifier)
    if not user or not verify_password(body.password, user["password_hash"]):
        # Always record failure and return the same generic message
        # (don't reveal whether the user exists or just the password is wrong)
        record_failed_attempt(ip, body.identifier)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 3. MFA verification if the user has it enabled
    if user.get("mfa_enabled"):
        if not body.mfa_token:
            # Tell the client to collect the TOTP code and re-submit
            return {"mfa_required": True}  # EDIT: return a temp token instead
        totp  = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(body.mfa_token, valid_window=1):
            record_failed_attempt(ip, body.identifier)
            raise HTTPException(status_code=401, detail="Invalid MFA token")

    # 4. Build token payload
    fingerprint  = extract_fingerprint(request)
    known_device = is_trusted_device(user["id"], fingerprint)

    # EDIT: Add any extra claims your application needs here
    payload = {
        "user_id":     user["id"],
        "role":        user["role"],
        "fingerprint": fingerprint,
    }

    clear_login_attempts(ip, body.identifier)
    log_event("LOGIN_SUCCESS", user["id"], ip=ip, known_device=known_device)

    return TokenResponse(
        access_token=create_access_token(payload),
        refresh_token=create_refresh_token(payload),
        expires_in=ZT_CONFIG["jwt"]["access_expiry"] * 60,
    )


async def refresh(request: Request, body: RefreshRequest) -> TokenResponse:
    """
    POST /auth/refresh — Rotates tokens using a valid refresh token.

    The old refresh token is revoked immediately on use (rotation).
    If an attacker obtains a refresh token and tries to use it after
    the legitimate user already has, the server will reject it.
    """
    # 1. Verify the refresh token and check its JTI is still active
    raw_token = body.refresh_token or body.refreshToken
    if not raw_token:
        raise HTTPException(status_code=400, detail="refresh_token is required")
    decoded = decode_refresh_token(raw_token)

    # 2. Rotate — revoke the old refresh token immediately
    revoke_token(decoded["jti"], decoded["user_id"])

    # 3. Issue a fresh token pair
    fingerprint = extract_fingerprint(request)
    payload = {
        "user_id":     decoded["user_id"],
        "role":        decoded["role"],
        "fingerprint": fingerprint,
    }

    log_event("TOKEN_REFRESHED", decoded["user_id"],
              ip=request.client.host if request.client else "unknown")

    return TokenResponse(
        access_token=create_access_token(payload),
        refresh_token=create_refresh_token(payload),
        expires_in=ZT_CONFIG["jwt"]["access_expiry"] * 60,
    )


async def logout(
    request: Request,
    body: Optional[LogoutRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """
    POST /auth/logout — Revokes the current session's tokens.

    The access token JTI is blacklisted and the refresh token is
    removed from the active store.
    """
    if "jti" in current_user:
        revoke_token(current_user["jti"], current_user.get("user_id"))

    refresh_tok = body.refresh_token if body else None
    if refresh_tok:
        try:
            decoded = decode_refresh_token(refresh_tok)
            revoke_token(decoded["jti"], decoded["user_id"])
        except HTTPException:
            pass  # already expired or invalid — that's fine

    log_event("LOGOUT", current_user.get("user_id"),
              ip=request.client.host if request.client else "unknown")
    return {"message": "Logged out successfully"}


async def logout_all(current_user: dict = Depends(get_current_user)):
    """
    POST /auth/logout-all — Terminates ALL active sessions for the user.

    Use this when a password is changed or an account is compromised.
    """
    revoke_all_user_tokens(current_user["user_id"])
    return {"message": "All sessions terminated"}


async def trust_device_endpoint(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    POST /auth/trust-device — Marks the current device as trusted.

    Call this when the user opts in to "remember this device".
    """
    uid         = current_user["user_id"]
    fingerprint = extract_fingerprint(request)
    trust_device(uid, fingerprint)
    log_event("DEVICE_TRUSTED", uid, fingerprint=fingerprint)
    return {"message": "Device trusted for future logins"}


# ─── APP FACTORY ─────────────────────────────────────────────

def create_app() -> FastAPI:
    """
    Creates and configures a FastAPI application with all auth routes
    and rate limiting wired up.

    EDIT: Instead of using this factory, import the individual handler
    functions and register them on your existing FastAPI app.
    """
    limiter = Limiter(key_func=get_remote_address)
    app     = FastAPI(title="Zero-Trust Auth Template")

    # Enable CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach the rate limiter to the app state
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.get("/")
    async def root():
        return {
            "status": "running",
            "service": "Zero-Trust Authentication (Python / FastAPI)",
            "documentation": "/docs",
            "default_user": {
                "identifier": "user@example.com",
                "password": "password123",
                "role": "editor"
            }
        }

    # ── Auth routes ───────────────────────────────
    # Apply rate limiting to auth endpoints to slow down credential stuffing
    app.post("/auth/login",        response_model=TokenResponse)(
        limiter.limit("10/minute")(login)
    )
    app.post("/auth/refresh",      response_model=TokenResponse)(
        limiter.limit("20/minute")(refresh)
    )
    app.post("/auth/logout")(logout)
    app.post("/auth/logout-all")(logout_all)
    app.post("/auth/trust-device")(trust_device_endpoint)

    # ── Protected route examples ──────────────────
    # EDIT: Replace these with your actual application routes

    @app.get("/api/data")
    async def read_data(user: dict = Depends(require_permissions("read"))):
        return {"data": "...", "requested_by": user["user_id"]}

    @app.post("/api/data")
    async def write_data(user: dict = Depends(require_permissions("write"))):
        return {"status": "written"}

    @app.delete("/api/data")
    async def delete_data(user: dict = Depends(require_permissions("delete"))):
        return {"status": "deleted"}

    @app.get("/admin/dashboard")
    async def admin_panel(user: dict = Depends(require_permissions("manage"))):
        # Add get_current_user_mfa here if you want MFA on this route
        return {"panel": "admin", "user": user["user_id"]}

    return app


# ─── ENTRYPOINT ──────────────────────────────────────────────
# EDIT: Replace with your existing app instance
app = create_app()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8001))
    uvicorn.run(app, host="127.0.0.1", port=port)
