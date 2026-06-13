"""
VibeLock — JWT Authentication Middleware
Provides JWT-based auth for dashboard API and internal service-to-service calls.
"""

import os
import time
import logging
from typing import Optional
from dataclasses import dataclass, field

import jwt
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# --- Config ---

@dataclass
class AuthConfig:
    jwt_secret: str = field(
        default_factory=lambda: os.getenv("VIBELOCK_JWT_SECRET", "change-me-in-production")
    )
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    api_key_header: str = "X-VibeLock-API-Key"
    internal_api_key: str = field(
        default_factory=lambda: os.getenv("VIBELOCK_INTERNAL_API_KEY", "")
    )


auth_config = AuthConfig()
security = HTTPBearer(auto_error=False)


# --- Models ---

class TokenPayload(BaseModel):
    sub: str  # Subject (user/org ID)
    org_id: Optional[str] = None
    role: str = "admin"  # admin, viewer, scanner
    exp: int  # Expiry timestamp
    iat: int  # Issued at


class AuthenticatedUser(BaseModel):
    user_id: str
    org_id: Optional[str] = None
    role: str = "admin"
    auth_method: str = "jwt"  # jwt, api_key, internal


# --- Token Management ---

def create_token(
    user_id: str,
    org_id: Optional[str] = None,
    role: str = "admin",
    expiry_minutes: Optional[int] = None,
) -> str:
    """Create a JWT token for a user."""
    now = int(time.time())
    exp = now + (expiry_minutes or auth_config.jwt_expiry_minutes) * 60

    payload = {
        "sub": user_id,
        "org_id": org_id,
        "role": role,
        "exp": exp,
        "iat": now,
    }

    return jwt.encode(payload, auth_config.jwt_secret, algorithm=auth_config.jwt_algorithm)


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            auth_config.jwt_secret,
            algorithms=[auth_config.jwt_algorithm],
            options={"require": ["exp", "sub"]},
        )
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


def create_internal_token(service_name: str) -> str:
    """Create a token for internal service-to-service communication."""
    return create_token(
        user_id=f"service:{service_name}",
        role="internal",
        expiry_minutes=5,
    )


# --- Auth Dependencies ---

async def authenticate_jwt(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """Authenticate via JWT Bearer token."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    token = credentials.credentials
    payload = decode_token(token)

    return AuthenticatedUser(
        user_id=payload.sub,
        org_id=payload.org_id,
        role=payload.role,
        auth_method="jwt",
    )


async def authenticate_api_key(
    request: Request,
) -> AuthenticatedUser:
    """Authenticate via API key header (for CI/CD or external integrations)."""
    api_key = request.headers.get(auth_config.api_key_header)

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key header")

    if not auth_config.internal_api_key:
        logger.warning("internal_api_key_not_configured")
        raise HTTPException(status_code=401, detail="API key auth not configured")

    # Constant-time comparison
    if not _constant_time_compare(api_key, auth_config.internal_api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return AuthenticatedUser(
        user_id="api_key",
        org_id=None,
        role="admin",
        auth_method="api_key",
    )


async def authenticate_any(
    request: Request,
    jwt_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """Try JWT first, fall back to API key."""
    # Try JWT
    if jwt_credentials:
        try:
            return await authenticate_jwt(request, jwt_credentials)
        except HTTPException:
            pass

    # Try API key
    api_key = request.headers.get(auth_config.api_key_header)
    if api_key:
        try:
            return await authenticate_api_key(request)
        except HTTPException:
            pass

    raise HTTPException(status_code=401, detail="Authentication required")


async def authenticate_internal(
    request: Request,
    jwt_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """Authenticate internal service-to-service calls."""
    if jwt_credentials is None:
        raise HTTPException(status_code=401, detail="Missing internal auth token")

    payload = decode_token(jwt_credentials.credentials)

    if payload.role != "internal":
        raise HTTPException(status_code=403, detail="Internal access only")

    return AuthenticatedUser(
        user_id=payload.sub,
        org_id=payload.org_id,
        role="internal",
        auth_method="jwt",
    )


# --- Role-Based Access ---

def require_role(*allowed_roles: str):
    """Dependency factory: require one of the given roles."""
    async def role_checker(user: AuthenticatedUser = Depends(authenticate_any)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user.role}' not allowed. Required: {allowed_roles}",
            )
        return user
    return role_checker


require_admin = require_role("admin")
require_admin_or_internal = require_role("admin", "internal")


# --- Middleware ---

async def auth_middleware(request: Request, call_next):
    """
    Global auth middleware — attaches user context to request.state.
    Skips auth for health endpoints and webhook receiver.
    """
    # Skip auth for public endpoints
    public_paths = ["/health", "/health/live", "/health/ready", "/webhook/github"]
    if any(request.url.path.startswith(p) for p in public_paths):
        return await call_next(request)

    # Skip auth for dashboard if no credentials (optional auth)
    # Dashboard endpoints use Depends(authenticate_any) explicitly
    if request.url.path.startswith("/api/"):
        # Try to extract user from headers
        auth_header = request.headers.get("Authorization", "")
        api_key = request.headers.get(auth_config.api_key_header, "")

        if auth_header.startswith("Bearer "):
            try:
                token = auth_header[7:]
                payload = decode_token(token)
                request.state.user = AuthenticatedUser(
                    user_id=payload.sub,
                    org_id=payload.org_id,
                    role=payload.role,
                    auth_method="jwt",
                )
            except HTTPException:
                pass  # Let endpoint-level Depends handle it
        elif api_key:
            if auth_config.internal_api_key and _constant_time_compare(
                api_key, auth_config.internal_api_key
            ):
                request.state.user = AuthenticatedUser(
                    user_id="api_key",
                    org_id=None,
                    role="admin",
                    auth_method="api_key",
                )

    return await call_next(request)


# --- Utilities ---

def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0