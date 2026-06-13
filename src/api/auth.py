"""
VibeLock — JWT Authentication Middleware
Provides JWT-based auth for dashboard API and internal service-to-service calls.
"""

import os
import time
import hashlib
import logging
from typing import Optional
from dataclasses import dataclass, field

import jwt
from fastapi import Request, HTTPException, Depends, APIRouter
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


async def resolve_org_from_api_key(api_key: str) -> Optional[str]:
    """
    Look up an organization by its vl_ prefixed API key.
    Returns org_id string or None if key is invalid/unknown.
    """
    if not api_key or not api_key.startswith("vl_"):
        return None

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    try:
        from vibelock.src.shared.supabase_client import supabase

        if not supabase.is_connected:
            logger.warning("resolve_org_from_api_key: supabase not connected")
            return None

        result = (
            supabase.client.table("organizations")
            .select("id")
            .eq("api_key_hash", key_hash)
            .single()
            .execute()
        )
        return result.data["id"] if result.data else None
    except Exception as e:
        logger.warning(f"resolve_org_from_api_key failed: {e}")
        return None


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
    """Authenticate via API key header (for CI/CD or external integrations).
    Supports both internal API keys and vl_ prefixed org-level API keys."""
    api_key = request.headers.get(auth_config.api_key_header)

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key header")

    # Check for vl_ prefixed org-level API keys first
    if api_key.startswith("vl_"):
        org_id = await resolve_org_from_api_key(api_key)
        if org_id:
            return AuthenticatedUser(
                user_id=f"org:{org_id}",
                org_id=org_id,
                role="admin",
                auth_method="api_key",
            )
        raise HTTPException(status_code=401, detail="Invalid org API key")

    # Fall back to internal API key check
    if not auth_config.internal_api_key:
        logger.warning("internal_api_key_not_configured")
        raise HTTPException(status_code=401, detail="API key auth not configured")

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
    Sets Supabase RLS context (app.current_org_id) for tenant isolation.
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

        user = None

        if auth_header.startswith("Bearer "):
            try:
                token = auth_header[7:]
                payload = decode_token(token)
                user = AuthenticatedUser(
                    user_id=payload.sub,
                    org_id=payload.org_id,
                    role=payload.role,
                    auth_method="jwt",
                )
            except HTTPException:
                pass  # Let endpoint-level Depends handle it
        elif api_key:
            # Check vl_ prefixed org API keys
            if api_key.startswith("vl_"):
                org_id = await resolve_org_from_api_key(api_key)
                if org_id:
                    user = AuthenticatedUser(
                        user_id=f"org:{org_id}",
                        org_id=org_id,
                        role="admin",
                        auth_method="api_key",
                    )
            elif auth_config.internal_api_key and _constant_time_compare(
                api_key, auth_config.internal_api_key
            ):
                user = AuthenticatedUser(
                    user_id="api_key",
                    org_id=None,
                    role="admin",
                    auth_method="api_key",
                )

        if user:
            request.state.user = user

            # Set RLS context for Supabase tenant isolation
            if user.org_id:
                try:
                    from vibelock.src.shared.supabase_client import supabase
                    if supabase.is_connected:
                        supabase.client.rpc(
                            "set_config",
                            {
                                "setting_name": "app.current_org_id",
                                "setting_value": user.org_id,
                            },
                        )
                except Exception as e:
                    logger.warning(f"Failed to set RLS context: {e}")

    return await call_next(request)


# --- Utilities ---

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """
    Authenticate user with username/password and return JWT token.
    Uses Supabase auth for credential verification.
    """
    try:
        from vibelock.src.shared.supabase_client import supabase

        if not supabase.is_connected:
            raise HTTPException(
                status_code=503,
                detail="Authentication service unavailable — Supabase not connected",
            )

        # Authenticate against Supabase
        auth_result = supabase.client.auth.sign_in_with_password({
            "email": body.username,
            "password": body.password,
        })

        if not auth_result or not auth_result.user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user = auth_result.user
        token = create_token(
            user_id=user.id,
            org_id=user.user_metadata.get("org_id") if user.user_metadata else None,
            role=user.user_metadata.get("role", "admin") if user.user_metadata else "admin",
        )

        return LoginResponse(access_token=token, token_type="bearer")

    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable — supabase-py not installed",
        )
    except Exception as e:
        logger.error("login_failed", error=str(e))
        raise HTTPException(status_code=401, detail="Invalid credentials")


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result


# --- Auth Router (login endpoint) ---

from fastapi import APIRouter
from pydantic import BaseModel

auth_router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@auth_router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """
    Authenticate user with username/password and return a JWT access token.

    For now, uses a simple credential check against environment variables.
    In production, this should validate against Supabase auth or an identity provider.
    """
    import os

    valid_username = os.getenv("VIBELOCK_ADMIN_USERNAME", "admin")
    valid_password = os.getenv("VIBELOCK_ADMIN_PASSWORD", "admin")

    if body.username != valid_username or body.password != valid_password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(
        user_id=body.username,
        org_id=None,
        role="admin",
    )

    return LoginResponse(access_token=token, token_type="bearer")