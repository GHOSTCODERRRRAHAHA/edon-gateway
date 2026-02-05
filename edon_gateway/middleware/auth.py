"""Authentication middleware for EDON Gateway."""

import os
import logging
import json
import time
from typing import Optional, Dict, Any, Tuple
import uuid

import requests
import jwt

from fastapi import Request, status
from fastapi.security import HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import config

logger = logging.getLogger(__name__)

# Security scheme for OpenAPI docs
security = HTTPBearer(auto_error=False)


_JWKS_CACHE: Dict[str, Any] = {"keys": None, "fetched_at": 0}


def _get_clerk_jwks(force_refresh: bool = False) -> Optional[list]:
    ttl_seconds = int(os.getenv("CLERK_JWKS_CACHE_TTL", "3600"))
    now = time.time()

    if not force_refresh and _JWKS_CACHE.get("keys") and (now - _JWKS_CACHE.get("fetched_at", 0) < ttl_seconds):
        return _JWKS_CACHE["keys"]

    jwks_url = os.getenv("CLERK_JWKS_URL", "https://api.clerk.com/v1/jwks")
    headers = {}
    if config.CLERK_SECRET_KEY:
        headers["Authorization"] = f"Bearer {config.CLERK_SECRET_KEY}"

    try:
        resp = requests.get(jwks_url, headers=headers, timeout=10)
        resp.raise_for_status()
        payload = resp.json()
        keys = payload.get("keys") if isinstance(payload, dict) else None
        if not keys:
            keys = payload if isinstance(payload, list) else None
        if not keys:
            return None
        _JWKS_CACHE["keys"] = keys
        _JWKS_CACHE["fetched_at"] = now
        return keys
    except Exception as exc:
        logger.debug(f"Failed to fetch Clerk JWKS: {exc}")
        return None


def verify_clerk_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or token.count(".") != 2:
        return None

    if not config.CLERK_SECRET_KEY and not os.getenv("CLERK_JWKS_URL"):
        return None

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            return None

        keys = _get_clerk_jwks() or []
        key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            keys = _get_clerk_jwks(force_refresh=True) or []
            key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            return None

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        issuer = os.getenv("CLERK_ISSUER")
        audience = os.getenv("CLERK_AUDIENCE")

        options = {
            "verify_aud": bool(audience),
            "verify_iss": bool(issuer),
        }

        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
            options=options,
        )
        return claims
    except Exception as exc:
        logger.debug(f"Clerk token verification failed: {exc}")
        return None


def resolve_tenant_for_clerk(claims: Dict[str, Any], fallback_email: Optional[str] = None) -> Dict[str, Any]:
    from ..persistence import get_db

    db = get_db()
    clerk_sub = (claims or {}).get("sub")
    if not clerk_sub:
        raise ValueError("Missing Clerk subject")

    email = (
        claims.get("email")
        or claims.get("email_address")
        or claims.get("primary_email_address")
        or fallback_email
        or "unknown@edoncore.com"
    )

    user = db.get_user_by_auth("clerk", clerk_sub)
    if not user:
        user_id = str(uuid.uuid4())
        db.create_user(user_id=user_id, email=email, auth_provider="clerk", auth_subject=clerk_sub, role="user")
    else:
        user_id = user["id"]

    tenant = db.get_tenant_by_user_id(user_id)
    if not tenant:
        tenant_id = f"tenant_{uuid.uuid4().hex[:12]}"
        db.create_tenant(tenant_id=tenant_id, user_id=user_id)
        tenant = db.get_tenant(tenant_id)

    return {
        "tenant_id": tenant["id"],
        "status": tenant["status"],
        "plan": tenant["plan"],
        "api_key_id": None,
        "user_id": user_id,
        "email": email,
    }


def verify_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify authentication token and return tenant info.

    Returns:
        (is_valid, tenant_info_dict)

    tenant_info_dict contains:
      - tenant_id
      - status
      - plan
      - api_key_id
    or None if legacy token/no tenant.
    """
    if not config.AUTH_ENABLED:
        return True, None  # Auth disabled

    token = (token or "").strip()
    if not token:
        return False, None

    # 1) DB lookup first (tenant-scoped API keys + channel tokens)
    try:
        import hashlib
        from ..persistence import get_db

        key_hash = hashlib.sha256(token.encode()).hexdigest()
        db = get_db()
        api_key = db.get_api_key_by_hash(key_hash)

        if api_key:
            db.update_api_key_last_used(api_key["id"])
            tenant = db.get_tenant(api_key["tenant_id"])
            if tenant:
                return True, {
                    "tenant_id": tenant["id"],
                    "status": tenant["status"],
                    "plan": tenant["plan"],
                    "api_key_id": api_key["id"],
                }
            return False, None

        channel_token = db.get_channel_token_by_hash(key_hash)
        if channel_token:
            db.update_channel_token_last_used(channel_token["id"])
            tenant = db.get_tenant(channel_token["tenant_id"])
            if tenant:
                return True, {
                    "tenant_id": tenant["id"],
                    "status": tenant["status"],
                    "plan": tenant["plan"],
                    "api_key_id": None,
                }
            return False, None

    except Exception as e:
        logger.debug(f"Database token lookup failed: {e}")

    # 1b) Clerk session JWT fallback
    try:
        clerk_claims = verify_clerk_token(token)
        if clerk_claims:
            tenant_info = resolve_tenant_for_clerk(clerk_claims)
            return True, tenant_info
    except Exception as e:
        logger.debug(f"Clerk token resolution failed: {e}")

    # 2) Env token fallback (legacy)
    # Default behavior: disabled in production to enforce DB keys.
    # Can be explicitly enabled for bootstrap/admin via EDON_ALLOW_ENV_TOKEN_IN_PROD=true.
    if config.is_production() and not config.ALLOW_ENV_TOKEN_IN_PROD:
        return False, None

    api_token = (config.API_TOKEN or "").strip()
    if not api_token or api_token == "your-secret-token":
        logger.warning("EDON_AUTH_ENABLED is true but EDON_API_TOKEN is not set")
        return False, None

    if token == api_token:
        return True, None

    return False, None


def get_token_from_header(request: Request) -> Optional[str]:
    """Extract token from headers.

    Primary: X-EDON-TOKEN
    Fallback: Authorization: Bearer <token>
    """
    token = request.headers.get("X-EDON-TOKEN")
    if token:
        token = token.strip()
        return token if token else None

    auth_header = (request.headers.get("Authorization", "") or "").strip()
    if auth_header.startswith("Bearer "):
        bearer = auth_header[7:].strip()
        return bearer if bearer else None

    return None


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate authentication token."""

    PUBLIC_ENDPOINTS = {
        "/health",
        "/healthz",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/debug/auth-public",
        "/auth/signup",
        "/auth/session",
        "/billing/checkout",
        "/billing/webhook",
        "/integrations/telegram/verify-code",
    }

    async def dispatch(self, request: Request, call_next):
        # Normalize path for trailing slashes
        path = request.url.path.rstrip("/")
        if config.DEMO_MODE and path == "/integrations/telegram/connect-code":
            return await call_next(request)
        if path in self.PUBLIC_ENDPOINTS or request.url.path in self.PUBLIC_ENDPOINTS:
            return await call_next(request)

        if not config.AUTH_ENABLED:
            return await call_next(request)

        token = get_token_from_header(request)

        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Missing authentication token. Provide X-EDON-TOKEN header or Authorization Bearer token."
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        is_valid, tenant_info = verify_token(token)

        if not is_valid:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Tenant-scoped behavior
        if tenant_info:
            tenant_status = tenant_info.get("status")
            tenant_plan = tenant_info.get("plan")

            # Demo mode bypass
            if config.DEMO_MODE:
                tenant_info["status"] = "active"
                tenant_info["plan"] = tenant_plan or "starter"
                tenant_status = "active"
            else:
                if tenant_status not in ["active", "trial"]:
                    return JSONResponse(
                        status_code=status.HTTP_402_PAYMENT_REQUIRED,
                        content={
                            "detail": f"Subscription inactive. Status: {tenant_status}",
                            "status": tenant_status,
                            "plan": tenant_plan,
                        },
                    )

            # Usage limits
            try:
                from ..billing.plans import check_usage_limit
                from ..persistence import get_db
                from datetime import date

                db = get_db()
                tenant_id = tenant_info["tenant_id"]

                monthly_usage = db.get_tenant_usage(tenant_id)
                if not check_usage_limit(tenant_plan, monthly_usage, "month"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": f"Monthly usage limit exceeded for plan '{tenant_plan}'",
                            "plan": tenant_plan,
                            "usage": monthly_usage,
                        },
                    )

                daily_usage = db.get_tenant_usage(tenant_id, date.today().isoformat())
                if not check_usage_limit(tenant_plan, daily_usage, "day"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": f"Daily usage limit exceeded for plan '{tenant_plan}'",
                            "plan": tenant_plan,
                            "usage": daily_usage,
                        },
                    )

                request.state.tenant_id = tenant_id
                request.state.tenant_plan = tenant_plan
                request.state.tenant_status = tenant_status

            except Exception as e:
                logger.error(f"Error checking tenant limits: {e}", exc_info=True)
                # Fail open on billing issues (your current behavior)
                pass

        elif (
            (os.getenv("EDON_ENV") == "development" or os.getenv("ENVIRONMENT") == "development")
            and token == (config.API_TOKEN or "").strip()
            and not getattr(request.state, "tenant_id", None)
        ):
            request.state.tenant_id = os.getenv("EDON_DEV_TENANT_ID", "tenant_dev")

        # Token → agent_id binding
        if config.TOKEN_BINDING_ENABLED:
            from ..persistence import get_db

            db = get_db()
            agent_id = request.query_params.get("agent_id") or request.headers.get("X-Agent-ID") or None

            if agent_id:
                db.bind_token_to_agent(token, agent_id)
                db.update_token_last_used(token)
            else:
                bound_agent_id = db.get_agent_id_for_token(token)
                if bound_agent_id:
                    request.state.bound_agent_id = bound_agent_id
                    db.update_token_last_used(token)

        request.state.auth_token = token

        return await call_next(request)
