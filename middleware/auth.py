"""Authentication middleware for EDON Gateway."""

import os
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from typing import Optional, Dict, Any
import logging
from ..config import config

logger = logging.getLogger(__name__)

# Get auth token from environment
EDON_AUTH_ENABLED = os.getenv("EDON_AUTH_ENABLED", "false").lower() == "true"
EDON_API_TOKEN = os.getenv("EDON_API_TOKEN", "")

# Security scheme for OpenAPI docs
security = HTTPBearer(auto_error=False)


def verify_token(token: str) -> tuple[bool, Optional[Dict[str, Any]]]:
    """Verify authentication token and return tenant info.
    
    Args:
        token: Token to verify
        
    Returns:
        Tuple of (is_valid, tenant_info_dict)
        tenant_info_dict contains: tenant_id, status, plan, or None if invalid
    """
    if not EDON_AUTH_ENABLED:
        return True, None  # Auth disabled in development
    
    # Try database lookup first (tenant-scoped API keys)
    try:
        import hashlib
        from ..persistence import get_db
        
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        db = get_db()
        api_key = db.get_api_key_by_hash(key_hash)
        
        if api_key:
            # Update last used timestamp
            db.update_api_key_last_used(api_key["id"])
            
            # Get tenant info
            tenant = db.get_tenant(api_key["tenant_id"])
            if tenant:
                return True, {
                    "tenant_id": tenant["id"],
                    "status": tenant["status"],
                    "plan": tenant["plan"],
                    "api_key_id": api_key["id"]
                }
            return False, None
    except Exception as e:
        logger.debug(f"Database token lookup failed: {e}")
    
    # Fallback to environment variable token (backward compatibility)
    if not EDON_API_TOKEN:
        logger.warning("EDON_AUTH_ENABLED is true but EDON_API_TOKEN is not set")
        return False, None
    
    if token == EDON_API_TOKEN:
        return True, None  # Legacy token, no tenant info
    
    return False, None


def get_token_from_header(request: Request) -> Optional[str]:
    """Extract token from request headers.
    
    Primary method: X-EDON-TOKEN header (recommended for production)
    Fallback: Authorization Bearer token (for compatibility)
    
    Args:
        request: FastAPI request object
        
    Returns:
        Token string or None if not found
    """
    # Primary: X-EDON-TOKEN header (recommended for production)
    token = request.headers.get("X-EDON-TOKEN")
    if token:
        return token
    
    # Fallback: Authorization header (Bearer token) for compatibility
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    
    return None


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate X-EDON-TOKEN header.
    
    Protected endpoints (require authentication when EDON_AUTH_ENABLED=true):
    - /execute
    - /intent/set
    - /intent/get
    - /audit/query
    - /decisions/query
    - /decisions/{decision_id}
    - /credentials/set
    - /credentials/{credential_id} (DELETE)
    - /metrics
    
    Note: Credential readback endpoints (GET) are disabled for security.
    
    Public endpoints (no authentication required):
    - /health
    - /docs
    - /openapi.json
    - /redoc
    """
    
    # Endpoints that don't require authentication (public endpoints only)
    PUBLIC_ENDPOINTS = {
        "/health",
        "/healthz",  # Render health check
        "/docs",
        "/openapi.json",
        "/redoc",
        "/auth/signup",  # Public - creates account
        "/auth/session",  # Public - gets session from Clerk token
        "/billing/checkout",  # Public - initiates Stripe checkout
        "/billing/webhook"  # Public - called by Stripe
    }
    
    async def dispatch(self, request: Request, call_next):
        """Process request and validate authentication."""
        # Skip auth for public endpoints (handle trailing slashes)
        path = request.url.path.rstrip('/')
        if path in self.PUBLIC_ENDPOINTS or request.url.path in self.PUBLIC_ENDPOINTS:
            return await call_next(request)
        
        # Skip auth if disabled
        if not EDON_AUTH_ENABLED:
            return await call_next(request)
        
        # Extract and verify token
        token = get_token_from_header(request)
        
        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing authentication token. Provide X-EDON-TOKEN header or Authorization Bearer token."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        is_valid, tenant_info = verify_token(token)
        
        if not is_valid:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check tenant status if tenant-scoped token
        if tenant_info:
            tenant_status = tenant_info.get("status")
            tenant_plan = tenant_info.get("plan")
            
            # Demo mode: bypass subscription checks
            if config.DEMO_MODE:
                # Override status to active for demo
                tenant_info["status"] = "active"
                tenant_info["plan"] = tenant_plan or "starter"
                tenant_status = "active"
            else:
                # Check if tenant is active
                if tenant_status not in ["active", "trial"]:
                    return JSONResponse(
                        status_code=status.HTTP_402_PAYMENT_REQUIRED,
                        content={
                            "detail": f"Subscription inactive. Status: {tenant_status}",
                            "status": tenant_status,
                            "plan": tenant_plan
                        }
                    )
            
            # Check usage limits
            try:
                from ..billing.plans import check_usage_limit
                from ..persistence import get_db
                from datetime import date
                
                db = get_db()
                tenant_id = tenant_info["tenant_id"]
                
                # Check monthly limit
                monthly_usage = db.get_tenant_usage(tenant_id)
                if not check_usage_limit(tenant_plan, monthly_usage, "month"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": f"Monthly usage limit exceeded for plan '{tenant_plan}'",
                            "plan": tenant_plan,
                            "usage": monthly_usage
                        }
                    )
                
                # Check daily limit
                daily_usage = db.get_tenant_usage(tenant_id, date.today().isoformat())
                if not check_usage_limit(tenant_plan, daily_usage, "day"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": f"Daily usage limit exceeded for plan '{tenant_plan}'",
                            "plan": tenant_plan,
                            "usage": daily_usage
                        }
                    )
                
                # Store tenant info in request state
                request.state.tenant_id = tenant_id
                request.state.tenant_plan = tenant_plan
                request.state.tenant_status = tenant_status
                
            except Exception as e:
                logger.error(f"Error checking tenant limits: {e}", exc_info=True)
                # Fail open for now (don't block requests on billing errors)
                pass
        
        # Token → agent_id binding (if enabled)
        import os
        token_binding_enabled = os.getenv("EDON_TOKEN_BINDING_ENABLED", "false").lower() == "true"
        
        if token_binding_enabled:
            from ..persistence import get_db
            db = get_db()
            
            # Get agent_id from request (query param, header, or body)
            agent_id = (
                request.query_params.get("agent_id") or
                request.headers.get("X-Agent-ID") or
                None
            )
            
            # If agent_id provided, bind token to agent_id
            if agent_id:
                db.bind_token_to_agent(token, agent_id)
                db.update_token_last_used(token)
            else:
                # Try to get agent_id from token binding
                bound_agent_id = db.get_agent_id_for_token(token)
                if bound_agent_id:
                    # Set agent_id from token binding
                    request.state.bound_agent_id = bound_agent_id
                    db.update_token_last_used(token)
        
        # Add token to request state for use in endpoints
        request.state.auth_token = token
        
        return await call_next(request)
