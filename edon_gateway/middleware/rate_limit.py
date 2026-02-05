"""Rate limiting middleware using database counters."""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from datetime import datetime, UTC
from typing import Optional
import logging
import os

from ..persistence import get_db
from ..config import config

logger = logging.getLogger(__name__)

# Check if we're in development mode
ENVIRONMENT = os.getenv("ENVIRONMENT", os.getenv("EDON_ENV", "production")).lower()
IS_DEVELOPMENT = ENVIRONMENT in ["development", "dev", "local"]

# Rate limit configuration - respect explicit setting, but default to disabled in dev
# If EDON_RATE_LIMIT_ENABLED is explicitly set, use it; otherwise disable in dev
rate_limit_setting = os.getenv("EDON_RATE_LIMIT_ENABLED", "").lower()
if rate_limit_setting:
    RATE_LIMIT_ENABLED = rate_limit_setting == "true"
else:
    # Default: disabled in dev, enabled in prod
    RATE_LIMIT_ENABLED = not IS_DEVELOPMENT

# Default limits (per agent)
# Higher limits in development to prevent self-DDoS during local testing
DEFAULT_LIMITS = {
    "per_minute": 300 if IS_DEVELOPMENT else 60,      # 300/min in dev, 60/min in prod
    "per_hour": 10000 if IS_DEVELOPMENT else 1000,    # 10000/hour in dev, 1000/hour in prod
    "per_day": 100000 if IS_DEVELOPMENT else 10000,   # 100000/day in dev, 10000/day in prod
}

# Anonymous request limits (much stricter)
ANONYMOUS_LIMITS = {
    "per_minute": 60 if IS_DEVELOPMENT else 10,       # 60/min in dev, 10/min in prod
    "per_hour": 1000 if IS_DEVELOPMENT else 100,      # 1000/hour in dev, 100/hour in prod
    "per_day": 5000 if IS_DEVELOPMENT else 500,       # 5000/day in dev, 500/day in prod
}

# Higher limits for polling endpoints (dashboard/analytics)
POLLING_ENDPOINT_LIMITS = {
    "per_minute": 120 if IS_DEVELOPMENT else 60,      # Allow more frequent polling
    "per_hour": 20000 if IS_DEVELOPMENT else 2000,     # Higher hourly limit
    "per_day": 200000 if IS_DEVELOPMENT else 20000,   # Higher daily limit
}


def get_rate_limit_key(agent_id: str, window: str) -> str:
    """Generate rate limit counter key.
    
    Args:
        agent_id: Agent identifier
        window: Time window (minute, hour, day)
        
    Returns:
        Counter key string
    """
    now = datetime.now(UTC)
    
    if window == "minute":
        time_key = now.strftime("%Y%m%d%H%M")
    elif window == "hour":
        time_key = now.strftime("%Y%m%d%H")
    elif window == "day":
        time_key = now.strftime("%Y%m%d")
    else:
        raise ValueError(f"Invalid window: {window}")
    
    return f"rate_limit:{agent_id}:{window}:{time_key}"


def check_rate_limit(agent_id: str, limits: Optional[dict] = None) -> tuple[bool, Optional[str]]:
    """Check if agent has exceeded rate limits.
    
    Args:
        agent_id: Agent identifier
        limits: Custom limits dict (defaults to DEFAULT_LIMITS)
        
    Returns:
        Tuple of (allowed, error_message)
    """
    if not RATE_LIMIT_ENABLED:
        return True, None
    
    if limits is None:
        limits = DEFAULT_LIMITS
    
    db = get_db()
    
    # Check each time window
    for window, limit in limits.items():
        if not window.startswith("per_"):
            continue
        
        window_name = window.replace("per_", "")
        counter_key = get_rate_limit_key(agent_id, window_name)
        current_count = db.get_counter(counter_key)
        
        if current_count >= limit:
            return False, f"Rate limit exceeded: {limit} requests per {window_name}"
    
    return True, None


def increment_rate_limit(agent_id: str):
    """Increment rate limit counters for agent.
    
    Args:
        agent_id: Agent identifier
    """
    if not RATE_LIMIT_ENABLED:
        return
    
    db = get_db()
    
    # Increment all time windows
    for window in ["minute", "hour", "day"]:
        counter_key = get_rate_limit_key(agent_id, window)
        db.increment_counter(counter_key, 1)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting per agent."""
    
    # Endpoints that don't count toward rate limits
    EXCLUDED_ENDPOINTS = {
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/metrics",
        "/stats"
    }
    
    # Endpoints that use polling (higher rate limits)
    POLLING_ENDPOINTS = {
        "/decisions/query",
        "/audit/query",
        "/timeseries",
        "/block-reasons",
    }
    
    def __init__(self, app, limits: Optional[dict] = None):
        """Initialize rate limit middleware.
        
        Args:
            app: FastAPI application
            limits: Custom rate limits (defaults to DEFAULT_LIMITS)
        """
        super().__init__(app)
        self.limits = limits or DEFAULT_LIMITS
    
    async def dispatch(self, request: Request, call_next):
        """Process request and check rate limits.
        
        Rate limits are applied BEFORE reading the full body to prevent DoS.
        Anonymous requests (no agent_id) are heavily limited.
        """
        # Skip rate limiting for excluded endpoints
        if request.url.path in self.EXCLUDED_ENDPOINTS:
            return await call_next(request)
        
        # In demo mode, skip rate limits for Telegram traffic
        if config.DEMO_MODE:
            header_agent = request.headers.get("X-Agent-ID") or request.headers.get("X-EDON-Agent-ID")
            if header_agent and header_agent.startswith("telegram:"):
                return await call_next(request)

        # Skip rate limiting if disabled
        if not RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Extract agent_id from headers/query params ONLY (no body read for DoS protection)
        agent_id = None
        
        # Try to get from query params first (doesn't require body read)
        agent_id = request.query_params.get("agent_id")
        
        # Try to get from headers
        if not agent_id:
            agent_id = request.headers.get("X-Agent-ID")
        if not agent_id:
            agent_id = request.headers.get("X-EDON-Agent-ID")
        
        # Determine which limits to use
        is_anonymous = agent_id is None
        is_polling_endpoint = request.url.path in self.POLLING_ENDPOINTS
        
        # Use higher limits for polling endpoints
        if is_polling_endpoint:
            limits_to_use = POLLING_ENDPOINT_LIMITS
        elif is_anonymous:
            limits_to_use = ANONYMOUS_LIMITS
        else:
            limits_to_use = self.limits
        
        # Use "anonymous" as the key for anonymous requests
        rate_limit_key = agent_id if agent_id else "anonymous"
        
        # Check rate limit BEFORE processing request
        allowed, error_msg = check_rate_limit(rate_limit_key, limits_to_use)
        
        if not allowed:
            # For anonymous requests, provide more specific error
            if is_anonymous:
                error_msg = f"{error_msg}. Anonymous requests are heavily rate-limited. Provide agent_id in X-Agent-ID header or query parameter."
            
            # Calculate retry-after based on which limit was hit
            retry_after = "60"  # Default 60 seconds
            if "per_minute" in error_msg:
                retry_after = "60"  # Wait 1 minute
            elif "per_hour" in error_msg:
                retry_after = "3600"  # Wait 1 hour
            elif "per_day" in error_msg:
                retry_after = "86400"  # Wait 1 day
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": error_msg},
                headers={"Retry-After": retry_after},
            )
        
        # Process request
        response = await call_next(request)
        
        # Increment counter only on successful requests (2xx status)
        if 200 <= response.status_code < 300:
            increment_rate_limit(rate_limit_key)
            
            # Track tenant usage if tenant-scoped request
            if hasattr(request.state, 'tenant_id'):
                from ..persistence import get_db
                db = get_db()
                db.increment_tenant_usage(request.state.tenant_id, 1)
        
        return response
