"""Rate limiting middleware using database counters."""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from datetime import datetime, UTC
from typing import Optional
import logging

from ..persistence import get_db

logger = logging.getLogger(__name__)

# Rate limit configuration
RATE_LIMIT_ENABLED = True

# Default limits (per agent)
DEFAULT_LIMITS = {
    "per_minute": 60,      # 60 requests per minute
    "per_hour": 1000,     # 1000 requests per hour
    "per_day": 10000,     # 10000 requests per day
}

# Anonymous request limits (much stricter)
ANONYMOUS_LIMITS = {
    "per_minute": 10,      # 10 requests per minute
    "per_hour": 100,       # 100 requests per hour
    "per_day": 500,        # 500 requests per day
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
        
        # Determine which limits to use
        is_anonymous = agent_id is None
        limits_to_use = ANONYMOUS_LIMITS if is_anonymous else self.limits
        
        # Use "anonymous" as the key for anonymous requests
        rate_limit_key = agent_id if agent_id else "anonymous"
        
        # Check rate limit BEFORE processing request
        allowed, error_msg = check_rate_limit(rate_limit_key, limits_to_use)
        
        if not allowed:
            # For anonymous requests, provide more specific error
            if is_anonymous:
                error_msg = f"{error_msg}. Anonymous requests are heavily rate-limited. Provide agent_id in X-Agent-ID header or query parameter."
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": error_msg},
                headers={"Retry-After": "60"},  # Suggest retry after 60 seconds
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
