"""EDON Gateway FastAPI application."""

# NOTE: dotenv loading is now handled in config.py (at the very top)
# Do NOT load dotenv here - config.py handles it before Config class is defined

from fastapi import FastAPI, HTTPException, Depends, status, Header, Request, Response
from starlette.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, Counter, Histogram, Gauge
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime, UTC
import os

from .governor import EDONGovernor
from .schemas import Action, Decision, IntentContract, Tool, RiskLevel, Verdict, ActionSource
from .audit import AuditLogger
from pathlib import Path
from .connectors.email_connector import email_connector
from .connectors.filesystem_connector import filesystem_connector
from .connectors.clawdbot_connector import clawdbot_connector
from .middleware import AuthMiddleware, RateLimitMiddleware, ValidationMiddleware
from .security.anti_bypass import (
    AntiBypassConfig, validate_anti_bypass_setup, get_bypass_resistance_score
)
from .policy_packs import (
    get_policy_pack, list_policy_packs, apply_policy_pack, POLICY_PACKS
)
from .benchmarking import get_trust_spec_sheet, get_benchmark_collector
from .logging_config import setup_logging, get_logger
from .config import config
from .monitoring.metrics import metrics as metrics_collector
from .routes.integrations import router as integrations_router
from .routes.integrations import get_integration_status as integrations_account_handler

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Validate configuration
warnings = config.validate()
if warnings:
    for warning in warnings:
        logger.warning(f"Configuration warning: {warning}")

app = FastAPI(
    title="EDON Gateway",
    version="1.0.1",
    description="AI Agent Safety Layer with Governance and Policy Enforcement",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Request ID + security headers middleware
@app.middleware("http")
async def request_id_and_security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or os.urandom(8).hex()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "0"
    return response

# Middleware order matters - add in reverse order of execution
# Validation first (innermost), then rate limiting, then auth (outermost)

# Input validation middleware (validates and sanitizes inputs)
app.add_middleware(ValidationMiddleware)

# Rate limiting middleware (enforces per-agent quotas)
app.add_middleware(RateLimitMiddleware)

# Authentication middleware (validates X-EDON-TOKEN header)
app.add_middleware(AuthMiddleware)

# Include routers
app.include_router(integrations_router)

# CORS configuration
# When allow_credentials=True, cannot use wildcard "*" - must specify origins
cors_origins = config.CORS_ORIGINS
if "*" in cors_origins:
    if config.is_production():
        raise RuntimeError(
            "EDON_CORS_ORIGINS cannot include '*' in production. "
            "Set explicit origins for the agent UI and production domains."
        )
    # Default to production origins only
    cors_origins = [
        "https://edoncore.com",
        "https://www.edoncore.com"
    ]
    # Add localhost only in development (not production)
    import os
    if os.getenv("ENVIRONMENT") != "production" and os.getenv("EDON_ENV") != "production":
        cors_origins.extend([
            "http://localhost:5173",
            "http://localhost:3000",
            "http://localhost:8080",  # Agent UI dev server (Vite configured port)
            "http://127.0.0.1:8080",
            "http://localhost:5174",  # Vite default fallback port
            "http://[::1]:8080",  # IPv6 localhost
        ])
    logger.warning("CORS wildcard detected - using default origins. Set EDON_CORS_ORIGINS for production.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Safety UX dashboard
# Try to serve React UI from console-ui/dist, fallback to simple HTML
try:
    ui_path = Path(__file__).parent / "ui"
    console_ui_dist = ui_path / "console-ui" / "dist"
    simple_ui_html = ui_path / "index.html"
    
    if console_ui_dist.exists() and (console_ui_dist / "index.html").exists():
        # Serve React UI from console-ui/dist
        app.mount("/ui", StaticFiles(directory=str(console_ui_dist), html=True), name="ui")
        app.mount("/assets", StaticFiles(directory=str(console_ui_dist / "assets")), name="assets")
        
        @app.get("/")
        async def root():
            """Serve React UI dashboard."""
            return FileResponse(str(console_ui_dist / "index.html"))
        
        import logging
        logging.info("Serving React UI from console-ui/dist")
    elif simple_ui_html.exists():
        # Fallback to simple HTML dashboard
        app.mount("/ui", StaticFiles(directory=str(ui_path), html=True), name="ui")
        
        @app.get("/")
        async def root():
            """Redirect to Safety UX dashboard."""
            return FileResponse(str(simple_ui_html))
        
        import logging
        logging.info("Serving simple HTML UI")
    else:
        import logging
        logging.warning("No UI found. Run setup_ui.sh or setup_ui.ps1 to set up React UI")
except Exception as e:
    import logging
    logging.warning(f"Could not mount UI: {e}")

# Global state
governor = EDONGovernor()
audit_logger = AuditLogger(Path("audit.log.jsonl"))  # Keep for backward compatibility
from .persistence import get_db
db = get_db()

# Initialize app state
import time
app.state.start_time = time.time()

# Prometheus metrics (for ops teams and standard tooling)
# Only create if metrics are enabled
if config.METRICS_ENABLED:
    prometheus_decisions_total = Counter(
        'edon_decisions_total',
        'Total number of governance decisions',
        ['verdict', 'reason_code']
    )
    prometheus_decision_latency_ms = Histogram(
        'edon_decision_latency_ms',
        'Decision evaluation latency in milliseconds',
        ['endpoint'],
        buckets=[10, 50, 100, 200, 500, 1000, 2000, 5000]
    )
    prometheus_rate_limit_hits_total = Counter(
        'edon_rate_limit_hits_total',
        'Total number of rate limit hits'
    )
    prometheus_active_intents = Gauge(
        'edon_active_intents',
        'Number of active intent contracts currently registered'
    )
    prometheus_uptime_seconds = Gauge(
        'edon_uptime_seconds',
        'Gateway uptime in seconds'
    )
else:
    # Dummy objects when metrics disabled (to avoid NameError)
    prometheus_decisions_total = None
    prometheus_decision_latency_ms = None
    prometheus_rate_limit_hits_total = None
    prometheus_active_intents = None
    prometheus_uptime_seconds = None

# Startup event - validate schema version
@app.on_event("startup")
async def startup_event():
    """Validate database schema version on startup and initialize Prometheus metrics."""
    logger.info("=" * 60)
    logger.info("Starting EDON Gateway...")
    logger.info(f"Gateway version: {app.version}")
    logger.info("=" * 60)
    
    from .persistence.schema_version import check_schema_version, set_schema_version, get_current_schema_version, SCHEMA_VERSION
    if not check_schema_version(db):
        current_version = get_current_schema_version(db)
        logger.warning(f"Database schema version mismatch. Current: {current_version}, Expected: {SCHEMA_VERSION}")
        # In production, you might want to run migrations here
        set_schema_version(db, SCHEMA_VERSION)
        logger.info(f"Schema version set to {SCHEMA_VERSION}")
    else:
        logger.info(f"Database schema version OK: {SCHEMA_VERSION}")
    
    # Initialize Prometheus gauges (if metrics enabled)
    if config.METRICS_ENABLED:
        prometheus_active_intents.set(len(db.list_intents()))
        prometheus_uptime_seconds.set(0)
    
    # Network gating validation
    if config.NETWORK_GATING:
        from .security.network_gating import validate_network_gating, get_clawdbot_base_url
        base_url = get_clawdbot_base_url()
        is_valid, reachability, risk, recommendation = validate_network_gating(base_url, True)
        
        if not is_valid:
            error_msg = (
                f"Network gating validation failed: Clawdbot Gateway is {reachability} (risk: {risk}).\n"
                f"Bypass risk detected - agents could call Clawdbot Gateway directly.\n\n"
                f"Recommendation:\n{recommendation}\n\n"
                f"To fix:\n"
                f"1. Set Clawdbot Gateway to loopback/private address (e.g., http://127.0.0.1:18789 or http://clawdbot-gateway:18789)\n"
                f"2. Or disable network gating: EDON_NETWORK_GATING=false (not recommended for production)\n"
                f"3. See NETWORK_ISOLATION_GUIDE.md for detailed setup instructions."
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        logger.info(f"Network gating validation passed: Clawdbot Gateway is {reachability} (risk: {risk})")
    
    logger.info("EDON Gateway startup complete")


# Request/Response Models
class ExecuteRequest(BaseModel):
    """Execute action request."""
    action: Dict[str, Any]
    intent_id: Optional[str] = None
    agent_id: str


class ExecuteResponse(BaseModel):
    """Execute action response."""
    verdict: str
    decision_id: str
    reason_code: Optional[str] = None
    explanation: str
    safe_alternative: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    timestamp: str


class IntentSetRequest(BaseModel):
    """Set intent contract request."""
    intent_id: Optional[str] = None
    objective: str
    scope: Dict[str, List[str]]
    constraints: Dict[str, Any] = {}
    risk_level: str = "medium"
    approved_by_user: bool = False


class IntentSetResponse(BaseModel):
    """Set intent contract response."""
    intent_id: str
    created_at: str
    status: str


class IntentGetResponse(BaseModel):
    """Get intent contract response."""
    intent_id: str
    objective: str
    scope: Dict[str, List[str]]
    constraints: Dict[str, Any]
    created_at: str


class AuditQueryResponse(BaseModel):
    """Audit query response."""
    events: List[Dict[str, Any]]
    total: int
    limit: int


class DecisionQueryResponse(BaseModel):
    """Decision query response."""
    decisions: List[Dict[str, Any]]
    total: int
    limit: int


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    uptime_seconds: int
    governor: Dict[str, Any]  # Includes policy_version, active_intents, active_preset


class MetricsResponse(BaseModel):
    """Metrics endpoint response."""
    # Decision counts (non-sensitive)
    decisions_total: int
    decisions_by_verdict: Dict[str, int]
    decisions_by_reason_code: Dict[str, int]
    
    # Rate limiting (non-sensitive aggregates)
    rate_limit_hits_total: int
    
    # Intent counts (non-sensitive)
    active_intents: int
    
    # System metrics (non-sensitive)
    uptime_seconds: int
    version: str
    active_preset: Optional[Dict[str, Any]] = None


@app.post("/execute", response_model=ExecuteResponse)
async def execute_action(request: ExecuteRequest):
    """Execute a single action through governance.
    
    This is the main entry point. Clawdbot calls this for every tool action.
    """
    try:
        # Input validation
        if not request.agent_id or not request.agent_id.strip():
            raise HTTPException(status_code=400, detail="agent_id is required")
        if not request.action:
            raise HTTPException(status_code=400, detail="action is required")
        if "tool" not in request.action:
            raise HTTPException(status_code=400, detail="action.tool is required")
        if "op" not in request.action:
            raise HTTPException(status_code=400, detail="action.op is required")
        # Load intent from database (Phase B: persistence)
        intent = None
        intent_id_for_audit = request.intent_id if request.intent_id else None
        
        if request.intent_id:
            intent_data = db.get_intent(request.intent_id)
            if intent_data:
                # Convert database dict to IntentContract
                # Parse created_at - handle both with and without timezone
                created_at_str = intent_data["created_at"]
                try:
                    if created_at_str.endswith('Z'):
                        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    else:
                        created_at = datetime.fromisoformat(created_at_str)
                except ValueError:
                    # Fallback: try parsing without timezone
                    created_at = datetime.fromisoformat(created_at_str.split('+')[0].split('Z')[0])
                
                intent = IntentContract(
                    objective=intent_data["objective"],
                    scope=intent_data["scope"],
                    constraints=intent_data["constraints"],
                    risk_level=RiskLevel(intent_data["risk_level"]),
                    approved_by_user=intent_data["approved_by_user"],
                    created_at=created_at
                )
                intent_id_for_audit = request.intent_id
        
        # Use default intent if not found or not specified
        if not intent:
            intent = IntentContract(
                objective="Default intent",
                scope={},
                constraints={},
                risk_level=RiskLevel.MEDIUM,
                approved_by_user=False
            )
            intent_id_for_audit = None  # Don't log default intents
        
        # Parse action
        action = Action(
            tool=Tool(request.action["tool"]),
            op=request.action["op"],
            params=request.action.get("params", {}),
            source=ActionSource.AGENT
        )
        
        # Check credentials in strict mode BEFORE governor evaluation
        # This ensures we fail closed even if action would be blocked by policy
        import os
        credentials_strict = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"
        
        if credentials_strict:
            # In strict mode, require credentials for tool execution
            tool_name = action.tool.value if hasattr(action.tool, 'value') else str(action.tool)
            tool_credentials = db.get_credentials_by_tool(tool_name)
            
            if not tool_credentials:
                # Fail closed - return 503 before any execution
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Service unavailable: No credentials found for tool '{tool_name}'. "
                           f"EDON_CREDENTIALS_STRICT=true requires credentials to be stored in database. "
                           f"Use POST /credentials/set to configure credentials."
                )
        
        # Evaluate action (with latency measurement)
        import time
        eval_start = time.time()
        decision = governor.evaluate(action, intent)
        eval_latency_ms = (time.time() - eval_start) * 1000
        
        # Record benchmark
        benchmark_collector = get_benchmark_collector()
        verdict_str = decision.verdict.value if hasattr(decision.verdict, "value") else str(decision.verdict)
        benchmark_collector.record_decision(
            verdict=verdict_str,
            latency_ms=eval_latency_ms,
            endpoint="/execute"
        )
        
        # Record metrics (both custom collector and Prometheus)
        metrics_collector.increment_counter("edon_decisions_total", {"verdict": verdict_str})
        metrics_collector.observe_histogram("edon_decision_latency_ms", eval_latency_ms, {"endpoint": "/execute"})
        
        # Record Prometheus metrics (if enabled)
        if config.METRICS_ENABLED:
            reason_code_str = decision.reason_code.value if hasattr(decision.reason_code, "value") else str(decision.reason_code)
            prometheus_decisions_total.labels(verdict=verdict_str, reason_code=reason_code_str).inc()
            prometheus_decision_latency_ms.labels(endpoint="/execute").observe(eval_latency_ms)
        
        # Save audit event to database (for all verdicts, including denied)
        try:
            action_dict = action.to_dict()
            decision_dict = decision.to_dict()
            decision_id = db.save_audit_event(
                action=action_dict,
                decision=decision_dict,
                intent_id=intent_id_for_audit,
                agent_id=request.agent_id,
                context={"agent_id": request.agent_id}
            )
        except Exception as e:
            # Log error but don't fail the request - audit logging should not block execution
            import logging
            logging.error(f"Failed to save audit event: {str(e)}")
            # Generate a fallback decision_id
            decision_id = f"dec-{action.id}-{datetime.now(UTC).isoformat()}"
        
        # Also log to JSONL for backward compatibility (Phase C: will remove)
        audit_logger.log(action, decision, intent, {
            "agent_id": request.agent_id,
            "intent_id": intent_id_for_audit
        })
        
        # SECURITY INVARIANT: Only execute on ALLOW or DEGRADE with safe_alternative
        # This ensures no execution occurs unless verdict is explicitly executable
        if decision.verdict not in [Verdict.ALLOW, Verdict.DEGRADE]:
            # Return decision without execution block
            return ExecuteResponse(
                verdict=decision.verdict.value,
                decision_id=decision_id,
                reason_code=decision.reason_code.value if decision.reason_code else None,
                explanation=decision.explanation,
                safe_alternative=decision.safe_alternative.to_dict() if decision.safe_alternative else None,
                execution=None,  # No execution for non-executable verdicts
                timestamp=datetime.now(UTC).isoformat()
            )
        
        if decision.verdict == Verdict.DEGRADE:
            if decision.safe_alternative is None:
                raise HTTPException(
                    status_code=500,
                    detail="DEGRADE verdict requires safe_alternative"
                )
        
        # If allowed, execute tool through real connector
        execution = None
        if decision.verdict == Verdict.ALLOW:
            try:
                execution = _execute_tool(action)
            except RuntimeError as e:
                # Credential errors in strict mode
                if "Credential" in str(e) and "not found" in str(e):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=f"Service unavailable: {str(e)}"
                    )
                raise
        elif decision.verdict == Verdict.DEGRADE and decision.safe_alternative:
            # Execute degraded action
            try:
                execution = _execute_tool(decision.safe_alternative)
            except RuntimeError as e:
                # Credential errors in strict mode
                if "Credential" in str(e) and "not found" in str(e):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=f"Service unavailable: {str(e)}"
                    )
                raise
        
        # Handle reason_code safely
        reason_code_value = None
        if decision.reason_code:
            if hasattr(decision.reason_code, 'value'):
                reason_code_value = decision.reason_code.value
            else:
                reason_code_value = str(decision.reason_code)
        
        return ExecuteResponse(
            verdict=decision.verdict.value if hasattr(decision.verdict, 'value') else str(decision.verdict),
            decision_id=decision_id,
            reason_code=reason_code_value,
            explanation=decision.explanation,
            safe_alternative=decision.safe_alternative.to_dict() if decision.safe_alternative else None,
            execution=execution,
            timestamp=datetime.now(UTC).isoformat()
        )
        
    except HTTPException:
        # Re-raise HTTPException as-is (preserve status codes exactly)
        raise
    except Exception as e:
        import os
        import logging
        import traceback
        
        # Log full traceback server-side (never sent to client)
        logger = logging.getLogger(__name__)
        logger.error(f"Execution error: {str(e)}", exc_info=True)
        
        # Check if we're in production mode
        is_production = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"
        
        if is_production:
            # Production: Never return tracebacks or file paths
            # Return generic error message
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error. Please contact support."
            )
        else:
            # Development: Can include error message (but not full traceback)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Execution error: {str(e)}"
            )


@app.post("/intent/set", response_model=IntentSetResponse)
async def set_intent(request: IntentSetRequest):
    """Set or update an intent contract."""
    try:
        import uuid
        # Use canonical UUID-based intent_id (stable and opaque)
        intent_id = request.intent_id or f"intent_{uuid.uuid4().hex[:16]}"
        
        intent = IntentContract(
            objective=request.objective,
            scope=request.scope,
            constraints=request.constraints,
            risk_level=RiskLevel(request.risk_level),
            approved_by_user=request.approved_by_user
        )
        
        # Save to database
        db.save_intent(
            intent_id=intent_id,
            objective=request.objective,
            scope=request.scope,
            constraints=request.constraints,
            risk_level=request.risk_level,
            approved_by_user=request.approved_by_user
        )
        
        return IntentSetResponse(
            intent_id=intent_id,
            created_at=intent.created_at.isoformat(),
            status="active"
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid intent: {str(e)}")


@app.get("/intent/get", response_model=IntentGetResponse)
async def get_intent(intent_id: str):
    """Get current intent contract."""
    intent_data = db.get_intent(intent_id)
    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")
    
    return IntentGetResponse(
        intent_id=intent_id,
        objective=intent_data["objective"],
        scope=intent_data["scope"],
        constraints=intent_data["constraints"],
        created_at=intent_data["created_at"]
    )


@app.get("/audit/query", response_model=AuditQueryResponse)
async def query_audit(
    agent_id: Optional[str] = None,
    verdict: Optional[str] = None,
    intent_id: Optional[str] = None,
    limit: int = 100
):
    """Query audit logs from database."""
    try:
        if limit < 1 or limit > 1000:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
        
        events = db.query_audit_events(
            agent_id=agent_id,
            verdict=verdict,
            intent_id=intent_id,
            limit=limit
        )
        
        return AuditQueryResponse(
            events=events,
            total=len(events),
            limit=limit
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit query error: {str(e)}")


@app.get("/decisions/query", response_model=DecisionQueryResponse)
async def query_decisions(
    action_id: Optional[str] = None,
    verdict: Optional[str] = None,
    intent_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100
):
    """Query decisions from database."""
    try:
        if limit < 1 or limit > 1000:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
        
        decisions = db.query_decisions(
            action_id=action_id,
            verdict=verdict,
            intent_id=intent_id,
            agent_id=agent_id,
            limit=limit
        )
        
        return DecisionQueryResponse(
            decisions=decisions,
            total=len(decisions),
            limit=limit
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decision query error: {str(e)}")


@app.get("/decisions/{decision_id}", response_model=Dict[str, Any])
async def get_decision(decision_id: str):
    """Get a specific decision by ID."""
    try:
        decision = db.get_decision(decision_id)
        if not decision:
            raise HTTPException(status_code=404, detail="Decision not found")
        return decision
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decision lookup error: {str(e)}")


@app.get("/health", response_model=HealthResponse)
@app.get("/healthz", response_model=HealthResponse)  # Render health check alias
async def health():
    """Health check endpoint for load balancers and monitoring."""
    import time
    # Simple uptime tracking (Phase C: will be more sophisticated)
    uptime_seconds = int(time.time() - app.state.start_time) if hasattr(app.state, 'start_time') else 0
    
    # Get active policy preset
    active_preset = db.get_active_policy_preset()
    preset_info = None
    if active_preset:
        preset_info = {
            "preset_name": active_preset["preset_name"],
            "applied_at": active_preset["applied_at"]
        }
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=uptime_seconds,
        governor={
            "policy_version": "1.0.0",
            "active_intents": len(db.list_intents()),
            "active_preset": preset_info
        }
    )


@app.get("/security/anti-bypass")
async def get_anti_bypass_status():
    """Get anti-bypass security status and recommendations.
    
    Returns:
        Security configuration, validation status, and bypass resistance score
    """
    status = validate_anti_bypass_setup()
    score = get_bypass_resistance_score()
    
    return {
        "status": status,
        "bypass_resistance": score,
        "secure": status.get("validation", {}).get("secure", False)
    }


# Policy Packs endpoints
@app.get("/policy-packs")
async def list_available_policy_packs():
    """List all available policy packs.
    
    Returns:
        List of policy packs with descriptions and summaries, plus active preset
    """
    return {
        "packs": list_policy_packs(),
        "default": "personal_safe",
        "active_preset": db.get_active_policy_preset()
    }


@app.post("/policy-packs/{pack_name}/apply")
async def apply_policy_pack_endpoint(
    pack_name: str,
    request: Request,
    objective: Optional[str] = None
):
    """Apply a policy pack and create an intent with clawdbot.invoke scope.
    
    This creates an intent contract that includes clawdbot.invoke in scope,
    ensuring Clawdbot users have a smooth experience without "not in scope" errors.
    
    For Clawdbot-specific packs (e.g., clawdbot_safe), the constraints include
    the allowed_clawdbot_tools list which is enforced during action evaluation.
    
    Args:
        pack_name: Policy pack name (personal_safe, work_safe, ops_admin, clawdbot_safe)
        objective: Optional custom objective
        request: FastAPI request (for tenant context if available)
        
    Returns:
        Created intent contract with intent_id (use this in X-Intent-ID header)
        
    Example Response:
        {
            "intent_id": "intent_abc123",
            "policy_pack": "clawdbot_safe",
            "intent": {...},
            "active_preset": "clawdbot_safe",
            "message": "Use X-Intent-ID header: intent_abc123"
        }
    """
    import uuid
    
    try:
        intent_dict = apply_policy_pack(pack_name, objective)
        
        # Ensure clawdbot.invoke is in scope (critical for Clawdbot users)
        if "clawdbot" not in intent_dict["scope"]:
            intent_dict["scope"]["clawdbot"] = []
        if "invoke" not in intent_dict["scope"]["clawdbot"]:
            intent_dict["scope"]["clawdbot"].append("invoke")
        
        # For Clawdbot-specific packs, ensure constraints include allowed_clawdbot_tools
        # This is already set in the pack definition, but we validate it here
        if pack_name == "clawdbot_safe" or "clawdbot" in intent_dict.get("scope", {}):
            constraints = intent_dict.get("constraints", {})
            if "allowed_clawdbot_tools" not in constraints:
                constraints["allowed_clawdbot_tools"] = []
            if "blocked_clawdbot_tools" not in constraints:
                constraints["blocked_clawdbot_tools"] = []
            # Ensure web_execute is blocked by default for clawdbot_safe
            if pack_name == "clawdbot_safe":
                blocked = constraints.get("blocked_clawdbot_tools", [])
                if "web_execute" not in blocked:
                    blocked.append("web_execute")
                constraints["blocked_clawdbot_tools"] = blocked
            intent_dict["constraints"] = constraints
        
        # Generate unique intent_id (include tenant if available for multi-tenancy)
        tenant_id = None
        if request and hasattr(request.state, 'tenant_id'):
            tenant_id = request.state.tenant_id
            intent_id = f"intent_{tenant_id}_{pack_name}_{uuid.uuid4().hex[:8]}"
        else:
            # Fallback: use UUID-based intent_id for single-tenant or demo
            intent_id = f"intent_{pack_name}_{uuid.uuid4().hex[:12]}"
        
        # Save intent to database
        db.save_intent(
            intent_id=intent_id,
            objective=intent_dict["objective"],
            scope=intent_dict["scope"],
            constraints=intent_dict["constraints"],
            risk_level=intent_dict["risk_level"],
            approved_by_user=intent_dict["approved_by_user"]
        )
        
        # Persist active preset in database
        db.set_active_policy_preset(pack_name, applied_by="api")
        
        # Set as tenant default intent if tenant_id available
        if tenant_id:
            db.update_tenant_default_intent(tenant_id, intent_id)
            logger.info(f"Set default_intent_id for tenant '{tenant_id}': {intent_id}")
        
        logger.info(f"Policy pack '{pack_name}' applied with intent_id '{intent_id}'. Scope includes clawdbot.invoke: {intent_dict['scope'].get('clawdbot', [])}")
        
        return {
            "intent_id": intent_id,
            "policy_pack": pack_name,
            "intent": intent_dict,
            "active_preset": pack_name,
            "message": f"Policy pack applied. Intent ID saved as default for tenant.",
            "scope_includes_clawdbot": "invoke" in intent_dict["scope"].get("clawdbot", [])
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




# Benchmarking endpoints
@app.get("/benchmark/trust-spec")
async def get_trust_spec_sheet_endpoint():
    """Get trust spec sheet with key metrics.
    
    This is what blitzscaling/adopters will ask for:
    - Latency overhead
    - Block rate
    - Bypass resistance
    - Integration time
    """
    return get_trust_spec_sheet()


@app.get("/benchmark/report")
async def get_benchmark_report():
    """Get comprehensive benchmark report."""
    collector = get_benchmark_collector()
    return collector.get_benchmark_report()


@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint (for ops teams and standard tooling).
    
    Returns metrics in Prometheus exposition format for scraping.
    Auth required in production (configure Prometheus with bearer token).
    """
    if not config.METRICS_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Metrics collection is disabled. Set EDON_METRICS_ENABLED=true to enable."
        )
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/timeseries")
async def get_timeseries(days: int = 7):
    """Get time series data for decisions over time.
    
    Args:
        days: Number of days to look back (default: 7, max: 30)
    
    Returns:
        List of time series points with decision counts by verdict
    """
    from datetime import datetime, timedelta, UTC
    from collections import defaultdict
    
    # Limit days to reasonable range
    days = min(max(days, 1), 30)
    
    # Calculate time range
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(days=days)
    
    # Get all decisions in time range
    all_decisions = db.query_decisions(limit=100000)
    
    # Filter by time range and group by hour/day
    time_buckets = defaultdict(lambda: {"allowed": 0, "blocked": 0, "confirm": 0})
    
    for decision in all_decisions:
        created_at_str = decision.get("created_at") or decision.get("timestamp")
        if not created_at_str:
            continue
        
        try:
            # Parse timestamp (ISO format)
            if isinstance(created_at_str, str):
                if 'T' in created_at_str:
                    decision_time = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                else:
                    decision_time = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S")
                    decision_time = decision_time.replace(tzinfo=UTC)
            else:
                continue
        except (ValueError, AttributeError):
            continue
        
        # Skip if outside time range
        if decision_time < start_time or decision_time > end_time:
            continue
        
        # Group by hour for <= 7 days, by day for > 7 days
        if days <= 7:
            bucket_key = decision_time.strftime("%Y-%m-%d %H:00")
            label = decision_time.strftime("%m/%d %H:00")
        else:
            bucket_key = decision_time.strftime("%Y-%m-%d")
            label = decision_time.strftime("%m/%d")
        
        # Get verdict and map to UI format
        verdict = decision.get("verdict", "").upper()
        if verdict == "ALLOW":
            time_buckets[bucket_key]["allowed"] += 1
        elif verdict == "BLOCK":
            time_buckets[bucket_key]["blocked"] += 1
        elif verdict in ["ESCALATE", "DEGRADE", "PAUSE"]:
            time_buckets[bucket_key]["confirm"] += 1
        
        # Store label if not set
        if "label" not in time_buckets[bucket_key]:
            time_buckets[bucket_key]["label"] = label
            time_buckets[bucket_key]["timestamp"] = decision_time.isoformat()
    
    # Convert to list and sort by timestamp
    result = []
    for bucket_key, counts in sorted(time_buckets.items()):
        result.append({
            "timestamp": counts.get("timestamp", bucket_key),
            "label": counts.get("label", bucket_key),
            "allowed": counts["allowed"],
            "blocked": counts["blocked"],
            "confirm": counts["confirm"],
        })
    
    return result


@app.get("/block-reasons")
async def get_block_reasons(days: int = 7):
    """Get top block reasons from decisions.
    
    Returns:
        List of block reasons with counts, sorted by count descending
    """
    from collections import Counter
    from datetime import datetime, timedelta, UTC
    
    # Get all decisions (filter to window below)
    all_decisions = db.query_decisions(limit=100000)

    # Time window (defaults to last 7 days)
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=max(days, 0)) if days else None

    def parse_ts(value):
        if not value:
            return None
        if isinstance(value, (int, float)):
            # Heuristic: ms vs seconds
            ts = value / 1000 if value > 1e12 else value
            return datetime.fromtimestamp(ts, UTC)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except Exception:
                return None
        return None
    
    # Filter blocked decisions and count reason codes
    block_reasons = Counter()
    
    for decision in all_decisions:
        decision_time = parse_ts(decision.get("timestamp") or decision.get("created_at"))
        if cutoff and (decision_time is None or decision_time < cutoff):
            continue
        verdict = decision.get("verdict", "").upper()
        if verdict == "BLOCK":
            reason_code = decision.get("reason_code", "UNKNOWN")
            explanation = decision.get("explanation", "")
            
            # Use explanation if available, otherwise reason_code
            reason_text = explanation if explanation else reason_code
            block_reasons[reason_text] += 1
    
    # Convert to list format and sort by count
    result = [
        {"reason": reason, "count": count}
        for reason, count in block_reasons.most_common(10)  # Top 10
    ]
    
    return result


@app.get("/debug/auth")
async def debug_auth_status():
    """Return safe auth/config info for debugging (no secrets)."""
    env_path = Path(__file__).parent / ".env"
    environment = os.getenv("ENVIRONMENT") or os.getenv("EDON_ENV") or "development"
    token_fallback_enabled = config.AUTH_ENABLED and not config.is_production()

    return {
        "environment": environment,
        "auth_enabled": config.AUTH_ENABLED,
        "credentials_strict": config.CREDENTIALS_STRICT,
        "token_hardening": config.TOKEN_HARDENING,
        "token_fallback_enabled": token_fallback_enabled,
        "env_file": {
            "path": str(env_path),
            "exists": env_path.exists(),
        },
        "cors_origins": config.CORS_ORIGINS,
    }


@app.get("/debug/auth-public")
async def debug_auth_public():
    """Public auth debug info (no secrets) for local troubleshooting."""
    env_path = Path(__file__).parent / ".env"
    environment = os.getenv("ENVIRONMENT") or os.getenv("EDON_ENV") or "development"
    api_token = config.API_TOKEN or ""
    token_is_default = api_token in ["", "your-secret-token", "your-secret-token-change-me", "production-token-change-me"]

    return {
        "environment": environment,
        "auth_enabled": config.AUTH_ENABLED,
        "credentials_strict": config.CREDENTIALS_STRICT,
        "token_hardening": config.TOKEN_HARDENING,
        "token_fallback_enabled": config.AUTH_ENABLED and not config.is_production(),
        "api_token": {
            "length": len(api_token),
            "last4": api_token[-4:] if api_token else "",
            "is_default": token_is_default,
        },
        "env_file": {
            "path": str(env_path),
            "exists": env_path.exists(),
        },
    }


@app.get("/stats", response_model=MetricsResponse)
async def get_stats():
    """JSON stats endpoint (for UI, demos, and quick debugging).
    
    Returns aggregated metrics in JSON format:
    - Decision counts by verdict and reason code
    - Rate limit hit counts
    - Intent counts
    - System uptime
    
    Note: No sensitive data (no credentials, no agent IDs, no tokens).
    Auth required.
    """
    import time
    from collections import Counter
    
    # Get decision counts from database
    # Query all decisions (no limit) to get accurate total count
    all_decisions = db.query_decisions(limit=100000)  # Get all decisions for accurate count
    
    # Count by verdict
    verdict_counts = Counter(dec.get("verdict", "UNKNOWN") for dec in all_decisions)
    
    # Count by reason code
    reason_counts = Counter(dec.get("reason_code", "UNKNOWN") for dec in all_decisions if dec.get("reason_code"))
    
    # Count rate limit hits (from counters table)
    rate_limit_hits = 0
    # Note: In a full implementation, we'd track rate limit hits separately
    # For now, we can query counters table for rate_limit:* keys
    
    # Get intent count
    active_intents = len(db.list_intents())
    
    # Get active preset
    active_preset = db.get_active_policy_preset()
    
    # Uptime
    uptime_seconds = int(time.time() - app.state.start_time) if hasattr(app.state, 'start_time') else 0
    
    # Update Prometheus gauges (if enabled)
    if config.METRICS_ENABLED:
        prometheus_active_intents.set(active_intents)
        prometheus_uptime_seconds.set(uptime_seconds)
    
    return MetricsResponse(
        decisions_total=len(all_decisions),
        decisions_by_verdict=dict(verdict_counts),
        decisions_by_reason_code=dict(reason_counts),
        rate_limit_hits_total=rate_limit_hits,
        active_intents=active_intents,
        uptime_seconds=uptime_seconds,
        version="1.0.0",
        active_preset=active_preset
    )


# Credential management endpoints
class CredentialSetRequest(BaseModel):
    """Set credential request."""
    credential_id: str
    tool_name: str
    credential_type: str
    credential_data: Dict[str, Any]
    encrypted: bool = False


class CredentialSetResponse(BaseModel):
    """Set credential response."""
    credential_id: str
    tool_name: str
    status: str


class CredentialGetResponse(BaseModel):
    """Get credential response."""
    credential_id: str
    tool_name: str
    credential_type: str
    credential_data: Dict[str, Any]
    encrypted: bool
    created_at: str
    updated_at: str


@app.post("/credentials/set", response_model=CredentialSetResponse)
async def set_credential(request: CredentialSetRequest):
    """Set or update a tool credential."""
    try:
        db.save_credential(
            credential_id=request.credential_id,
            tool_name=request.tool_name,
            credential_type=request.credential_type,
            credential_data=request.credential_data,
            encrypted=request.encrypted
        )
        
        return CredentialSetResponse(
            credential_id=request.credential_id,
            tool_name=request.tool_name,
            status="saved"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid credential: {str(e)}")


# Credential readback disabled for security
# Credentials can be set but not read back via API
# This prevents credential exfiltration even if API is compromised

@app.delete("/credentials/{credential_id}")
async def delete_credential(credential_id: str):
    """Delete a credential.
    
    Note: Credential readback is disabled for security.
    Use this endpoint only to remove credentials.
    """
    deleted = db.delete_credential(credential_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"status": "deleted", "credential_id": credential_id}


# Clawdbot Proxy Endpoint - Drop-in replacement for Clawdbot Gateway /tools/invoke
class ClawdbotInvokeRequest(BaseModel):
    """Clawdbot invoke request - mirrors Clawdbot Gateway schema exactly."""
    tool: str
    action: str = "json"
    args: Dict[str, Any] = {}
    sessionKey: Optional[str] = None


class ClawdbotInvokeResponse(BaseModel):
    """Clawdbot invoke response - mirrors Clawdbot Gateway schema."""
    ok: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # EDON-specific fields (added for transparency)
    edon_verdict: Optional[str] = None
    edon_explanation: Optional[str] = None




# Alias endpoint for /edon/invoke (calls same handler as /clawdbot/invoke)
# This provides a prettier name but uses the same implementation
@app.post("/edon/invoke", response_model=ClawdbotInvokeResponse)
async def edon_invoke_alias(
    http_request: Request,
    payload: ClawdbotInvokeRequest,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    x_edon_agent_id: Optional[str] = Header(None, alias="X-EDON-Agent-ID"),
    x_intent_id: Optional[str] = Header(None, alias="X-Intent-ID")
):
    """Alias for /clawdbot/invoke - provides prettier endpoint name.
    
    This endpoint calls the same handler as /clawdbot/invoke.
    Use /clawdbot/invoke for the canonical adoption endpoint.
    """
    # Call the same handler function
    return await clawdbot_invoke_proxy(
        http_request=http_request,
        payload=payload,
        x_agent_id=x_agent_id,
        x_edon_agent_id=x_edon_agent_id,
        x_intent_id=x_intent_id
    )


@app.post("/clawdbot/invoke", response_model=ClawdbotInvokeResponse)
async def clawdbot_invoke_proxy(
    http_request: Request,
    payload: ClawdbotInvokeRequest,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    x_edon_agent_id: Optional[str] = Header(None, alias="X-EDON-Agent-ID"),
    x_intent_id: Optional[str] = Header(None, alias="X-Intent-ID")
):
    """EDON Proxy Runner - Drop-in replacement for Clawdbot Gateway /tools/invoke.
    
    This endpoint mirrors Clawdbot's exact schema, allowing users to switch from:
        POST clawdbot-gateway/tools/invoke
    to:
        POST edon-gateway/clawdbot/invoke
    
    in 5 minutes with zero code changes.
    
    **How it works:**
    1. Accepts Clawdbot's exact request schema
    2. Converts to EDON Action format
    3. Evaluates through EDON governance
    4. If ALLOW → calls Clawdbot Gateway
    5. If BLOCK → returns BLOCK + explanation (Clawdbot never receives call)
    
    **Request Schema (matches Clawdbot exactly):**
    ```json
    {
      "tool": "sessions_list",
      "action": "json",
      "args": {},
      "sessionKey": "optional-session-key"
    }
    ```
    
    **Response Schema (matches Clawdbot, with EDON transparency):**
    ```json
    {
      "ok": true,
      "result": {...},
      "edon_verdict": "ALLOW",
      "edon_explanation": "Action approved"
    }
    ```
    
    Or if blocked:
    ```json
    {
      "ok": false,
      "error": "Clawdbot tool 'web_execute' not in allowed list",
      "edon_verdict": "BLOCK",
      "edon_explanation": "Clawdbot tool 'web_execute' not in allowed list. Allowed: ['sessions_list']"
    }
    ```
    """
    try:
        # Get agent_id from headers (prefer X-EDON-Agent-ID, fallback to X-Agent-ID, then default)
        agent_id = x_edon_agent_id or x_agent_id or "clawdbot-agent"
        intent_id = x_intent_id
        
        # Convert Clawdbot request to EDON Action format
        action = Action(
            tool=Tool.CLAWDBOT,
            op="invoke",
            params={
                "tool": payload.tool,
                "action": payload.action,
                "args": payload.args,
                "sessionKey": payload.sessionKey
            },
            requested_at=datetime.now(UTC),
            source=ActionSource.AGENT,
            tags=["clawdbot-proxy"]
        )
        
        # Load intent (use tenant default if not provided)
        intent = None
        intent_id_for_audit = intent_id
        
        # Get tenant_id from request state
        tenant_id = None
        if http_request and hasattr(http_request.state, 'tenant_id'):
            tenant_id = http_request.state.tenant_id
        
        # If no X-Intent-ID header, try tenant default_intent_id
        if not intent_id and tenant_id:
            default_intent_id = db.get_tenant_default_intent(tenant_id)
            if default_intent_id:
                intent_id = default_intent_id
                intent_id_for_audit = intent_id
                logger.info(f"Using tenant default_intent_id: {intent_id}")
        
        if intent_id:
            intent_data = db.get_intent(intent_id)
            if intent_data:
                intent = IntentContract(
                    objective=intent_data["objective"],
                    scope=intent_data["scope"],
                    constraints=intent_data["constraints"],
                    risk_level=RiskLevel(intent_data["risk_level"]),
                    approved_by_user=bool(intent_data["approved_by_user"])
                )
        
        # If no intent provided, return clean error
        if not intent:
            raise HTTPException(
                status_code=400,
                detail="No intent configured. Apply a policy pack first via POST /policy-packs/{pack_name}/apply"
            )
        
        # Check credentials in strict mode BEFORE governor evaluation
        import os
        credentials_strict = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"
        
        if credentials_strict:
            tool_name = "clawdbot"
            tool_credentials = db.get_credentials_by_tool(tool_name)
            
            if not tool_credentials:
                return ClawdbotInvokeResponse(
                    ok=False,
                    error=f"Service unavailable: No credentials found for tool 'clawdbot'. EDON_CREDENTIALS_STRICT=true requires credentials to be stored in database.",
                    edon_verdict="BLOCK",
                    edon_explanation="Credentials not configured"
                )
        
        # Evaluate action through EDON governance
        decision = governor.evaluate(action, intent)
        
        # Save audit event
        try:
            action_dict = action.to_dict()
            decision_dict = decision.to_dict()
            decision_id = db.save_audit_event(
                action=action_dict,
                decision=decision_dict,
                intent_id=intent_id_for_audit,
                agent_id=agent_id,
                context={"agent_id": agent_id, "proxy": True}
            )
        except Exception as e:
            import logging
            logging.error(f"Failed to save audit event: {str(e)}")
            decision_id = f"dec-{action.id}-{datetime.now(UTC).isoformat()}"
        
        # If BLOCK/ESCALATE/PAUSE, return error (Clawdbot never receives call)
        if decision.verdict not in [Verdict.ALLOW, Verdict.DEGRADE]:
            return ClawdbotInvokeResponse(
                ok=False,
                error=decision.explanation or f"Action blocked: {decision.verdict.value}",
                edon_verdict=decision.verdict.value,
                edon_explanation=decision.explanation
            )
        
        # ALLOW or DEGRADE → Execute through Clawdbot connector
        # Load credential from DB and create connector instance
        try:
            from .connectors.clawdbot_connector import ClawdbotConnector
            
            # Get tenant_id from request state
            tenant_id = None
            if http_request and hasattr(http_request.state, 'tenant_id'):
                tenant_id = http_request.state.tenant_id
            
            # Get credential_id from config (loads from DB)
            credential_id = config.CLAWDBOT_CREDENTIAL_ID
            
            # Create connector instance with credential_id and tenant_id (loads from DB)
            connector = ClawdbotConnector(credential_id=credential_id, tenant_id=tenant_id)
            
            result = connector.invoke(
                tool=request.tool,
                action=request.action,
                args=request.args,
                sessionKey=request.sessionKey
            )
            
            # Convert EDON connector result to Clawdbot format
            if result.get("success"):
                return ClawdbotInvokeResponse(
                    ok=True,
                    result=result.get("result", {}),
                    edon_verdict=decision.verdict.value,
                    edon_explanation=decision.explanation
                )
            else:
                return ClawdbotInvokeResponse(
                    ok=False,
                    error=result.get("error", "Unknown error"),
                    edon_verdict=decision.verdict.value,
                    edon_explanation=decision.explanation
                )
        except Exception as e:
            return ClawdbotInvokeResponse(
                ok=False,
                error=f"Execution failed: {str(e)}",
                edon_verdict=decision.verdict.value,
                edon_explanation=decision.explanation
            )
            
    except Exception as e:
        import logging
        logging.error(f"Clawdbot proxy error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Proxy error: {str(e)}"
        )


def _execute_tool(action: Action) -> Dict[str, Any]:
    """Execute tool through real connector.
    
    This is the ONLY path to side effects. The agent cannot execute
    tools directly - it must go through EDON Gateway.
    
    Args:
        action: Action to execute
        
    Returns:
        Execution result dictionary
    """
    try:
        if action.tool == Tool.EMAIL:
            if action.op == "draft":
                result = email_connector.draft(
                    recipients=action.params.get("recipients", []),
                    subject=action.params.get("subject", ""),
                    body=action.params.get("body", "")
                )
            elif action.op == "send":
                result = email_connector.send(
                    recipients=action.params.get("recipients", []),
                    subject=action.params.get("subject", ""),
                    body=action.params.get("body", "")
                )
            else:
                return {
                    "tool": action.tool.value,
                    "op": action.op,
                    "result": {
                        "success": False,
                        "error": f"Unknown email operation: {action.op}"
                    }
                }
            
            return {
                "tool": action.tool.value,
                "op": action.op,
                "result": result
            }
        
        elif action.tool == Tool.FILE:
            if action.op == "read_file":
                result = filesystem_connector.read_file(
                    path=action.params.get("path", "")
                )
            elif action.op == "write_file":
                result = filesystem_connector.write_file(
                    path=action.params.get("path", ""),
                    content=action.params.get("content", "")
                )
            elif action.op == "delete_file":
                result = filesystem_connector.delete_file(
                    path=action.params.get("path", "")
                )
            else:
                return {
                    "tool": action.tool.value,
                    "op": action.op,
                    "result": {
                        "success": False,
                        "error": f"Unknown file operation: {action.op}"
                    }
                }
            
            return {
                "tool": action.tool.value,
                "op": action.op,
                "result": result
            }
        
        elif action.tool == Tool.CLAWDBOT:
            if action.op == "invoke":
                # Load credential from DB and create connector instance
                from .connectors.clawdbot_connector import ClawdbotConnector
                
                # Get tenant_id if available (from request context if available)
                tenant_id = None
                # Note: In _execute_tool, we don't have direct access to request
                # This is called from /execute endpoint which has request context
                # For now, use default credential_id
                credential_id = config.CLAWDBOT_CREDENTIAL_ID
                
                # Create connector instance with credential_id (loads from DB)
                connector = ClawdbotConnector(credential_id=credential_id, tenant_id=tenant_id)
                
                result = connector.invoke(
                    tool=action.params.get("tool", ""),
                    action=action.params.get("action", "json"),
                    args=action.params.get("args", {}),
                    sessionKey=action.params.get("sessionKey")
                )
            else:
                return {
                    "tool": action.tool.value,
                    "op": action.op,
                    "result": {
                        "success": False,
                        "error": f"Unknown clawdbot operation: {action.op}"
                    }
                }
            
            return {
                "tool": action.tool.value,
                "op": action.op,
                "result": result
            }
        
        else:
            # Other tools not yet implemented
            return {
                "tool": action.tool.value,
                "op": action.op,
                "result": {
                    "success": False,
                    "error": f"Tool connector not implemented: {action.tool.value}"
                }
            }
    
    except Exception as e:
        return {
            "tool": action.tool.value,
            "op": action.op,
            "result": {
                "success": False,
                "error": str(e)
            }
        }

# ============================================
# Auth Provider Abstraction Layer
# ============================================

# Auth provider abstraction - Session Claims Contract
class SessionClaims(BaseModel):
    """Standardized session claims contract (auth provider agnostic).
    
    This contract allows easy migration between auth providers.
    All auth providers must yield these claims when validating tokens.
    """
    user_id: str  # Internal UUID (never changes)
    tenant_id: str  # Tenant UUID
    email: str
    role: str  # 'user', 'admin', etc.
    plan: str  # 'starter', 'pro', 'enterprise'
    status: str  # 'active', 'trial', 'past_due', 'canceled', 'inactive'


def validate_clerk_token(clerk_token: str) -> Optional[SessionClaims]:
    """Validate Clerk token and return standardized session claims.
    
    This function abstracts Clerk-specific token validation.
    To migrate to Supabase, replace this function's implementation.
    
    Args:
        clerk_token: Clerk session token (JWT)
        
    Returns:
        SessionClaims if valid, None if invalid
    """
    try:
        # TODO: Implement Clerk token validation
        # For now, this is a placeholder that shows the contract
        
        # In production, you would:
        # 1. Verify Clerk JWT signature
        # 2. Extract clerk_user_id from token
        # 3. Look up user in database by auth_provider='clerk', auth_subject=clerk_user_id
        # 4. Get tenant for that user
        # 5. Return SessionClaims with user_id, tenant_id, etc.
        
        # Example implementation (pseudo-code):
        # import jwt
        # decoded = jwt.decode(clerk_token, CLERK_PUBLIC_KEY, algorithms=["RS256"])
        # clerk_user_id = decoded["sub"]
        # 
        # from .persistence import get_db
        # db = get_db()
        # user = db.get_user_by_auth("clerk", clerk_user_id)
        # if not user:
        #     return None
        # tenant = db.get_tenant_by_user_id(user["id"])
        # if not tenant:
        #     return None
        # 
        # return SessionClaims(
        #     user_id=user["id"],
        #     tenant_id=tenant["id"],
        #     email=user["email"],
        #     role=user["role"],
        #     plan=tenant["plan"],
        #     status=tenant["status"]
        # )
        
        return None  # Placeholder
    except Exception as e:
        logger.error(f"Clerk token validation failed: {e}")
        return None


class AuthProviderRequest(BaseModel):
    """Request to link auth provider account."""
    auth_provider: str  # 'clerk', 'supabase', etc.
    auth_subject: str  # Provider's user ID
    email: str


class AuthProviderResponse(BaseModel):
    """Response after linking auth provider."""
    user_id: str  # Internal UUID
    tenant_id: str
    session_token: str  # EDON session token (JWT or similar)


@app.post("/auth/signup", response_model=AuthProviderResponse)
async def auth_signup(request: AuthProviderRequest):
    """Create or link auth provider account to EDON user/tenant.
    
    This endpoint creates:
    1. Internal user record (with UUID)
    2. Tenant record (linked to user)
    3. Returns session token
    
    Auth provider agnostic - works with Clerk, Supabase, etc.
    
    Args:
        request: Auth provider credentials (clerk_user_id, supabase_user_id, etc.)
        
    Returns:
        user_id, tenant_id, session_token
    """
    import uuid
    import hashlib
    from .persistence import get_db
    
    db = get_db()
    
    # Check if user already exists for this auth provider
    existing_user = db.get_user_by_auth(request.auth_provider, request.auth_subject)
    
    if existing_user:
        # User exists - get their tenant
        tenant = db.get_tenant_by_user_id(existing_user["id"])
        if tenant:
            # Generate session token (simplified - in production use JWT)
            session_token = f"edon_session_{uuid.uuid4().hex}"
            return AuthProviderResponse(
                user_id=existing_user["id"],
                tenant_id=tenant["id"],
                session_token=session_token
            )
    
    # Create new user
    user_id = str(uuid.uuid4())
    db.create_user(
        user_id=user_id,
        email=request.email,
        auth_provider=request.auth_provider,
        auth_subject=request.auth_subject,
        role="user"
    )
    
    # Create tenant for user
    tenant_id = f"tenant_{uuid.uuid4().hex[:16]}"
    db.create_tenant(tenant_id, user_id)
    
    # Generate initial API key
    api_key = f"edon_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    db.create_api_key(tenant_id, key_hash, "Initial Key")
    
    # Generate session token
    session_token = f"edon_session_{uuid.uuid4().hex}"
    
    return AuthProviderResponse(
        user_id=user_id,
        tenant_id=tenant_id,
        session_token=session_token
    )


@app.post("/auth/session")
async def get_session(authorization: str = Header(None)):
    """Get session claims from auth token.
    
    Validates auth provider token (Clerk, Supabase, etc.) and returns
    standardized session claims.
    
    This is the single contract point - all auth providers must yield SessionClaims.
    
    Args:
        authorization: Bearer token from auth provider
        
    Returns:
        SessionClaims
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    # Validate token based on auth provider
    # For Clerk, use validate_clerk_token
    # For Supabase, use validate_supabase_token (when migrated)
    claims = validate_clerk_token(token)
    
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return claims


# ============================================
# Billing & Subscription Endpoints
# ============================================

class SignupRequest(BaseModel):
    """Signup request."""
    email: str


class SignupResponse(BaseModel):
    """Signup response."""
    tenant_id: str
    checkout_url: Optional[str] = None
    message: str


@app.post("/billing/signup", response_model=SignupResponse)
async def signup(request: SignupRequest):
    """Sign up for EDON Gateway.
    
    Step 1: User provides email
    Step 2: Create tenant + Stripe customer
    Step 3: Return checkout URL (or success if free plan)
    
    Returns:
        Tenant ID and checkout URL (if payment required)
    """
    import uuid
    import hashlib
    
    try:
        from .billing import StripeClient
        from .persistence import get_db
        
        # NOTE: This endpoint is deprecated - use /auth/signup instead
        # Keeping for backward compatibility during migration
        
        # For new signups, user should come from Clerk first, then call this
        # For now, create a placeholder user if needed
        db = get_db()
        
        # Check if user exists by email (legacy support)
        # In production, this should come from Clerk session
        user_id = str(uuid.uuid4())
        auth_subject = f"legacy_{request.email}"  # Placeholder
        
        try:
            # Try to create Stripe customer
            stripe_client = StripeClient()
            tenant_id = f"tenant_{uuid.uuid4().hex[:16]}"
            customer = stripe_client.create_customer(
                email=request.email,
                metadata={"tenant_id": tenant_id}
            )
            stripe_customer_id = customer.id
        except Exception as e:
            logger.warning(f"Stripe customer creation failed: {e}")
            stripe_customer_id = None
            tenant_id = f"tenant_{uuid.uuid4().hex[:16]}"
        
        # Create user (legacy mode - no auth provider)
        try:
            db.create_user(
                user_id=user_id,
                email=request.email,
                auth_provider="legacy",
                auth_subject=auth_subject,
                role="user"
            )
        except Exception:
            # User might already exist
            pass
        
        # Create tenant linked to user
        db.create_tenant(tenant_id, user_id, stripe_customer_id)
        
        # Generate initial API key
        api_key = f"edon_{uuid.uuid4().hex}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        db.create_api_key(tenant_id, key_hash, "Initial Key")
        
        # For now, return success (free plan)
        # In production, redirect to Stripe checkout if payment required
        return SignupResponse(
            tenant_id=tenant_id,
            checkout_url=None,
            message=f"Account created! Your API key: {api_key} (save this - it won't be shown again)"
        )
        
    except Exception as e:
        logger.error(f"Signup error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")


class CreateCheckoutRequest(BaseModel):
    """Create checkout session request."""
    tenant_id: str
    plan: str  # starter, pro, enterprise
    success_url: str
    cancel_url: str


@app.post("/billing/checkout")
async def create_checkout(request: CreateCheckoutRequest):
    """Create Stripe checkout session.
    
    Step 2: User clicks "Upgrade" → creates checkout session
    
    Returns:
        Checkout session URL
    """
    try:
        from .billing import StripeClient
        from .persistence import get_db
        
        db = get_db()
        tenant = db.get_tenant(request.tenant_id)
        
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        import os
        
        # Use Stripe Payment Links for Starter plan (simpler, no customer required upfront)
        # For Enterprise, use custom checkout session
        if request.plan.lower() == "starter":
            # Use direct payment link for Starter plan
            payment_link = os.getenv("STRIPE_PAYMENT_LINK_STARTER", "https://buy.stripe.com/00w7sK5a0b5077YgXSfIs02")
            
            # Append tenant_id and plan to success URL for webhook processing
            # Stripe payment links support success_url parameter
            success_url_with_params = f"{request.success_url}?tenant_id={request.tenant_id}&plan={request.plan}"
            
            # For payment links, append tenant_id as client_reference_id
            # Stripe will include this in checkout.session.completed webhook
            checkout_url = f"{payment_link}?client_reference_id={request.tenant_id}"
            
            # Note: Payment links don't support custom success_url in the same way
            # The success URL is configured in Stripe dashboard for the payment link
            # You can configure it to redirect to: /onboarding/success?tenant_id={CLIENT_REFERENCE_ID}
            
            return {
                "checkout_url": checkout_url,
                "session_id": None,  # Payment links don't have session IDs upfront
                "payment_link": True
            }
        
        # For Enterprise, use custom checkout session (requires customer)
        if request.plan.lower() == "enterprise":
            if not tenant.get("stripe_customer_id"):
                raise HTTPException(status_code=400, detail="Stripe customer required for Enterprise plan. Please contact sales.")
            
            # Map plan names to Stripe price IDs
            price_ids = {
                "enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE", "")
            }
            
            price_id = price_ids.get(request.plan.lower())
            if not price_id:
                raise HTTPException(status_code=400, detail=f"Enterprise plan not configured. Please contact sales.")
            
            stripe_client = StripeClient()
            session = stripe_client.create_checkout_session(
                customer_id=tenant["stripe_customer_id"],
                price_id=price_id,
                success_url=request.success_url,
                cancel_url=request.cancel_url,
                metadata={"tenant_id": request.tenant_id, "plan": request.plan}
            )
            
            return {
                "checkout_url": session.url,
                "session_id": session.id,
                "payment_link": False
            }
        
        raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan}")
        
    except Exception as e:
        logger.error(f"Checkout creation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Checkout failed: {str(e)}")


@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events.
    
    Handles:
    - checkout.session.completed
    - invoice.paid
    - customer.subscription.updated
    - invoice.payment_failed
    """
    import os
    from .billing import StripeClient
    from .persistence import get_db
    
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    
    if not signature:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")
    
    try:
        stripe_client = StripeClient()
        event = stripe_client.verify_webhook(payload, signature)
        
        db = get_db()
        event_type = event["type"]
        data = event["data"]["object"]
        
        if event_type == "checkout.session.completed":
            # Payment successful - provision tenant + generate token + activate subscription
            # Support both payment links (client_reference_id) and checkout sessions (metadata)
            tenant_id = data.get("metadata", {}).get("tenant_id") or data.get("client_reference_id")
            subscription_id = data.get("subscription")
            customer_email = data.get("customer_details", {}).get("email") or data.get("customer_email")
            
            if tenant_id and subscription_id:
                subscription = stripe_client.get_subscription(subscription_id)
                # Get plan name from subscription or default to "starter" for payment links
                plan_name = subscription.get("items", {}).get("data", [{}])[0].get("price", {}).get("nickname") or "starter"
                
                # Check if tenant already has an API key (idempotent)
                existing_keys = db.list_api_keys(tenant_id)
                if not existing_keys:
                    # Generate API token (only if tenant doesn't have one)
                    import uuid
                    import hashlib
                    api_key = f"edon_{uuid.uuid4().hex}"
                    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
                    db.create_api_key(tenant_id, key_hash, "Initial Key")
                    logger.info(f"Generated API key for tenant {tenant_id}")
                    
                    # Store full token temporarily for onboarding email
                    # (In production, send email with token or store in secure cache)
                    # For now, token is shown once in onboarding success page
                
                # Activate subscription
                db.update_tenant_subscription(
                    tenant_id=tenant_id,
                    status="active",
                    plan=plan_name.lower() if plan_name else "starter",
                    stripe_subscription_id=subscription_id,
                    current_period_start=datetime.fromtimestamp(subscription.current_period_start, UTC).isoformat(),
                    current_period_end=datetime.fromtimestamp(subscription.current_period_end, UTC).isoformat()
                )
                logger.info(f"Subscription activated for tenant {tenant_id} (plan: {plan_name})")
            elif tenant_id and not subscription_id:
                # Payment link completed but no subscription yet (one-time payment)
                # This shouldn't happen for subscription payment links, but handle gracefully
                logger.warning(f"Payment completed for tenant {tenant_id} but no subscription found")
            elif not tenant_id and customer_email:
                # Payment link completed but no tenant_id - try to find by email
                # This can happen if payment link is used without client_reference_id
                user = db.get_user_by_auth("legacy", f"email_{customer_email}")
                if user:
                    tenant = db.get_tenant_by_user_id(user["id"])
                    if tenant:
                        tenant_id = tenant["id"]
                        logger.info(f"Found tenant {tenant_id} by email for payment link")
        
        elif event_type == "invoice.paid":
            # Invoice paid - ensure subscription is active
            subscription_id = data.get("subscription")
            if subscription_id:
                tenant = db.get_tenant_by_stripe_subscription(subscription_id)
                if tenant:
                    db.update_tenant_subscription(
                        tenant_id=tenant["id"],
                        status="active"
                    )
                    logger.info(f"Invoice paid for tenant {tenant['id']}")
        
        elif event_type == "customer.subscription.updated":
            # Subscription updated (plan change, cancellation, etc.)
            subscription_id = data.get("id")
            tenant = db.get_tenant_by_stripe_subscription(subscription_id)
            
            if tenant:
                status_map = {
                    "active": "active",
                    "trialing": "trial",
                    "past_due": "past_due",
                    "canceled": "canceled",
                    "unpaid": "inactive"
                }
                stripe_status = data.get("status", "active")
                new_status = status_map.get(stripe_status, "inactive")
                
                # Get plan from subscription
                plan_name = data.get("items", {}).get("data", [{}])[0].get("price", {}).get("nickname", "starter")
                
                db.update_tenant_subscription(
                    tenant_id=tenant["id"],
                    status=new_status,
                    plan=plan_name.lower() if plan_name else None,
                    current_period_start=datetime.fromtimestamp(data.get("current_period_start", 0), UTC).isoformat() if data.get("current_period_start") else None,
                    current_period_end=datetime.fromtimestamp(data.get("current_period_end", 0), UTC).isoformat() if data.get("current_period_end") else None,
                    cancel_at_period_end=data.get("cancel_at_period_end", False)
                )
                logger.info(f"Subscription updated for tenant {tenant['id']}: {new_status}")
        
        elif event_type == "invoice.payment_failed":
            # Payment failed - mark as past_due
            subscription_id = data.get("subscription")
            if subscription_id:
                tenant = db.get_tenant_by_stripe_subscription(subscription_id)
                if tenant:
                    db.update_tenant_subscription(
                        tenant_id=tenant["id"],
                        status="past_due"
                    )
                    logger.warning(f"Payment failed for tenant {tenant['id']}")
        
        return {"status": "success"}
        
    except ValueError as e:
        logger.error(f"Webhook verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    except Exception as e:
        logger.error(f"Webhook processing error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Webhook processing failed: {str(e)}")


class CreateApiKeyRequest(BaseModel):
    """Create API key request."""
    name: Optional[str] = None


class CreateApiKeyResponse(BaseModel):
    """Create API key response."""
    api_key: str
    api_key_id: str
    message: str


@app.post("/billing/api-keys", response_model=CreateApiKeyResponse)
async def create_api_key(request_body: CreateApiKeyRequest, request: Request):
    """Create a new API key for the authenticated tenant.
    
    Returns:
        New API key (shown only once)
    """
    import uuid
    import hashlib
    
    # Get tenant from request state (set by auth middleware)
    if not hasattr(request.state, 'tenant_id'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    tenant_id = request.state.tenant_id
    
    # Generate API key
    api_key = f"edon_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    db = get_db()
    api_key_id = db.create_api_key(tenant_id, key_hash, request.name)
    
    return CreateApiKeyResponse(
        api_key=api_key,
        api_key_id=api_key_id,
        message="API key created. Save this key - it won't be shown again."
    )


@app.get("/billing/api-keys")
async def list_api_keys(request: Request):
    """List all API keys for the authenticated tenant."""
    # Get tenant from request state
    if not hasattr(request.state, 'tenant_id'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    tenant_id = request.state.tenant_id
    db = get_db()
    keys = db.list_api_keys(tenant_id)
    
    return {
        "keys": keys,  # Changed from "api_keys" to "keys" to match frontend
        "total": len(keys)
    }


@app.delete("/billing/api-keys/{api_key_id}")
async def revoke_api_key(api_key_id: str):
    """Revoke an API key."""
    # Get tenant from request state
    if not hasattr(request.state, 'tenant_id'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    tenant_id = request.state.tenant_id
    db = get_db()
    
    # Verify key belongs to tenant
    keys = db.list_api_keys(tenant_id)
    if not any(k["id"] == api_key_id for k in keys):
        raise HTTPException(status_code=404, detail="API key not found")
    
    revoked = db.revoke_api_key(api_key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return {"status": "revoked", "api_key_id": api_key_id}


# Account endpoints (aliases for /billing/* for frontend consistency)
@app.get("/account/api-keys")
async def account_list_api_keys(request: Request):
    """List all API keys for the authenticated tenant (account endpoint)."""
    return await list_api_keys(request)


@app.get("/account/integrations")
async def get_integrations(request: Request):
    """Get integration details for the authenticated tenant.
    
    Returns:
        Clawdbot endpoint URL and instructions
    """
    return await integrations_account_handler(request)


@app.get("/demo/credentials")
async def get_demo_credentials():
    """Get demo credentials for testing (only available in demo mode).
    
    Returns demo tenant_id and API key for testing without payment.
    """
    from .config import config
    
    if not config.DEMO_MODE:
        raise HTTPException(
            status_code=403, 
            detail="Demo mode is not enabled. Set EDON_DEMO_MODE=true to enable."
        )
    
    return {
        "tenant_id": config.DEMO_TENANT_ID,
        "api_key": config.DEMO_API_KEY,
        "status": "active",
        "plan": "starter",
        "message": "Demo mode active - subscription checks bypassed"
    }


@app.get("/billing/status")
async def get_billing_status(request: Request):
    """Get billing status for the authenticated tenant."""
    from .config import config
    
    # In demo mode, return demo status without auth
    if config.DEMO_MODE:
        return {
            "tenant_id": config.DEMO_TENANT_ID,
            "email": "demo@edon.ai",
            "status": "active",
            "plan": "starter",
            "plan_limits": {
                "requests_per_month": 10000,
                "requests_per_day": 500,
                "requests_per_minute": 60
            },
            "usage": {
                "monthly": 0,
                "daily": 0
            },
            "current_period_end": None,
            "demo_mode": True
        }
    
    # Get tenant from request state
    if not hasattr(request.state, 'tenant_id'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    tenant_id = request.state.tenant_id
    db = get_db()
    tenant = db.get_tenant(tenant_id)
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Get usage
    from datetime import date
    monthly_usage = db.get_tenant_usage(tenant_id)
    daily_usage = db.get_tenant_usage(tenant_id, date.today().isoformat())
    
    # Get plan limits
    from .billing.plans import get_plan_limits
    limits = get_plan_limits(tenant["plan"])
    
    return {
        "tenant_id": tenant["id"],
        "email": tenant["email"],
        "status": tenant["status"],
        "plan": tenant["plan"],
        "plan_limits": {
            "requests_per_month": limits.requests_per_month,
            "requests_per_day": limits.requests_per_day,
            "requests_per_minute": limits.requests_per_minute
        },
        "usage": {
            "monthly": monthly_usage,
            "daily": daily_usage
        },
        "current_period_end": tenant["current_period_end"]
    }


# SPA Routing: Catch-all route for React Router (must be LAST, after all API routes)
# This ensures /audit, /decisions, etc. serve index.html for client-side routing
try:
    ui_path = Path(__file__).parent / "ui"
    console_ui_dist = ui_path / "console-ui" / "dist"
    
    if console_ui_dist.exists() and (console_ui_dist / "index.html").exists():
        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str, request: Request):
            """Serve React UI for all non-API routes (SPA routing support).
            
            This catch-all route handles client-side routing for React Router.
            API routes are matched first, so they won't be affected.
            """
            # Skip API routes, static files, and docs (these should already be handled)
            if (full_path.startswith("api/") or 
                full_path.startswith("docs") or 
                full_path.startswith("redoc") or 
                full_path.startswith("openapi.json") or
                full_path.startswith("health") or
                full_path.startswith("healthz") or
                full_path.startswith("assets/") or
                full_path.startswith("ui/")):
                raise HTTPException(status_code=404, detail="Not found")
            
            # Serve index.html for all other routes (React Router handles routing)
            return FileResponse(str(console_ui_dist / "index.html"))
except Exception:
    # If UI not available, let 404 handler catch it
    pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
