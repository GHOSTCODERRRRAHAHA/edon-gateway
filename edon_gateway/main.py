# THIS IS THE EDON GATEWAY ENTRYPOINT. Do not start app.main:app for gateway traffic.
"""EDON Gateway FastAPI application."""

# NOTE: dotenv loading is now handled in config.py (at the very top)
# Do NOT load dotenv here - config.py handles it before Config class is defined

from fastapi import FastAPI, HTTPException, Depends, status, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, Counter, Histogram, Gauge
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, UTC
import os
from pathlib import Path

from .governor import EDONGovernor
from .schemas import Action, Decision, IntentContract, Tool, RiskLevel, Verdict, ActionSource
from .audit import AuditLogger
from .connectors.email_connector import email_connector, EmailConnector
from .connectors.filesystem_connector import filesystem_connector
from .connectors.clawdbot_connector import get_clawdbot_connector
from .middleware import AuthMiddleware, RateLimitMiddleware, ValidationMiddleware, MagValidationMiddleware
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
from .tenancy import get_request_tenant_id
from .routes.integrations import router as integrations_router
from .routes.integrations import get_integration_status as integrations_account_handler
from .routes.analytics import router as analytics_router
from .routes.auth import router as auth_router


# Setup logging
setup_logging()
logger = get_logger(__name__)

# Validate configuration
warnings = config.validate()
if warnings:
    for warning in warnings:
        logger.warning(f"Configuration warning: {warning}")


# Create the FastAPI app FIRST (so routers can be attached safely)
app = FastAPI(
    title="EDON Gateway",
    version="1.0.1",
    description="AI Agent Safety Layer with Governance and Policy Enforcement",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Conditionally include billing router AFTER app exists
if os.getenv("EDON_ENABLE_BILLING", "true").lower() == "true":
    from .billing.bootstrap import router as billing_router
    app.include_router(billing_router)
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

# MAG governance enforcement (requires Auth to resolve tenant)
app.add_middleware(MagValidationMiddleware)

# Authentication middleware (validates X-EDON-TOKEN header)
app.add_middleware(AuthMiddleware)

# Include routers
app.include_router(integrations_router)
app.include_router(analytics_router)
app.include_router(auth_router)

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
        "https://www.edoncore.com",
    ]
    # Add localhost only in development (not production)
    if os.getenv("ENVIRONMENT") != "production" and os.getenv("EDON_ENV") != "production":
        cors_origins.extend(
            [
                "http://localhost:5173",
                "http://localhost:3000",
                "http://localhost:8080",  # Agent UI dev server (Vite configured port)
                "http://127.0.0.1:8080",
                "http://localhost:5174",  # Vite default fallback port
                "http://[::1]:8080",  # IPv6 localhost
            ]
        )
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
from .persistence import get_db
db = get_db()
governor = EDONGovernor(db=db)
audit_logger = AuditLogger(Path("audit.log.jsonl"))  # Keep for backward compatibility

# Initialize app state
import time
app.state.start_time = time.time()


# Prometheus metrics (for ops teams and standard tooling)
# Only create if metrics are enabled
if config.METRICS_ENABLED:
    prometheus_decisions_total = Counter(
        "edon_decisions_total",
        "Total number of governance decisions",
        ["verdict", "reason_code"],
    )
    prometheus_decision_latency_ms = Histogram(
        "edon_decision_latency_ms",
        "Decision evaluation latency in milliseconds",
        ["endpoint"],
        buckets=[10, 50, 100, 200, 500, 1000, 2000, 5000],
    )
    prometheus_rate_limit_hits_total = Counter(
        "edon_rate_limit_hits_total",
        "Total number of rate limit hits",
    )
    prometheus_active_intents = Gauge(
        "edon_active_intents",
        "Number of active intent contracts currently registered",
    )
    prometheus_uptime_seconds = Gauge(
        "edon_uptime_seconds",
        "Gateway uptime in seconds",
    )
else:
    # Dummy objects when metrics disabled (to avoid NameError)
    prometheus_decisions_total = None
    prometheus_decision_latency_ms = None
    prometheus_rate_limit_hits_total = None
    prometheus_active_intents = None
    prometheus_uptime_seconds = None
# Startup event - validate schema version and network gating
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("Starting EDON Gateway...")
    logger.info(f"Gateway version: {app.version}")
    logger.info("=" * 60)

    from .persistence.schema_version import (
        check_schema_version,
        set_schema_version,
        get_current_schema_version,
        SCHEMA_VERSION,
    )

    if not check_schema_version(db):
        current_version = get_current_schema_version(db)
        logger.warning(
            f"Database schema version mismatch. Current: {current_version}, Expected: {SCHEMA_VERSION}"
        )
        set_schema_version(db, SCHEMA_VERSION)
        logger.info(f"Schema version set to {SCHEMA_VERSION}")
    else:
        logger.info(f"Database schema version OK: {SCHEMA_VERSION}")

    if config.METRICS_ENABLED:
        prometheus_active_intents.set(len(db.list_intents()))
        prometheus_uptime_seconds.set(0)

    if config.NETWORK_GATING:
        from .security.network_gating import validate_network_gating, get_clawdbot_base_url

        base_url = get_clawdbot_base_url()
        is_valid, reachability, risk, recommendation = validate_network_gating(base_url, True)

        if not is_valid:
            error_msg = (
                f"Network gating validation failed: Clawdbot Gateway is {reachability} (risk: {risk}).\n"
                f"Recommendation:\n{recommendation}"
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        logger.info(
            f"Network gating validation passed: Clawdbot Gateway is {reachability} (risk: {risk})"
        )

    logger.info("EDON Gateway startup complete")
# =========================
# Request / Response Models
# =========================

class ExecuteRequest(BaseModel):
    action: Dict[str, Any]
    intent_id: Optional[str] = None
    decision_id: Optional[str] = None
    decision_bundle: Optional[Dict[str, Any]] = None
    agent_id: str


class ExecuteResponse(BaseModel):
    verdict: str
    decision_id: str
    reason_code: Optional[str] = None
    explanation: str
    safe_alternative: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    timestamp: str


class IntentSetRequest(BaseModel):
    intent_id: Optional[str] = None
    objective: str
    scope: Dict[str, List[str]]
    constraints: Dict[str, Any] = {}
    risk_level: str = "medium"
    approved_by_user: bool = False


class IntentSetResponse(BaseModel):
    intent_id: str
    created_at: str
    status: str


class IntentGetResponse(BaseModel):
    intent_id: str
    objective: str
    scope: Dict[str, List[str]]
    constraints: Dict[str, Any]
    created_at: str


def _execute_tool(action: Action) -> Dict[str, Any]:
    """Execute the action via the appropriate connector. Returns dict with result or error and optional status_code (503)."""
    params = action.params or {}
    try:
        if action.tool == Tool.EMAIL:
            cred_id = os.getenv("EDON_EMAIL_CREDENTIAL_ID", "email_gateway")
            connector = EmailConnector(credential_id=cred_id) if cred_id else email_connector
            if action.op == "send":
                out = connector.send(
                    recipients=params.get("recipients", []),
                    subject=params.get("subject", ""),
                    body=params.get("body", ""),
                    **{k: v for k, v in params.items() if k not in ("recipients", "subject", "body")},
                )
            else:
                out = connector.draft(
                    recipients=params.get("recipients", []),
                    subject=params.get("subject", ""),
                    body=params.get("body", ""),
                    **{k: v for k, v in params.items() if k not in ("recipients", "subject", "body")},
                )
            return {"result": out}
        return {"result": {}}
    except Exception as e:
        logger.warning("Tool execution failed: %s", e)
        return {"error": str(e), "status_code": 503}


@app.post("/execute", response_model=ExecuteResponse)
async def execute_action(req: ExecuteRequest):
    if not req.agent_id.strip():
        raise HTTPException(status_code=400, detail="agent_id is required")
    if not req.action or "tool" not in req.action or "op" not in req.action:
        raise HTTPException(status_code=400, detail="Invalid action payload")

    intent = None
    intent_id_for_audit = req.intent_id

    if req.intent_id:
        intent_data = db.get_intent(req.intent_id)
        if intent_data:
            intent = IntentContract(
                objective=intent_data["objective"],
                scope=intent_data["scope"],
                constraints=intent_data["constraints"],
                risk_level=RiskLevel(intent_data["risk_level"]),
                approved_by_user=bool(intent_data["approved_by_user"]),
            )

    if not intent:
        intent = IntentContract(
            objective="Default intent",
            scope={},
            constraints={},
            risk_level=RiskLevel.MEDIUM,
            approved_by_user=False,
        )
        intent_id_for_audit = None

    action = Action(
        tool=Tool(req.action["tool"]),
        op=req.action["op"],
        params=req.action.get("params", {}),
        source=ActionSource.AGENT,
    )

    start = datetime.now(UTC)
    decision = governor.evaluate(action, intent)
    latency_ms = (datetime.now(UTC) - start).total_seconds() * 1000

    verdict_str = decision.verdict.value
    metrics_collector.increment_counter("edon_decisions_total", {"verdict": verdict_str})
    metrics_collector.observe_histogram(
        "edon_decision_latency_ms", latency_ms, {"endpoint": "/execute"}
    )

    try:
        decision_id = db.save_audit_event(
            action=action.to_dict(),
            decision=decision.to_dict(),
            intent_id=intent_id_for_audit,
            agent_id=req.agent_id,
            context={"agent_id": req.agent_id},
        )
    except Exception:
        logger.exception("Failed to persist decision/audit for /execute")
        decision_id = f"dec-{action.id}-{datetime.now(UTC).isoformat()}"

    if decision.verdict not in [Verdict.ALLOW, Verdict.DEGRADE]:
        return ExecuteResponse(
            verdict=decision.verdict.value,
            decision_id=decision_id,
            reason_code=decision.reason_code.value if decision.reason_code else None,
            explanation=decision.explanation,
            timestamp=datetime.now(UTC).isoformat(),
        )

    execution = _execute_tool(action)
    if isinstance(execution, dict) and execution.get("status_code") == 503:
        raise HTTPException(
            status_code=503,
            detail=execution.get("error", "Service unavailable"),
        )

    return ExecuteResponse(
        verdict=decision.verdict.value,
        decision_id=decision_id,
        reason_code=decision.reason_code.value if decision.reason_code else None,
        explanation=decision.explanation,
        execution=execution,
        timestamp=datetime.now(UTC).isoformat(),
    )
@app.post("/intent/set", response_model=IntentSetResponse)
async def set_intent(req: IntentSetRequest):
    import uuid

    intent_id = req.intent_id or f"intent_{uuid.uuid4().hex[:16]}"

    db.save_intent(
        intent_id=intent_id,
        objective=req.objective,
        scope=req.scope,
        constraints=req.constraints,
        risk_level=req.risk_level,
        approved_by_user=req.approved_by_user,
    )

    return IntentSetResponse(
        intent_id=intent_id,
        created_at=datetime.now(UTC).isoformat(),
        status="active",
    )


@app.get("/intent/get", response_model=IntentGetResponse)
async def get_intent(intent_id: str):
    intent_data = db.get_intent(intent_id)
    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    return IntentGetResponse(
        intent_id=intent_id,
        objective=intent_data["objective"],
        scope=intent_data["scope"],
        constraints=intent_data["constraints"],
        created_at=intent_data["created_at"],
    )
class AuditQueryResponse(BaseModel):
    events: List[Dict[str, Any]]
    total: int
    limit: int


class DecisionQueryResponse(BaseModel):
    decisions: List[Dict[str, Any]]
    total: int
    limit: int


@app.get("/audit/query", response_model=AuditQueryResponse)
async def query_audit(
    agent_id: Optional[str] = None,
    verdict: Optional[str] = None,
    intent_id: Optional[str] = None,
    limit: int = 100,
):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")

    events = db.query_audit_events(
        agent_id=agent_id,
        verdict=verdict,
        intent_id=intent_id,
        limit=limit,
    )

    return AuditQueryResponse(events=events, total=len(events), limit=limit)


@app.get("/decisions/query", response_model=DecisionQueryResponse)
async def query_decisions(
    action_id: Optional[str] = None,
    verdict: Optional[str] = None,
    intent_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100,
):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")

    decisions = db.query_decisions(
        action_id=action_id,
        verdict=verdict,
        intent_id=intent_id,
        agent_id=agent_id,
        limit=limit,
    )

    return DecisionQueryResponse(decisions=decisions, total=len(decisions), limit=limit)


@app.get("/decisions/{decision_id}")
async def get_decision(decision_id: str):
    decision = db.get_decision(decision_id)
    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")
    return decision
class HealthResponse(BaseModel):
    ok: bool = True
    status: str
    version: str
    uptime_seconds: int
    governor: Dict[str, Any]


class VersionResponse(BaseModel):
    version: str
    git_sha: str


@app.get("/health", response_model=HealthResponse)
@app.get("/healthz", response_model=HealthResponse)
async def health():
    import time

    uptime_seconds = int(time.time() - app.state.start_time)

    active_preset = db.get_active_policy_preset()
    preset_info = None
    if active_preset:
        preset_info = {
            "preset_name": active_preset["preset_name"],
            "applied_at": active_preset["applied_at"],
        }

    return HealthResponse(
        ok=True,
        status="healthy",
        version=app.version,
        uptime_seconds=uptime_seconds,
        governor={
            "policy_version": "1.0.0",
            "active_intents": len(db.list_intents()),
            "active_preset": preset_info,
        },
    )


@app.get("/version", response_model=VersionResponse)
def version():
    """Return app version and optional git SHA (set GIT_SHA at build time)."""
    git_sha = os.getenv("GIT_SHA", os.getenv("EDON_GIT_SHA", "unknown"))
    return VersionResponse(version=app.version, git_sha=git_sha)


@app.get("/security/anti-bypass")
async def get_anti_bypass_status():
    status_info = validate_anti_bypass_setup()
    score = get_bypass_resistance_score()
    return {
        "status": status_info,
        "bypass_resistance": score,
        "secure": status_info.get("validation", {}).get("secure", False),
    }


@app.get("/metrics")
def metrics():
    if not config.METRICS_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Metrics collection is disabled",
        )
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
@app.get("/policy-packs")
async def list_available_policy_packs():
    return {
        "packs": list_policy_packs(),
        "default": "personal_safe",
        "active_preset": db.get_active_policy_preset(),
    }


@app.post("/policy-packs/{pack_name}/apply")
async def apply_policy_pack_endpoint(
    pack_name: str,
    request: Request,
    objective: Optional[str] = None,
):
    import uuid

    intent_dict = apply_policy_pack(pack_name, objective)

    if "clawdbot" not in intent_dict["scope"]:
        intent_dict["scope"]["clawdbot"] = []
    if "invoke" not in intent_dict["scope"]["clawdbot"]:
        intent_dict["scope"]["clawdbot"].append("invoke")

    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        intent_id = f"intent_{tenant_id}_{pack_name}_{uuid.uuid4().hex[:8]}"
    else:
        intent_id = f"intent_{pack_name}_{uuid.uuid4().hex[:12]}"

    db.save_intent(
        intent_id=intent_id,
        objective=intent_dict["objective"],
        scope=intent_dict["scope"],
        constraints=intent_dict["constraints"],
        risk_level=intent_dict["risk_level"],
        approved_by_user=intent_dict["approved_by_user"],
    )

    db.set_active_policy_preset(pack_name, applied_by="api")

    return {
        "intent_id": intent_id,
        "policy_pack": pack_name,
        "intent": intent_dict,
        "active_preset": pack_name,
    }
class ClawdbotInvokeRequest(BaseModel):
    tool: str
    action: str = "json"
    args: Dict[str, Any] = {}
    sessionKey: Optional[str] = None
    decision_id: Optional[str] = None
    decision_bundle: Optional[Dict[str, Any]] = None
    credential_id: Optional[str] = Field(
        default=None,
        description="Optional Clawdbot credential_id to use for this invoke (tenant-scoped). "
        "If omitted, uses DEFAULT_CLAWDBOT_CREDENTIAL_ID.",
    )


class ClawdbotInvokeResponse(BaseModel):
    ok: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    edon_verdict: Optional[str] = None
    edon_explanation: Optional[str] = None
    details: Optional[Dict[str, Any]] = None  # dev-only: e.g. used_credential_id for tests


@app.post("/edon/invoke", response_model=ClawdbotInvokeResponse)
async def edon_invoke_alias(
    http_request: Request,
    payload: ClawdbotInvokeRequest,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    x_edon_agent_id: Optional[str] = Header(None, alias="X-EDON-Agent-ID"),
    x_intent_id: Optional[str] = Header(None, alias="X-Intent-ID"),
):
    return await clawdbot_invoke_proxy(
        http_request=http_request,
        payload=payload,
        x_agent_id=x_agent_id,
        x_edon_agent_id=x_edon_agent_id,
        x_intent_id=x_intent_id,
    )
@app.post("/clawdbot/invoke", response_model=ClawdbotInvokeResponse)
async def clawdbot_invoke_proxy(
    http_request: Request,
    payload: ClawdbotInvokeRequest,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    x_edon_agent_id: Optional[str] = Header(None, alias="X-EDON-Agent-ID"),
    x_intent_id: Optional[str] = Header(None, alias="X-Intent-ID"),
):
    agent_id = x_edon_agent_id or x_agent_id or "clawdbot-agent"
    tenant_id = get_request_tenant_id(http_request)

    # Build the Action (make sure 'action' exists before evaluate_action)
    action = Action(
        tool=Tool.CLAWDBOT,
        op="invoke",
        params={
            "tool": payload.tool,
            "action": payload.action,
            "args": payload.args,
            "sessionKey": payload.sessionKey,
        },
        requested_at=datetime.now(UTC),
        source=ActionSource.CLAWDBOT,
        tags=["clawdbot-proxy"],
    )

    # ───────────────────────── Governance ─────────────────────────
    default_intent = IntentContract(
        objective="Default intent",
        scope={},
        constraints={},
        risk_level=RiskLevel.MEDIUM,
        approved_by_user=False,
    )
    try:
        # Load intent contract (governor expects the full IntentContract)
        if x_intent_id:
            try:
                intent_contract = governor.get_intent(x_intent_id)
            except ValueError:
                intent_contract = default_intent
        else:
            # If no intent specified, fall back to active policy preset when available
            intent_contract = default_intent
            try:
                active_preset = db.get_active_policy_preset()
                if active_preset and active_preset.get("preset_name"):
                    pack = get_policy_pack(active_preset["preset_name"])
                    intent_dict = pack.to_intent_dict()
                    intent_contract = IntentContract(
                        objective=intent_dict["objective"],
                        scope=intent_dict["scope"],
                        constraints=intent_dict.get("constraints", {}),
                        risk_level=RiskLevel(intent_dict.get("risk_level", "LOW")),
                        approved_by_user=bool(intent_dict.get("approved_by_user", False)),
                    )
            except Exception:
                intent_contract = default_intent

        decision = governor.evaluate(
            action=action,
            intent=intent_contract,
            context={
                "agent_id": agent_id,
                "source": "clawdbot",
            },
        )
    except Exception as e:
        logger.exception("Decision evaluation failed")
        return ClawdbotInvokeResponse(
            ok=False,
            result=None,
            error=str(e),
            edon_verdict=Verdict.ERROR.value,
            edon_explanation="Decision engine error",
        )

    # ───────────────────────── Persist decision + audit (every verdict) ─────────────────────────
    persist_decisions = os.getenv("EDON_PERSIST_DECISIONS", "true").strip().lower() in ("true", "1", "yes")
    if not persist_decisions:
        logger.warning(
            "EDON_PERSIST_DECISIONS is disabled; decision/audit records for clawdbot invoke will not be persisted"
        )
    else:
        try:
            decision_id = db.save_audit_event(
                action=action.to_dict(),
                decision=decision.to_dict(),
                intent_id=x_intent_id,
                agent_id=agent_id,
                context={"agent_id": agent_id, "source": "clawdbot"},
            )
        except Exception as e:
            logger.exception("Failed to persist decision/audit for clawdbot invoke")
            return ClawdbotInvokeResponse(
                ok=False,
                result=None,
                error=f"Persistence failed: {str(e)}",
                edon_verdict=decision.verdict.value,
                edon_explanation=decision.explanation or "Decision recorded but DB write failed",
            )

    # Enforce executable allowlist (only allow forward execution on ALLOW/DEGRADE)
    if decision.verdict not in (Verdict.ALLOW, Verdict.DEGRADE):
        return ClawdbotInvokeResponse(
            ok=False,
            result=None,
            error=decision.explanation or f"Blocked: {decision.verdict.value}",
            edon_verdict=decision.verdict.value,
            edon_explanation=decision.explanation,
        )

    # ─────────────────── Execution (try/except inside function) ───────────────────
    from .config import config as app_config

    # Credential selection: payload.credential_id if present, else default
    credential_id = payload.credential_id or app_config.DEFAULT_CLAWDBOT_CREDENTIAL_ID
    _is_dev = os.getenv("ENVIRONMENT") != "production" and os.getenv("EDON_ENV") != "production"
    payload_dict = payload.model_dump()
    logger.info(
        "clawdbot/invoke payload (credential_id in request: %s), chosen credential_id: %s",
        payload_dict.get("credential_id"),
        credential_id,
    )

    try:
        from .connectors.clawdbot_connector import ClawdbotConnector

        connector = ClawdbotConnector(
            credential_id=credential_id,
            tenant_id=tenant_id,
        )

        result = connector.invoke(
            tool=payload.tool,
            action=payload.action,
            args=payload.args,
            sessionKey=payload.sessionKey,
        )

        _details = {"used_credential_id": credential_id} if _is_dev else None

        if result.get("success"):
            return ClawdbotInvokeResponse(
                ok=True,
                result=result.get("result", {}),
                edon_verdict=decision.verdict.value,
                edon_explanation=decision.explanation,
                details=_details,
            )

        # Downstream (Clawdbot Gateway) unreachable -> 503 with same envelope
        if result.get("downstream_unavailable"):
            body = ClawdbotInvokeResponse(
                ok=False,
                error=result.get("error", "Unknown Clawdbot execution error"),
                edon_verdict=Verdict.ERROR.value,
                edon_explanation="Clawdbot execution failed",
                details=_details,
            )
            return JSONResponse(status_code=503, content=body.model_dump())

        return ClawdbotInvokeResponse(
            ok=False,
            error=result.get("error", "Unknown Clawdbot execution error"),
            edon_verdict=Verdict.ERROR.value,
            edon_explanation="Clawdbot execution failed",
            details=_details,
        )
    except Exception as e:
        logger.error("Clawdbot proxy error", exc_info=True)
        _details = {"used_credential_id": credential_id} if _is_dev else None
        error_msg = str(e)
        if "HTTP error 401" in error_msg:
            body = ClawdbotInvokeResponse(
                ok=False,
                error=f"Execution failed: {error_msg}",
                edon_verdict=Verdict.ERROR.value,
                edon_explanation="Internal execution error",
                details=_details,
            )
            return JSONResponse(status_code=401, content=body.model_dump())
        return ClawdbotInvokeResponse(
            ok=False,
            error=f"Execution failed: {error_msg}",
            edon_verdict=Verdict.ERROR.value,
            edon_explanation="Internal execution error",
            details=_details,
        )
