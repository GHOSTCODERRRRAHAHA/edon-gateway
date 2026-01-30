"""Integration routes for EDON Gateway."""

from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any, Optional
from ..schemas.integrations import ClawdbotConnectRequest, ClawdbotConnectResponse
from ..persistence import get_db
from ..connectors.clawdbot_connector import ClawdbotConnector
from ..logging_config import get_logger
from ..config import config

logger = get_logger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.post("/clawdbot/connect", response_model=ClawdbotConnectResponse)
async def connect_clawdbot(request: Request, body: ClawdbotConnectRequest):
    """Connect Clawdbot Gateway integration.
    
    Validates connection by calling sessions_list (if probe=true), then stores credentials.
    
    Args:
        request: FastAPI request (auth middleware populates tenant_id)
        body: Connection details
        
    Returns:
        Connection status and credential info
    """
    # Auth middleware already populated tenant_id (for tenant scoped keys)
    tenant_id = getattr(request.state, "tenant_id", None)
    
    # Optional probe before saving
    if body.probe:
        try:
            # Create an ephemeral connector instance using provided creds (not DB)
            connector = ClawdbotConnector.from_inline(
                base_url=body.base_url,
                auth_mode=body.auth_mode,
                secret=body.secret,
            )
            # Minimal probe: sessions_list
            result = connector.invoke(tool="sessions_list", action="json", args={})
            if not result.get("success"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Clawdbot probe failed: {result.get('error', 'Unknown error')}"
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Clawdbot probe failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=400, detail=f"Clawdbot probe failed: {str(e)}")
    
    # Save credential in EDON DB (tenant-scoped if tenant_id exists)
    db = get_db()
    credential_data = {
        "base_url": body.base_url,
        "auth_mode": body.auth_mode,
        "secret": body.secret,
    }
    
    # Use tenant-scoped credential_id if tenant_id exists
    credential_id = body.credential_id
    if tenant_id:
        credential_id = f"{body.credential_id}_{tenant_id}"
    
    db.save_credential(
        credential_id=credential_id,
        tool_name="clawdbot",
        credential_type="gateway",
        credential_data=credential_data,
        encrypted=True,
        tenant_id=tenant_id
    )
    
    logger.info(f"Clawdbot connected successfully. Credential ID: {credential_id}, Tenant: {tenant_id}")
    
    return ClawdbotConnectResponse(
        connected=True,
        credential_id=credential_id,
        base_url=body.base_url,
        auth_mode=body.auth_mode,
        message="Clawdbot connected. Credential saved.",
    )


@router.get("/account/integrations")
async def get_integration_status(request: Request) -> Dict[str, Any]:
    """Get integration status for current tenant.
    
    Returns:
        Integration status including:
        - connected: bool
        - base_url: Optional[str]
        - auth_mode: Optional[str]
        - last_ok_at: Optional[str]
        - last_error: Optional[str]
        - active_policy_pack: Optional[str]
        - default_intent_id: Optional[str]
    """
    try:
        # Get tenant_id from request state
        tenant_id = None
        if hasattr(request.state, 'tenant_id'):
            tenant_id = request.state.tenant_id
        
        db = get_db()
        
        # Get Clawdbot integration status
        integration_status = db.get_integration_status(tenant_id, tool_name="clawdbot")
        
        # Get active policy pack
        active_preset = db.get_active_policy_preset()
        
        # Get tenant default intent
        default_intent_id = None
        if tenant_id:
            default_intent_id = db.get_tenant_default_intent(tenant_id)
        
        # Network gating status
        from ..security.network_gating import validate_network_gating, get_clawdbot_base_url
        
        base_url = integration_status.get("base_url") or get_clawdbot_base_url()
        network_gating_enabled = config.NETWORK_GATING
        
        is_valid, reachability, risk, recommendation = validate_network_gating(
            base_url, 
            network_gating_enabled
        )
        
        clawdbot_status = {
            "connected": integration_status.get("connected", False),
            "base_url": integration_status.get("base_url"),
            "auth_mode": integration_status.get("auth_mode"),
            "last_ok_at": integration_status.get("last_ok_at"),
            "last_error": integration_status.get("last_error"),
            "active_policy_pack": active_preset.get("preset_name") if active_preset else None,
            "default_intent_id": default_intent_id,
            "network_gating_enabled": network_gating_enabled,
            "clawdbot_reachability": reachability,
            "bypass_risk": risk,
            "recommendation": recommendation if risk == "high" else None
        }
        
        return {"clawdbot": clawdbot_status}
        
    except Exception as e:
        logger.error(f"Failed to get integration status: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get integration status: {str(e)}"
        )
