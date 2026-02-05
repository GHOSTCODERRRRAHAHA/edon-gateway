"""Integration routes for EDON Gateway."""

from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta, UTC
from ..schemas.integrations import ClawdbotConnectRequest, ClawdbotConnectResponse
from ..persistence import get_db
from ..connectors.clawdbot_connector import ClawdbotConnector
from ..logging_config import get_logger
from ..config import config
from ..tenancy import get_request_tenant_id

logger = get_logger(__name__)

VALID_CONNECT_SERVICES = {"gmail", "google_calendar", "brave_search", "github", "elevenlabs"}
CONNECT_TTL_SECONDS = 600  # 10 minutes

router = APIRouter(prefix="/integrations", tags=["integrations"])

# Connect services for Telegram /connect command: id, label, type (oauth vs api_key)
CONNECT_SERVICES: List[Dict[str, str]] = [
    {"id": "gmail", "label": "Gmail", "type": "oauth"},
    {"id": "google_calendar", "label": "Google Calendar", "type": "oauth"},
    {"id": "brave_search", "label": "Brave Search", "type": "api_key"},
    {"id": "github", "label": "GitHub", "type": "api_key"},
    {"id": "elevenlabs", "label": "ElevenLabs", "type": "api_key"},
]

# Telegram inline keyboard: one row per service (callback_data = connect_<id>)
TELEGRAM_CONNECT_KEYBOARD: List[List[Dict[str, str]]] = [
    [{"text": "📧 Gmail", "callback_data": "connect_gmail"}],
    [{"text": "📅 Google Calendar", "callback_data": "connect_google_calendar"}],
    [{"text": "🔍 Brave Search", "callback_data": "connect_brave_search"}],
    [{"text": "🐙 GitHub", "callback_data": "connect_github"}],
    [{"text": "🔊 ElevenLabs", "callback_data": "connect_elevenlabs"}],
]


class TelegramConnectCodeRequest(BaseModel):
    channel: str = "telegram"


class TelegramVerifyCodeRequest(BaseModel):
    code: str
    user_id: str
    chat_id: Optional[str] = None
    username: Optional[str] = None


class ConnectLinkRequest(BaseModel):
    service: str
    chat_id: Optional[str] = None


class ApiKeySubmitRequest(BaseModel):
    code: str
    api_key: str


class GitHubTokenSubmitRequest(BaseModel):
    code: str
    token: str


def _resolve_connect_base_url(request: Request) -> str:
    """Base URL for connect pages (config or request base)."""
    base = config.CONNECT_BASE_URL
    if base:
        return base
    return str(request.base_url).rstrip("/")


def _get_and_validate_service_code(code: str) -> Dict[str, Any]:
    """Resolve service code; raise HTTPException if invalid."""
    code = (code or "").strip().upper()
    db = get_db()
    entry = db.get_connect_service_code(code)
    if not entry:
        raise HTTPException(status_code=404, detail="Connect code not found")
    if entry.get("used_at"):
        raise HTTPException(status_code=409, detail="Connect code already used")
    try:
        expires_at = datetime.fromisoformat(entry["expires_at"])
    except Exception:
        expires_at = None
    if not expires_at or expires_at < datetime.now(UTC):
        raise HTTPException(status_code=410, detail="Connect code expired")
    return entry


@router.get("/connect/buttons")
async def get_connect_buttons() -> Dict[str, Any]:
    """Return connect service buttons for Telegram /connect command.

    Use this from the Telegram bot to show which services users can connect
    (Gmail, Google Calendar, Brave Search, GitHub, ElevenLabs).
    Returns both a list of services (id, label, type) and a ready-to-use
    Telegram inline keyboard (inline_keyboard format).
    """
    return {
        "services": CONNECT_SERVICES,
        "telegram_inline_keyboard": TELEGRAM_CONNECT_KEYBOARD,
    }


@router.post("/connect/link")
async def create_connect_link(request: Request, body: ConnectLinkRequest) -> Dict[str, Any]:
    """Create a one-time connect link for a service. Bot calls this when user taps a connect button."""
    tenant_id = get_request_tenant_id(request)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant context required")
    service = (body.service or "").strip().lower()
    if service not in VALID_CONNECT_SERVICES:
        raise HTTPException(status_code=400, detail=f"Invalid service. Use one of: {sorted(VALID_CONNECT_SERVICES)}")
    expires_at = (datetime.now(UTC) + timedelta(seconds=CONNECT_TTL_SECONDS)).isoformat()
    db = get_db()
    code = db.create_connect_service_code(
        tenant_id=tenant_id,
        service=service,
        expires_at=expires_at,
        chat_id=body.chat_id,
    )
    base = _resolve_connect_base_url(request)
    path = f"/integrations/connect/{service}"
    if service in ("gmail", "google_calendar"):
        path = f"/integrations/connect/{service}/start"
    url = f"{base}{path}?code={code}"
    return {"url": url, "code": code, "expires_in": CONNECT_TTL_SECONDS}


@router.get("/connect/status")
async def get_connect_status(request: Request) -> Dict[str, Any]:
    """Return which services are connected for the current tenant (for /connections in Telegram)."""
    tenant_id = get_request_tenant_id(request)
    if not tenant_id:
        return {"services": {s: False for s in VALID_CONNECT_SERVICES}}
    db = get_db()
    connected = db.list_connected_services_for_tenant(tenant_id)
    return {"services": {s: (s in connected) for s in VALID_CONNECT_SERVICES}}


def _api_key_form_html(service: str, label: str, code: str, post_path: str, field_name: str = "api_key", field_placeholder: str = "Paste your API key") -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Connect {label}</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:2rem auto;padding:1rem;">
<h1>Connect {label}</h1>
<p>Paste your {label} {field_name.replace("_", " ")} below. It will be stored securely and never shown again.</p>
<form method="post" action="{post_path}">
<input type="hidden" name="code" value="{code}" />
<label>{field_name.replace("_", " ").title()}: <input type="password" name="{field_name}" placeholder="{field_placeholder}" style="width:100%;padding:0.5rem;" /></label>
<br><br><button type="submit">Connect</button>
</form>
<p style="color:#666;font-size:0.9rem;">After connecting, return to Telegram.</p>
</body></html>"""


@router.get("/connect/brave_search", response_class=HTMLResponse)
async def connect_brave_form(request: Request, code: str = "") -> str:
    """Serve form to paste Brave Search API key."""
    _get_and_validate_service_code(code)
    base = _resolve_connect_base_url(request)
    return _api_key_form_html("brave_search", "Brave Search", code, f"{base}/integrations/connect/brave_search", "api_key", "Brave API key")


@router.post("/connect/brave_search")
async def connect_brave_submit(request: Request, code: str = Form(""), api_key: str = Form("")) -> RedirectResponse:
    """Store Brave Search credential for tenant from connect code."""
    entry = _get_and_validate_service_code(code)
    api_key = (api_key or "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    db = get_db()
    credential_id = f"brave_search_{entry['tenant_id']}"
    db.save_credential(
        credential_id=credential_id,
        tool_name="brave_search",
        credential_type="api_key",
        credential_data={"api_key": api_key},
        encrypted=False,
        tenant_id=entry["tenant_id"],
    )
    db.mark_connect_service_code_used(code)
    base = _resolve_connect_base_url(request)
    return RedirectResponse(url=f"{base}/integrations/connect/success?service=Brave%20Search", status_code=302)


@router.get("/connect/github", response_class=HTMLResponse)
async def connect_github_form(request: Request, code: str = "") -> str:
    """Serve form to paste GitHub token."""
    _get_and_validate_service_code(code)
    base = _resolve_connect_base_url(request)
    return _api_key_form_html("github", "GitHub", code, f"{base}/integrations/connect/github", "token", "Personal access token")


@router.post("/connect/github")
async def connect_github_submit(request: Request, code: str = Form(""), token: str = Form("")) -> RedirectResponse:
    """Store GitHub credential for tenant from connect code."""
    entry = _get_and_validate_service_code(code)
    token = (token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    db = get_db()
    credential_id = f"github_{entry['tenant_id']}"
    db.save_credential(
        credential_id=credential_id,
        tool_name="github",
        credential_type="token",
        credential_data={"token": token},
        encrypted=False,
        tenant_id=entry["tenant_id"],
    )
    db.mark_connect_service_code_used(code)
    base = _resolve_connect_base_url(request)
    return RedirectResponse(url=f"{base}/integrations/connect/success?service=GitHub", status_code=302)


@router.get("/connect/elevenlabs", response_class=HTMLResponse)
async def connect_elevenlabs_form(request: Request, code: str = "") -> str:
    """Serve form to paste ElevenLabs API key."""
    _get_and_validate_service_code(code)
    base = _resolve_connect_base_url(request)
    return _api_key_form_html("elevenlabs", "ElevenLabs", code, f"{base}/integrations/connect/elevenlabs", "api_key", "ElevenLabs API key")


@router.post("/connect/elevenlabs")
async def connect_elevenlabs_submit(request: Request, code: str = Form(""), api_key: str = Form("")) -> RedirectResponse:
    """Store ElevenLabs credential for tenant from connect code."""
    entry = _get_and_validate_service_code(code)
    api_key = (api_key or "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    db = get_db()
    credential_id = f"elevenlabs_{entry['tenant_id']}"
    db.save_credential(
        credential_id=credential_id,
        tool_name="elevenlabs",
        credential_type="api_key",
        credential_data={"api_key": api_key},
        encrypted=False,
        tenant_id=entry["tenant_id"],
    )
    db.mark_connect_service_code_used(code)
    base = _resolve_connect_base_url(request)
    return RedirectResponse(url=f"{base}/integrations/connect/success?service=ElevenLabs", status_code=302)


@router.get("/connect/success", response_class=HTMLResponse)
async def connect_success(request: Request, service: str = "Service") -> str:
    """Shown after user completes connect (OAuth or API key)."""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Connected</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:2rem auto;padding:1rem;text-align:center;">
<h1>✓ {service} connected</h1>
<p>You can close this page and return to Telegram.</p>
</body></html>"""


# --- Gmail OAuth ---
GMAIL_SCOPES = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.modify"
GOOGLE_CALENDAR_SCOPES = "https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events"


@router.get("/connect/gmail/start")
async def connect_gmail_start(request: Request, code: str = "") -> RedirectResponse:
    """Redirect to Google OAuth for Gmail. state = our connect code."""
    entry = _get_and_validate_service_code(code)
    client_id = config.GOOGLE_CLIENT_ID
    if not client_id:
        raise HTTPException(status_code=503, detail="Gmail OAuth not configured (GOOGLE_CLIENT_ID)")
    base = _resolve_connect_base_url(request)
    redirect_uri = f"{base}/integrations/connect/gmail/callback"
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={GMAIL_SCOPES}&state={code}&access_type=offline&prompt=consent"
    )
    return RedirectResponse(url=url, status_code=302)


@router.get("/connect/gmail/callback")
async def connect_gmail_callback(request: Request, state: str = "", code: str = "", error: Optional[str] = None) -> RedirectResponse:
    """Exchange Google OAuth code for tokens and save Gmail credential."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    entry = _get_and_validate_service_code(state)
    client_id = config.GOOGLE_CLIENT_ID
    client_secret = config.GOOGLE_CLIENT_SECRET
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail="Gmail OAuth not configured")
    base = _resolve_connect_base_url(request)
    redirect_uri = f"{base}/integrations/connect/gmail/callback"
    import requests as req_lib
    resp = req_lib.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text[:200]}")
    data = resp.json()
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", 3600)
    expires_at_ts = int(datetime.now(UTC).timestamp()) + expires_in
    db = get_db()
    credential_id = f"gmail_{entry['tenant_id']}"
    db.save_credential(
        credential_id=credential_id,
        tool_name="gmail",
        credential_type="oauth2",
        credential_data={
            "access_token": access_token,
            "refresh_token": refresh_token or "",
            "client_id": client_id,
            "client_secret": client_secret,
            "token_uri": "https://oauth2.googleapis.com/token",
            "expires_at": expires_at_ts,
        },
        encrypted=False,
        tenant_id=entry["tenant_id"],
    )
    db.mark_connect_service_code_used(state)
    return RedirectResponse(url=f"{base}/integrations/connect/success?service=Gmail", status_code=302)


@router.get("/connect/google_calendar/start")
async def connect_google_calendar_start(request: Request, code: str = "") -> RedirectResponse:
    """Redirect to Google OAuth for Calendar. state = our connect code."""
    entry = _get_and_validate_service_code(code)
    client_id = config.GOOGLE_CLIENT_ID
    if not client_id:
        raise HTTPException(status_code=503, detail="Google Calendar OAuth not configured (GOOGLE_CLIENT_ID)")
    base = _resolve_connect_base_url(request)
    redirect_uri = f"{base}/integrations/connect/google_calendar/callback"
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={GOOGLE_CALENDAR_SCOPES}&state={code}&access_type=offline&prompt=consent"
    )
    return RedirectResponse(url=url, status_code=302)


@router.get("/connect/google_calendar/callback")
async def connect_google_calendar_callback(request: Request, state: str = "", code: str = "", error: Optional[str] = None) -> RedirectResponse:
    """Exchange Google OAuth code for tokens and save Google Calendar credential."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    entry = _get_and_validate_service_code(state)
    client_id = config.GOOGLE_CLIENT_ID
    client_secret = config.GOOGLE_CLIENT_SECRET
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail="Google Calendar OAuth not configured")
    base = _resolve_connect_base_url(request)
    redirect_uri = f"{base}/integrations/connect/google_calendar/callback"
    import requests as req_lib
    resp = req_lib.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text[:200]}")
    data = resp.json()
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", 3600)
    expires_at_ts = int(datetime.now(UTC).timestamp()) + expires_in
    db = get_db()
    credential_id = f"google_calendar_{entry['tenant_id']}"
    db.save_credential(
        credential_id=credential_id,
        tool_name="google_calendar",
        credential_type="oauth2",
        credential_data={
            "access_token": access_token,
            "refresh_token": refresh_token or "",
            "client_id": client_id,
            "client_secret": client_secret,
            "token_uri": "https://oauth2.googleapis.com/token",
            "expires_at": expires_at_ts,
            "calendar_id": "primary",
        },
        encrypted=False,
        tenant_id=entry["tenant_id"],
    )
    db.mark_connect_service_code_used(state)
    return RedirectResponse(url=f"{base}/integrations/connect/success?service=Google%20Calendar", status_code=302)


@router.post("/clawdbot/connect", response_model=ClawdbotConnectResponse)
async def connect_clawdbot(request: Request, body: ClawdbotConnectRequest):
    """Connect Edonbot (bot gateway) integration.
    
    Validates connection by calling sessions_list (if probe=true), then stores credentials.
    
    Args:
        request: FastAPI request (auth middleware populates tenant_id)
        body: Connection details
        
    Returns:
        Connection status and credential info
    """
    tenant_id = get_request_tenant_id(request)
    
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
                    detail=f"Edonbot probe failed: {result.get('error', 'Unknown error')}"
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Clawdbot probe failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=400, detail=f"Edonbot probe failed: {str(e)}")
    
    # Save credential in EDON DB (tenant-scoped if tenant_id exists)
    db = get_db()
    credential_data = {
        "base_url": body.base_url,
        "auth_mode": body.auth_mode,
        "secret": body.secret,
    }
    
    default_cred_id = config.DEFAULT_CLAWDBOT_CREDENTIAL_ID
    credential_id = (body.credential_id or "").strip() or default_cred_id
    if credential_id == "clawdbot_gateway":
        credential_id = default_cred_id
    if tenant_id and credential_id != default_cred_id:
        credential_id = f"{credential_id}_{tenant_id}"
    
    db.save_credential(
        credential_id=credential_id,
        tool_name="clawdbot",
        credential_type="gateway",
        credential_data=credential_data,
        encrypted=True,
        tenant_id=tenant_id
    )
    if body.probe:
        db.update_credential_status(credential_id, tenant_id, success=True, error_message=None)
    logger.info(f"Edonbot connected successfully. Credential ID: {credential_id}, Tenant: {tenant_id}")
    
    return ClawdbotConnectResponse(
        connected=True,
        credential_id=credential_id,
        base_url=body.base_url,
        auth_mode=body.auth_mode,
        message="Edonbot connected. Credential saved.",
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
        tenant_id = get_request_tenant_id(request)
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


@router.post("/telegram/connect-code")
async def create_telegram_connect_code(request: Request, body: TelegramConnectCodeRequest):
    """Create a short-lived connect code for Telegram binding."""
    tenant_id = get_request_tenant_id(request)
    if not tenant_id:
        if not config.DEMO_MODE:
            raise HTTPException(status_code=401, detail="No tenant context for connect code")
        tenant_id = config.DEMO_TENANT_ID
        # Ensure demo tenant exists
        db = get_db()
        tenant = db.get_tenant(tenant_id)
        if not tenant:
            import uuid
            demo_user = db.get_user_by_auth("demo", "demo")
            user_id = demo_user["id"] if demo_user else str(uuid.uuid4())
            if not demo_user:
                db.create_user(
                    user_id=user_id,
                    email="demo@edoncore.com",
                    auth_provider="demo",
                    auth_subject="demo",
                    role="admin",
                )
            db.create_tenant(tenant_id=tenant_id, user_id=user_id)

    ttl_minutes = config.TELEGRAM_CONNECT_TTL_MIN
    expires_at = (datetime.now(UTC) + timedelta(minutes=ttl_minutes)).isoformat()
    db = get_db()
    code = db.create_connect_code(tenant_id=tenant_id, expires_at=expires_at, channel=body.channel)
    return {"code": code, "expires_at": expires_at, "ttl_minutes": ttl_minutes}


@router.post("/telegram/verify-code")
async def verify_telegram_connect_code(request: Request, body: TelegramVerifyCodeRequest):
    """Verify a Telegram connect code and bind the user to a tenant."""
    bot_secret = config.TELEGRAM_BOT_SECRET
    if not bot_secret:
        raise HTTPException(status_code=500, detail="Telegram bot secret not configured")

    header_secret = request.headers.get("X-EDON-BOT-SECRET") or request.headers.get("X-TELEGRAM-BOT-SECRET")
    if not header_secret or header_secret != bot_secret:
        raise HTTPException(status_code=401, detail="Invalid bot secret")

    code = (body.code or "").strip().upper()
    db = get_db()
    entry = db.get_connect_code(code)
    if not entry:
        raise HTTPException(status_code=404, detail="Connect code not found")
    if entry.get("used_at"):
        raise HTTPException(status_code=409, detail="Connect code already used")

    try:
        expires_at = datetime.fromisoformat(entry["expires_at"])
    except Exception:
        expires_at = None
    if not expires_at or expires_at < datetime.now(UTC):
        raise HTTPException(status_code=410, detail="Connect code expired")

    tenant_id = entry["tenant_id"]
    db.mark_connect_code_used(code, used_by=body.user_id)
    db.upsert_channel_binding(
        tenant_id=tenant_id,
        channel="telegram",
        external_user_id=str(body.user_id),
        external_chat_id=str(body.chat_id) if body.chat_id is not None else None,
        username=body.username,
    )
    token_info = db.create_channel_token(
        tenant_id=tenant_id,
        channel="telegram",
        external_user_id=str(body.user_id),
    )
    return {
        "tenant_id": tenant_id,
        "token": token_info["raw_token"],
        "channel": "telegram",
    }
