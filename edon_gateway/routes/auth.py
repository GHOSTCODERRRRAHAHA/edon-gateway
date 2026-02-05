"""Authentication routes for EDON Gateway (Clerk-backed)."""

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from ..middleware.auth import get_token_from_header, verify_token, verify_clerk_token, resolve_tenant_for_clerk
from ..persistence import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class SignupRequest(BaseModel):
    auth_provider: str = "clerk"
    auth_subject: str
    email: str


@router.post("/signup")
async def signup(request: Request, body: SignupRequest):
    """
    Create (or fetch) a user + tenant for a Clerk user.
    Requires a valid Clerk session token in Authorization or X-EDON-TOKEN.
    """
    token = get_token_from_header(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Clerk session token")

    clerk_claims = verify_clerk_token(token)
    if not clerk_claims:
        raise HTTPException(status_code=401, detail="Invalid Clerk session token")

    if body.auth_provider != "clerk":
        raise HTTPException(status_code=400, detail="Unsupported auth provider")

    clerk_sub = (clerk_claims or {}).get("sub")
    if clerk_sub and body.auth_subject and clerk_sub != body.auth_subject:
        raise HTTPException(status_code=403, detail="Clerk subject mismatch")

    tenant_info = resolve_tenant_for_clerk(clerk_claims, fallback_email=body.email)
    return {
        "tenant_id": tenant_info["tenant_id"],
        "session_token": token,
        "user": {
            "id": tenant_info.get("user_id"),
            "email": tenant_info.get("email"),
            "tenant_id": tenant_info["tenant_id"],
            "plan": tenant_info.get("plan"),
            "status": tenant_info.get("status"),
        },
    }


@router.get("/session")
async def session(request: Request):
    """
    Validate a session token and return user + tenant context.
    Accepts either an EDON API key or a Clerk session token.
    """
    token = get_token_from_header(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    is_valid, tenant_info = verify_token(token)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    if not tenant_info:
        return {
            "id": None,
            "email": None,
            "tenant_id": None,
            "plan": None,
            "status": None,
        }

    db = get_db()
    tenant = db.get_tenant(tenant_info["tenant_id"])
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return {
        "id": tenant.get("user_id"),
        "email": tenant.get("email"),
        "tenant_id": tenant.get("id"),
        "plan": tenant.get("plan"),
        "status": tenant.get("status"),
    }
