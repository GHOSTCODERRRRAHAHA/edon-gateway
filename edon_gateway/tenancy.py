"""Single source of truth for tenant scoping."""

from typing import Optional
from starlette.requests import Request


def get_request_tenant_id(request: Request) -> Optional[str]:
    """
    Single source of truth for tenant scoping.

    Priority:
      1) request.state.tenant_id (set by auth middleware)
      2) explicit header override (dev/test only) X-Tenant-ID
      3) None (global)
    """
    tid = getattr(request.state, "tenant_id", None)
    if tid:
        return tid

    hdr = request.headers.get("X-Tenant-ID")
    if hdr and hdr.strip():
        return hdr.strip()

    return None
