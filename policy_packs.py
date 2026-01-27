"""
Policy Packs - Pre-configured policy modes for Clawdbot users.

Users don't want to design policies. They want presets.

Three modes:
1. Personal Safe (default) - Conservative, safe for personal use
2. Work Safe - Balanced for work environments
3. Ops/Admin - Permissive with tight scopes and heavy audit
"""

from typing import Dict, Any, List
from .schemas import RiskLevel


class PolicyPack:
    """Pre-configured policy pack."""
    
    def __init__(
        self,
        name: str,
        description: str,
        scope: Dict[str, List[str]],
        constraints: Dict[str, Any],
        risk_level: RiskLevel,
        approved_by_user: bool = True
    ):
        self.name = name
        self.description = description
        self.scope = scope
        self.constraints = constraints
        self.risk_level = risk_level
        self.approved_by_user = approved_by_user
    
    def to_intent_dict(self, objective: str = None) -> Dict[str, Any]:
        """Convert to intent contract dictionary."""
        return {
            "objective": objective or self.description,
            "scope": self.scope,
            "constraints": self.constraints,
            "risk_level": self.risk_level.value,
            "approved_by_user": self.approved_by_user
        }


# Mode 1: Personal Safe (default)
PERSONAL_SAFE = PolicyPack(
    name="personal_safe",
    description="Personal Safe - Conservative policy for personal use",
    scope={
        "clawdbot": ["invoke"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "web_read",      # Read web pages
            "web_summarize", # Summarize content
            "web_draft",     # Draft content
            "web_search"    # Search web
        ],
        "blocked_clawdbot_tools": [
            "web_send",      # Send emails/messages
            "web_delete",    # Delete operations
            "shell_execute", # Shell commands
            "file_write"     # File write operations
        ],
        "confirm_irreversible": True,  # Confirm on irreversible actions
        "max_recipients": 1,  # Max 1 recipient for any send operation
        "no_external_sharing": True  # Block external sharing
    },
    risk_level=RiskLevel.LOW,
    approved_by_user=True
)


# Mode 2: Work Safe
WORK_SAFE = PolicyPack(
    name="work_safe",
    description="Work Safe - Balanced policy for work environments",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "read"],
        "file": ["read"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "web_read",
            "web_summarize",
            "web_draft",
            "web_search",
            "sessions_list",
            "calendar_view"
        ],
        "confirm_on": [
            "web_send",      # Confirm before sending
            "file_write",    # Confirm before writing files
            "calendar_create"  # Confirm before creating calendar events
        ],
        "blocked_clawdbot_tools": [
            "shell_execute",  # No shell access
            "mass_outbound",  # No mass operations
            "credential_operations"  # No credential management
        ],
        "max_recipients": 10,  # Max 10 recipients
        "work_hours_only": True,  # Only during work hours
        "no_external_sharing": False  # Allow internal sharing
    },
    risk_level=RiskLevel.MEDIUM,
    approved_by_user=True
)


# Mode 3: Ops/Admin
OPS_ADMIN = PolicyPack(
    name="ops_admin",
    description="Ops/Admin - Permissive with tight scopes and heavy audit",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "send", "read"],
        "file": ["read", "write"],
        "shell": ["read_only"]  # Read-only shell access
    },
    constraints={
        "allowed_clawdbot_tools": [
            "web_read",
            "web_summarize",
            "web_draft",
            "web_search",
            "web_send",  # Allowed but with confirmation
            "sessions_list",
            "calendar_view",
            "calendar_create"
        ],
        "confirm_on": [
            "web_send",      # Confirm high blast radius
            "file_write",    # Confirm file writes
            "shell_execute"  # Confirm shell commands (if allowed)
        ],
        "blocked_clawdbot_tools": [
            "mass_outbound",  # Block mass operations
            "credential_operations"  # Block credential changes
        ],
        "max_recipients": 50,  # Higher limit for ops
        "audit_level": "detailed",  # Heavy audit logging
        "rate_limit_strict": True,  # Strict rate limits
        "work_hours_only": False  # 24/7 access
    },
    risk_level=RiskLevel.HIGH,
    approved_by_user=True
)


# Registry of all policy packs
POLICY_PACKS = {
    "personal_safe": PERSONAL_SAFE,
    "work_safe": WORK_SAFE,
    "ops_admin": OPS_ADMIN
}


def get_policy_pack(name: str) -> PolicyPack:
    """Get a policy pack by name.
    
    Args:
        name: Policy pack name (personal_safe, work_safe, ops_admin)
        
    Returns:
        PolicyPack instance
        
    Raises:
        ValueError: If pack name not found
    """
    if name not in POLICY_PACKS:
        raise ValueError(
            f"Unknown policy pack: {name}. "
            f"Available: {list(POLICY_PACKS.keys())}"
        )
    return POLICY_PACKS[name]


def list_policy_packs() -> List[Dict[str, Any]]:
    """List all available policy packs."""
    return [
        {
            "name": pack.name,
            "description": pack.description,
            "risk_level": pack.risk_level.value,
            "scope_summary": {
                tool: len(ops) for tool, ops in pack.scope.items()
            },
            "constraints_summary": {
                "allowed_tools": len(pack.constraints.get("allowed_clawdbot_tools", [])),
                "blocked_tools": len(pack.constraints.get("blocked_clawdbot_tools", [])),
                "confirm_required": "confirm_on" in pack.constraints
            }
        }
        for pack in POLICY_PACKS.values()
    ]


def apply_policy_pack(pack_name: str, objective: str = None) -> Dict[str, Any]:
    """Apply a policy pack and return intent contract dictionary.
    
    Args:
        pack_name: Policy pack name
        objective: Optional custom objective (uses pack description if not provided)
        
    Returns:
        Intent contract dictionary ready for POST /intent/set
    """
    pack = get_policy_pack(pack_name)
    return pack.to_intent_dict(objective)
