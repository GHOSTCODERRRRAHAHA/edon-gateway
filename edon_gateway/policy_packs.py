"""
Policy Packs - Pre-configured policy modes for Edonbot users.

Users don't want to design policies. They want presets.

Preset modes:
1. Casual User - Ultra-safe everyday use
2. Market Analyst - Financial research focus
3. Ops Commander - Workflow automation with confirmations
4. Founder Mode - Power user with conservative limits
5. Helpdesk - Customer support focus
6. Autonomy Mode - High-risk full co-pilot
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


# Mode 1: Casual User (Ultra-Safe / Everyday Use)
CASUAL_USER = PolicyPack(
    name="casual_user",
    description="Casual User - Ultra-safe everyday use",
    scope={
        "clawdbot": ["invoke"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "message",
            "web_read",
            "web_summarize",
            "web_draft",
            "web_search"
        ],
        "blocked_clawdbot_tools": [
            "web_send",
            "web_delete",
            "web_execute",
            "shell_execute",
            "file_write",
            "mass_outbound",
            "credential_operations"
        ],
        "confirm_irreversible": True,
        "max_recipients": 1,
        "no_external_sharing": True
    },
    risk_level=RiskLevel.LOW,
    approved_by_user=True
)


# Mode 2: Market Analyst (Financial + Research Focus)
MARKET_ANALYST = PolicyPack(
    name="market_analyst",
    description="Market Analyst - Financial research focus",
    scope={
        "clawdbot": ["invoke"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "web_read",
            "web_search",
            "web_summarize",
            "web_draft"
        ],
        "blocked_clawdbot_tools": [
            "message",
            "web_send",
            "web_execute",
            "shell_execute",
            "file_write",
            "mass_outbound",
            "credential_operations"
        ],
        "confirm_irreversible": True,
        "max_recipients": 1,
        "no_external_sharing": True
    },
    risk_level=RiskLevel.LOW,
    approved_by_user=True
)


# Mode 3: Ops Commander (Productivity / Workflow Focus)
OPS_COMMANDER = PolicyPack(
    name="ops_commander",
    description="Ops Commander - Workflow automation with confirmations",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "read"],
        "calendar": ["view", "propose"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "message",
            "web_read",
            "web_search",
            "web_summarize",
            "web_draft",
            "calendar_view",
            "calendar_create"
        ],
        "confirm_on": [
            "web_send",
            "calendar_create",
            "file_write",
            "message"
        ],
        "blocked_clawdbot_tools": [
            "web_execute",
            "shell_execute",
            "mass_outbound",
            "credential_operations"
        ],
        "max_recipients": 10,
        "work_hours_only": True,
        "no_external_sharing": True
    },
    risk_level=RiskLevel.MEDIUM,
    approved_by_user=True
)


# Mode 4: Founder Mode (Power User / Flexible Ops)
FOUNDER_MODE = PolicyPack(
    name="founder_mode",
    description="Founder Mode - Power user with conservative limits",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "read"],
        "file": ["read"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "message",
            "web_read",
            "web_search",
            "web_summarize",
            "web_draft",
            "sessions_list"
        ],
        "confirm_on": [
            "web_send",
            "file_write",
            "message"
        ],
        "blocked_clawdbot_tools": [
            "web_execute",
            "shell_execute",
            "mass_outbound",
            "credential_operations"
        ],
        "max_recipients": 5,
        "no_external_sharing": True
    },
    risk_level=RiskLevel.MEDIUM,
    approved_by_user=True
)


# Mode 5: Helpdesk (Customer Support Focus)
HELPDESK = PolicyPack(
    name="helpdesk",
    description="Helpdesk - Customer support focus",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "read"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "message",
            "web_read",
            "web_search",
            "web_summarize",
            "web_draft",
            "sessions_list"
        ],
        "confirm_on": [
            "web_send",
            "message"
        ],
        "blocked_clawdbot_tools": [
            "web_execute",
            "shell_execute",
            "file_write",
            "mass_outbound",
            "credential_operations"
        ],
        "max_recipients": 3,
        "no_external_sharing": True
    },
    risk_level=RiskLevel.LOW,
    approved_by_user=True
)


# Mode 6: Autonomy Mode (High-Risk / Full Co-Pilot)
AUTONOMY_MODE = PolicyPack(
    name="autonomy_mode",
    description="Autonomy Mode - High-risk full co-pilot",
    scope={
        "clawdbot": ["invoke"],
        "email": ["draft", "send", "read"],
        "file": ["read", "write"]
    },
    constraints={
        "allowed_clawdbot_tools": [
            "message",
            "web_read",
            "web_search",
            "web_summarize",
            "web_draft",
            "web_send",
            "sessions_list",
            "calendar_view",
            "calendar_create"
        ],
        "confirm_on": [
            "web_send",
            "file_write",
            "message"
        ],
        "blocked_clawdbot_tools": [
            "shell_execute",
            "mass_outbound",
            "credential_operations"
        ],
        "max_recipients": 50,
        "audit_level": "detailed",
        "work_hours_only": False
    },
    risk_level=RiskLevel.HIGH,
    approved_by_user=True
)


# Registry of all policy packs
POLICY_PACKS = {
    "casual_user": CASUAL_USER,
    "market_analyst": MARKET_ANALYST,
    "ops_commander": OPS_COMMANDER,
    "founder_mode": FOUNDER_MODE,
    "helpdesk": HELPDESK,
    "autonomy_mode": AUTONOMY_MODE,
    # Backwards-compat alias used by regression tests / older clients
    "clawdbot_safe": AUTONOMY_MODE
}


def get_policy_pack(name: str) -> PolicyPack:
    """Get a policy pack by name."""
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
    """Apply a policy pack and return intent contract dictionary."""
    pack = get_policy_pack(pack_name)
    return pack.to_intent_dict(objective)
