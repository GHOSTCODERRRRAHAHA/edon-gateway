"""Subscription plan definitions and limits."""

from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class PlanLimits:
    """Plan limits for a subscription tier."""
    name: str
    requests_per_month: int
    requests_per_day: Optional[int] = None
    requests_per_minute: Optional[int] = None


# Plan definitions
PLANS: Dict[str, PlanLimits] = {
    "free": PlanLimits(
        name="Free",
        requests_per_month=1000,
        requests_per_day=50,
        requests_per_minute=10
    ),
    "starter": PlanLimits(
        name="Starter",
        requests_per_month=10000,
        requests_per_day=500,
        requests_per_minute=60
    ),
    "pro": PlanLimits(
        name="Pro",
        requests_per_month=100000,
        requests_per_day=5000,
        requests_per_minute=300
    ),
    "enterprise": PlanLimits(
        name="Enterprise",
        requests_per_month=-1,  # Unlimited
        requests_per_day=-1,
        requests_per_minute=-1
    ),
}


def get_plan_limits(plan_name: str) -> PlanLimits:
    """Get plan limits for a plan name.
    
    Args:
        plan_name: Plan name (free, starter, pro, enterprise)
        
    Returns:
        PlanLimits object
        
    Raises:
        ValueError: If plan name not found
    """
    plan_name_lower = plan_name.lower()
    if plan_name_lower not in PLANS:
        raise ValueError(f"Unknown plan: {plan_name}")
    return PLANS[plan_name_lower]


def check_usage_limit(plan_name: str, current_usage: int, period: str = "month") -> bool:
    """Check if usage exceeds plan limit.
    
    Args:
        plan_name: Plan name
        current_usage: Current usage count
        period: Period to check (month, day, minute)
        
    Returns:
        True if within limit, False if exceeded
    """
    limits = get_plan_limits(plan_name)
    
    if period == "month":
        limit = limits.requests_per_month
    elif period == "day":
        limit = limits.requests_per_day or limits.requests_per_month // 30
    elif period == "minute":
        limit = limits.requests_per_minute or limits.requests_per_month // (30 * 24 * 60)
    else:
        return True
    
    # -1 means unlimited
    if limit == -1:
        return True
    
    return current_usage < limit
