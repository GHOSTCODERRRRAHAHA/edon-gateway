"""EDON Governor - Main governance engine."""

from datetime import datetime
from typing import Optional
from .schemas import (
    Action, Decision, IntentContract, Verdict, ReasonCode,
    RiskLevel, Tool, ActionSource
)
from .policies import PolicyEngine, PolicyConfig


class EDONGovernor:
    """EDON Governance engine."""
    
    def __init__(self, policy_config: PolicyConfig = None, db=None):
        """Initialize governor."""
        self.policy_engine = PolicyEngine(policy_config)
        self.db = db
    
    def get_intent(self, intent_id: str) -> IntentContract:
        """Fetch intent contract from storage.
        
        Args:
            intent_id: Intent identifier
            
        Returns:
            IntentContract object
            
        Raises:
            ValueError: If intent not found
        """
        if not self.db:
            raise ValueError("Database not configured")
        
        intent_dict = self.db.get_intent(intent_id)
        if not intent_dict:
            raise ValueError(f"Intent not found: {intent_id}")
        
        # Convert dict to IntentContract (dataclass)
        # Filter to only fields that IntentContract accepts
        return IntentContract(
            objective=intent_dict["objective"],
            scope=intent_dict["scope"],
            constraints=intent_dict.get("constraints", {}),
            risk_level=RiskLevel(intent_dict.get("risk_level", "LOW")),
            approved_by_user=intent_dict.get("approved_by_user", False)
        )
    
    def evaluate(
        self,
        action: Action,
        intent: IntentContract,
        context: dict = None
    ) -> Decision:
        """Evaluate action against intent and policies.
        
        Args:
            action: Proposed action
            intent: Active intent contract
            context: Additional context (optional)
            
        Returns:
            Decision with verdict and reasoning
        """
        if context is None:
            context = {}
        
        current_time = action.requested_at
        
        # 0. Compute server-side risk first (before other checks)
        computed_risk = action.estimated_risk  # Start with agent's estimate
        
        # Override for dangerous shell commands
        if action.tool == Tool.SHELL:
            command = action.params.get("command", "")
            if self.policy_engine.is_dangerous_command(command):
                computed_risk = RiskLevel.CRITICAL
        
        # Store computed risk in action for audit
        action.computed_risk = computed_risk
        
        # 1. Check drafts_only constraint FIRST (before scope, so we can degrade send->draft)
        if intent.constraints.get("drafts_only", False):
            if action.tool == Tool.EMAIL and action.op == "send":
                # Degrade to draft (this allows send even if not in scope)
                draft_action = Action(
                    tool=action.tool,
                    op="draft",
                    params=action.params.copy(),
                    requested_at=action.requested_at,
                    source=action.source,
                    tags=action.tags + ["degraded"],
                    computed_risk=computed_risk
                )
                return Decision(
                    verdict=Verdict.DEGRADE,
                    reason_code=ReasonCode.DEGRADED_TO_SAFE_ALTERNATIVE,
                    explanation="Intent requires drafts_only, degrading send to draft",
                    safe_alternative=draft_action
                )
        
        # 2. Check scope boundaries (after drafts_only check)
        # But prioritize risk if computed_risk is critical
        scope_violation = not intent.allows_tool_op(action.tool.value, action.op)
        
        if scope_violation:
            # If also dangerous, prioritize risk reason
            if computed_risk == RiskLevel.CRITICAL:
                return Decision(
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.RISK_TOO_HIGH,
                    explanation=f"Dangerous operation blocked: {action.tool.value}.{action.op} (also out of scope)"
                )
            else:
                return Decision(
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.SCOPE_VIOLATION,
                    explanation=f"Action {action.tool.value}.{action.op} not in scope. Allowed: {intent.scope.get(action.tool.value, [])}"
                )
        
        # 2.5. Check allowed_clawdbot_tools constraint (for Clawdbot tool)
        if action.tool == Tool.CLAWDBOT and action.op == "invoke":
            allowed_tools = intent.constraints.get("allowed_clawdbot_tools", [])
            if allowed_tools:  # Only check if constraint is set
                underlying_tool = action.params.get("tool", "")
                if underlying_tool not in allowed_tools:
                    return Decision(
                        verdict=Verdict.BLOCK,
                        reason_code=ReasonCode.SCOPE_VIOLATION,
                        explanation=f"Clawdbot tool '{underlying_tool}' not in allowed list. Allowed: {allowed_tools}"
                    )
        
        # 3. Check work hours constraint
        if intent.constraints.get("work_hours_only", False):
            if not self.policy_engine.is_work_hours(current_time):
                return Decision(
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.OUT_OF_HOURS,
                    explanation=f"Action requested outside work hours (current: {current_time.hour}:00, work hours: {self.policy_engine.config.work_hours_start}-{self.policy_engine.config.work_hours_end})"
                )
        
        # 4. Record action for loop detection (before other checks that might block)
        params_hash = str(sorted(action.params.items()))
        self.policy_engine.record_action(action, current_time)
        
        # 5. Loop detection (check after recording)
        if self.policy_engine.detect_loop(action.tool, action.op, params_hash, current_time):
            return Decision(
                verdict=Verdict.PAUSE,
                reason_code=ReasonCode.LOOP_DETECTED,
                explanation=f"Loop detected: {action.tool.value}.{action.op} repeated {self.policy_engine.config.loop_detection_threshold}+ times in {self.policy_engine.config.loop_detection_window_seconds}s"
            )
        
        # 6. Check rate limiting
        if self.policy_engine.check_rate_limit(current_time):
            return Decision(
                verdict=Verdict.PAUSE,
                reason_code=ReasonCode.RATE_LIMIT,
                explanation=f"Rate limit exceeded: {self.policy_engine.config.max_actions_per_minute} actions per minute"
            )
        
        # 7. Check for dangerous shell commands (computed_risk already set above)
        if action.tool == Tool.SHELL:
            command = action.params.get("command", "")
            if self.policy_engine.is_dangerous_command(command):
                return Decision(
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.RISK_TOO_HIGH,
                    explanation=f"Dangerous shell command detected: {command[:50]}"
                )
        
        # 8. Check for data exfiltration
        if intent.constraints.get("no_external_sharing", False):
            if self.policy_engine.is_external_sharing(action.op, action.params):
                return Decision(
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.DATA_EXFIL,
                    explanation=f"External sharing detected in {action.op} operation"
                )
        
        # 9. Check max_recipients constraint
        if "max_recipients" in intent.constraints:
            max_recipients = intent.constraints["max_recipients"]
            recipients = action.params.get("recipients", [])
            if isinstance(recipients, str):
                recipients = [r.strip() for r in recipients.split(",")]
            recipient_count = len(recipients) if isinstance(recipients, list) else 1
            
            if recipient_count > max_recipients:
                if action.op == "send":
                    # Escalate: high-impact public action (many recipients)
                    draft_action = Action(
                        tool=action.tool,
                        op="draft",
                        params=action.params.copy(),
                        requested_at=action.requested_at,
                        source=action.source,
                        tags=action.tags + ["degraded", "too_many_recipients"],
                        computed_risk=computed_risk
                    )
                    return Decision(
                        verdict=Verdict.ESCALATE,
                        reason_code=ReasonCode.NEED_CONFIRMATION,
                        explanation=f"Recipient count ({recipient_count}) exceeds max ({max_recipients}). Requires confirmation.",
                        safe_alternative=draft_action,
                        required_confirmation=True,
                        escalation_question=f"Send email to {recipient_count} recipients? (max allowed: {max_recipients})",
                        escalation_options=[
                            {"id": "allow_once", "label": "Allow once"},
                            {"id": "draft_only", "label": "Save as draft only"},
                            {"id": "keep_blocking", "label": "Keep blocking"},
                        ],
                    )
        
        # 10. Check risk level and escalation requirements (use computed_risk, not estimated_risk)
        if computed_risk in self.policy_engine.config.escalate_risk_levels:
            if not (intent.approved_by_user and computed_risk == RiskLevel.HIGH):
                return Decision(
                    verdict=Verdict.ESCALATE,
                    reason_code=ReasonCode.NEED_CONFIRMATION,
                    explanation=f"High/critical risk action requires user confirmation (risk: {computed_risk.value})",
                    required_confirmation=True
                )
        
        # 11. Check intent objective alignment (basic keyword matching)
        # Ambiguous intent: short objective + no scope match -> escalate with one precise question
        if not self._check_intent_alignment(action, intent):
            # Optional: if objective is very short, treat as ambiguous and escalate instead of hard block
            objective_short = len((intent.objective or "").strip()) < 15
            if objective_short and intent.constraints.get("escalate_on_ambiguous_intent", False):
                return Decision(
                    verdict=Verdict.ESCALATE,
                    reason_code=ReasonCode.NEED_CONFIRMATION,
                    explanation="Intent is ambiguous; please clarify.",
                    required_confirmation=True,
                    escalation_question="What would you like to do? (e.g. search, send email, create calendar event)",
                    escalation_options=[
                        {"id": "clarify", "label": "I'll clarify"},
                        {"id": "keep_blocking", "label": "Cancel"},
                    ],
                )
            return Decision(
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.INTENT_MISMATCH,
                explanation=f"Action does not align with intent objective: {intent.objective}"
            )
        
        # All checks passed - ALLOW
        return Decision(
            verdict=Verdict.ALLOW,
            reason_code=ReasonCode.APPROVED,
            explanation="Action approved: within scope, constraints satisfied, risk acceptable"
        )
    
    def _check_intent_alignment(self, action: Action, intent: IntentContract) -> bool:
        """Basic intent alignment check using keyword matching."""
        objective_lower = intent.objective.lower()
        
        # Simple keyword-based alignment
        # In production, this would be more sophisticated
        action_keywords = {
            Tool.EMAIL: ["email", "inbox", "message", "mail"],
            Tool.CALENDAR: ["calendar", "meeting", "schedule", "event"],
            Tool.FILE: ["file", "document", "folder"],
            Tool.SHELL: ["command", "system", "terminal"],
            Tool.BRAVE_SEARCH: ["search", "web", "research", "look up", "find"],
            Tool.GMAIL: ["gmail", "inbox", "email", "mail"],
            Tool.GOOGLE_CALENDAR: ["calendar", "event", "schedule", "meeting"],
            Tool.ELEVENLABS: ["voice", "speech", "tts", "read aloud", "storytelling"],
            Tool.GITHUB: ["github", "repo", "issue", "code", "pr"],
            Tool.MEMORY: ["memory", "preference", "remember", "episode", "past task"],
        }
        
        # Check if action tool type aligns with intent
        keywords = action_keywords.get(action.tool, [])
        return any(keyword in objective_lower for keyword in keywords) or len(keywords) == 0
