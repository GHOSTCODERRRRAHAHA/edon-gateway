"""
Planning + decomposition — non-executing.
Breaks an objective into steps (read / draft / execute). Execution still goes through governor.
"""

from typing import Dict, Any, List


# Step types: read (no side effects), draft (preview), execute (requires confirmation when high-impact)
STEP_TYPES = ("read", "draft", "execute")


def decompose(objective: str, context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Decompose an objective into ordered steps. Non-executing; returns step list only.
    
    Uses keyword/heuristic rules. Each step has: id, tool, op, params (suggested), step_type.
    """
    context = context or {}
    objective_lower = (objective or "").strip().lower()
    steps: List[Dict[str, Any]] = []
    step_id = 0

    def add(tool: str, op: str, step_type: str, params: Dict[str, Any] = None):
        nonlocal step_id
        step_id += 1
        steps.append({
            "id": f"step_{step_id}",
            "tool": tool,
            "op": op,
            "step_type": step_type,
            "params": params or {},
        })

    # Search / research first (read)
    if any(k in objective_lower for k in ("search", "find", "look up", "research", "web", "look for")):
        add("brave_search", "search", "read", {"q": objective[:200], "count": 10})

    # Email: read inbox then send (execute requires confirmation in governor)
    if any(k in objective_lower for k in ("email", "send mail", "mail to", "e-mail", "gmail")):
        add("gmail", "list_messages", "read", {"max_results": 10})
        if "draft" not in objective_lower and "compose" not in objective_lower:
            add("gmail", "send", "execute", {"subject": "", "body": "", "recipients": []})

    # Calendar: list then optionally create (execute)
    if any(k in objective_lower for k in ("calendar", "schedule", "meeting", "event", "book")):
        add("google_calendar", "list_events", "read", {"max_results": 20})
        if any(k in objective_lower for k in ("create", "add", "schedule", "book")):
            add("google_calendar", "create_event", "execute", {"summary": "", "start": "", "end": ""})

    # GitHub: read (list/get) then optionally execute (create issue)
    if any(k in objective_lower for k in ("github", "repo", "issue", "pr", "pull request")):
        add("github", "list_repos", "read", {"per_page": 20})
        if any(k in objective_lower for k in ("create issue", "open issue", "file issue")):
            add("github", "create_issue", "execute", {"owner": "", "repo": "", "title": "", "body": ""})

    # Memory: read preferences / episodes before acting
    if any(k in objective_lower for k in ("remember", "preference", "last time", "before")):
        add("memory", "read_preferences", "read", {})
        add("memory", "query_episodes", "read", {"limit": 10})

    # Voice / TTS: execute (low risk)
    if any(k in objective_lower for k in ("voice", "speak", "read aloud", "tts")):
        add("elevenlabs", "text_to_speech", "execute", {"text": ""})

    # If nothing matched, single generic step (agent can refine)
    if not steps:
        steps.append({
            "id": "step_1",
            "tool": "brave_search",
            "op": "search",
            "step_type": "read",
            "params": {"q": objective[:200], "count": 5},
        })

    return steps


def plan(objective: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Return a plan (steps only). No execution.
    """
    steps = decompose(objective, context)
    return {
        "objective": objective,
        "steps": steps,
        "count": len(steps),
        "note": "Planning is non-executing. Execute each step via POST /execute with governor.",
    }
