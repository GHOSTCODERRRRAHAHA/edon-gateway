#!/usr/bin/env python3
"""
EDON Proxy Client - Drop-in replacement for Clawdbot Gateway client.

Usage:
    Replace your Clawdbot Gateway calls:
    
    OLD:
        POST http://clawdbot-gateway:18789/tools/invoke
        Headers: Authorization: Bearer <clawdbot-token>
        Body: {"tool": "sessions_list", "action": "json", "args": {}}
    
    NEW:
        POST http://edon-gateway:8000/clawdbot/invoke
        Headers: X-EDON-TOKEN: <edon-token>
                 X-Agent-ID: <your-agent-id> (optional)
        Body: {"tool": "sessions_list", "action": "json", "args": {}}
    
    Zero code changes needed - just change the URL and token header!
"""

import requests
import json
import os
import sys
from typing import Dict, Any, Optional


class EDONClawdbotProxyClient:
    """Drop-in replacement client for Clawdbot Gateway."""
    
    def __init__(
        self,
        edon_gateway_url: str = None,
        edon_token: str = None,
        agent_id: str = "clawdbot-agent",
        intent_id: Optional[str] = None
    ):
        """Initialize EDON Proxy Client.
        
        Args:
            edon_gateway_url: EDON Gateway URL (default: from EDON_GATEWAY_URL env var or http://127.0.0.1:8000)
            edon_token: EDON Gateway token (default: from EDON_GATEWAY_TOKEN env var)
            agent_id: Agent identifier for audit logging
            intent_id: Optional intent ID for governance
        """
        self.edon_gateway_url = edon_gateway_url or os.getenv("EDON_GATEWAY_URL", "http://127.0.0.1:8000")
        self.edon_token = edon_token or os.getenv("EDON_GATEWAY_TOKEN") or os.getenv("EDON_API_TOKEN")
        self.agent_id = agent_id
        self.intent_id = intent_id
        
        if not self.edon_token:
            raise ValueError(
                "EDON token required. Set EDON_GATEWAY_TOKEN or EDON_API_TOKEN environment variable, "
                "or pass edon_token parameter."
            )
    
    def invoke(
        self,
        tool: str,
        action: str = "json",
        args: Dict[str, Any] = None,
        sessionKey: Optional[str] = None
    ) -> Dict[str, Any]:
        """Invoke a Clawdbot tool via EDON Proxy.
        
        This method has the EXACT same signature as Clawdbot Gateway client,
        making it a drop-in replacement.
        
        Args:
            tool: Clawdbot tool name (e.g., "sessions_list", "web_*")
            action: Action type (default: "json")
            args: Tool arguments
            sessionKey: Optional session key
            
        Returns:
            Clawdbot-compatible response:
            {
                "ok": True/False,
                "result": {...} if ok=True,
                "error": "..." if ok=False,
                "edon_verdict": "ALLOW" | "BLOCK" | ...,
                "edon_explanation": "..."
            }
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        if args is None:
            args = {}
        
        # Prepare request body (matches Clawdbot schema exactly)
        request_body = {
            "tool": tool,
            "action": action,
            "args": args
        }
        if sessionKey:
            request_body["sessionKey"] = sessionKey
        
        # Prepare headers
        headers = {
            "X-EDON-TOKEN": self.edon_token,
            "Content-Type": "application/json",
            "X-Agent-ID": self.agent_id
        }
        if self.intent_id:
            headers["X-Intent-ID"] = self.intent_id
        
        # Call EDON Proxy endpoint
        url = f"{self.edon_gateway_url}/clawdbot/invoke"
        
        try:
            response = requests.post(url, json=request_body, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Try to parse error response
            try:
                error_data = e.response.json()
                return {
                    "ok": False,
                    "error": error_data.get("detail", str(e)),
                    "edon_verdict": "BLOCK",
                    "edon_explanation": f"HTTP {e.response.status_code}: {error_data.get('detail', str(e))}"
                }
            except:
                return {
                    "ok": False,
                    "error": f"HTTP {e.response.status_code}: {str(e)}",
                    "edon_verdict": "BLOCK",
                    "edon_explanation": f"HTTP error: {str(e)}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "ok": False,
                "error": f"Request failed: {str(e)}",
                "edon_verdict": "BLOCK",
                "edon_explanation": f"Connection error: {str(e)}"
            }


def main():
    """Example usage - demonstrates drop-in replacement."""
    import argparse
    
    parser = argparse.ArgumentParser(description="EDON Clawdbot Proxy Client")
    parser.add_argument("--edon-url", default=os.getenv("EDON_GATEWAY_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--edon-token", default=os.getenv("EDON_GATEWAY_TOKEN") or os.getenv("EDON_API_TOKEN"))
    parser.add_argument("--agent-id", default="clawdbot-agent")
    parser.add_argument("--intent-id", default=None)
    parser.add_argument("--tool", required=True, help="Clawdbot tool name (e.g., sessions_list)")
    parser.add_argument("--action", default="json", help="Action type")
    parser.add_argument("--args", default="{}", help="Tool arguments as JSON string")
    parser.add_argument("--session-key", default=None, help="Optional session key")
    
    args = parser.parse_args()
    
    if not args.edon_token:
        print("Error: EDON token required. Set EDON_GATEWAY_TOKEN or pass --edon-token", file=sys.stderr)
        sys.exit(1)
    
    # Parse args JSON
    try:
        args_dict = json.loads(args.args)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in --args: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create client and invoke
    client = EDONClawdbotProxyClient(
        edon_gateway_url=args.edon_url,
        edon_token=args.edon_token,
        agent_id=args.agent_id,
        intent_id=args.intent_id
    )
    
    result = client.invoke(
        tool=args.tool,
        action=args.action,
        args=args_dict,
        sessionKey=args.session_key
    )
    
    # Print result
    print(json.dumps(result, indent=2))
    
    # Exit with error code if failed
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
