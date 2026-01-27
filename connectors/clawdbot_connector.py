"""Clawdbot connector - calls Clawdbot Gateway /tools/invoke endpoint."""

import os
import json
import requests
from typing import Dict, Any, Optional
from pathlib import Path


class ClawdbotConnector:
    """Clawdbot connector that calls Clawdbot Gateway /tools/invoke endpoint.
    
    This proves "EDON is the only path to side effects" - the agent cannot
    call Clawdbot tools directly because it doesn't have the token/access.
    Only EDON can execute Clawdbot operations.
    """
    
    def __init__(self, credential_id: Optional[str] = None):
        """Initialize Clawdbot connector.
        
        Args:
            credential_id: Optional credential ID to load from database
        """
        self.credential_id = credential_id
        self._credentials = None
        self._base_url = None
        self._token = None
        
        # Load credentials if credential_id provided
        if credential_id:
            self._load_credentials()
        else:
            # Fallback to environment variables (for development)
            self._load_from_env()
    
    def _load_credentials(self):
        """Load credentials from database.
        
        Raises:
            RuntimeError: If EDON_CREDENTIALS_STRICT=true and credential not found
        """
        from ..persistence import get_db
        db = get_db()
        credential = db.get_credential(self.credential_id)
        
        if credential:
            self._credentials = credential["credential_data"]
            self._base_url = self._credentials.get("gateway_url")
            self._token = self._credentials.get("gateway_token")
            # Update last_used_at
            db.update_credential_last_used(self.credential_id)
            return
        
        # Check strict mode
        credentials_strict = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"
        
        if credentials_strict:
            # PROD mode: fail closed - no fallback
            raise RuntimeError(
                f"Credential '{self.credential_id}' not found in database. "
                "EDON_CREDENTIALS_STRICT=true requires all credentials to be in database. "
                "Set EDON_CREDENTIALS_STRICT=false for development mode."
            )
        
        # DEV mode: fallback to environment variables
        self._load_from_env()
    
    def _load_from_env(self):
        """Load credentials from environment variables (development mode)."""
        self._base_url = os.getenv("CLAWDBOT_GATEWAY_URL", "http://127.0.0.1:18789")
        self._token = os.getenv("CLAWDBOT_GATEWAY_TOKEN", "")
    
    def invoke(
        self,
        tool: str,
        action: str = "json",
        args: Dict[str, Any] = None,
        sessionKey: Optional[str] = None
    ) -> Dict[str, Any]:
        """Invoke a Clawdbot tool via Gateway /tools/invoke endpoint.
        
        Args:
            tool: Clawdbot tool name (e.g., "sessions_list", "web_*")
            action: Action type (default: "json")
            args: Tool arguments
            sessionKey: Optional session key for tool execution
            
        Returns:
            Result dictionary with Clawdbot response
            
        Raises:
            RuntimeError: If credentials not configured
            requests.RequestException: If HTTP request fails
        """
        if not self._token:
            raise RuntimeError(
                "Clawdbot Gateway token not configured. "
                "Set CLAWDBOT_GATEWAY_TOKEN environment variable or configure credentials in database."
            )
        
        if args is None:
            args = {}
        
        # Prepare request body matching Clawdbot schema
        request_body = {
            "tool": tool,
            "action": action,
            "args": args
        }
        
        if sessionKey:
            request_body["sessionKey"] = sessionKey
        
        # Call Clawdbot Gateway
        url = f"{self._base_url}/tools/invoke"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                url,
                json=request_body,
                headers=headers,
                timeout=30  # 30 second timeout
            )
            
            # Clawdbot returns 200 with { ok: true, result } or policy errors like 404
            response.raise_for_status()
            
            result = response.json()
            
            # Clawdbot response format: { ok: true, result: {...} } or { ok: false, error: "..." }
            if result.get("ok"):
                return {
                    "success": True,
                    "tool": tool,
                    "action": action,
                    "result": result.get("result", {}),
                    "clawdbot_response": result
                }
            else:
                # Clawdbot returned ok: false (policy error, tool not allowlisted, etc.)
                return {
                    "success": False,
                    "tool": tool,
                    "action": action,
                    "error": result.get("error", "Unknown Clawdbot error"),
                    "clawdbot_response": result
                }
                
        except requests.exceptions.HTTPError as e:
            # HTTP error (404 if tool not allowlisted, 401 if auth fails, etc.)
            error_msg = f"Clawdbot Gateway HTTP error: {e.response.status_code}"
            try:
                error_body = e.response.json()
                error_msg += f" - {error_body.get('error', str(e))}"
            except:
                error_msg += f" - {str(e)}"
            
            return {
                "success": False,
                "tool": tool,
                "action": action,
                "error": error_msg,
                "http_status": e.response.status_code
            }
        except requests.exceptions.RequestException as e:
            # Network error, timeout, etc.
            return {
                "success": False,
                "tool": tool,
                "action": action,
                "error": f"Clawdbot Gateway request failed: {str(e)}"
            }


# Global instance (credentials would be loaded from EDON config in production)
clawdbot_connector = ClawdbotConnector()
