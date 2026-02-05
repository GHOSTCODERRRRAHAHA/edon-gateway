"""SQLite database for EDON Gateway persistence."""

import os
import sqlite3
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, UTC
from contextlib import contextmanager


def _resolve_db_path() -> Path:
    """Resolve DB file path from EDON_DB_URL (sqlite:///path) or EDON_DATABASE_PATH."""
    url = os.getenv("EDON_DB_URL", "").strip()
    if url and url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "", 1)
        return Path(path)
    path = os.getenv("EDON_DATABASE_PATH", "edon_gateway.db")
    return Path(path)


class Database:
    """SQLite database for storing intents, audit events, and decisions."""
    
    def __init__(self, db_path: Path = Path("edon_gateway.db")):
        """Initialize database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
    
    def _init_schema(self):
        """Initialize database schema."""
        from .schema_version import check_schema_version, set_schema_version, SCHEMA_VERSION
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Intents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS intents (
                    intent_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    scope TEXT NOT NULL,  -- JSON
                    constraints TEXT NOT NULL,  -- JSON
                    risk_level TEXT NOT NULL,
                    approved_by_user INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Audit events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_tool TEXT NOT NULL,
                    action_op TEXT NOT NULL,
                    action_params TEXT NOT NULL,  -- JSON
                    action_source TEXT NOT NULL,
                    action_estimated_risk TEXT NOT NULL,
                    action_computed_risk TEXT,
                    decision_verdict TEXT NOT NULL,
                    decision_reason_code TEXT NOT NULL,
                    decision_explanation TEXT NOT NULL,
                    decision_policy_version TEXT NOT NULL,
                    intent_id TEXT,
                    agent_id TEXT,
                    context TEXT,  -- JSON
                    created_at TEXT NOT NULL
                )
            """)
            
            # Decisions table (for quick lookup)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    intent_id TEXT,
                    agent_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Policy versions table (for tracking policy changes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_versions (
                    version TEXT PRIMARY KEY,
                    description TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Active policy preset table (stores currently active preset)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_policy_preset (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    preset_name TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    applied_by TEXT,
                    UNIQUE(id)
                )
            """)
            
            # Users table (internal user IDs - auth provider agnostic)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,  -- Internal UUID (never changes)
                    email TEXT NOT NULL UNIQUE,
                    auth_provider TEXT NOT NULL DEFAULT 'clerk',  -- 'clerk', 'supabase', etc.
                    auth_subject TEXT NOT NULL,  -- Provider's user ID (clerk_user_id, supabase_user_id)
                    role TEXT NOT NULL DEFAULT 'user',  -- 'user', 'admin', etc.
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(auth_provider, auth_subject)  -- One user per auth provider ID
                )
            """)
            
            # Index for auth provider lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_auth_provider 
                ON users(auth_provider, auth_subject)
            """)
            
            # Tenants table (multi-tenant billing) - now references user_id
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,  -- References users.id (internal UUID)
                    status TEXT NOT NULL DEFAULT 'trial',  -- trial, active, past_due, canceled, inactive
                    plan TEXT NOT NULL DEFAULT 'free',  -- free, starter, pro, enterprise
                    mag_enabled INTEGER NOT NULL DEFAULT 0,  -- 1 = MAG enforcement enabled
                    stripe_customer_id TEXT UNIQUE,
                    stripe_subscription_id TEXT UNIQUE,
                    current_period_start TEXT,
                    current_period_end TEXT,
                    cancel_at_period_end INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Index for Stripe lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenants_user_id 
                ON tenants(user_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenants_stripe_customer 
                ON tenants(stripe_customer_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenants_stripe_subscription 
                ON tenants(stripe_subscription_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenants_status 
                ON tenants(status)
            """)
            
            # API Keys table (tenant-scoped authentication)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,  -- SHA256 hash of the actual key
                    name TEXT,  -- User-friendly name for the key
                    status TEXT NOT NULL DEFAULT 'active',  -- active, revoked
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            
            # Indexes for API key lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_keys_tenant 
                ON api_keys(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_keys_hash 
                ON api_keys(key_hash)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_keys_status 
                ON api_keys(status)
            """)

            # Channel tokens (e.g., Telegram/SMS)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS channel_tokens (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    external_user_id TEXT,
                    token_hash TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_channel_tokens_tenant 
                ON channel_tokens(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_channel_tokens_hash 
                ON channel_tokens(token_hash)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_channel_tokens_status 
                ON channel_tokens(status)
            """)

            # Connect codes (short-lived binding codes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connect_codes (
                    code TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    channel TEXT NOT NULL DEFAULT 'telegram',
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    used_by TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connect_codes_tenant 
                ON connect_codes(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connect_codes_expires 
                ON connect_codes(expires_at)
            """)

            # Connect service codes (one-time links for Gmail/Calendar/Brave/GitHub/ElevenLabs)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connect_service_codes (
                    code TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    chat_id TEXT,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connect_service_codes_tenant 
                ON connect_service_codes(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connect_service_codes_expires 
                ON connect_service_codes(expires_at)
            """)

            # Channel bindings (telegram user/chat -> tenant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS channel_bindings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    external_user_id TEXT NOT NULL,
                    external_chat_id TEXT,
                    username TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(channel, external_user_id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_channel_bindings_tenant 
                ON channel_bindings(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_channel_bindings_user 
                ON channel_bindings(channel, external_user_id)
            """)
            
            # Tenant usage tracking (for plan limits)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tenant_usage (
                    tenant_id TEXT NOT NULL,
                    period_start TEXT NOT NULL,  -- YYYY-MM-DD format
                    requests_count INTEGER DEFAULT 0,
                    PRIMARY KEY (tenant_id, period_start),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            
            # Counters table (for rate limiting and metrics)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS counters (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Credentials table (for tool credentials)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tenant_id TEXT,
                    credential_type TEXT NOT NULL,  -- e.g., "smtp", "api_key", "oauth"
                    credential_data TEXT NOT NULL,  -- JSON encrypted/encoded
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT,
                    last_error TEXT,
                    PRIMARY KEY (credential_id, tenant_id)
                )
            """)
            
            # Index for tool lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_credentials_tool 
                ON credentials(tool_name)
            """)
            
            # Token to agent_id binding table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS token_agent_bindings (
                    token_hash TEXT PRIMARY KEY,  -- SHA256 hash of token
                    agent_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL
                )
            """)
            
            # Index for agent lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_token_bindings_agent 
                ON token_agent_bindings(agent_id)
            """)
            
            # Indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_events(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_agent_id 
                ON audit_events(agent_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_intent_id 
                ON audit_events(intent_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_verdict 
                ON audit_events(decision_verdict)
            """)
            
            conn.commit()
            
            # Migration: Add default_intent_id to tenants table (if not exists)
            try:
                cursor.execute("ALTER TABLE tenants ADD COLUMN default_intent_id TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                # Column already exists, ignore
                pass

            # Migration: Add mag_enabled to tenants table (if not exists)
            try:
                cursor.execute("ALTER TABLE tenants ADD COLUMN mag_enabled INTEGER NOT NULL DEFAULT 0")
                conn.commit()
            except sqlite3.OperationalError:
                # Column already exists, ignore
                pass
            
            # Migration: Add tenant_id and last_error to credentials table (if not exists)
            try:
                cursor.execute("ALTER TABLE credentials ADD COLUMN tenant_id TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                # Column already exists, ignore
                pass
            
            try:
                cursor.execute("ALTER TABLE credentials ADD COLUMN last_error TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                # Column already exists, ignore
                pass
            
            # Memory: long-term preferences (KV per tenant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS preference_memory (
                    tenant_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, key),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_preference_memory_tenant 
                ON preference_memory(tenant_id)
            """)
            
            # Memory: episodic task memory (past tasks, outcomes, context)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS episodic_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    task_summary TEXT NOT NULL,
                    outcome TEXT,
                    tool TEXT,
                    op TEXT,
                    context TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_episodic_memory_tenant_created 
                ON episodic_memory(tenant_id, created_at)
            """)
            
            conn.commit()
            
            # Check and set schema version
            from .schema_version import check_schema_version, set_schema_version, SCHEMA_VERSION
            if not check_schema_version(self):
                set_schema_version(self, SCHEMA_VERSION)
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper error handling."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        # Enable foreign keys and WAL mode for better concurrency
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
        except sqlite3.Error as e:
            conn.rollback()
            raise RuntimeError(f"Database error: {str(e)}") from e
        finally:
            conn.close()
    
    def save_intent(self, intent_id: str, objective: str, scope: Dict, 
                   constraints: Dict, risk_level: str, approved_by_user: bool):
        """Save or update an intent contract.
        
        Args:
            intent_id: Unique intent identifier
            objective: Intent objective
            scope: Tool scope dictionary
            constraints: Constraints dictionary
            risk_level: Risk level string
            approved_by_user: Whether user approved
            
        Raises:
            ValueError: If validation fails
            RuntimeError: If database operation fails
        """
        # Validation
        if not intent_id or not intent_id.strip():
            raise ValueError("intent_id cannot be empty")
        if not objective or not objective.strip():
            raise ValueError("objective cannot be empty")
        if not isinstance(scope, dict):
            raise ValueError("scope must be a dictionary")
        if not isinstance(constraints, dict):
            raise ValueError("constraints must be a dictionary")
        if risk_level not in ["low", "medium", "high", "critical"]:
            raise ValueError(f"Invalid risk_level: {risk_level}")
        
        now = datetime.now(UTC).isoformat()
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO intents 
                    (intent_id, objective, scope, constraints, risk_level, 
                     approved_by_user, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 
                            COALESCE((SELECT created_at FROM intents WHERE intent_id = ?), ?), ?)
                """, (
                    intent_id, objective, json.dumps(scope), json.dumps(constraints),
                    risk_level, approved_by_user, intent_id, now, now
                ))
                conn.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Failed to save intent: {str(e)}") from e
    
    def get_intent(self, intent_id: str) -> Optional[Dict[str, Any]]:
        """Get an intent contract by ID.
        
        Args:
            intent_id: Intent identifier
            
        Returns:
            Intent dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM intents WHERE intent_id = ?
            """, (intent_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    "intent_id": row["intent_id"],
                    "objective": row["objective"],
                    "scope": json.loads(row["scope"]),
                    "constraints": json.loads(row["constraints"]),
                    "risk_level": row["risk_level"],
                    "approved_by_user": bool(row["approved_by_user"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    def list_intents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List all intents.
        
        Args:
            limit: Maximum number of intents to return
            
        Returns:
            List of intent dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM intents 
                ORDER BY updated_at DESC 
                LIMIT ?
            """, (limit,))
            
            return [
                {
                    "intent_id": row["intent_id"],
                    "objective": row["objective"],
                    "scope": json.loads(row["scope"]),
                    "constraints": json.loads(row["constraints"]),
                    "risk_level": row["risk_level"],
                    "approved_by_user": bool(row["approved_by_user"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
                for row in cursor.fetchall()
            ]
    
    def get_latest_intent(self) -> Optional[Dict[str, Any]]:
        """Get the most recently updated intent.
        
        Returns:
            Intent dictionary or None if no intents exist
        """
        intents = self.list_intents(limit=1)
        return intents[0] if intents else None
    
    def save_audit_event(self, action: Dict, decision: Dict, intent_id: Optional[str],
                        agent_id: Optional[str], context: Dict) -> str:
        """Save an audit event.
        
        Args:
            action: Action dictionary
            decision: Decision dictionary
            intent_id: Intent identifier (optional)
            agent_id: Agent identifier (optional)
            context: Additional context dictionary
            
        Returns:
            Decision ID that was created
        """
        now = datetime.now(UTC).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_events (
                    timestamp, action_id, action_tool, action_op, action_params,
                    action_source, action_estimated_risk, action_computed_risk,
                    decision_verdict, decision_reason_code, decision_explanation,
                    decision_policy_version, intent_id, agent_id, context, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action.get("requested_at", now),
                action.get("id", ""),
                action.get("tool", ""),
                action.get("op", ""),
                json.dumps(action.get("params", {})),
                action.get("source", ""),
                action.get("estimated_risk", ""),
                action.get("computed_risk"),
                decision.get("verdict", ""),
                decision.get("reason_code", ""),
                decision.get("explanation", ""),
                decision.get("policy_version", "1.0.0"),
                intent_id,
                agent_id,
                json.dumps(context),
                now
            ))
            
            # Also save to decisions table for quick lookup
            # Use action_id + timestamp for unique decision_id
            action_id = action.get("id", "")
            decision_id = f"dec-{action_id}-{now}" if action_id else f"dec-{now}"
            cursor.execute("""
                INSERT OR REPLACE INTO decisions 
                (decision_id, action_id, verdict, reason_code, explanation,
                 policy_version, intent_id, agent_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision_id,
                action_id,
                decision.get("verdict", ""),
                decision.get("reason_code", ""),
                decision.get("explanation", ""),
                decision.get("policy_version", "1.0.0"),
                intent_id,
                agent_id,
                now
            ))
            
            conn.commit()
            return decision_id
    
    def query_audit_events(self, agent_id: Optional[str] = None,
                          verdict: Optional[str] = None,
                          intent_id: Optional[str] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events.
        
        Args:
            agent_id: Filter by agent ID
            verdict: Filter by verdict
            intent_id: Filter by intent ID
            limit: Maximum number of events to return
            
        Returns:
            List of audit event dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            
            if verdict:
                query += " AND decision_verdict = ?"
                params.append(verdict)
            
            if intent_id:
                query += " AND intent_id = ?"
                params.append(intent_id)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            return [
                {
                    "timestamp": row["timestamp"],
                    "action": {
                        "id": row["action_id"],
                        "tool": row["action_tool"],
                        "op": row["action_op"],
                        "params": json.loads(row["action_params"]),
                        "source": row["action_source"],
                        "estimated_risk": row["action_estimated_risk"],
                        "computed_risk": row["action_computed_risk"]
                    },
                    "decision": {
                        "verdict": row["decision_verdict"],
                        "reason_code": row["decision_reason_code"],
                        "explanation": row["decision_explanation"],
                        "policy_version": row["decision_policy_version"]
                    },
                    "intent_id": row["intent_id"],
                    "context": json.loads(row["context"]) if row["context"] else {},
                    "created_at": row["created_at"]
                }
                for row in cursor.fetchall()
            ]
    
    def increment_counter(self, key: str, amount: int = 1) -> int:
        """Increment a counter (for rate limiting).
        
        Args:
            key: Counter key (e.g., "agent:clawdbot-001:actions:minute")
            amount: Amount to increment
            
        Returns:
            New counter value
        """
        now = datetime.now(UTC).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO counters (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = value + ?,
                    updated_at = ?
            """, (key, amount, now, amount, now))
            
            cursor.execute("SELECT value FROM counters WHERE key = ?", (key,))
            row = cursor.fetchone()
            conn.commit()
            
            return row["value"] if row else amount
    
    def get_counter(self, key: str) -> int:
        """Get counter value.
        
        Args:
            key: Counter key
            
        Returns:
            Counter value (0 if not found)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM counters WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else 0
    
    def save_credential(self, credential_id: str, tool_name: str, 
                      credential_type: str, credential_data: Dict[str, Any],
                      encrypted: bool = False, tenant_id: Optional[str] = None) -> None:
        """Save or update a credential.
        
        Args:
            credential_id: Unique credential identifier
            tool_name: Tool name (e.g., "email", "filesystem", "clawdbot")
            credential_type: Type of credential (e.g., "smtp", "api_key", "gateway")
            credential_data: Credential data dictionary
            encrypted: Whether credential_data is encrypted
            tenant_id: Optional tenant ID for tenant-scoped credentials
            
        Raises:
            ValueError: If validation fails
            RuntimeError: If database operation fails
        """
        # Validation
        if not credential_id or not credential_id.strip():
            raise ValueError("credential_id cannot be empty")
        if not tool_name or not tool_name.strip():
            raise ValueError("tool_name cannot be empty")
        if not isinstance(credential_data, dict):
            raise ValueError("credential_data must be a dictionary")
        
        now = datetime.now(UTC).isoformat()
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO credentials 
                    (credential_id, tool_name, tenant_id, credential_type, credential_data,
                     encrypted, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 
                            COALESCE((SELECT created_at FROM credentials WHERE credential_id = ? AND (tenant_id = ? OR (tenant_id IS NULL AND ? IS NULL))), ?), ?)
                """, (
                    credential_id, tool_name, tenant_id, credential_type,
                    json.dumps(credential_data), 1 if encrypted else 0,
                    credential_id, tenant_id, tenant_id, now, now
                ))
                conn.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Failed to save credential: {str(e)}") from e
    
    def get_credential(self, credential_id: str, tool_name: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get a credential by ID. Deterministic: strict tenant match, most recent row.
        
        When tenant_id is provided: match only that tenant.
        When tenant_id is None: match only tenant_id IS NULL (no fallback to other tenant).
        When multiple rows exist: select most recent (ORDER BY rowid DESC LIMIT 1).
        
        Args:
            credential_id: Credential identifier
            tool_name: Optional tool name filter
            tenant_id: Optional tenant ID for tenant-scoped lookup (None = global only)
            
        Returns:
            Credential dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM credentials WHERE credential_id = ?"
            params: List[Any] = [credential_id]
            if tool_name:
                query += " AND tool_name = ?"
                params.append(tool_name)
            if tenant_id is not None:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            else:
                query += " AND tenant_id IS NULL"
            query += " ORDER BY rowid DESC LIMIT 1"
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()
            if row:
                result = {
                    "credential_id": row["credential_id"],
                    "tool_name": row["tool_name"],
                    "credential_type": row["credential_type"],
                    "credential_data": json.loads(row["credential_data"]),
                    "encrypted": bool(row["encrypted"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                if "last_used_at" in row.keys():
                    result["last_used_at"] = row["last_used_at"]
                if "tenant_id" in row.keys():
                    result["tenant_id"] = row["tenant_id"]
                if "last_error" in row.keys():
                    result["last_error"] = row["last_error"]
                return result
            return None
    
    def get_credentials_by_tool(self, tool_name: str) -> List[Dict[str, Any]]:
        """Get all credentials for a tool.
        
        Args:
            tool_name: Tool name
            
        Returns:
            List of credential dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM credentials 
                WHERE tool_name = ?
                ORDER BY updated_at DESC
            """, (tool_name,))
            
            return [
                {
                    "credential_id": row["credential_id"],
                    "tool_name": row["tool_name"],
                    "credential_type": row["credential_type"],
                    "credential_data": json.loads(row["credential_data"]),
                    "encrypted": bool(row["encrypted"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "last_used_at": row["last_used_at"]
                }
                for row in cursor.fetchall()
            ]
    
    def update_credential_last_used(self, credential_id: str, tenant_id: Optional[str] = None):
        """Update last_used_at timestamp for a credential (by credential_id and optional tenant_id)."""
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id is not None:
                cursor.execute("""
                    UPDATE credentials SET last_used_at = ?
                    WHERE credential_id = ? AND tenant_id = ?
                """, (now, credential_id, tenant_id))
            else:
                cursor.execute("""
                    UPDATE credentials SET last_used_at = ?
                    WHERE credential_id = ? AND tenant_id IS NULL
                """, (now, credential_id))
            conn.commit()

    def update_credential_status(
        self,
        credential_id: str,
        tenant_id: Optional[str],
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """Record Edonbot invoke result for integration status.
        On success: set last_used_at, clear last_error.
        On failure: set last_error (user-safe message).
        """
        now = datetime.now(UTC).isoformat()
        err_safe = (error_message or "")[:500] if error_message else None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id is not None:
                if success:
                    cursor.execute("""
                        UPDATE credentials SET last_used_at = ?, last_error = NULL
                        WHERE credential_id = ? AND tenant_id = ?
                    """, (now, credential_id, tenant_id))
                else:
                    cursor.execute("""
                        UPDATE credentials SET last_error = ?
                        WHERE credential_id = ? AND tenant_id = ?
                    """, (err_safe, credential_id, tenant_id))
            else:
                if success:
                    cursor.execute("""
                        UPDATE credentials SET last_used_at = ?, last_error = NULL
                        WHERE credential_id = ? AND tenant_id IS NULL
                    """, (now, credential_id))
                else:
                    cursor.execute("""
                        UPDATE credentials SET last_error = ?
                        WHERE credential_id = ? AND tenant_id IS NULL
                    """, (err_safe, credential_id))
            conn.commit()

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential.
        
        Args:
            credential_id: Credential identifier
            
        Returns:
            True if deleted, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE credential_id = ?", (credential_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def bind_token_to_agent(self, token: str, agent_id: str):
        """Bind a token to an agent_id.
        
        Args:
            token: Authentication token
            agent_id: Agent identifier
        """
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(UTC).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO token_agent_bindings 
                (token_hash, agent_id, created_at, last_used_at)
                VALUES (?, ?, 
                        COALESCE((SELECT created_at FROM token_agent_bindings WHERE token_hash = ?), ?), ?)
            """, (token_hash, agent_id, token_hash, now, now))
            conn.commit()
    
    def get_agent_id_for_token(self, token: str) -> Optional[str]:
        """Get agent_id bound to a token.
        
        Args:
            token: Authentication token
            
        Returns:
            Agent ID or None if not found
        """
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT agent_id FROM token_agent_bindings WHERE token_hash = ?
            """, (token_hash,))
            row = cursor.fetchone()
            return row["agent_id"] if row else None
    
    def update_token_last_used(self, token: str):
        """Update last_used_at for a token.
        
        Args:
            token: Authentication token
        """
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(UTC).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE token_agent_bindings 
                SET last_used_at = ?
                WHERE token_hash = ?
            """, (now, token_hash))
            conn.commit()
    
    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Get a decision by ID.
        
        Args:
            decision_id: Decision identifier
            
        Returns:
            Decision dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM decisions WHERE decision_id = ?
            """, (decision_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    "decision_id": row["decision_id"],
                    "action_id": row["action_id"],
                    "verdict": row["verdict"],
                    "reason_code": row["reason_code"],
                    "explanation": row["explanation"],
                    "policy_version": row["policy_version"],
                    "intent_id": row["intent_id"],
                    "agent_id": row["agent_id"],
                    "created_at": row["created_at"]
                }
            return None
    
    def query_decisions(self, action_id: Optional[str] = None,
                       verdict: Optional[str] = None,
                       intent_id: Optional[str] = None,
                       agent_id: Optional[str] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Query decisions with action details from audit_events.
        
        Args:
            action_id: Filter by action ID
            verdict: Filter by verdict
            intent_id: Filter by intent ID
            agent_id: Filter by agent ID
            limit: Maximum number of decisions to return
            
        Returns:
            List of decision dictionaries with action details
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Join with audit_events to get action details (tool, op)
            query = """
                SELECT 
                    d.decision_id,
                    d.action_id,
                    d.verdict,
                    d.reason_code,
                    d.explanation,
                    d.policy_version,
                    d.intent_id,
                    d.agent_id,
                    d.created_at,
                    a.action_tool,
                    a.action_op,
                    a.action_params,
                    a.timestamp
                FROM decisions d
                LEFT JOIN audit_events a ON d.action_id = a.action_id
                WHERE 1=1
            """
            params = []
            
            if action_id:
                query += " AND d.action_id = ?"
                params.append(action_id)
            
            if verdict:
                query += " AND d.verdict = ?"
                params.append(verdict)
            
            if intent_id:
                query += " AND d.intent_id = ?"
                params.append(intent_id)
            
            if agent_id:
                query += " AND d.agent_id = ?"
                params.append(agent_id)
            
            query += " ORDER BY d.created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                # Map verdict to UI format (ALLOW -> allowed, BLOCK -> blocked, etc.)
                verdict_map = {
                    "ALLOW": "allowed",
                    "BLOCK": "blocked",
                    "ESCALATE": "confirm",
                    "DEGRADE": "confirm",
                    "PAUSE": "confirm"
                }
                verdict = row["verdict"] or "UNKNOWN"
                verdict_lower = verdict_map.get(verdict, verdict.lower())
                
                decision = {
                    "id": row["decision_id"],  # Use 'id' for UI compatibility
                    "decision_id": row["decision_id"],
                    "action_id": row["action_id"],
                    "verdict": verdict_lower,
                    "reason_code": row["reason_code"],
                    "explanation": row["explanation"],
                    "policy_version": row["policy_version"],
                    "intent_id": row["intent_id"],
                    "agent_id": row["agent_id"] or "unknown",
                    "created_at": row["created_at"],
                    "timestamp": row["timestamp"] or row["created_at"],  # Use timestamp from audit if available
                }
                
                # Add tool information if available
                if row["action_tool"] and row["action_op"]:
                    decision["tool"] = {
                        "name": row["action_tool"],
                        "op": row["action_op"]
                    }
                
                # Add latency_ms if available (could be calculated from timestamps)
                decision["latency_ms"] = 0  # Default, can be calculated if needed
                
                results.append(decision)
            
            return results
    
    def get_decision_by_action_id(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get decision by action ID (most recent).
        
        Args:
            action_id: Action identifier
            
        Returns:
            Decision dictionary or None if not found
        """
        decisions = self.query_decisions(action_id=action_id, limit=1)
        return decisions[0] if decisions else None
    
    def set_active_policy_preset(self, preset_name: str, applied_by: Optional[str] = None):
        """Set the active policy preset.
        
        Args:
            preset_name: Name of the policy preset
            applied_by: Optional identifier of who applied it
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO active_policy_preset (id, preset_name, applied_at, applied_by)
                VALUES (1, ?, ?, ?)
            """, (preset_name, now, applied_by))
            conn.commit()
    
    def get_active_policy_preset(self) -> Optional[Dict[str, Any]]:
        """Get the currently active policy preset.
        
        Returns:
            Dictionary with preset_name, applied_at, applied_by, or None if not set
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT preset_name, applied_at, applied_by 
                FROM active_policy_preset 
                WHERE id = 1
            """)
            row = cursor.fetchone()
            if row:
                return {
                    "preset_name": row["preset_name"],
                    "applied_at": row["applied_at"],
                    "applied_by": row["applied_by"]
                }
            return None
    
    # User management methods (auth provider agnostic)
    def create_user(self, user_id: str, email: str, auth_provider: str, auth_subject: str, role: str = "user") -> str:
        """Create a new user with internal UUID.
        
        Args:
            user_id: Internal UUID (generated by caller)
            email: User email address
            auth_provider: Auth provider name ('clerk', 'supabase', etc.)
            auth_subject: Provider's user ID (clerk_user_id, supabase_user_id, etc.)
            role: User role ('user', 'admin', etc.)
            
        Returns:
            user_id
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users 
                (id, email, auth_provider, auth_subject, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, email, auth_provider, auth_subject, role, now, now))
            conn.commit()
        return user_id
    
    def get_user_by_auth(self, auth_provider: str, auth_subject: str) -> Optional[Dict[str, Any]]:
        """Get user by auth provider credentials.
        
        Args:
            auth_provider: Auth provider name ('clerk', 'supabase', etc.)
            auth_subject: Provider's user ID
            
        Returns:
            User dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE auth_provider = ? AND auth_subject = ?
            """, (auth_provider, auth_subject))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "email": row["email"],
                    "auth_provider": row["auth_provider"],
                    "auth_subject": row["auth_subject"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by internal ID.
        
        Args:
            user_id: Internal user UUID
            
        Returns:
            User dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE id = ?
            """, (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "email": row["email"],
                    "auth_provider": row["auth_provider"],
                    "auth_subject": row["auth_subject"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    # Tenant management methods
    def create_tenant(self, tenant_id: str, user_id: str, stripe_customer_id: Optional[str] = None) -> str:
        """Create a new tenant linked to a user.
        
        Args:
            tenant_id: Unique tenant identifier
            user_id: Internal user UUID (from users table)
            stripe_customer_id: Optional Stripe customer ID
            
        Returns:
            tenant_id
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tenants 
                (id, user_id, status, plan, mag_enabled, stripe_customer_id, created_at, updated_at)
                VALUES (?, ?, 'trial', 'free', 0, ?, ?, ?)
            """, (tenant_id, user_id, stripe_customer_id, now, now))
            conn.commit()
        return tenant_id
    
    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by ID.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Tenant dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, u.email, u.id as user_id
                FROM tenants t
                JOIN users u ON t.user_id = u.id
                WHERE t.id = ?
            """, (tenant_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "status": row["status"],
                    "plan": row["plan"],
                    "mag_enabled": bool(row["mag_enabled"]) if "mag_enabled" in row.keys() else False,
                    "stripe_customer_id": row["stripe_customer_id"],
                    "stripe_subscription_id": row["stripe_subscription_id"],
                    "current_period_start": row["current_period_start"],
                    "current_period_end": row["current_period_end"],
                    "cancel_at_period_end": bool(row["cancel_at_period_end"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None

    def is_mag_enabled(self, tenant_id: str) -> bool:
        """Check if MAG enforcement is enabled for a tenant."""
        if not tenant_id:
            return False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mag_enabled FROM tenants WHERE id = ?", (tenant_id,))
            row = cursor.fetchone()
            if not row:
                return False
            try:
                return bool(row["mag_enabled"])
            except Exception:
                return False
    
    def get_tenant_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by user ID.
        
        Args:
            user_id: Internal user UUID
            
        Returns:
            Tenant dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, u.email, u.id as user_id
                FROM tenants t
                JOIN users u ON t.user_id = u.id
                WHERE t.user_id = ?
            """, (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "status": row["status"],
                    "plan": row["plan"],
                    "mag_enabled": bool(row["mag_enabled"]) if "mag_enabled" in row.keys() else False,
                    "stripe_customer_id": row["stripe_customer_id"],
                    "stripe_subscription_id": row["stripe_subscription_id"],
                    "current_period_start": row["current_period_start"],
                    "current_period_end": row["current_period_end"],
                    "cancel_at_period_end": bool(row["cancel_at_period_end"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    def get_tenant_by_stripe_customer(self, stripe_customer_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by Stripe customer ID.
        
        Args:
            stripe_customer_id: Stripe customer ID
            
        Returns:
            Tenant dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, u.email, u.id as user_id
                FROM tenants t
                JOIN users u ON t.user_id = u.id
                WHERE t.stripe_customer_id = ?
            """, (stripe_customer_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "status": row["status"],
                    "plan": row["plan"],
                    "mag_enabled": bool(row["mag_enabled"]) if "mag_enabled" in row.keys() else False,
                    "stripe_customer_id": row["stripe_customer_id"],
                    "stripe_subscription_id": row["stripe_subscription_id"],
                    "current_period_start": row["current_period_start"],
                    "current_period_end": row["current_period_end"],
                    "cancel_at_period_end": bool(row["cancel_at_period_end"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    def get_tenant_by_stripe_subscription(self, stripe_subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by Stripe subscription ID.
        
        Args:
            stripe_subscription_id: Stripe subscription ID
            
        Returns:
            Tenant dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, u.email, u.id as user_id
                FROM tenants t
                JOIN users u ON t.user_id = u.id
                WHERE t.stripe_subscription_id = ?
            """, (stripe_subscription_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "status": row["status"],
                    "plan": row["plan"],
                    "mag_enabled": bool(row["mag_enabled"]) if "mag_enabled" in row.keys() else False,
                    "stripe_customer_id": row["stripe_customer_id"],
                    "stripe_subscription_id": row["stripe_subscription_id"],
                    "current_period_start": row["current_period_start"],
                    "current_period_end": row["current_period_end"],
                    "cancel_at_period_end": bool(row["cancel_at_period_end"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
    
    def update_tenant_subscription(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        plan: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
        current_period_start: Optional[str] = None,
        current_period_end: Optional[str] = None,
        cancel_at_period_end: Optional[bool] = None
    ):
        """Update tenant subscription information.
        
        Args:
            tenant_id: Tenant identifier
            status: Subscription status
            plan: Plan name
            stripe_subscription_id: Stripe subscription ID
            current_period_start: Period start timestamp
            current_period_end: Period end timestamp
            cancel_at_period_end: Whether to cancel at period end
        """
        now = datetime.now(UTC).isoformat()
        updates = []
        params = []
        
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if plan is not None:
            updates.append("plan = ?")
            params.append(plan)
        if stripe_subscription_id is not None:
            updates.append("stripe_subscription_id = ?")
            params.append(stripe_subscription_id)
        if current_period_start is not None:
            updates.append("current_period_start = ?")
            params.append(current_period_start)
        if current_period_end is not None:
            updates.append("current_period_end = ?")
            params.append(current_period_end)
        if cancel_at_period_end is not None:
            updates.append("cancel_at_period_end = ?")
            params.append(1 if cancel_at_period_end else 0)
        
        updates.append("updated_at = ?")
        params.append(now)
        params.append(tenant_id)
        
        if updates:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"""
                    UPDATE tenants 
                    SET {', '.join(updates)}
                    WHERE id = ?
                """, params)
                conn.commit()
    
    def get_tenant_default_intent(self, tenant_id: str) -> Optional[str]:
        """Get tenant's default intent ID.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Intent ID or None if not set
        """
        tenant = self.get_tenant(tenant_id)
        if tenant:
            return tenant.get("default_intent_id")
        return None

    def update_tenant_default_intent(self, tenant_id: str, intent_id: str) -> None:
        """Update tenant's default intent ID.
        
        Args:
            tenant_id: Tenant identifier
            intent_id: Intent identifier to set as default
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE tenants
                SET default_intent_id = ?, updated_at = ?
                WHERE id = ?
            """, (intent_id, now, tenant_id))
            conn.commit()
    
    def get_integration_status(self, tenant_id: Optional[str], tool_name: str = "clawdbot") -> Dict[str, Any]:
        """Get integration status for a tool.
        
        connected = True only if credential exists AND last successful invoke/probe succeeded
        (i.e. last_error is None). last_ok_at = last_used_at when connected; last_error surfaced.
        """
        credential_id = f"{tool_name}_gateway_{tenant_id}" if tenant_id else f"{tool_name}_gateway"
        credential = self.get_credential(credential_id, tool_name=tool_name, tenant_id=tenant_id)
        if not credential:
            return {
                "connected": False,
                "last_ok_at": None,
                "last_error": None,
                "base_url": None,
                "auth_mode": None,
            }
        data = credential.get("credential_data", {}) or {}
        last_error = credential.get("last_error")
        last_used_at = credential.get("last_used_at")
        connected = last_used_at is not None
        return {
            "connected": connected,
            "last_ok_at": last_used_at,
            "last_error": last_error,
            "base_url": data.get("base_url") or data.get("gateway_url"),
            "auth_mode": data.get("auth_mode") or "token",
        }
    
    # API Key management methods
    def create_api_key(self, tenant_id: str, key_hash: str, name: Optional[str] = None) -> str:
        """Create a new API key.
        
        Args:
            tenant_id: Tenant identifier
            key_hash: SHA256 hash of the API key
            name: Optional user-friendly name
            
        Returns:
            API key ID
        """
        import uuid
        api_key_id = f"key_{uuid.uuid4().hex[:16]}"
        now = datetime.now(UTC).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_keys 
                (id, tenant_id, key_hash, name, status, created_at)
                VALUES (?, ?, ?, ?, 'active', ?)
            """, (api_key_id, tenant_id, key_hash, name, now))
            conn.commit()
        return api_key_id
    
    def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Get API key by hash.
        
        Args:
            key_hash: SHA256 hash of the API key
            
        Returns:
            API key dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM api_keys WHERE key_hash = ? AND status = 'active'
            """, (key_hash,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "tenant_id": row["tenant_id"],
                    "key_hash": row["key_hash"],
                    "name": row["name"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "last_used_at": row["last_used_at"]
                }
            return None
    
    def update_api_key_last_used(self, api_key_id: str):
        """Update API key last used timestamp.
        
        Args:
            api_key_id: API key identifier
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys 
                SET last_used_at = ?
                WHERE id = ?
            """, (now, api_key_id))
            conn.commit()
    
    def revoke_api_key(self, api_key_id: str) -> bool:
        """Revoke an API key.
        
        Args:
            api_key_id: API key identifier
            
        Returns:
            True if revoked, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys 
                SET status = 'revoked'
                WHERE id = ?
            """, (api_key_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def list_api_keys(self, tenant_id: str) -> List[Dict[str, Any]]:
        """List all API keys for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            List of API key dictionaries with key preview
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, status, key_hash, created_at, last_used_at
                FROM api_keys 
                WHERE tenant_id = ?
                ORDER BY created_at DESC
            """, (tenant_id,))
            
            keys = []
            for row in cursor.fetchall():
                # Create preview: first 12 chars + "••••••"
                key_hash = row["key_hash"]
                preview = f"edon_{key_hash[:8]}••••••" if key_hash else "edon_••••••"
                
                keys.append({
                    "id": row["id"],
                    "name": row["name"],
                    "status": row["status"],
                    "key_preview": preview,
                    "is_active": row["status"] == "active",
                    "created_at": row["created_at"],
                    "last_used": row["last_used_at"]
                })
            
            return keys

    # Channel token + connect code methods (Telegram/SMS)
    def create_connect_code(
        self,
        tenant_id: str,
        expires_at: str,
        channel: str = "telegram",
    ) -> str:
        """Create a short-lived connect code for a tenant/channel."""
        import secrets
        now = datetime.now(UTC).isoformat()
        code = f"EDON-{secrets.token_hex(3).upper()}"  # 6 hex chars
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO connect_codes (code, tenant_id, channel, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (code, tenant_id, channel, expires_at, now))
            conn.commit()
        return code

    def get_connect_code(self, code: str) -> Optional[Dict[str, Any]]:
        """Fetch a connect code entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM connect_codes WHERE code = ?
            """, (code,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "code": row["code"],
                "tenant_id": row["tenant_id"],
                "channel": row["channel"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "used_by": row["used_by"],
                "created_at": row["created_at"],
            }

    def mark_connect_code_used(self, code: str, used_by: Optional[str] = None) -> None:
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE connect_codes
                SET used_at = ?, used_by = ?
                WHERE code = ?
            """, (now, used_by, code))
            conn.commit()

    def create_connect_service_code(
        self,
        tenant_id: str,
        service: str,
        expires_at: str,
        chat_id: Optional[str] = None,
    ) -> str:
        """Create a short-lived code for connecting a service (gmail, brave_search, etc.)."""
        import secrets
        now = datetime.now(UTC).isoformat()
        code = f"EDON-{secrets.token_hex(4).upper()}"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO connect_service_codes (code, tenant_id, service, chat_id, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (code, tenant_id, service, chat_id, expires_at, now))
            conn.commit()
        return code

    def get_connect_service_code(self, code: str) -> Optional[Dict[str, Any]]:
        """Fetch a connect service code entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM connect_service_codes WHERE code = ?
            """, (code,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "code": row["code"],
                "tenant_id": row["tenant_id"],
                "service": row["service"],
                "chat_id": row["chat_id"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "created_at": row["created_at"],
            }

    def mark_connect_service_code_used(self, code: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE connect_service_codes SET used_at = ? WHERE code = ?
            """, (now, code))
            conn.commit()

    def list_connected_services_for_tenant(self, tenant_id: str) -> List[str]:
        """Return list of tool_name values that have at least one credential for this tenant."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT tool_name FROM credentials
                WHERE tenant_id = ? AND tool_name IN ('gmail', 'google_calendar', 'brave_search', 'github', 'elevenlabs')
                ORDER BY tool_name
            """, (tenant_id,))
            return [row["tool_name"] for row in cursor.fetchall()]

    def upsert_channel_binding(
        self,
        tenant_id: str,
        channel: str,
        external_user_id: str,
        external_chat_id: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO channel_bindings
                (tenant_id, channel, external_user_id, external_chat_id, username, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(channel, external_user_id)
                DO UPDATE SET
                  tenant_id = excluded.tenant_id,
                  external_chat_id = excluded.external_chat_id,
                  username = excluded.username,
                  status = 'active',
                  updated_at = excluded.updated_at
            """, (tenant_id, channel, external_user_id, external_chat_id, username, now, now))
            conn.commit()

    def create_channel_token(
        self,
        tenant_id: str,
        channel: str,
        external_user_id: Optional[str] = None,
        token_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a channel token and return {id, raw_token}."""
        import uuid
        import secrets
        import hashlib
        raw_token = secrets.token_hex(24)
        key_hash = token_hash or hashlib.sha256(raw_token.encode()).hexdigest()
        token_id = f"cht_{uuid.uuid4().hex[:16]}"
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO channel_tokens
                (id, tenant_id, channel, external_user_id, token_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?)
            """, (token_id, tenant_id, channel, external_user_id, key_hash, now))
            conn.commit()
        return {"id": token_id, "raw_token": raw_token}

    def get_channel_token_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM channel_tokens WHERE token_hash = ? AND status = 'active'
            """, (key_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "channel": row["channel"],
                "external_user_id": row["external_user_id"],
                "status": row["status"],
                "created_at": row["created_at"],
                "last_used_at": row["last_used_at"],
            }

    def update_channel_token_last_used(self, token_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE channel_tokens
                SET last_used_at = ?
                WHERE id = ?
            """, (now, token_id))
            conn.commit()
    
    # Usage tracking methods
    def increment_tenant_usage(self, tenant_id: str, count: int = 1):
        """Increment tenant usage counter for current period.
        
        Args:
            tenant_id: Tenant identifier
            count: Number of requests to add
        """
        from datetime import date
        period_start = date.today().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Try to update existing record
            cursor.execute("""
                UPDATE tenant_usage 
                SET requests_count = requests_count + ?
                WHERE tenant_id = ? AND period_start = ?
            """, (count, tenant_id, period_start))
            
            # If no record exists, create one
            if cursor.rowcount == 0:
                cursor.execute("""
                    INSERT INTO tenant_usage (tenant_id, period_start, requests_count)
                    VALUES (?, ?, ?)
                """, (tenant_id, period_start, count))
            
            conn.commit()
    
    def get_tenant_usage(self, tenant_id: str, period_start: Optional[str] = None) -> int:
        """Get tenant usage for a period.
        
        Args:
            tenant_id: Tenant identifier
            period_start: Period start date (YYYY-MM-DD), defaults to today
            
        Returns:
            Number of requests in the period
        """
        from datetime import date
        if period_start is None:
            period_start = date.today().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT requests_count 
                FROM tenant_usage 
                WHERE tenant_id = ? AND period_start = ?
            """, (tenant_id, period_start))
            row = cursor.fetchone()
            return row["requests_count"] if row else 0

    # Memory: long-term preferences (KV per tenant)
    def write_preference(self, tenant_id: str, key: str, value: str) -> None:
        """Write a preference (intentional, governor-approved)."""
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO preference_memory (tenant_id, key, value, updated_at)
                VALUES (?, ?, ?, ?)
            """, (tenant_id, key, value, now))
            conn.commit()

    def read_preferences(self, tenant_id: str, keys: Optional[List[str]] = None) -> Dict[str, str]:
        """Read preferences. If keys is None, return all for tenant."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if keys:
                placeholders = ",".join("?" * len(keys))
                cursor.execute(
                    f"""
                    SELECT key, value FROM preference_memory
                    WHERE tenant_id = ? AND key IN ({placeholders})
                    """,
                    (tenant_id, *keys),
                )
            else:
                cursor.execute(
                    "SELECT key, value FROM preference_memory WHERE tenant_id = ?",
                    (tenant_id,),
                )
            rows = cursor.fetchall()
            return {row["key"]: row["value"] for row in rows} if rows else {}

    # Memory: episodic task memory
    def append_episode(
        self,
        tenant_id: str,
        episode_id: str,
        task_summary: str,
        outcome: Optional[str] = None,
        tool: Optional[str] = None,
        op: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append an episode (intentional, governor-approved)."""
        now = datetime.now(UTC).isoformat()
        ctx_json = json.dumps(context) if context else None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO episodic_memory
                (tenant_id, episode_id, task_summary, outcome, tool, op, context, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (tenant_id, episode_id, task_summary, outcome or "", tool or "", op or "", ctx_json, now))
            conn.commit()

    def query_episodes(
        self,
        tenant_id: str,
        limit: int = 50,
        since: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query episodic memory (most recent first)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            sql = """
                SELECT episode_id, task_summary, outcome, tool, op, context, created_at
                FROM episodic_memory WHERE tenant_id = ?
            """
            params: List[Any] = [tenant_id]
            if since:
                sql += " AND created_at >= ?"
                params.append(since)
            if tool:
                sql += " AND tool = ?"
                params.append(tool)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            out = []
            for row in rows:
                ctx = json.loads(row["context"]) if row["context"] else None
                out.append({
                    "episode_id": row["episode_id"],
                    "task_summary": row["task_summary"],
                    "outcome": row["outcome"],
                    "tool": row["tool"],
                    "op": row["op"],
                    "context": ctx,
                    "created_at": row["created_at"],
                })
            return out


# Global database instance
_db_instance: Optional[Database] = None


def get_db() -> Database:
    """Get global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path=_resolve_db_path())
    return _db_instance
