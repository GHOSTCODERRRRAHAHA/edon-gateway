"""Centralized configuration management for EDON Gateway."""

# 🔐 CRITICAL: Load gateway .env FIRST, before anything else
# This MUST happen before Config class reads os.getenv()
from pathlib import Path
from dotenv import load_dotenv
import os

# 🔐 HARD-OVERRIDE: gateway-only env
ENV_PATH = Path(__file__).resolve().parent / ".env"
if ENV_PATH.exists():
    try:
        load_dotenv(dotenv_path=ENV_PATH, override=True, encoding="utf-8")
    except UnicodeDecodeError:
        # If UTF-8 fails, try to detect and convert encoding
        try:
            # Try reading as UTF-16 (common Windows issue)
            with open(ENV_PATH, "r", encoding="utf-16") as f:
                content = f.read()
            # Write back as UTF-8
            with open(ENV_PATH, "w", encoding="utf-8") as f:
                f.write(content)
            # Reload as UTF-8
            load_dotenv(dotenv_path=ENV_PATH, override=True, encoding="utf-8")
            print(f"⚠️  Converted {ENV_PATH} from UTF-16 to UTF-8")
        except Exception as e:
            raise RuntimeError(
                f"Failed to load {ENV_PATH}: Invalid encoding (not UTF-8). "
                f"Please run: cd edon_gateway && .\\fix_env_encoding.ps1\n"
                f"Or recreate the file with UTF-8 encoding. Error: {e}"
            )

# 🚨 Guardrail: token presence sanity
def _is_production_env() -> bool:
    return os.getenv("ENVIRONMENT") == "production" or os.getenv("EDON_ENV") == "production"

if os.getenv("EDON_AUTH_ENABLED", "true").lower() == "true":
    token = os.getenv("EDON_API_TOKEN")
    if not token:
        raise RuntimeError(
            f"EDON_API_TOKEN missing — gateway cannot start. "
            f"Set EDON_API_TOKEN in {ENV_PATH} or environment variables."
        )
    elif token in ["your-secret-token", "your-secret-token-change-me", "production-token-change-me"]:
        if _is_production_env():
            raise RuntimeError(
                f"EDON_API_TOKEN is set to a default value. "
                f"Change EDON_API_TOKEN in {ENV_PATH} before running in production."
            )
        else:
            import warnings
            warnings.warn(
                f"⚠️  Using default API token! Change EDON_API_TOKEN in {ENV_PATH} for production.",
                UserWarning
            )

from typing import Optional, List


class Config:
    """EDON Gateway configuration.

    Reads environment variables at instance creation time to ensure .env is loaded first.
    """

    def __init__(self):
        # =========================
        # Authentication
        # =========================
        self._AUTH_ENABLED = os.getenv("EDON_AUTH_ENABLED", "true").lower() == "true"
        self._API_TOKEN = os.getenv("EDON_API_TOKEN", "your-secret-token")
        self._TOKEN_BINDING_ENABLED = os.getenv("EDON_TOKEN_BINDING_ENABLED", "false").lower() == "true"

        # Bootstrap / admin override:
        # Allow env token auth in production (default false).
        # If false, production forces tenant-scoped API keys (DB lookup).
        self._ALLOW_ENV_TOKEN_IN_PROD = os.getenv("EDON_ALLOW_ENV_TOKEN_IN_PROD", "false").lower() == "true"

        # =========================
        # Security
        # =========================
        self._CREDENTIALS_STRICT = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"

        # Environment
        self._ENVIRONMENT = os.getenv("ENVIRONMENT") or os.getenv("EDON_ENV") or "development"
        self._TOKEN_HARDENING = os.getenv("EDON_TOKEN_HARDENING", "true").lower() == "true"
        self._NETWORK_GATING = os.getenv("EDON_NETWORK_GATING", "false").lower() == "true"
        self._VALIDATE_STRICT = os.getenv("EDON_VALIDATE_STRICT", "true").lower() == "true"

        # =========================
        # Database
        # =========================
        self._DATABASE_PATH = Path(os.getenv("EDON_DATABASE_PATH", "edon_gateway.db"))

        # =========================
        # Logging
        # =========================
        self._LOG_LEVEL = os.getenv("EDON_LOG_LEVEL", "INFO").upper()
        self._JSON_LOGGING = os.getenv("EDON_JSON_LOGGING", "false").lower() == "true"

        # =========================
        # Monitoring
        # =========================
        self._METRICS_ENABLED = os.getenv("EDON_METRICS_ENABLED", "true").lower() == "true"
        self._METRICS_PORT = int(os.getenv("EDON_METRICS_PORT", "9090"))

        # =========================
        # Rate Limiting
        # =========================
        self._RATE_LIMIT_ENABLED = os.getenv("EDON_RATE_LIMIT_ENABLED", "true").lower() == "true"
        self._RATE_LIMIT_PER_MINUTE = int(os.getenv("EDON_RATE_LIMIT_PER_MINUTE", "60"))
        self._RATE_LIMIT_PER_HOUR = int(os.getenv("EDON_RATE_LIMIT_PER_HOUR", "1000"))

        # =========================
        # CORS
        # =========================
        cors_origins_str = os.getenv("EDON_CORS_ORIGINS", "*")
        self._CORS_ORIGINS = [o.strip() for o in cors_origins_str.split(",") if o.strip()]

        # =========================
        # Server
        # =========================
        self._HOST = os.getenv("EDON_HOST", "0.0.0.0")
        self._PORT = int(os.getenv("EDON_PORT", "8000"))
        self._WORKERS = int(os.getenv("EDON_WORKERS", "1"))

        # =========================
        # UI (you can keep this even if not used)
        # =========================
        self._BUILD_UI = os.getenv("EDON_BUILD_UI", "false").lower() == "true"
        self._UI_REPO_URL = os.getenv(
            "EDON_UI_REPO_URL",
            "https://github.com/GHOSTCODERRRRAHAHA/edon-console-ui.git",
        )

        # =========================
        # Edonbot (single source of truth for default credential_id)
        # =========================
        self._DEFAULT_CLAWDBOT_CREDENTIAL_ID = "clawdbot_gateway_tenant_dev"
        self._CLAWDBOT_GATEWAY_URL = os.getenv("CLAWDBOT_GATEWAY_URL")
        self._CLAWDBOT_GATEWAY_TOKEN = os.getenv("CLAWDBOT_GATEWAY_TOKEN")
        self._CLAWDBOT_CREDENTIAL_ID = os.getenv("EDON_CLAWDBOT_CREDENTIAL_ID", self._DEFAULT_CLAWDBOT_CREDENTIAL_ID)

        # =========================
        # Clerk Authentication
        # =========================
        self._CLERK_SECRET_KEY = os.getenv("CLERK_SECRET_KEY")

        # =========================
        # Telegram / Channel bindings
        # =========================
        self._TELEGRAM_BOT_SECRET = os.getenv("EDON_TELEGRAM_BOT_SECRET") or os.getenv("TELEGRAM_BOT_SECRET")
        self._TELEGRAM_CONNECT_TTL_MIN = int(os.getenv("EDON_TELEGRAM_CONNECT_TTL_MIN", "10"))

        # =========================
        # Connect flow (Gmail, Brave, etc.) — base URL for connect pages
        # =========================
        self._CONNECT_BASE_URL = (os.getenv("EDON_CONNECT_BASE_URL") or os.getenv("CONNECT_BASE_URL") or "").rstrip("/")
        self._GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID") or os.getenv("GMAIL_CLIENT_ID")
        self._GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET") or os.getenv("GMAIL_CLIENT_SECRET")

        # =========================
        # MAG Governance
        # =========================
        self._MAG_ENABLED = os.getenv("EDON_MAG_ENABLED", "false").lower() == "true"
        self._MAG_URL = os.getenv("EDON_MAG_URL", "http://127.0.0.1:8002").rstrip("/")
        mag_paths = os.getenv("EDON_MAG_ENFORCE_PATHS", "/execute,/clawdbot/invoke,/edon/invoke")
        self._MAG_ENFORCE_PATHS = [p.strip() for p in mag_paths.split(",") if p.strip()]

        # =========================
        # Demo Mode
        # =========================
        self._DEMO_MODE = os.getenv("EDON_DEMO_MODE", "false").lower() == "true"
        self._DEMO_TENANT_ID = os.getenv("EDON_DEMO_TENANT_ID", "demo_tenant_001")
        self._DEMO_API_KEY = os.getenv("EDON_DEMO_API_KEY", "edon_demo_key_12345")

    # ===== Properties =====
    @property
    def AUTH_ENABLED(self) -> bool:
        return self._AUTH_ENABLED

    @property
    def API_TOKEN(self) -> str:
        return self._API_TOKEN

    @property
    def TOKEN_BINDING_ENABLED(self) -> bool:
        return self._TOKEN_BINDING_ENABLED

    @property
    def ALLOW_ENV_TOKEN_IN_PROD(self) -> bool:
        return self._ALLOW_ENV_TOKEN_IN_PROD

    @property
    def CREDENTIALS_STRICT(self) -> bool:
        return self._CREDENTIALS_STRICT

    @property
    def TOKEN_HARDENING(self) -> bool:
        return self._TOKEN_HARDENING

    @property
    def NETWORK_GATING(self) -> bool:
        return self._NETWORK_GATING

    @property
    def VALIDATE_STRICT(self) -> bool:
        return self._VALIDATE_STRICT

    @property
    def DATABASE_PATH(self) -> Path:
        return self._DATABASE_PATH

    @property
    def LOG_LEVEL(self) -> str:
        return self._LOG_LEVEL

    @property
    def JSON_LOGGING(self) -> bool:
        return self._JSON_LOGGING

    @property
    def METRICS_ENABLED(self) -> bool:
        return self._METRICS_ENABLED

    @property
    def METRICS_PORT(self) -> int:
        return self._METRICS_PORT

    @property
    def RATE_LIMIT_ENABLED(self) -> bool:
        return self._RATE_LIMIT_ENABLED

    @property
    def RATE_LIMIT_PER_MINUTE(self) -> int:
        return self._RATE_LIMIT_PER_MINUTE

    @property
    def RATE_LIMIT_PER_HOUR(self) -> int:
        return self._RATE_LIMIT_PER_HOUR

    @property
    def CORS_ORIGINS(self) -> List[str]:
        return self._CORS_ORIGINS

    @property
    def HOST(self) -> str:
        return self._HOST

    @property
    def PORT(self) -> int:
        return self._PORT

    @property
    def WORKERS(self) -> int:
        return self._WORKERS

    @property
    def BUILD_UI(self) -> bool:
        return self._BUILD_UI

    @property
    def UI_REPO_URL(self) -> str:
        return self._UI_REPO_URL

    @property
    def CLAWDBOT_GATEWAY_URL(self) -> Optional[str]:
        return self._CLAWDBOT_GATEWAY_URL

    @property
    def CLAWDBOT_GATEWAY_TOKEN(self) -> Optional[str]:
        return self._CLAWDBOT_GATEWAY_TOKEN

    @property
    def DEFAULT_CLAWDBOT_CREDENTIAL_ID(self) -> str:
        return self._DEFAULT_CLAWDBOT_CREDENTIAL_ID

    @property
    def CLAWDBOT_CREDENTIAL_ID(self) -> str:
        return self._CLAWDBOT_CREDENTIAL_ID

    @property
    def CLERK_SECRET_KEY(self) -> Optional[str]:
        return self._CLERK_SECRET_KEY

    @property
    def MAG_ENABLED(self) -> bool:
        return self._MAG_ENABLED

    @property
    def MAG_URL(self) -> str:
        return self._MAG_URL

    @property
    def MAG_ENFORCE_PATHS(self) -> List[str]:
        return self._MAG_ENFORCE_PATHS

    @property
    def DEMO_MODE(self) -> bool:
        return self._DEMO_MODE

    @property
    def DEMO_TENANT_ID(self) -> str:
        return self._DEMO_TENANT_ID

    @property
    def DEMO_API_KEY(self) -> str:
        return self._DEMO_API_KEY

    @property
    def TELEGRAM_BOT_SECRET(self) -> Optional[str]:
        return self._TELEGRAM_BOT_SECRET

    @property
    def TELEGRAM_CONNECT_TTL_MIN(self) -> int:
        return self._TELEGRAM_CONNECT_TTL_MIN

    @property
    def CONNECT_BASE_URL(self) -> str:
        return self._CONNECT_BASE_URL

    @property
    def GOOGLE_CLIENT_ID(self) -> Optional[str]:
        return self._GOOGLE_CLIENT_ID

    @property
    def GOOGLE_CLIENT_SECRET(self) -> Optional[str]:
        return self._GOOGLE_CLIENT_SECRET

    @classmethod
    def validate(cls) -> List[str]:
        warnings = []
        instance = cls()

        # Production checks
        if instance.CREDENTIALS_STRICT:
            if not instance.AUTH_ENABLED:
                warnings.append("EDON_CREDENTIALS_STRICT=true but EDON_AUTH_ENABLED=false")

            if instance.API_TOKEN == "your-secret-token":
                warnings.append("Using default API token! Change EDON_API_TOKEN in production")

        if instance.TOKEN_HARDENING and not instance.CREDENTIALS_STRICT:
            warnings.append(
                "EDON_TOKEN_HARDENING=true but EDON_CREDENTIALS_STRICT=false. "
                "Set EDON_CREDENTIALS_STRICT=true for full protection"
            )

        if "*" in instance.CORS_ORIGINS:
            warnings.append(
                "CORS allows all origins (*). Set EDON_CORS_ORIGINS to specific origins "
                "(e.g., http://localhost:3000,http://localhost:5173)"
            )

        if instance.is_production() and instance.AUTH_ENABLED and not instance.ALLOW_ENV_TOKEN_IN_PROD:
            warnings.append(
                "Production mode: env token auth is disabled (tenant-scoped DB keys required). "
                "Set EDON_ALLOW_ENV_TOKEN_IN_PROD=true ONLY if you need bootstrap access."
            )

        if instance.MAG_ENABLED and not instance.MAG_URL:
            warnings.append("EDON_MAG_ENABLED=true but EDON_MAG_URL is empty")

        return warnings

    @classmethod
    def is_production(cls) -> bool:
        instance = cls()
        # Your existing rule, keep it
        return instance._ENVIRONMENT == "production" or (instance.CREDENTIALS_STRICT and instance.AUTH_ENABLED)


# Global config instance (created AFTER .env is loaded)
config = Config()
