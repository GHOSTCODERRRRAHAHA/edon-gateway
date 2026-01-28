"""Centralized configuration management for EDON Gateway."""

import os
from typing import Optional, List
from pathlib import Path


class Config:
    """EDON Gateway configuration."""
    
    # Authentication
    AUTH_ENABLED: bool = os.getenv("EDON_AUTH_ENABLED", "true").lower() == "true"
    API_TOKEN: str = os.getenv("EDON_API_TOKEN", "your-secret-token")
    TOKEN_BINDING_ENABLED: bool = os.getenv("EDON_TOKEN_BINDING_ENABLED", "false").lower() == "true"
    
    # Security
    CREDENTIALS_STRICT: bool = os.getenv("EDON_CREDENTIALS_STRICT", "false").lower() == "true"
    TOKEN_HARDENING: bool = os.getenv("EDON_TOKEN_HARDENING", "true").lower() == "true"
    NETWORK_GATING: bool = os.getenv("EDON_NETWORK_GATING", "false").lower() == "true"
    VALIDATE_STRICT: bool = os.getenv("EDON_VALIDATE_STRICT", "true").lower() == "true"
    
    # Database
    DATABASE_PATH: Path = Path(os.getenv("EDON_DATABASE_PATH", "edon_gateway.db"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("EDON_LOG_LEVEL", "INFO").upper()
    JSON_LOGGING: bool = os.getenv("EDON_JSON_LOGGING", "false").lower() == "true"
    
    # Monitoring
    METRICS_ENABLED: bool = os.getenv("EDON_METRICS_ENABLED", "true").lower() == "true"
    METRICS_PORT: int = int(os.getenv("EDON_METRICS_PORT", "9090"))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("EDON_RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("EDON_RATE_LIMIT_PER_MINUTE", "60"))
    RATE_LIMIT_PER_HOUR: int = int(os.getenv("EDON_RATE_LIMIT_PER_HOUR", "1000"))
    
    # CORS
    CORS_ORIGINS: List[str] = [
        origin.strip() 
        for origin in os.getenv("EDON_CORS_ORIGINS", "*").split(",")
        if origin.strip()
    ]
    
    # Server
    HOST: str = os.getenv("EDON_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("EDON_PORT", "8000"))
    WORKERS: int = int(os.getenv("EDON_WORKERS", "1"))
    
    # UI
    BUILD_UI: bool = os.getenv("EDON_BUILD_UI", "false").lower() == "true"
    UI_REPO_URL: str = os.getenv(
        "EDON_UI_REPO_URL", 
        "https://github.com/GHOSTCODERRRRAHAHA/edon-console-ui.git"
    )
    
    # Clawdbot
    CLAWDBOT_GATEWAY_URL: Optional[str] = os.getenv("CLAWDBOT_GATEWAY_URL")
    CLAWDBOT_GATEWAY_TOKEN: Optional[str] = os.getenv("CLAWDBOT_GATEWAY_TOKEN")
    
    # Clerk Authentication
    CLERK_SECRET_KEY: Optional[str] = os.getenv("CLERK_SECRET_KEY")
    
    # Demo Mode (bypasses subscription checks for testing)
    DEMO_MODE: bool = os.getenv("EDON_DEMO_MODE", "false").lower() == "true"
    DEMO_TENANT_ID: str = os.getenv("EDON_DEMO_TENANT_ID", "demo_tenant_001")
    DEMO_API_KEY: str = os.getenv("EDON_DEMO_API_KEY", "edon_demo_key_12345")
    
    @classmethod
    def validate(cls) -> List[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        
        # Production checks
        if cls.CREDENTIALS_STRICT:
            if not cls.AUTH_ENABLED:
                warnings.append("EDON_CREDENTIALS_STRICT=true but EDON_AUTH_ENABLED=false")
            
            if cls.API_TOKEN == "your-secret-token":
                warnings.append("Using default API token! Change EDON_API_TOKEN in production")
        
        if cls.TOKEN_HARDENING and not cls.CREDENTIALS_STRICT:
            warnings.append(
                "EDON_TOKEN_HARDENING=true but EDON_CREDENTIALS_STRICT=false. "
                "Set EDON_CREDENTIALS_STRICT=true for full protection"
            )
        
        if "*" in cls.CORS_ORIGINS:
            warnings.append(
                "CORS allows all origins (*). Set EDON_CORS_ORIGINS to specific origins (e.g., http://localhost:3000,http://localhost:5173)"
            )
        
        return warnings
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production mode."""
        return cls.CREDENTIALS_STRICT and cls.AUTH_ENABLED


# Global config instance
config = Config()
