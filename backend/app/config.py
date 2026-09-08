import os
from pathlib import Path
from typing import List, Optional
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "GridPulse"
    VERSION: str = "0.1.0"
    DEBUG: bool = False

    # PostgreSQL Database Settings
    POSTGRES_USER: str = "gridpulse"
    POSTGRES_PASSWORD: str = "gridpulse_secret"
    POSTGRES_DB: str = "gridpulse"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    # Database URL override (if provided directly in .env)
    DATABASE_URL: Optional[str] = None

    @computed_field
    @property
    def async_database_url(self) -> str:
        """Returns the asyncpg connection string required for async SQLAlchemy."""
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @computed_field
    @property
    def sync_database_url(self) -> str:
        """Returns the synchronous connection string if needed for sync tools."""
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            if url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
            return url
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:4321",
        "http://127.0.0.1:4321",
    ]

    # Tailscale Configuration (used in Step 5 & beyond)
    TAILSCALE_API_KEY: Optional[str] = None
    TAILSCALE_TAILNET: Optional[str] = None
    TAILSCALE_WEBHOOK_SECRET: Optional[str] = None
    TAILSCALE_WEBHOOK_TOLERANCE_SECONDS: int = 300
    TAILSCALE_WEBHOOK_VERIFY_SIGNATURE: bool = True
    TAILSCALE_WEBHOOK_AUTO_FETCH_ACL: bool = True
    TAILSCALE_BASE_URL: str = "https://api.tailscale.com"
    TAILSCALE_REQUEST_TIMEOUT: float = 30.0

    # APScheduler & Background Polling Settings (Step 6)
    TAILSCALE_POLL_INTERVAL_MINUTES: int = 10
    TAILSCALE_POLL_ENABLED: bool = True
    TAILSCALE_POLL_ON_STARTUP: bool = False

    # Version Drift & Key Expiry Posture Settings (Step 8)
    TAILSCALE_STABLE_VERSION: str = "1.60.0"
    KEY_EXPIRY_WARNING_DAYS: int = 14
    KEY_EXPIRY_CRITICAL_DAYS: int = 3

    # Network Routing & DERP Auditor Settings (Step 9)
    AUTHORIZED_EXIT_NODE_TAGS: List[str] = [
        "tag:exit-node",
        "tag:exitnode",
        "tag:gateway",
        "tag:authorized-exit-node",
        "tag:vpn",
    ]
    AUTHORIZED_EXIT_NODE_HOSTNAMES: List[str] = []
    ALLOW_UNTAGGED_EXIT_NODES: bool = False
    DERP_LATENCY_THRESHOLD_MS: float = 150.0

    # Device Posture & Compliance Settings (Step 10)
    POSTURE_REQUIRE_AUTO_UPDATE: bool = True
    POSTURE_REQUIRE_STATE_ENCRYPTED: bool = True
    POSTURE_STRICT_MODE: bool = False
    POSTURE_AUTO_UPDATE_SEVERITY: str = "high"
    POSTURE_STATE_ENCRYPTED_SEVERITY: str = "critical"
    POSTURE_EXEMPT_TAGS: List[str] = [
        "tag:posture-exempt",
        "tag:exempt-posture",
        "tag:compliance-exempt",
    ]

    # Geolocation Anomaly Tracker Settings (Step 11)
    GEOLOCATION_TRACKING_ENABLED: bool = True
    IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH: float = 800.0
    IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM: float = 100.0
    IMPOSSIBLE_TRAVEL_MIN_TIME_SECONDS: float = 60.0
    IMPOSSIBLE_TRAVEL_SEVERITY: str = "critical"
    GEOLOCATION_ALERT_ON_COUNTRY_CHANGE: bool = False

    # Tailnet Lock Status Tracker Settings (Step 12)
    TAILNET_LOCK_ENABLED: bool = True
    TAILNET_LOCK_ALERT_ON_LOCKED_OUT: bool = True
    TAILNET_LOCK_ALERT_ON_UNSIGNED: bool = True
    TAILNET_LOCK_ALERT_ON_KEY_ROTATION: bool = True
    TAILNET_LOCK_LOCKED_OUT_SEVERITY: str = "critical"
    TAILNET_LOCK_UNSIGNED_SEVERITY: str = "high"
    TAILNET_LOCK_EXEMPT_TAGS: List[str] = [
        "tag:tailnet-lock-exempt",
        "tag:lock-exempt",
        "tag:compliance-exempt",
    ]

    # MagicDNS SSL Monitor Settings (Step 13)
    MAGICDNS_SSL_MONITOR_ENABLED: bool = True
    MAGICDNS_SSL_POLL_INTERVAL_MINUTES: int = 60
    MAGICDNS_SSL_PORT: int = 443
    MAGICDNS_SSL_TIMEOUT_SECONDS: float = 10.0
    MAGICDNS_SSL_EXPIRY_WARNING_DAYS: int = 30
    MAGICDNS_SSL_EXPIRY_CRITICAL_DAYS: int = 7
    MAGICDNS_SSL_CONCURRENCY_LIMIT: int = 10
    MAGICDNS_SSL_VERIFY_TLS: bool = True
    MAGICDNS_SSL_ALERT_ON_EXPIRY: bool = True


    model_config = SettingsConfigDict(
        env_file=(str(ROOT_DIR / ".env"), str(BASE_DIR / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
