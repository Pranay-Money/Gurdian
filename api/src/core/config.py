"""
Application Configuration
"""
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Guardian API"
    app_env: str = "development"
    debug: bool = True
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://guardian:guardian@localhost:5432/guardian"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 3600

    # Security
    secret_key: str = "change-me-in-production-use-strong-random-key"
    device_token_ttl_days: int = 365
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # Device token signing (HS256 JWT)
    device_token_algorithm: str = "HS256"
    device_token_rotation_days: int = 30  # Rotate token every 30 days

    # CORS - restricted to extension origin
    cors_allowed_origins: List[str] = Field(default_factory=lambda: ["chrome-extension://*"])

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_cors_allowed_origins(cls, value: Any) -> List[str]:
        if value is None:
            return ["chrome-extension://*"]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return ["chrome-extension://*"]
            if value.startswith("["):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [entry.strip() for entry in value.split(",") if entry.strip()]
        return [str(value).strip()]

    cors_allow_credentials: bool = True

    # Request limits
    max_request_size_bytes: int = 1024 * 1024  # 1 MB
    max_text_length: int = 50000
    max_urls_per_request: int = 20

    # External APIs
    google_safe_browsing_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    urlhaus_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None

    # Intel adapter settings
    gsb_timeout: float = 10.0
    gsb_rate_limit: int = 10000  # per day
    vt_timeout: float = 15.0
    vt_rate_limit: int = 4  # per minute
    rdap_timeout: float = 10.0
    rdap_rate_limit: int = 60  # per minute
    dns_timeout: float = 5.0
    dns_rate_limit: int = 200  # per minute
    tls_timeout: float = 10.0
    tls_rate_limit: int = 100  # per minute
    feed_timeout: float = 1.0

    # Feed paths
    openphish_feed_path: str = "data/feeds/openphish.txt"
    phishtank_feed_path: str = "data/feeds/phishtank.json"

    # Cache TTLs by verdict
    cache_clean_ttl: int = 86400 * 7      # 7 days
    cache_suspicious_ttl: int = 86400      # 1 day
    cache_malicious_ttl: int = 86400 * 30  # 30 days
    cache_unknown_ttl: int = 3600          # 1 hour
    cache_error_ttl: int = 300             # 5 minutes

    # ML Model
    model_path: Path = Path(__file__).resolve().parents[2] / "models" / "model.joblib"
    model_version: str = "1.0.0"

    # Blocklist
    blocklist_sync_interval_seconds: int = 300
    blocklist_cache_ttl: int = 86400

    # Privacy
    default_retention_days: int = 30
    max_retention_days: int = 365

    # Jobs
    job_blocklist_sync_enabled: bool = True
    job_stats_aggregation_enabled: bool = True
    job_retention_cleanup_enabled: bool = True
    job_feed_update_enabled: bool = True

    # Observability
    sentry_dsn: Optional[str] = None
    sentry_environment: str = "production"
    sentry_traces_sample_rate: float = 0.1
    sentry_profiles_sample_rate: float = 0.1


@lru_cache
def get_settings() -> Settings:
    return Settings()