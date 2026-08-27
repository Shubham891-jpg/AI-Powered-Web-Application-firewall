"""
AI-WAF Central Configuration Module.
Loads environment variables using Pydantic Settings and enforces validation rules.
"""

from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # Application Environment
    APP_NAME: str = "AI-WAF"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "dev-secret-key-must-be-changed-in-production-min-32-chars"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # Gateway Server Settings
    WAF_HOST: str = "0.0.0.0"
    WAF_PORT: int = 8000

    # Protected Upstream Web Application Target
    UPSTREAM_URL: str = Field(
        default="http://127.0.0.1:3000",
        description="Target upstream application to protect. Must be an HTTP/HTTPS URL.",
    )

    # Database Settings (PostgreSQL)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://waf_user:waf_secure_password_change_me@localhost:5432/ai_waf",
        description="Async connection string for PostgreSQL",
    )
    POSTGRES_USER: str = "waf_user"
    POSTGRES_PASSWORD: str = "waf_secure_password_change_me"
    POSTGRES_DB: str = "ai_waf"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    # Redis Settings
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for rate limiting & caching",
    )
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None

    # Security Thresholds (0 - 100)
    ALLOW_THRESHOLD: int = Field(default=29, ge=0, le=100)
    FLAG_THRESHOLD: int = Field(default=69, ge=0, le=100)
    BLOCK_THRESHOLD: int = Field(default=70, ge=0, le=100)

    # Detection Mode
    DETECTION_MODE: Literal["BLOCK", "FLAG_ONLY", "MONITOR"] = "BLOCK"

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=100, ge=1)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=1)
    RATE_LIMIT_BURST_ALLOWANCE: int = Field(default=20, ge=0)

    # Safety Safeguards
    MAX_REQUEST_BODY_SIZE: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="Maximum request body size in bytes",
    )
    MAX_HEADER_SIZE: int = Field(
        default=16 * 1024,  # 16KB
        description="Maximum total header size in bytes",
    )
    REQUEST_TIMEOUT_SECONDS: float = Field(
        default=10.0,
        description="Timeout for upstream proxy requests in seconds",
    )

    # Machine Learning Models
    ML_MODEL_PATH: str = "ml/models/waf_classifier_v1.joblib"
    ML_VECTORIZER_PATH: str = "ml/models/tfidf_vectorizer_v1.joblib"
    ML_METADATA_PATH: str = "ml/models/metadata_v1.json"
    ML_ENABLED: bool = False

    @field_validator("BLOCK_THRESHOLD")
    @classmethod
    def validate_thresholds(cls, v: int, info) -> int:
        allow_threshold = info.data.get("ALLOW_THRESHOLD", 29)
        if v <= allow_threshold:
            raise ValueError("BLOCK_THRESHOLD must be strictly greater than ALLOW_THRESHOLD")
        return v

    @field_validator("UPSTREAM_URL")
    @classmethod
    def validate_upstream_url(cls, v: str) -> str:
        v = v.rstrip("/")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("UPSTREAM_URL must start with http:// or https://")
        return v


# Singleton settings instance
settings = Settings()
