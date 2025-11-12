# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

"""Application configuration management using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration."""
    
    url: str = Field(default="postgresql://postgres:postgres@localhost:5432/devflowfix", alias="DATABASE_URL")
    pool_size: int = Field(default=5, alias="DB_POOL_SIZE")
    max_overflow: int = Field(default=10, alias="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, alias="DB_POOL_TIMEOUT")
    pool_recycle: int = Field(default=3600, alias="DB_POOL_RECYCLE")
    pool_pre_ping: bool = Field(default=True, alias="DB_POOL_PRE_PING")


class GitHubSettings(BaseSettings):
    """GitHub integration configuration."""
    
    webhook_secret: str = Field(alias="GITHUB_WEBHOOK_SECRET")
    token: Optional[str] = Field(default=None, alias="GITHUB_TOKEN")
    app_id: Optional[str] = Field(default=None, alias="GITHUB_APP_ID")
    app_private_key_path: Optional[str] = Field(default=None, alias="GITHUB_APP_PRIVATE_KEY_PATH")
    app_installation_id: Optional[str] = Field(default=None, alias="GITHUB_APP_INSTALLATION_ID")


class AWSSettings(BaseSettings):
    """AWS configuration."""
    
    region: str = Field(default="us-east-1", alias="AWS_REGION")
    lambda_function_name: Optional[str] = Field(default=None, alias="AWS_LAMBDA_FUNCTION_NAME")


class AISettings(BaseSettings):
    """AI/ML configuration."""
    
    openai_api_key: str = Field(alias="OPENAI_API_KEY")
    nvidia_api_key: Optional[str] = Field(default=None, alias="NVIDIA_API_KEY")
    embedding_model: str = Field(default="nvidia/nv-embed-v1", alias="EMBEDDING_MODEL")
    embedding_dimensions: int = Field(default=768, alias="EMBEDDING_DIMENSIONS")
    llm_model: str = Field(default="gpt-4-turbo-preview", alias="LLM_MODEL")
    llm_temperature: float = Field(default=0.2, alias="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(default=2000, alias="LLM_MAX_TOKENS")


class RedisSettings(BaseSettings):
    """Redis configuration."""
    
    url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    ttl: int = Field(default=3600, alias="REDIS_TTL")


class ObservabilitySettings(BaseSettings):
    """Observability and monitoring configuration."""
    
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    sentry_dsn: Optional[str] = Field(default=None, alias="SENTRY_DSN")
    datadog_api_key: Optional[str] = Field(default=None, alias="DATADOG_API_KEY")
    xray_enabled: bool = Field(default=False, alias="XRAY_ENABLED")


class SecuritySettings(BaseSettings):
    """Security configuration."""
    
    secret_key: str = Field(alias="SECRET_KEY")
    jwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(default=24, alias="JWT_EXPIRATION_HOURS")


class FeatureFlagSettings(BaseSettings):
    """Feature flags configuration."""
    
    enable_auto_remediation: bool = Field(default=True, alias="ENABLE_AUTO_REMEDIATION")
    enable_slack_notifications: bool = Field(default=True, alias="ENABLE_SLACK_NOTIFICATIONS")
    enable_pagerduty_escalation: bool = Field(default=False, alias="ENABLE_PAGERDUTY_ESCALATION")
    enable_metrics_collection: bool = Field(default=True, alias="ENABLE_METRICS_COLLECTION")
    enable_learning_mode: bool = Field(default=True, alias="ENABLE_LEARNING_MODE")


class ConfidenceSettings(BaseSettings):
    """Confidence threshold configuration."""
    
    threshold_dev: float = Field(default=0.70, alias="CONFIDENCE_THRESHOLD_DEV")
    threshold_staging: float = Field(default=0.85, alias="CONFIDENCE_THRESHOLD_STAGING")
    threshold_prod: float = Field(default=0.95, alias="CONFIDENCE_THRESHOLD_PROD")


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""
    
    enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
    window: int = Field(default=60, alias="RATE_LIMIT_WINDOW")


class Settings(BaseSettings):
    """Main application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",  
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  
    )
    
    environment: str = Field(default="dev", alias="ENVIRONMENT")
    app_name: str = Field(default="DevFlowFix", alias="APP_NAME")
    app_version: str = Field(default="1.0.0", alias="APP_VERSION")
    debug: bool = Field(default=True, alias="DEBUG")
    
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")
    
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        alias="CORS_ORIGINS"
    )
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse comma-separated CORS origins."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @property
    def database(self) -> DatabaseSettings:
        """Get database settings."""
        return DatabaseSettings()
    
    @property
    def github(self) -> GitHubSettings:
        """Get GitHub settings."""
        return GitHubSettings()
    
    @property
    def aws(self) -> AWSSettings:
        """Get AWS settings."""
        return AWSSettings()
    
    @property
    def ai(self) -> AISettings:
        """Get AI settings."""
        return AISettings()
    
    @property
    def redis(self) -> RedisSettings:
        """Get Redis settings."""
        return RedisSettings()
    
    @property
    def observability(self) -> ObservabilitySettings:
        """Get observability settings."""
        return ObservabilitySettings()
    
    @property
    def security(self) -> SecuritySettings:
        """Get security settings."""
        return SecuritySettings()
    
    @property
    def features(self) -> FeatureFlagSettings:
        """Get feature flags."""
        return FeatureFlagSettings()
    
    @property
    def confidence(self) -> ConfidenceSettings:
        """Get confidence thresholds."""
        return ConfidenceSettings()
    
    @property
    def rate_limit(self) -> RateLimitSettings:
        """Get rate limit settings."""
        return RateLimitSettings()


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings.
    
    This function is cached to ensure settings are only loaded once.
    """
    return Settings()


settings = get_settings()
