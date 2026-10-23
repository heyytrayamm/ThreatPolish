"""Core configuration module for ThreatPolish."""

import os
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    # General Application Info
    APP_NAME: str = "ThreatPolish Honeypot Platform"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server Bind Configuration (Localhost default for defensive safety)
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # CORS Origins
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Database Configuration (Planned for Phase 2 persistence)
    POSTGRES_USER: str = "threatpolish_user"
    POSTGRES_PASSWORD: str = "threatpolish_dev_secret_change_in_prod"
    POSTGRES_DB: str = "threatpolish_db"
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = (
        "postgresql+psycopg://threatpolish_user:threatpolish_dev_secret_change_in_prod@127.0.0.1:5432/threatpolish_db"
    )

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origins(self) -> List[str]:
        """Parse comma-separated allowed origins into a list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


# Global singleton settings instance
settings = Settings()
