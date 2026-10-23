"""Core configuration module for ThreatPolish."""

import os
from typing import List
from pydantic import Field, model_validator
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

    # Database Configuration (PostgreSQL)
    POSTGRES_USER: str = "threatpolish_user"
    POSTGRES_PASSWORD: str = "threatpolish_dev_secret_change_in_prod"
    POSTGRES_DB: str = "threatpolish_db"
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str | None = None

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def assemble_database_url(self) -> "Settings":
        """
        Dynamically assemble DATABASE_URL from components when omitted,
        and ensure that an explicit POSTGRES_HOST (e.g. 'db' in Docker Compose)
        is not silently overridden by a localhost default in DATABASE_URL.
        """
        constructed = (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
        if not self.DATABASE_URL:
            self.DATABASE_URL = constructed
        elif self.POSTGRES_HOST != "127.0.0.1" and (
            "@127.0.0.1:" in self.DATABASE_URL or "@localhost:" in self.DATABASE_URL
        ):
            # POSTGRES_HOST was explicitly configured (e.g. 'db' in Docker), but
            # DATABASE_URL still pointed to localhost (e.g. inherited from .env).
            # Reconstruct to respect the container network topology.
            self.DATABASE_URL = constructed
        return self

    @property
    def cors_origins(self) -> List[str]:
        """Parse comma-separated allowed origins into a list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


# Global singleton settings instance
settings = Settings()
