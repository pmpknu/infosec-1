from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    app_name: str = "Infosec Lab API"
    secret_key: str = "change-me"  # noqa: S105 - default value, overridden by env
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./app.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="APP_",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
