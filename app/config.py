from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    database_url: str = "sqlite+pysqlite:///./license_server.db"
    app_secret: str = "local-development-secret-change-me"
    license_key_pepper: str = "local-development-pepper-change-me"
    signing_private_key_path: Path = Path("secrets/ed25519-private.pem")
    admin_timezone: str = "Asia/Ho_Chi_Minh"
    lease_hours: int = 24
    min_client_version: str = "1.3.0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def resolve_paths(self):
        if not self.signing_private_key_path.is_absolute():
            self.signing_private_key_path = (
                Path(__file__).resolve().parents[1] / self.signing_private_key_path
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
