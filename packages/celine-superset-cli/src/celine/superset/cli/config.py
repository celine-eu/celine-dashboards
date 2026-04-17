"""
CLI configuration via env vars or ~/.config/celine-superset/config.yaml.

Precedence: CLI flags > env vars > config file > defaults.

Auth flow:
  Every request carries Authorization: Bearer <kc-jwt> (client credentials
  grant). oauth2_proxy forwards requests with a valid KC JWT without SSO
  redirect (skip-jwt-bearer-tokens=true). Superset's before_request hook
  validates the KC JWT, calls login_user(), and authenticates the request.
  After the first response the Flask session cookie is cached in the httpx
  Client for the lifetime of the CLI invocation.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_CONFIG_FILE = Path.home() / ".config" / "celine-superset" / "config.yaml"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SUPERSET_",
        yaml_file=str(_CONFIG_FILE) if _CONFIG_FILE.exists() else None,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    url: str = "http://superset.celine.localhost"

    # KC client credentials — oauth2_proxy bypass + Superset identity
    kc_issuer_url: str = "http://keycloak.celine.localhost/realms/celine"
    kc_client_id: str = "celine-cli"
    kc_client_secret: str = "celine-cli"

    verify_ssl: bool = True

    @field_validator("url", "kc_issuer_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")


def get_settings() -> Settings:
    return Settings()
