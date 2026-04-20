"""
CLI configuration.

Precedence: CLI flags > instances.yaml (selected env) > env vars > ~/.config file > defaults.

instances.yaml (CWD) stores per-environment connection details and passwords.
Run `celine-superset bootstrap` to create/update the entry for the current env.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSTANCES_FILE = Path("instances.yaml")
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
    kc_issuer_url: str = "http://keycloak.celine.localhost/realms/celine"
    kc_client_id: str = "celine-cli"
    kc_client_secret: str = "celine-cli"
    verify_ssl: bool = True

    bootstrap_db_name: str = "celine_dev"
    bootstrap_db_uri: str = (
        "postgresql+psycopg2://postgres:securepassword123@host.docker.internal:15432/datasets"
    )
    bootstrap_db_schema: str = "ds_dev_gold"

    @field_validator("url", "kc_issuer_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")


class InstanceConfig(BaseModel):
    """Per-environment config stored in instances.yaml."""

    url: Optional[str] = None
    kc_issuer_url: Optional[str] = None
    kc_client_id: Optional[str] = None
    kc_client_secret: Optional[str] = None
    verify_ssl: Optional[bool] = None
    # {"databases/<Name>.yaml": "<password>"} — injected on import
    passwords: dict[str, str] = {}
    bootstrap_db_name: Optional[str] = None
    bootstrap_db_uri: Optional[str] = None
    bootstrap_db_schema: Optional[str] = None


class InstancesFile(BaseModel):
    instances: dict[str, InstanceConfig] = {}


def load_instances_file(path: Path = INSTANCES_FILE) -> InstancesFile:
    if not path.exists():
        return InstancesFile()
    data = yaml.safe_load(path.read_text()) or {}
    return InstancesFile.model_validate(data)


def get_instance_settings(env: str, path: Path = INSTANCES_FILE) -> tuple[Settings, dict[str, str]]:
    """Return (Settings, passwords) for the given env, merging instances.yaml over env-var defaults."""
    base = Settings()
    instances = load_instances_file(path)
    cfg = instances.instances.get(env)
    if cfg is None:
        return base, {}
    overrides = cfg.model_dump(exclude_none=True, exclude={"passwords"})
    return base.model_copy(update=overrides), cfg.passwords


def write_instance(env: str, cfg: InstanceConfig, path: Path = INSTANCES_FILE) -> None:
    """Upsert an instance entry into instances.yaml."""
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
    else:
        data = {}
    data.setdefault("instances", {})[env] = cfg.model_dump(exclude_none=True)
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True))


def get_settings() -> Settings:
    return Settings()
