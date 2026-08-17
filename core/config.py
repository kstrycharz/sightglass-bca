"""Process-wide configuration.

Everything is env-driven with safe defaults, and the defaults are the
*restrictive* ones: egress denied, dynamic analysis off, plaintext secret
retention off. An operator has to consciously loosen the posture; forgetting to
set a variable can never quietly open the trust boundary.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core import __version__

# Single source of truth; core/__init__.py is dependency-free by design.
SIGHTGLASS_VERSION = __version__


class EgressPolicy(StrEnum):
    DENY = "deny"
    ALLOW = "allow"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIGHTGLASS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "development"
    log_level: str = "INFO"
    log_json: bool = True

    # --- storage ----------------------------------------------------------
    database_url: str = "postgresql+psycopg://sightglass:sightglass@postgres:5432/sightglass"
    redis_url: str = "redis://redis:6379/0"

    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key: str = "sightglass"
    s3_secret_key: str = "sightglass"
    s3_bucket_artifacts: str = "sightglass-artifacts"
    s3_region: str = "us-east-1"

    # --- sandbox ----------------------------------------------------------
    sandbox_driver: str = "docker"
    run_root: Path = Path("/var/lib/sightglass/runs")
    """Directory holding per-run staging and results, as *this process* sees
    it. The only path an analyzer container may ever see."""

    run_root_host: str = ""
    """The same directory as the *Docker daemon* sees it, when the orchestrator
    is itself containerised. Empty means they are identical.

    Deliberately a ``str`` and not a ``Path``: on a Windows host reached from a
    Linux worker this holds something like ``C:\\sightglass\\runs``, which
    ``PosixPath.resolve()`` would mangle into a relative path under the
    container's cwd."""
    repo_root: Path = Path(".")
    """Used to resolve seccomp profile paths."""
    reaper_max_age_hours: int = 6
    reaper_interval_seconds: int = 300

    # --- trust boundary ---------------------------------------------------
    egress_policy: EgressPolicy = EgressPolicy.DENY
    air_gapped: bool = False
    dynamic_analysis_enabled: bool = False
    retain_plaintext_secrets: bool = False

    @field_validator("run_root", "repo_root")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        return value.expanduser().resolve()

    @property
    def llm_enabled(self) -> bool:
        """M3 wires this to config/llm.yaml. Until then the pipeline is
        deterministic-only, which is the CI default anyway (§2.5)."""
        return False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
