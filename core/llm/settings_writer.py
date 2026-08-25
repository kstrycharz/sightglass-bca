"""Editing `config/llm.yaml` from the console.

The file stays the source of truth and stays hot-reloadable — this writes it,
it does not shadow it with a database table. An operator who edits the YAML by
hand and an operator who uses the settings page must not end up with two
different notions of which model is running.

Two things make that safe:

* **The document is rewritten from a parsed copy, not regenerated.** Unknown
  keys, ordering and the comments that explain the role routing all survive,
  because a config file people are expected to read by hand loses most of its
  value the first time a UI reformats it.
* **The result is validated before it replaces anything**, and written through
  a temporary file in the same directory. A half-written config is how a
  deployment discovers its scanner cannot start.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.llm.router import DEFAULT_CONFIG_PATH, LLMConfigError, load_config

log = structlog.get_logger(__name__)

# Roles the console may reassign. Anything else in the file is preserved but
# not editable here — a UI that can write a role the pipeline never reads is a
# UI that lies about what it did.
EDITABLE_ROLES = ("triage", "discover", "explain", "remediate", "summarize")


@dataclass(frozen=True, slots=True)
class LlmUpdate:
    """One change from the settings page. Every field is optional so the caller
    can send only what the operator touched."""

    enabled: bool | None = None
    roles: dict[str, str] | None = None
    provider_models: dict[str, str] | None = None
    """Provider name to model id — how "change the model" actually lands."""


def _config_path() -> Path:
    from core.config import get_settings

    return Path(get_settings().repo_root) / DEFAULT_CONFIG_PATH


def _write_atomically(path: Path, text: str) -> None:
    """Replace the file in one step.

    A torn write leaves a config that fails to parse, and the next thing to
    read it is a worker starting a scan. The temporary file is created in the
    same directory so the replace stays on one filesystem and is atomic.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def apply_update(update: LlmUpdate, *, path: Path | None = None) -> Path:
    """Apply a settings change and return the path written.

    Raises :class:`LLMConfigError` if the result would not load, having changed
    nothing — the console must not be able to write a config that stops the
    next scan.
    """
    target = path or _config_path()

    document: dict[str, Any] = {}
    if target.is_file():
        try:
            document = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise LLMConfigError(f"{target} is not valid YAML: {exc}") from None
    if not isinstance(document, dict):
        raise LLMConfigError(f"{target} does not contain a mapping")

    if update.enabled is not None:
        document["enabled"] = bool(update.enabled)

    if update.roles:
        roles = dict(document.get("roles") or {})
        providers = document.get("providers") or {}
        for role, provider in update.roles.items():
            if role not in EDITABLE_ROLES:
                raise LLMConfigError(
                    f"unknown role {role!r}; expected one of {list(EDITABLE_ROLES)}"
                )
            if provider not in providers:
                raise LLMConfigError(
                    f"role {role!r} would point at provider {provider!r}, "
                    "which is not defined in this config"
                )
            roles[role] = provider
        document["roles"] = roles

    if update.provider_models:
        providers = dict(document.get("providers") or {})
        for name, model in update.provider_models.items():
            if name not in providers:
                raise LLMConfigError(f"no provider named {name!r} in this config")
            if not str(model).strip():
                raise LLMConfigError(f"provider {name!r}: model must not be empty")
            entry = dict(providers[name])
            entry["model"] = str(model).strip()
            providers[name] = entry
        document["providers"] = providers

    rendered = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=88)

    # Validate before replacing anything. `load_config` is the same function
    # the pipeline uses, so "it parsed here" means "a scan will start".
    probe_fd, probe_name = tempfile.mkstemp(dir=str(target.parent), suffix=".probe")
    os.close(probe_fd)
    probe = Path(probe_name)
    try:
        probe.write_text(rendered, encoding="utf-8")
        load_config(probe)
    finally:
        probe.unlink(missing_ok=True)

    _write_atomically(target, rendered)
    log.info(
        "llm.config_updated",
        path=str(target),
        enabled=update.enabled,
        roles=update.roles,
        models=update.provider_models,
    )
    return target
