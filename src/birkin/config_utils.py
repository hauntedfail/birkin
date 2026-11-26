"""Configuration loading, secret hygiene, dotenv parsing, and provider lookup helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

from birkin.models import HarnessPolicy

_NON_SECRET_SUFFIXES = (
    "_env",
    "_env_var",
    "_env_vars",
    "_tokens",
    "_token_limit",
    "_token_budget",
    "_token_count",
    "_token_threshold",
    "_count",
    "_limit",
    "_budget",
    "_threshold",
    "_window",
    "_mode",
    "_path",
    "_file",
    "_cmd",
    "_from",
)
_SECRET_EXACT_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "bot_token",
        "bearer_token",
        "password",
        "passwd",
        "private_key",
        "signing_key",
        "webhook_secret",
    }
)
_SECRET_SUFFIXES = (
    "_api_key",
    "_apikey",
    "_secret",
    "_token",
    "_password",
    "_passwd",
    "_private_key",
    "_signing_key",
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_number(value: Any) -> bool:
    """Return True for int/float excluding bool (since bool subclasses int in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_positive_int(value: Any) -> bool:
    """Return True for positive int excluding bool."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_secret_key(key: str) -> bool:
    kl = str(key).strip().lower()
    if not kl:
        return False
    if kl in _SECRET_EXACT_KEYS:
        return True
    if any(kl.endswith(suffix) for suffix in _NON_SECRET_SUFFIXES):
        return False
    return any(kl.endswith(suffix) for suffix in _SECRET_SUFFIXES)


def _strip_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            if _is_secret_key(str(k)):
                cleaned[k] = "<REDACTED>" if v else ""
            else:
                cleaned[k] = _strip_secrets(v)
        return cleaned
    if isinstance(obj, list):
        return [_strip_secrets(item) for item in obj]
    return obj


def canonical_config_sha256(cfg: dict[str, Any]) -> str:
    """Deterministic SHA-256 fingerprint of config with secret values redacted."""
    sanitized = _strip_secrets(cfg)
    payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_yaml_file(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} did not parse to a YAML mapping")
    return raw


def load_policy(path: Path) -> HarnessPolicy:
    return HarnessPolicy.model_validate(load_yaml_file(path))


def _unquote_dotenv_value(raw_val: str) -> str:
    val = raw_val.strip()
    if not val:
        return ""
    quote = val[0]
    if quote in ('"', "'"):
        # Find matching unescaped closing quote.
        escaped = False
        chars: list[str] = []
        for idx in range(1, len(val)):
            ch = val[idx]
            if quote == '"' and ch == "\\" and not escaped:
                escaped = True
                continue
            if ch == quote and not escaped:
                return "".join(chars)
            chars.append(ch)
            escaped = False
        # Unclosed quote: strip only the leading quote.
        return val[1:]
    # Unquoted value: strip inline comment preceded by whitespace.
    for idx, ch in enumerate(val):
        if ch == "#" and idx > 0 and val[idx - 1].isspace():
            return val[:idx].strip()
    return val


def _parse_dotenv_entries(env_path: Path) -> dict[str, str]:
    """Parse a .env file into key -> value (last definition wins)."""
    entries: dict[str, str] = {}
    if not env_path.exists():
        return entries
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export ") and len(line) > 7:
            line = line[7:].lstrip()
            if "=" not in line:
                continue
        key, raw_val = line.split("=", 1)
        key = key.strip()
        if not key or not _ENV_KEY_RE.match(key):
            continue
        entries[key] = _unquote_dotenv_value(raw_val)
    return entries


def parse_dotenv_keys(env_path: Path) -> dict[str, bool]:
    """Return mapping of env key -> whether non-empty value is present. Never returns values."""
    return {key: bool(val) for key, val in _parse_dotenv_entries(env_path).items()}


def read_env_secret(env_path: Path | None, key_name: str) -> str:
    """Resolve secret from process env first, then .env file (last definition wins)."""
    if not key_name:
        return ""
    val = os.environ.get(key_name, "").strip()
    if val:
        return val
    if env_path is None or not env_path.exists():
        return ""
    return _parse_dotenv_entries(env_path).get(key_name, "").strip()


def norm_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def resolve_provider_block(cfg: dict[str, Any], active_provider: str) -> dict[str, Any] | None:
    """Find the active provider block under `providers.<name>` or `custom_providers[]`."""
    if not active_provider:
        return None
    providers_cfg = cfg.get("providers")
    if isinstance(providers_cfg, dict):
        block = providers_cfg.get(active_provider)
        if isinstance(block, dict):
            return block
    custom_providers = cfg.get("custom_providers")
    if isinstance(custom_providers, list):
        for entry in custom_providers:
            if not isinstance(entry, dict):
                continue
            slug = str(entry.get("slug") or entry.get("name") or "").strip()
            if slug == active_provider:
                return entry
    return None


def resolve_provider_models(provider_block: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Normalize provider `models` (mapping or list) into `{model_id: metadata_dict}`."""
    if not isinstance(provider_block, dict):
        return {}
    raw_models = provider_block.get("models")
    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(raw_models, dict):
        for mid, meta in raw_models.items():
            mid_str = str(mid).strip()
            if not mid_str:
                continue
            normalized[mid_str] = meta if isinstance(meta, dict) else {}
    elif isinstance(raw_models, list):
        for item in raw_models:
            if isinstance(item, str):
                mid_str = item.strip()
                if mid_str:
                    normalized[mid_str] = {}
            elif isinstance(item, dict):
                mid_str = str(item.get("id") or item.get("model") or item.get("name") or "").strip()
                if mid_str:
                    normalized[mid_str] = item
    return normalized


def extract_context_length(models_map: dict[str, Any], model_id: str) -> int | None:
    entry = models_map.get(model_id)
    if isinstance(entry, dict):
        val = entry.get("context_length")
        if is_positive_int(val):
            return val
    return None


def resolve_key_env(model_cfg: dict[str, Any], provider_block: dict[str, Any] | None) -> str:
    """Return configured credential env var name (`key_env` or `api_key_env`)."""
    pblock = provider_block if isinstance(provider_block, dict) else {}
    for candidate in (
        model_cfg.get("key_env"),
        model_cfg.get("api_key_env"),
        pblock.get("key_env"),
        pblock.get("api_key_env"),
    ):
        name = str(candidate or "").strip()
        if name:
            return name
    return ""


def resolve_api_key(
    model_cfg: dict[str, Any],
    provider_block: dict[str, Any] | None,
    env_path: Path | None,
) -> str:
    """Resolve API key from configured env var or inline config fallback."""
    key_env = resolve_key_env(model_cfg, provider_block)
    if key_env:
        secret = read_env_secret(env_path, key_env)
        if secret:
            return secret
    pblock = provider_block if isinstance(provider_block, dict) else {}
    for inline_key in (model_cfg.get("api_key"), pblock.get("api_key")):
        raw = str(inline_key or "").strip()
        if raw:
            if raw.startswith("${") and raw.endswith("}") and len(raw) > 3:
                return read_env_secret(env_path, raw[2:-1].strip())
            return raw
    return ""
