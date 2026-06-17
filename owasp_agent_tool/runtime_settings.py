"""Mutable runtime settings that can be updated from the browser UI without
restarting the server - this is how the Anthropic (Opus) API key entered in
the Settings tab actually reaches the agents.

Persisted to a local JSON file so they survive a restart. That file holds a
secret in plaintext, same tradeoff as a .env file - keep this server off the
public internet, and never commit runtime_settings.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

from config import settings as env_defaults

_STORE_PATH = Path(__file__).parent / "runtime_settings.json"
_lock = Lock()


def _load() -> dict:
    if _STORE_PATH.exists():
        return json.loads(_STORE_PATH.read_text())
    return {}


def _save(data: dict) -> None:
    _STORE_PATH.write_text(json.dumps(data, indent=2))


def get_settings() -> dict:
    data = _load()
    return {
        "anthropic_api_key": data.get("anthropic_api_key") or env_defaults.anthropic_api_key,
        "agent_model": data.get("agent_model") or env_defaults.agent_model,
        "zap_api_url": data.get("zap_api_url") or env_defaults.zap_api_url,
        "zap_api_key": data.get("zap_api_key") or env_defaults.zap_api_key,
        "slack_webhook_url": data.get("slack_webhook_url") or env_defaults.slack_webhook_url,
        "token_limit": data.get("token_limit") or 0,  # 0 = unlimited
    }


def update_settings(**kwargs) -> dict:
    with _lock:
        data = _load()
        for key, value in kwargs.items():
            if value is not None and value != "":
                data[key] = value
        _save(data)
        return get_settings()


def has_api_key() -> bool:
    return bool(get_settings()["anthropic_api_key"])


def masked(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
