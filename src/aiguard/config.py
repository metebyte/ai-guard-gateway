"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise RuntimeError(f"{name} must be one of: 1, 0, true, false, yes, no, on, off")


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 0:
        raise RuntimeError(f"{name} must be >= 0")
    return value


@dataclass(frozen=True)
class Settings:
    """Process-wide settings.

    The client authenticates to this gateway with its own bearer token.
    ``upstream_api_key`` is sent only to the upstream model API.
    """

    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    mock_upstream: bool = False
    restore_pii: bool = True
    budget_requests_per_day: int = 1_000
    budget_tokens_per_day: int = 100_000
    audit_log_path: str = "audit.jsonl"

    @classmethod
    def from_env(cls) -> Settings:
        base = os.environ.get("UPSTREAM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
        return cls(
            upstream_base_url=base or "https://api.openai.com/v1",
            upstream_api_key=os.environ.get("UPSTREAM_API_KEY", ""),
            mock_upstream=_flag("MOCK_UPSTREAM", False),
            restore_pii=_flag("RESTORE_PII", True),
            budget_requests_per_day=_int_env("BUDGET_REQUESTS_PER_DAY", 1_000),
            budget_tokens_per_day=_int_env("BUDGET_TOKENS_PER_DAY", 100_000),
            audit_log_path=os.environ.get("AUDIT_LOG_PATH", "audit.jsonl").strip() or "audit.jsonl",
        )
