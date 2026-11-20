"""Shared app factory for API tests."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from aiguard.budget import BudgetStore
from aiguard.config import Settings
from aiguard.main import create_app


def build_app(tmp_path: Path, upstream: object | None = None, budget: BudgetStore | None = None, **settings):
    params = {"audit_log_path": str(tmp_path / "audit.jsonl"), "mock_upstream": True}
    params.update(settings)
    return create_app(Settings(**params), upstream=upstream, budget=budget)


def build_client(tmp_path: Path, **kwargs) -> TestClient:
    return TestClient(build_app(tmp_path, **kwargs))


def read_audit(tmp_path: Path) -> list[dict]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


CHAT = "/v1/chat/completions"
REDACT = "/v1/redact"


def chat_body(content: str, **extra) -> dict:
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}]}
    body.update(extra)
    return body
