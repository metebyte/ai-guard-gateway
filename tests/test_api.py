"""Proxy, redact endpoint, audit log, and budgets over HTTP."""

from __future__ import annotations

import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from aiguard.audit import key_id_for
from aiguard.budget import BudgetStore
from aiguard.config import Settings
from aiguard.proxy import HttpxUpstream, UpstreamError, upstream_headers
from tests.conftest import CHAT, REDACT, build_app, build_client, chat_body, read_audit
from tests.support import KNOWN_TCKN, VISA_16

AUDIT_KEYS = {"timestamp", "key_id", "endpoint", "pii", "status"}


def test_settings_defaults_and_flags(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "UPSTREAM_BASE_URL",
        "UPSTREAM_API_KEY",
        "MOCK_UPSTREAM",
        "RESTORE_PII",
        "BUDGET_REQUESTS_PER_DAY",
        "BUDGET_TOKENS_PER_DAY",
        "AUDIT_LOG_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.from_env()
    assert settings.upstream_base_url == "https://api.openai.com/v1"
    assert settings.upstream_api_key == ""
    assert settings.mock_upstream is False
    assert settings.restore_pii is True
    assert settings.budget_requests_per_day == 1000
    assert settings.budget_tokens_per_day == 100_000

    monkeypatch.setenv("MOCK_UPSTREAM", "1")
    monkeypatch.setenv("RESTORE_PII", "0")
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://llm.internal/v1/")
    monkeypatch.setenv("BUDGET_REQUESTS_PER_DAY", "3")
    flagged = Settings.from_env()
    assert flagged.mock_upstream is True
    assert flagged.restore_pii is False
    assert flagged.upstream_base_url == "https://llm.internal/v1"
    assert flagged.budget_requests_per_day == 3


def test_upstream_header_uses_the_upstream_key_only():
    headers = upstream_headers(Settings(upstream_api_key="sk-upstream"))
    assert headers["Authorization"] == "Bearer sk-upstream"
    assert "demo-key" not in headers["Authorization"]
    assert upstream_headers(Settings()).get("Authorization") is None


def test_health_and_root(tmp_path):
    with build_client(tmp_path) as client:
        assert client.get("/health").json() == {"status": "ok"}
        body = client.get("/").json()
        assert body["name"] == "ai-guard-gateway"
        assert body["chat"] == CHAT


def test_redact_endpoint_returns_placeholders_and_no_raw_values(tmp_path):
    text = (
        "Customer 10000000146 paid from TR33 0006 1005 1978 6457 8413 26 "
        "with card 4111 1111 1111 1111, phone +90 532 111 22 33, "
        "email ayse.yilmaz@example.com."
    )
    with build_client(tmp_path) as client:
        response = client.post(REDACT, json={"text": text})
    assert response.status_code == 200
    payload = response.json()
    assert payload["redacted_text"] == (
        "Customer [TCKN_1] paid from [IBAN_1] "
        "with card [CARD_1], phone [PHONE_1], "
        "email [EMAIL_1]."
    )
    assert payload["counts"] == {"TCKN": 1, "IBAN": 1, "CARD": 1, "PHONE": 1, "EMAIL": 1}
    assert [item["type"] for item in payload["findings"]] == ["TCKN", "IBAN", "CARD", "PHONE", "EMAIL"]
    assert "value" not in payload["findings"][0]
    raw_response = response.text
    for secret in (KNOWN_TCKN, VISA_16, "ayse.yilmaz@example.com", "TR330006100519786457841326"):
        assert secret not in raw_response
    assert response.headers["X-AIGuard-PII"] == "TCKN=1, IBAN=1, CARD=1, PHONE=1, EMAIL=1"
    event = read_audit(tmp_path)[0]
    assert set(event) == AUDIT_KEYS
    assert event["endpoint"] == REDACT
    assert event["pii"] == payload["counts"]
    assert event["status"] == 200
    assert KNOWN_TCKN not in json.dumps(event)


def test_redact_leaves_order_numbers(tmp_path):
    with build_client(tmp_path) as client:
        response = client.post(REDACT, json={"text": "Order 48291736501 is packed."})
    assert response.status_code == 200
    assert response.json()["redacted_text"] == "Order 48291736501 is packed."
    assert response.json()["findings"] == []
    assert "X-AIGuard-PII" not in response.headers


def test_redact_requires_text(tmp_path):
    with build_client(tmp_path) as client:
        response = client.post(REDACT, json={"note": "hi"})
    assert response.status_code == 422


def test_mock_upstream_echoes_the_redacted_prompt(tmp_path):
    with build_client(tmp_path, restore_pii=False) as client:
        response = client.post(
            CHAT,
            headers={"Authorization": "Bearer demo-key"},
            json=chat_body(f"Summarise customer {KNOWN_TCKN}."),
        )
    assert response.status_code == 200
    body = response.json()
    content = body["choices"][0]["message"]["content"]
    assert content == f"user: Summarise customer [TCKN_1]."
    assert KNOWN_TCKN not in response.text
    assert body["model"] == "gpt-4o-mini"
    assert body["object"] == "chat.completion"
    assert response.headers["X-AIGuard-PII"] == "TCKN=1"
    event = read_audit(tmp_path)[0]
    assert event["key_id"] == key_id_for("demo-key")
    assert event["key_id"].startswith("key_")
    assert "demo-key" not in json.dumps(event)
    assert KNOWN_TCKN not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", event["timestamp"])


def test_mock_redacts_every_message_including_multimodal_parts(tmp_path):
    messages = [
        {"role": "system", "content": f"The file owner is {KNOWN_TCKN}."},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": f"Card {VISA_16}"},
                {"type": "image_url", "image_url": {"url": "https://cdn.example/a.png"}},
            ],
        },
    ]
    with build_client(tmp_path, restore_pii=False) as client:
        response = client.post(CHAT, json={"model": "mock", "messages": messages})
    content = response.json()["choices"][0]["message"]["content"]
    assert "[TCKN_1]" in content
    assert "[CARD_1]" in content
    assert KNOWN_TCKN not in content
    assert VISA_16 not in content
    assert response.headers["X-AIGuard-PII"] == "TCKN=1, CARD=1"


def test_restore_puts_placeholders_back_for_the_client_only(tmp_path):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content.decode())
        reply = {
            "id": "chatcmpl-up",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4o-mini",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "File [TCKN_1] is open."}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
        }
        return httpx.Response(200, json=reply)

    upstream = HttpxUpstream(
        Settings(upstream_base_url="https://upstream.test/v1", upstream_api_key="sk-upstream"),
        transport=httpx.MockTransport(handler),
    )
    app = build_app(tmp_path, upstream=upstream, mock_upstream=False, restore_pii=True)
    with TestClient(app) as client:
        response = client.post(
            CHAT,
            headers={"Authorization": "Bearer client-secret"},
            json={
                "model": "gpt-4o-mini",
                "temperature": 0.2,
                "messages": [
                    {"role": "user", "content": f"Customer {KNOWN_TCKN}"},
                    {"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "function": {"arguments": "{}"}}]},
                ],
            },
        )
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == f"File {KNOWN_TCKN} is open."
    forwarded = seen["body"]
    assert forwarded["temperature"] == 0.2
    assert forwarded["messages"][0]["content"] == "Customer [TCKN_1]"
    assert KNOWN_TCKN not in json.dumps(forwarded["messages"][0])
    assert forwarded["messages"][1]["tool_calls"][0]["id"] == "call_1"
    assert "stream" not in forwarded
    assert seen["url"] == "https://upstream.test/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-upstream"
    assert "client-secret" not in seen["auth"]
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert KNOWN_TCKN not in audit
    assert "client-secret" not in audit
    assert "sk-upstream" not in audit


def test_restore_can_be_disabled(tmp_path):
    class Recording:
        def __init__(self) -> None:
            self.bodies: list[dict] = []

        async def complete(self, body: dict):
            self.bodies.append(body)
            payload = {
                "choices": [{"message": {"role": "assistant", "content": "echo [TCKN_1]"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            from aiguard.proxy import UpstreamResult

            return UpstreamResult(200, payload, json.dumps(payload).encode())

    recording = Recording()
    app = build_app(tmp_path, upstream=recording, restore_pii=False)
    with TestClient(app) as client:
        response = client.post(CHAT, json=chat_body(f"id {KNOWN_TCKN}"))
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "echo [TCKN_1]"
    assert recording.bodies[0]["messages"][0]["content"] == f"id [TCKN_1]"


def test_request_budget_returns_429_and_skips_upstream(tmp_path):
    class Recording:
        def __init__(self) -> None:
            self.calls = 0

        async def complete(self, body: dict):
            self.calls += 1
            payload = {"choices": [{"message": {"role": "assistant", "content": "ok"}}], "usage": {"completion_tokens": 1}}
            from aiguard.proxy import UpstreamResult

            return UpstreamResult(200, payload, json.dumps(payload).encode())

    recording = Recording()
    app = build_app(tmp_path, upstream=recording, budget_requests_per_day=1, restore_pii=False)
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer alpha"}
        first = client.post(CHAT, headers=headers, json=chat_body("hello"))
        second = client.post(CHAT, headers=headers, json=chat_body("hello again"))
        other = client.post(CHAT, headers={"Authorization": "Bearer beta"}, json=chat_body("hello"))
        via_header = client.post(CHAT, headers={"X-API-Key": "gamma"}, json=chat_body("hello"))
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limit_exceeded"
    assert "request" in second.json()["error"]["message"].lower()
    assert int(second.headers["Retry-After"]) >= 1
    assert other.status_code == 200
    assert via_header.status_code == 200
    assert recording.calls == 3
    statuses = [event["status"] for event in read_audit(tmp_path)]
    assert statuses == [200, 429, 200, 200]
    assert read_audit(tmp_path)[1]["key_id"] == key_id_for("alpha")
    assert read_audit(tmp_path)[3]["key_id"] == key_id_for("gamma")


def test_token_budget_returns_429(tmp_path):
    app = build_app(tmp_path, budget_tokens_per_day=5, budget_requests_per_day=50)
    with TestClient(app) as client:
        response = client.post(CHAT, json=chat_body("lorem ipsum " * 80))
    assert response.status_code == 429
    assert "token" in response.json()["error"]["message"].lower()


def test_invalid_chat_requests(tmp_path):
    with build_client(tmp_path) as client:
        invalid_json = client.post(CHAT, content=b"{", headers={"content-type": "application/json"})
        missing = client.post(CHAT, json={"model": "gpt-4o-mini"})
        empty = client.post(CHAT, json={"model": "gpt-4o-mini", "messages": []})
        bad_item = client.post(CHAT, json={"model": "m", "messages": ["hi"]})
        streaming = client.post(CHAT, json=chat_body("hi", stream=True))
        streaming_text = client.post(CHAT, json=chat_body("hi", stream="true"))
    assert invalid_json.status_code == 400
    assert invalid_json.json()["error"]["code"] == "invalid_json"
    assert missing.status_code == 400
    assert empty.status_code == 400
    assert bad_item.status_code == 400
    assert streaming.status_code == 400
    assert streaming.json()["error"]["code"] == "stream_unsupported"
    assert streaming_text.status_code == 400
    assert read_audit(tmp_path) == []


def test_upstream_status_is_passed_through(tmp_path):
    class Upstream:
        async def complete(self, body: dict):
            from aiguard.proxy import UpstreamResult

            payload = {"error": {"message": "unknown model", "type": "invalid_request_error"}}
            return UpstreamResult(404, payload, json.dumps(payload).encode())

    app = build_app(tmp_path, upstream=Upstream(), mock_upstream=False)
    with TestClient(app) as client:
        response = client.post(CHAT, json=chat_body("hello"))
    assert response.status_code == 404
    assert response.json()["error"]["message"] == "unknown model"
    assert read_audit(tmp_path)[0]["status"] == 404


def test_upstream_network_error_is_502(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    upstream = HttpxUpstream(Settings(upstream_base_url="https://upstream.test/v1"), transport=httpx.MockTransport(handler))
    app = build_app(tmp_path, upstream=upstream, mock_upstream=False)
    with TestClient(app) as client:
        response = client.post(CHAT, json=chat_body(f"secret {KNOWN_TCKN}"))
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unavailable"
    assert KNOWN_TCKN not in response.text
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert KNOWN_TCKN not in audit
    assert read_audit(tmp_path)[0]["pii"] == {"TCKN": 1}
    assert read_audit(tmp_path)[0]["status"] == 502


def test_same_placeholder_across_messages(tmp_path):
    messages = [
        {"role": "user", "content": f"Email ayse.yilmaz@example.com about {VISA_16}"},
        {"role": "user", "content": "Again ayse.yilmaz@example.com"},
    ]
    with build_client(tmp_path, restore_pii=False) as client:
        response = client.post(CHAT, json={"model": "m", "messages": messages})
    content = response.json()["choices"][0]["message"]["content"]
    assert content.count("[EMAIL_1]") == 2
    assert "[EMAIL_2]" not in content
    assert "[CARD_1]" in content
    assert read_audit(tmp_path)[0]["pii"] == {"CARD": 1, "EMAIL": 2}


def test_budget_day_rollover_through_the_api(tmp_path):
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 11, 20, 22, 0, tzinfo=timezone.utc)
    clock = {"now": now}
    budget = BudgetStore(1, 100_000, clock=lambda: clock["now"])
    app = build_app(tmp_path, budget=budget, restore_pii=False)
    with TestClient(app) as client:
        assert client.post(CHAT, json=chat_body("one")).status_code == 200
        assert client.post(CHAT, json=chat_body("two")).status_code == 429
        clock["now"] = now + timedelta(days=1)
        assert client.post(CHAT, json=chat_body("three")).status_code == 200


def test_upstream_error_type_is_safe():
    error = UpstreamError("ConnectError")
    assert "prompt" not in str(error)
