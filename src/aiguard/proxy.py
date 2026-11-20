"""OpenAI chat-completion shaping: redaction, mock echo, and the upstream call."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx

from aiguard.budget import estimate_tokens
from aiguard.config import Settings
from aiguard.pii import RedactionSession

USER_AGENT = "ai-guard-gateway/0.1.0"


class UpstreamError(Exception):
    """The upstream could not be reached. The message must not include prompt text."""


@dataclass(frozen=True)
class UpstreamResult:
    status_code: int
    payload: dict | None
    raw: bytes
    media_type: str = "application/json"


def upstream_headers(settings: Settings) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if settings.upstream_api_key:
        headers["Authorization"] = f"Bearer {settings.upstream_api_key}"
    return headers


def flatten_content(content: object) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "\n".join(parts)
    return ""


def estimate_messages_tokens(messages: list) -> int:
    total = 0
    for message in messages:
        if isinstance(message, dict):
            total += estimate_tokens(flatten_content(message.get("content")))
    return total


def redact_messages(session: RedactionSession, messages: list) -> list:
    redacted: list[dict] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"messages[{index}] must be an object")
        updated = dict(message)
        if "content" in updated:
            updated["content"] = _redact_content(session, updated["content"])
        redacted.append(updated)
    return redacted


def _redact_content(session: RedactionSession, content: object) -> object:
    if content is None or isinstance(content, (int, float, bool)):
        return content
    if isinstance(content, str):
        return session.redact(content).text
    if isinstance(content, list):
        parts: list[object] = []
        for part in content:
            if isinstance(part, str):
                parts.append(session.redact(part).text)
            elif isinstance(part, dict):
                part_type = part.get("type", "text")
                if part_type == "text" and isinstance(part.get("text"), str):
                    cloned = dict(part)
                    cloned["text"] = session.redact(part["text"]).text
                    parts.append(cloned)
                else:
                    parts.append(part)
            else:
                parts.append(part)
        return parts
    return content


def build_mock_completion(body: dict) -> dict:
    """Echo the already-redacted conversation so a demo needs no API key."""

    lines: list[str] = []
    messages = body.get("messages", [])
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = message.get("role") or "user"
            lines.append(f"{role}: {flatten_content(message.get('content'))}")
    content = "\n".join(lines)
    prompt_tokens = estimate_messages_tokens(messages if isinstance(messages, list) else [])
    completion_tokens = estimate_tokens(content)
    model = body.get("model") if isinstance(body.get("model"), str) and body.get("model") else "mock"
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


class MockUpstream:
    async def complete(self, body: dict) -> UpstreamResult:
        payload = build_mock_completion(body)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return UpstreamResult(200, payload, raw)


class HttpxUpstream:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def open(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=10.0),
                transport=self._transport,
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def complete(self, body: dict) -> UpstreamResult:
        await self.open()
        assert self._client is not None
        url = self._settings.upstream_base_url.rstrip("/") + "/chat/completions"
        try:
            response = await self._client.post(url, json=body, headers=upstream_headers(self._settings))
        except httpx.HTTPError as exc:
            raise UpstreamError(exc.__class__.__name__) from exc
        media = response.headers.get("content-type", "application/json").split(";", 1)[0] or "application/json"
        payload: dict | None = None
        try:
            parsed = response.json()
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            payload = parsed
        return UpstreamResult(response.status_code, payload, response.content, media)
