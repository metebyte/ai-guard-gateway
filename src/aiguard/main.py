"""FastAPI application: OpenAI-compatible proxy plus a local redact endpoint."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aiguard import __version__
from aiguard.audit import AuditLog, key_id_for
from aiguard.budget import BudgetStore, estimate_tokens
from aiguard.config import Settings
from aiguard.pii import PII_ORDER, RedactionSession
from aiguard.proxy import (
    HttpxUpstream,
    MockUpstream,
    UpstreamError,
    UpstreamResult,
    estimate_messages_tokens,
    redact_messages,
)

logger = logging.getLogger("aiguard")

CHAT_PATH = "/v1/chat/completions"
REDACT_PATH = "/v1/redact"
PII_HEADER = "X-AIGuard-PII"


class RedactRequest(BaseModel):
    text: str = Field(examples=["Customer TCKN 10000000146"])


class FindingModel(BaseModel):
    type: str
    placeholder: str
    start: int
    end: int


class RedactResponse(BaseModel):
    redacted_text: str
    findings: list[FindingModel]
    counts: dict[str, int]


def create_app(
    settings: Settings | None = None,
    upstream: object | None = None,
    budget: BudgetStore | None = None,
    audit: AuditLog | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    if upstream is None:
        upstream = MockUpstream() if settings.mock_upstream else HttpxUpstream(settings)
    if budget is None:
        budget = BudgetStore(settings.budget_requests_per_day, settings.budget_tokens_per_day)
    if audit is None:
        audit = AuditLog(settings.audit_log_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        opener = getattr(app.state.upstream, "open", None)
        closer = getattr(app.state.upstream, "close", None)
        if opener is not None:
            await opener()
        try:
            yield
        finally:
            if closer is not None:
                await closer()

    app = FastAPI(
        title="AI Guard Gateway",
        version=__version__,
        summary="Redact Turkish and English PII before prompts reach a public model.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.upstream = upstream
    app.state.budget = budget
    app.state.audit = audit

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    async def root() -> dict[str, str]:
        return {
            "name": "ai-guard-gateway",
            "version": __version__,
            "chat": CHAT_PATH,
            "redact": REDACT_PATH,
            "docs": "/docs",
        }

    @app.post(REDACT_PATH, response_model=RedactResponse)
    async def redact_endpoint(body: RedactRequest, request: Request) -> Response:
        session = RedactionSession()
        result = session.redact(body.text)
        blocked = _enforce_budget(
            request,
            session,
            REDACT_PATH,
            estimate_tokens(body.text),
        )
        if blocked is not None:
            return blocked
        payload = RedactResponse(
            redacted_text=result.text,
            findings=[FindingModel(**finding.as_dict()) for finding in result.findings],
            counts=session.counts(),
        )
        response = JSONResponse(payload.model_dump())
        _finish(request, session, REDACT_PATH, 200, response)
        return response

    @app.post(CHAT_PATH)
    async def chat_completions(request: Request) -> Response:
        try:
            body = json.loads(await request.body() or b"null")
        except json.JSONDecodeError:
            return _openai_error("Invalid JSON body", "invalid_request_error", "invalid_json", 400)
        if not isinstance(body, dict):
            return _openai_error("Request body must be a JSON object", "invalid_request_error", "invalid_body", 400)
        if _streaming_requested(body):
            return _openai_error(
                "Streaming is not supported",
                "invalid_request_error",
                "stream_unsupported",
                400,
            )
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return _openai_error(
                "messages must be a non-empty list",
                "invalid_request_error",
                "invalid_messages",
                400,
            )
        session = RedactionSession()
        try:
            redacted_messages = redact_messages(session, messages)
        except ValueError as exc:
            return _openai_error(str(exc), "invalid_request_error", "invalid_messages", 400)

        blocked = _enforce_budget(
            request,
            session,
            CHAT_PATH,
            estimate_messages_tokens(redacted_messages),
        )
        if blocked is not None:
            return blocked

        outgoing = dict(body)
        outgoing["messages"] = redacted_messages
        outgoing.pop("stream", None)
        try:
            result = await app.state.upstream.complete(outgoing)
        except UpstreamError as exc:
            logger.warning("upstream request failed: %s", exc)
            response = _openai_error(
                "Upstream request failed",
                "upstream_error",
                "upstream_unavailable",
                502,
            )
            _finish(request, session, CHAT_PATH, 502, response)
            return response

        _charge_completion(request, result)
        status = result.status_code
        if settings.restore_pii and isinstance(result.payload, dict):
            restored = session.restore_data(result.payload)
            content = json.dumps(restored, ensure_ascii=False).encode("utf-8")
            media_type = "application/json"
        else:
            content = result.raw
            media_type = result.media_type
        response = Response(content=content, status_code=status, media_type=media_type)
        _finish(request, session, CHAT_PATH, status, response)
        return response

    def _enforce_budget(request: Request, session: RedactionSession, endpoint: str, tokens: int) -> Response | None:
        key_id = key_id_for(_client_key(request))
        decision = app.state.budget.try_consume(key_id, tokens)
        if decision.allowed:
            return None
        message = (
            "Daily request budget exceeded"
            if decision.reason == "requests"
            else "Daily token budget exceeded"
        )
        response = _openai_error(message, "budget_exceeded", "rate_limit_exceeded", 429)
        response.headers["Retry-After"] = str(decision.retry_after)
        _apply_pii_header(response, session)
        app.state.audit.write(key_id=key_id, endpoint=endpoint, pii_counts=session.counts(), status=429)
        return response

    def _charge_completion(request: Request, result: UpstreamResult) -> None:
        completion = 0
        usage = result.payload.get("usage") if isinstance(result.payload, dict) else None
        if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
            completion = max(0, usage["completion_tokens"])
        elif isinstance(result.payload, dict):
            choices = result.payload.get("choices")
            if isinstance(choices, list):
                for choice in choices:
                    if isinstance(choice, dict):
                        message = choice.get("message")
                        if isinstance(message, dict) and isinstance(message.get("content"), str):
                            completion += estimate_tokens(message["content"])
        if completion:
            app.state.budget.add_tokens(key_id_for(_client_key(request)), completion)

    def _finish(request: Request, session: RedactionSession, endpoint: str, status: int, response: Response) -> None:
        _apply_pii_header(response, session)
        app.state.audit.write(
            key_id=key_id_for(_client_key(request)),
            endpoint=endpoint,
            pii_counts=session.counts(),
            status=status,
        )

    return app


def _client_key(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def _streaming_requested(body: dict) -> bool:
    stream = body.get("stream", False)
    if isinstance(stream, str):
        return stream.strip().lower() == "true"
    return stream is True


def _apply_pii_header(response: Response, session: RedactionSession) -> None:
    counts = session.counts()
    if not counts:
        return
    response.headers[PII_HEADER] = ", ".join(f"{name}={counts[name]}" for name in PII_ORDER if counts.get(name))


def _openai_error(message: str, error_type: str, code: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"message": message, "type": error_type, "code": code}},
    )


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "aiguard.main:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
    )
