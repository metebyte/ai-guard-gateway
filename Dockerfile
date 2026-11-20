FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data \
    && chown appuser /app/data

USER appuser

ENV MOCK_UPSTREAM=1 \
    AUDIT_LOG_PATH=/app/data/audit.jsonl \
    PYTHONUNBUFFERED=1 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

CMD ["uvicorn", "aiguard.main:app", "--host", "0.0.0.0", "--port", "8080"]
