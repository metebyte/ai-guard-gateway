# AI Guard Gateway

[![tests](https://github.com/metebyte/ai-guard-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/metebyte/ai-guard-gateway/actions/workflows/test.yml)

Open-source AI gateway for small and mid-sized companies. It redacts Turkish and English personal data in a prompt before the prompt is sent to a public model.

Staff paste customer records into ChatGPT and similar tools: a T.C. Kimlik No, an IBAN, a card, a mobile number, an email. That paste is a disclosure under KVKK and GDPR. The model vendor becomes an unplanned processor, and the text may be stored outside the company. This gateway sits on the path those calls already use. Applications keep the OpenAI SDK. The provider receives placeholders.

Author: [metebyte](https://metebyte.net)

## What it does

`POST /v1/chat/completions` accepts an OpenAI chat request.

1. Every message `content` string, including text parts of a multipart message, is scanned.
2. Values that pass a real check (not a bare pattern) are replaced with typed placeholders such as `[TCKN_1]` and `[IBAN_1]`. The same value in the same request keeps the same placeholder.
3. The redacted body is forwarded to `UPSTREAM_BASE_URL` (default `https://api.openai.com/v1`) with `UPSTREAM_API_KEY`.
4. When `RESTORE_PII` is on (the default), placeholders in the upstream JSON are swapped back to the original values. The map lives only in memory for that request.
5. Each call appends one JSON line to the audit log: time, key id, PII types and counts. Raw values are never written.
6. A per-key daily budget of requests and estimated tokens returns HTTP 429 when the cap is reached.

`POST /v1/redact` does only the redaction step and returns the text plus findings. It is the easiest way to demo the engine.

`MOCK_UPSTREAM=1` skips the network and returns the redacted conversation as the assistant message, so the proxy runs with no API key.

The examples below use checksum-valid fixtures (a synthetic TCKN, a mod-97 Turkish IBAN, the common Visa test number, a reserved phone pattern, and `example.com`). They are not real customer data.

## Quickstart

Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
MOCK_UPSTREAM=1 uvicorn aiguard.main:app --host 0.0.0.0 --port 8080
```

`MOCK_UPSTREAM=1 ai-guard-gateway` starts the same server via the installed console script (`HOST` and `PORT` default to `0.0.0.0:8080`).

Docker, from a clone of this repo:

```bash
docker build -t ai-guard-gateway . && docker run --rm -p 8080:8080 -e MOCK_UPSTREAM=1 ai-guard-gateway
```

The image listens on port 8080 and, unless you override it, talks to the mock upstream. Point a real deployment at your model API with `MOCK_UPSTREAM=0` and `UPSTREAM_API_KEY`.

## Example

Before, the text a staff member would paste:

```text
Customer 10000000146 paid from TR33 0006 1005 1978 6457 8413 26 with card 4111 1111 1111 1111, phone +90 532 111 22 33, email ayse.yilmaz@example.com. Order 48291736501 stays.
```

```bash
curl -s http://localhost:8080/v1/redact \
  -H 'Content-Type: application/json' \
  -d '{"text":"Customer 10000000146 paid from TR33 0006 1005 1978 6457 8413 26 with card 4111 1111 1111 1111, phone +90 532 111 22 33, email ayse.yilmaz@example.com. Order 48291736501 stays."}'
```

After:

```json
{
  "redacted_text": "Customer [TCKN_1] paid from [IBAN_1] with card [CARD_1], phone [PHONE_1], email [EMAIL_1]. Order 48291736501 stays.",
  "findings": [
    {"type": "TCKN", "placeholder": "[TCKN_1]", "start": 9, "end": 20},
    {"type": "IBAN", "placeholder": "[IBAN_1]", "start": 31, "end": 63},
    {"type": "CARD", "placeholder": "[CARD_1]", "start": 74, "end": 93},
    {"type": "PHONE", "placeholder": "[PHONE_1]", "start": 101, "end": 118},
    {"type": "EMAIL", "placeholder": "[EMAIL_1]", "start": 126, "end": 149}
  ],
  "counts": {"TCKN": 1, "IBAN": 1, "CARD": 1, "PHONE": 1, "EMAIL": 1}
}
```

`start` and `end` are indexes into the original text. The order number `48291736501` is eleven digits and fails the TCKN checksum, so it is left as written. Findings do not repeat the raw value.

The same sentence through the proxy, with the mock upstream and `RESTORE_PII=0` so the echo shows what the model would see:

```bash
curl -sD - http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarise the case for customer 10000000146, card 4111 1111 1111 1111."}]}'
```

```text
x-aiguard-pii: TCKN=1, CARD=1
```

```json
{
  "id": "chatcmpl-mock",
  "object": "chat.completion",
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "user: Summarise the case for customer [TCKN_1], card [CARD_1]."
      },
      "finish_reason": "stop"
    }
  ]
}
```

The live payload also includes `created` and `usage`.

With the default `RESTORE_PII=1`, placeholders in that assistant text are turned back into the caller's original values before the HTTP response is returned. The upstream request still contains only placeholders. `X-AIGuard-PII` and the audit line are how you see what left the building.

```json
{"timestamp":"2026-11-20T00:52:44Z","key_id":"key_c48a01f49fd0","endpoint":"/v1/chat/completions","pii":{"TCKN":1,"CARD":1},"status":200}
```

`key_c48a01f49fd0` is the first 12 hex characters of SHA-256 over the gateway bearer token `demo-key`. The token itself is not stored. The gateway token and `UPSTREAM_API_KEY` are different secrets: clients authenticate to this process, and only this process holds the upstream key.

## Configuration

| Variable | Default | Role |
| --- | --- | --- |
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `UPSTREAM_API_KEY` | empty | Bearer token sent only upstream |
| `MOCK_UPSTREAM` | `0` | `1` returns the redacted prompt and does not call upstream |
| `RESTORE_PII` | `1` | Put original values back into the upstream JSON response |
| `BUDGET_REQUESTS_PER_DAY` | `1000` | Per gateway-key request cap, UTC day, in memory |
| `BUDGET_TOKENS_PER_DAY` | `100000` | Per gateway-key token cap (about 4 characters per token, plus completion tokens reported by the upstream) |
| `AUDIT_LOG_PATH` | `audit.jsonl` | JSON-lines audit file |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | Bind address for `ai-guard-gateway` |

A client key is the `Authorization: Bearer` token, or `X-API-Key`. Calls with no key share an `anonymous` budget. Caps reset at UTC midnight. Crossing either cap returns:

```json
{"error":{"message":"Daily request budget exceeded","type":"budget_exceeded","code":"rate_limit_exceeded"}}
```

HTTP 429, with `Retry-After` set to the seconds until the next UTC day. `stream: true` is rejected so a streaming body cannot skip redaction.

## Detection

| Type | Placeholder | What must pass |
| --- | --- | --- |
| Turkish national ID | `[TCKN_n]` | 11 digits, first digit not zero. Digit 10 is `((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`. Digit 11 is the sum of the first 10 digits mod 10. |
| IBAN | `[IBAN_n]` | ISO 13616 length for the country (TR is 26) and ISO 7064 mod-97. Spaces and dashes are ignored. |
| Payment card | `[CARD_n]` | 13–19 digits, Luhn, and a Visa, Mastercard, Amex, Discover, Troy (`9792`), Diners, or JCB prefix. Spaces and dashes are allowed. |
| Turkish mobile | `[PHONE_n]` | `+90`, `0090`, or a leading `0`, then a mobile prefix (`50x`, `53x`–`55x`, `516`, `561`). |
| Email | `[EMAIL_n]` | One `@`, a dotted domain, and an alphabetic TLD. |

Overlapping spans keep the longer match, so a digit run inside a valid IBAN is reported as the IBAN.

## Architecture

```text
staff app (OpenAI SDK)
        |
        |  POST /v1/chat/completions
        v
+--------------------------------------+
| AI Guard Gateway                     |
|  redact message content              |
|  enforce the per-key daily budget    |
|  append an audit line (counts only)  |
|  optional in-memory restore on reply |
+------------------+-------------------+
                   |  placeholders only
                   v
        upstream model API
        (or the mock echo)
```

```text
src/aiguard/pii.py      checksums and the per-request redactor
src/aiguard/proxy.py    message walk, mock completion, upstream HTTP
src/aiguard/budget.py   in-memory daily caps
src/aiguard/audit.py    JSON-lines log and key ids
src/aiguard/main.py     FastAPI routes
```

This process is the trust boundary. Restarting it clears budgets and drops any placeholder map, which is never written to disk.

## Development

```bash
pip install -e ".[dev]"
pytest
```

GitHub Actions runs the suite on Python 3.11 and builds the Docker image, then calls `/v1/redact` inside the container.

## Roadmap

- A prompt-injection and tool-call policy engine, so tool arguments are inspected before they run and hostile instructions in retrieved text can be blocked.
- Output grounding checks, comparing model claims with the sources the request was allowed to use.
- KVKK, GDPR, and EU AI Act evidence reports built from the audit stream.
- A Helm chart for deploying the gateway next to the applications that call it.

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Mete. [metebyte](https://metebyte.net)
