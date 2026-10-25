"""Correlation ID propagation and sensitive data redaction filter."""

import logging
import re
import time
from contextvars import ContextVar
from typing import Optional
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Request-scoped correlation ID context variable
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")

# Allowed characters in correlation ID: alphanumeric, dash, underscore
_CORRELATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Sensitive data rules (pattern, replacement) to redact in logs and diagnostic outputs
SENSITIVE_RULES = [
    # Quoted or unquoted sensitive key-values (password, secret, token, api_key, private_key)
    (
        re.compile(r'(?i)([\'\"]?(?:password|secret|token|api_key|private_key)[\'\"]?\s*[:=]\s*)([\'\"][^\'\"]+[\'\"]|[^\s,;\'\"]+)'),
        r'\1"[REDACTED]"',
    ),
    # Authorization header with Bearer token
    (
        re.compile(r'(?i)([\'\"]?authorization[\'\"]?\s*[:=]\s*[\'\"]?Bearer\s+)([\'\"][^\'\"]+[\'\"]|[^\s,;\'\"]+)'),
        r'\1"[REDACTED]"',
    ),
    # PostgreSQL connection URLs with embedded passwords
    (
        re.compile(r'(?i)(postgres(?:ql)?(?:\+asyncpg)?://[^:]+:)([^@]+)(@)'),
        r'\1[REDACTED]\3',
    ),
    # Redis connection URLs with embedded passwords
    (
        re.compile(r'(?i)(redis(?:s)?://:)([^@]+)(@)'),
        r'\1[REDACTED]\3',
    ),
]

SENSITIVE_PATTERNS = [rule[0] for rule in SENSITIVE_RULES]


def redact_text(text: str) -> str:
    """Scrub sensitive credentials, passwords, tokens, and database URLs from text."""
    if not isinstance(text, str):
        return text
    for pattern, repl in SENSITIVE_RULES:
        text = pattern.sub(repl, text)
    return text


def get_request_id() -> str:
    """Retrieve current correlation ID from context, or empty string."""
    return request_id_ctx.get()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that ensures every HTTP request has a traceable correlation ID,

    propagates it into contextvars, attaches it to response headers, and records request metrics.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract existing correlation ID or generate a new one
        raw_req_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
        if raw_req_id and _CORRELATION_ID_PATTERN.match(raw_req_id.strip()):
            correlation_id = raw_req_id.strip()
        else:
            correlation_id = f"req_{uuid4().hex[:12]}"

        token = request_id_ctx.set(correlation_id)
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Attach correlation ID to response headers
            response.headers["X-Request-ID"] = correlation_id

            # Record bounded metrics
            try:
                from waliya.observability.metrics import get_metrics_collector
                get_metrics_collector().record_http_request(
                    method=request.method,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                )
            except Exception:
                pass

            return response
        finally:
            request_id_ctx.reset(token)


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive fields and attaches correlation ID to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # 1. Attach correlation ID to log record if available
        cid = get_request_id()
        if cid:
            record.correlation_id = cid
        elif not hasattr(record, "correlation_id"):
            record.correlation_id = "-"

        # 2. Redact sensitive patterns in message string
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)

        # 3. Redact in args if string or dict args
        if record.args:
            if isinstance(record.args, dict):
                redacted_args = {}
                for k, v in record.args.items():
                    if any(s in k.lower() for s in ["password", "secret", "token", "auth", "key"]):
                        redacted_args[k] = "[REDACTED]"
                    elif isinstance(v, str):
                        redacted_args[k] = redact_text(v)
                    else:
                        redacted_args[k] = v
                record.args = redacted_args
            elif isinstance(record.args, tuple):
                new_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        new_args.append(redact_text(arg))
                    elif isinstance(arg, dict):
                        redacted_d = {}
                        for k, v in arg.items():
                            if any(s in k.lower() for s in ["password", "secret", "token", "auth", "key"]):
                                redacted_d[k] = "[REDACTED]"
                            elif isinstance(v, str):
                                redacted_d[k] = redact_text(v)
                            else:
                                redacted_d[k] = v
                        new_args.append(redacted_d)
                    else:
                        new_args.append(arg)
                record.args = tuple(new_args)

        return True
