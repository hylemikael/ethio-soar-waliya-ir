"""Main FastAPI application factory and entrypoint for Waliya-IR."""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from waliya.api.routes.agents import router as agents_router
from waliya.api.routes.assets import router as assets_router
from waliya.api.routes.auth import router as auth_router
from waliya.api.routes.correlation import router as correlation_router
from waliya.api.routes.health import router as health_router
from waliya.api.routes.incidents import router as incidents_router
from waliya.api.routes.integrations import router as integrations_router
from waliya.api.routes.overview import router as overview_router
from waliya.api.routes.rules import router as rules_router
from waliya.api.routes.simulations import router as simulations_router
from waliya.api.routes.soar import router as soar_router
from waliya.api.routes.telemetry import router as telemetry_router
from waliya.api.routes.threat_intel import router as threat_intel_router
from waliya.api.routes.users import router as users_router
from waliya.config import settings
from waliya.db.session import engine
from waliya.observability.correlation import (
    CorrelationIdMiddleware,
    SensitiveDataFilter,
    get_request_id,
)

logger = logging.getLogger("waliya.main")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce defense-in-depth HTTP security response headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if settings.SESSION_COOKIE_SECURE:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with payloads exceeding 10MB to protect against resource exhaustion DoS."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length_int = int(content_length)
                if length_int > MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={
                            "error": "Payload Too Large",
                            "detail": f"Request body size exceeds maximum allowed limit of {MAX_REQUEST_BODY_BYTES} bytes.",
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context managing startup and graceful shutdown."""
    # Configure sensitive data scrubbing on root logging handlers
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=log_level)
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveDataFilter())

    yield

    # Shutdown tasks: dispose DB connection pool
    await engine.dispose()


def create_app() -> FastAPI:
    """Factory function creating and configuring the Waliya-IR FastAPI application."""
    is_prod = settings.ENV.lower() in ("production", "prod")
    docs_enabled = not is_prod or settings.ENABLE_PUBLIC_DOCS

    app = FastAPI(
        title="Ethio-SOAR (Waliya-IR) API",
        description="Linux-First Security Operations, Threat Detection & Automated Incident Response Platform",
        version="2.0.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/api/v1/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    # Security Headers Middleware (outer layer)
    app.add_middleware(SecurityHeadersMiddleware)

    # Request Body Size Limit Middleware (DoS protection)
    app.add_middleware(RequestSizeLimitMiddleware)

    # CORS Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Correlation ID & Observability Middleware
    app.add_middleware(CorrelationIdMiddleware)

    # Global unhandled exception handler to prevent traceback and sensitive leaks
    @app.exception_handler(Exception)
    async def global_unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = get_request_id() or "unknown"
        logger.exception(
            "Unhandled server exception during request [correlation_id=%s]: %s",
            correlation_id,
            exc,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "detail": "An internal error occurred. Please contact the administrator with the correlation ID.",
                "correlation_id": correlation_id,
            },
            headers={"X-Request-ID": correlation_id},
        )

    # Mount API Routers under /api/v1
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(overview_router, prefix="/api/v1")
    app.include_router(telemetry_router, prefix="/api/v1")
    app.include_router(rules_router, prefix="/api/v1")
    app.include_router(correlation_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(agents_router, prefix="/api/v1")
    app.include_router(soar_router, prefix="/api/v1")
    app.include_router(simulations_router, prefix="/api/v1")
    app.include_router(threat_intel_router, prefix="/api/v1")
    app.include_router(assets_router, prefix="/api/v1")
    app.include_router(integrations_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("waliya.main:app", host="127.0.0.1", port=8000, reload=True)
