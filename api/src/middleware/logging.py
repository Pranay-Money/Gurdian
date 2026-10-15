"""
Structured JSON Logging Middleware
Logs without message bodies, structured fields for observability.
"""
import hashlib
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Configure structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("guardian.api")


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured JSON logging.
    Logs request/response metadata without sensitive data or message bodies.
    """

    def __init__(self, app: ASGIApp, excluded_paths: Optional[list] = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or ["/health", "/docs", "/redoc", "/openapi.json"]

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timer
        start_time = time.perf_counter()

        # Extract device ID if available
        device_id = None
        auth_header = request.headers.get("X-Device-Token", "")
        if auth_header.startswith("dev_"):
            # Hash token for logging (don't log actual token)
            device_id = hashlib.sha256(auth_header.encode()).hexdigest()[:16]

        # Log request start
        logger.info(
            "request_started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            device_id_hash=device_id,
            client_ip=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:100],
        )

        # Process request
        response = None
        error = None
        try:
            response = await call_next(request)
        except Exception as e:
            error = e
            # Re-raise to let FastAPI handle it
            raise
        finally:
            # Calculate latency
            latency_ms = int((time.perf_counter() - start_time) * 1000)

            # Log request completion
            log_data: Dict[str, Any] = {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code if response else 500,
                "latency_ms": latency_ms,
                "device_id_hash": device_id,
            }

            if error:
                log_data["error_type"] = type(error).__name__
                log_data["error_message"] = str(error)[:200]
                logger.error("request_failed", **log_data)
            else:
                logger.info("request_completed", **log_data)

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, considering proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        if request.client:
            return request.client.host
        return "unknown"


# Helper functions for structured logging in endpoints
def log_analysis(
    device_id: str,
    case_id: str,
    score: int,
    level: str,
    action: str,
    latency_ms: int,
    signals_count: int,
    urls_count: int,
    channel: str,
):
    """Log analysis event."""
    logger.info(
        "analysis_completed",
        device_id_hash=hashlib.sha256(device_id.encode()).hexdigest()[:16],
        case_id=case_id,
        score=score,
        level=level,
        action=action,
        latency_ms=latency_ms,
        signals_count=signals_count,
        urls_count=urls_count,
        channel=channel,
    )


def log_feedback(device_id: str, case_id: str, verdict: str):
    """Log feedback event."""
    logger.info(
        "feedback_submitted",
        device_id_hash=hashlib.sha256(device_id.encode()).hexdigest()[:16],
        case_id=case_id,
        verdict=verdict,
    )


def log_report(device_id: str, report_id: str, url: str):
    """Log URL report event."""
    logger.info(
        "url_reported",
        device_id_hash=hashlib.sha256(device_id.encode()).hexdigest()[:16],
        report_id=report_id,
        url_hash=hashlib.sha256(url.encode()).hexdigest()[:16],
    )


def log_blocklist_delta(device_id: Optional[str], since: datetime, additions: int, removals: int):
    """Log blocklist delta request."""
    logger.info(
        "blocklist_delta_requested",
        device_id_hash=hashlib.sha256(device_id.encode()).hexdigest()[:16] if device_id else None,
        since=since.isoformat(),
        additions=additions,
        removals=removals,
    )


def log_device_wipe(device_id: str, cases_deleted: int, feedback_deleted: int):
    """Log device data wipe event."""
    logger.warning(
        "device_wipe_completed",
        device_id_hash=hashlib.sha256(device_id.encode()).hexdigest()[:16],
        cases_deleted=cases_deleted,
        feedback_deleted=feedback_deleted,
    )



def log_auth_event(
    event: str,
    device_id: Optional[str] = None,
    token_hash: Optional[str] = None,
    error: Optional[str] = None,
):
    """Log authentication events."""
    log_data: Dict[str, Any] = {"auth_event": event}

    if device_id:
        log_data["device_id_hash"] = hashlib.sha256(
            device_id.encode()
        ).hexdigest()[:16]

    if token_hash:
        log_data["token_hash"] = token_hash

    if error:
        log_data["error"] = error

    if event in ("token_created", "token_rotated", "device_registered"):
        logger.info("Authentication event", **log_data)
    else:
        logger.warning("Authentication event", **log_data)
