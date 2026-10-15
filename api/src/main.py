import hashlib
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

import sentry_sdk
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import HttpUrl
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from src.core.config import get_settings
from src.db.models import (
    ActionType,
    ApiUsage,
    BlocklistEntry,
    Case,
    ChannelType,
    Device,
    Feedback,
    ReportedUrl,
    RiskLevel,
    VerdictType,
)
from src.db.session import Base, close_db, get_session, init_db
from src.middleware.auth import RateLimitConfig, check_rate_limit
from src.middleware.logging import (
    StructuredLoggingMiddleware,
    log_analysis,
    log_auth_event,
    log_blocklist_delta,
    log_device_wipe,
    log_feedback,
    log_report,
)
from src.schemas import (
    ActionType,
    AnalyzeRequest,
    AnalyzeResponse,
    BlocklistDeltaResponse,
    CaseDetail,
    CaseListResponse,
    CaseSummary,
    ChannelType,
    DeviceRegisterResponse,
    ErrorDetail,
    ErrorResponse,
    EvidenceItem,
    FeedbackRequest,
    IntelSource,
    IntelVerdict,
    ReportRequest,
    RiskLevel,
    Signal,
    SignalCategory,
    StatsResponse,
    URLAnalysis,
    VerdictType,
)
from src.services.analyzer import get_analyzer

settings = get_settings()

# Initialize Sentry
if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        profiles_sample_rate=settings.sentry_profiles_sample_rate,
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),
            SqlalchemyIntegration(),
            RedisIntegration(),
        ],
        # Don't send PII
        send_default_pii=False,
        # Custom tags
        _experiments={
            "enable_logs": True,
        },
    )

# Prometheus metrics
REQUEST_COUNT = Counter(
    "guardian_http_requests_total",
    "Total HTTP requests",
    ["method", "handler", "status"]
)

REQUEST_LATENCY = Histogram(
    "guardian_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["handler"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

ANALYSES_TOTAL = Counter(
    "guardian_analyses_total",
    "Total analyses performed",
    ["level", "action", "channel"]
)

DETECTIONS_TOTAL = Counter(
    "guardian_detections_total",
    "Total detections by level",
    ["level"]
)

INTEL_ADAPTER_REQUESTS = Counter(
    "guardian_intel_adapter_requests_total",
    "Total intel adapter requests",
    ["adapter", "verdict"]
)

INTEL_ADAPTER_FAILURES = Counter(
    "guardian_intel_adapter_failures_total",
    "Total intel adapter failures",
    ["adapter"]
)

CACHE_HITS = Counter(
    "guardian_cache_hits_total",
    "Total cache hits",
    ["cache_type"]
)

CACHE_MISSES = Counter(
    "guardian_cache_misses_total",
    "Total cache misses",
    ["cache_type"]
)

BLOCKLIST_SYNC = Counter(
    "guardian_blocklist_sync_total",
    "Total blocklist sync operations"
)

BLOCKLIST_SYNC_FAILURES = Counter(
    "guardian_blocklist_sync_failures_total",
    "Total blocklist sync failures"
)

RATE_LIMIT_EXCEEDED = Counter(
    "guardian_rate_limit_exceeded_total",
    "Total rate limit exceeded events",
    ["endpoint"]
)

DB_POOL_CHECKED_OUT = Gauge(
    "guardian_db_pool_checked_out",
    "Database connections checked out"
)

DB_POOL_SIZE = Gauge(
    "guardian_db_pool_size",
    "Database connection pool size"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_analyzer()
    await init_db()
    # Update DB pool metrics
    DB_POOL_SIZE.set(settings.database_pool_size + settings.database_max_overflow)
    yield
    await close_db()


app = FastAPI(
    title="Guardian API",
    version="1.0.0",
    description="Phishing, scam, and malicious URL detection API",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Add structured logging middleware FIRST (before other middleware)
app.add_middleware(StructuredLoggingMiddleware)

# CORS - restricted to extension origin(s) from env
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Device-Token", "X-Request-ID"],
    expose_headers=["X-Device-Token-New", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    max_age=3600,
)


async def get_device_token(x_device_token: Optional[str] = Header(None, alias="X-Device-Token")) -> str:
    if not x_device_token:
        raise HTTPException(status_code=401, detail="Device token required")
    return x_device_token


async def get_device(
    device_token: str = Depends(get_device_token),
    session: AsyncSession = Depends(get_session),
) -> Device:
    stmt = select(Device).where(Device.device_token == device_token, Device.is_active == True)
    result = await session.execute(stmt)
    device = result.scalar_one_or_none()

    if device is None and settings.app_env.lower() in {"development", "test"} and device_token.startswith("dev_"):
        device = await _ensure_test_device(session, device_token)

    if not device:
        token_hash = hashlib.sha256(device_token.encode()).hexdigest()[:16]
        log_auth_event("token_invalid", token_hash=token_hash)
        raise HTTPException(status_code=401, detail="Invalid or expired device token")
    if device.expires_at < datetime.utcnow():
        log_auth_event("token_expired", device_id=device_token, error="expired")
        raise HTTPException(status_code=401, detail="Device token expired")
    device.last_seen_at = datetime.utcnow()
    await session.commit()
    return device


async def _ensure_test_device(session: AsyncSession, device_token: str) -> Optional[Device]:
    """Allow local/test tokens in development mode while keeping JWT validation in production."""
    stmt = select(Device).where(Device.device_token == device_token)
    result = await session.execute(stmt)
    device = result.scalar_one_or_none()
    if device is not None:
        return device

    expires_at = datetime.utcnow() + timedelta(days=settings.device_token_ttl_days)
    device = Device(device_token=device_token, expires_at=expires_at, is_active=True)
    session.add(device)
    await session.commit()
    log_auth_event("device_registered", device_id=device_token)
    return device


async def record_api_usage(
    device: Device,
    endpoint: str,
    status_code: int,
    latency_ms: int,
    session: AsyncSession,
):
    usage = ApiUsage(
        device_id=device.id,
        endpoint=endpoint,
        status_code=status_code,
        latency_ms=latency_ms,
    )
    session.add(usage)
    await session.commit()


# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post(
    "/v1/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze(
    request: AnalyzeRequest,
    response: Response,
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    if request.text and len(request.text) > settings.max_text_length:
        raise HTTPException(status_code=413, detail=f"Text exceeds maximum length of {settings.max_text_length} characters")
    if request.urls and len(request.urls) > settings.max_urls_per_request:
        raise HTTPException(status_code=422, detail=f"Too many URLs. Maximum {settings.max_urls_per_request} allowed")

    await check_rate_limit(device, "/v1/analyze", session)
    limit_config = RateLimitConfig.get_limit("/v1/analyze")
    response.headers["X-RateLimit-Limit"] = str(limit_config["requests"])
    response.headers["X-RateLimit-Remaining"] = str(max(0, limit_config["requests"] - 1))
    response.headers["X-RateLimit-Reset"] = str(limit_config["window"])

    start_time = time.perf_counter()

    # Use real analyzer
    analyzer = get_analyzer()
    result = analyzer.analyze(
        channel=request.channel.value,
        sender=request.sender,
        text=request.text,
        urls=[str(u) for u in request.urls] if request.urls else None,
        deep=request.options.get("deep", False) if request.options else False
    )

    latency_ms = int((time.perf_counter() - start_time) * 1000)

    # Convert signals to schema format
    signals = []
    for s in result.signals:
        evidence = s.get("evidence") or []
        evidence_items = []
        for item in evidence:
            if isinstance(item, dict):
                evidence_items.append(EvidenceItem(
                    type=item.get("type", s["category"]),
                    value=str(item.get("value", "")),
                    description=item.get("description", s["reason"]),
                ))
            elif isinstance(item, str):
                evidence_items.append(EvidenceItem(
                    type=s["category"],
                    value=item,
                    description=s["reason"],
                ))
        signals.append(Signal(
            key=s["key"],
            category=SignalCategory(s["category"]),
            label=s["label"],
            points=s["points"],
            reason=s["reason"],
            evidence=evidence_items,
        ))

    # Convert URLs to schema format
    urls = []
    for u in result.urls:
        raw_redirects = u.get("redirects", [])
        urls.append(URLAnalysis(
            url=str(u["url"]),
            host=u["host"],
            registrable_domain=u["registrable_domain"],
            tld=u["tld"],
            https=u["https"],
            subdomains=u["subdomains"],
            length=u["length"],
            age_days=u.get("age_days"),
            redirects=[str(r) for r in raw_redirects],
            intel=u.get("intel")
        ))

    case = Case(
        id=result.case_id,
        device_id=device.id,
        channel=request.channel,
        sender=request.sender,
        text=request.text if device.store_raw_text else None,
        text_hash=result.text_hash if not device.store_raw_text else None,
        score=result.score,
        level=RiskLevel(result.level),
        action=ActionType(result.action),
        model_version=result.model_version,
        latency_ms=latency_ms,
        signals=[s.model_dump(mode="json") for s in signals],
        urls=[u.model_dump(mode="json") for u in urls],
    )
    session.add(case)
    await session.commit()

    await record_api_usage(device, "/v1/analyze", 200, latency_ms, session)

    # Update Prometheus metrics
    ANALYSES_TOTAL.labels(level=result.level, action=result.action, channel=request.channel.value).inc()
    DETECTIONS_TOTAL.labels(level=result.level).inc()

    # Structured logging
    log_analysis(
        device_id=device.device_token,
        case_id=str(result.case_id),
        score=result.score,
        level=result.level,
        action=result.action,
        latency_ms=latency_ms,
        signals_count=len(signals),
        urls_count=len(urls),
        channel=request.channel.value,
    )

    return AnalyzeResponse(
        case_id=result.case_id,
        score=result.score,
        level=RiskLevel(result.level),
        action=ActionType(result.action),
        signals=signals,
        urls=urls,
        model_version=result.model_version,
        latency_ms=latency_ms,
    )


@app.get(
    "/v1/cases",
    response_model=CaseListResponse,
    responses={401: {"model": ErrorResponse}},
)
async def list_cases(
    q: Optional[str] = Query(None),
    level: Optional[RiskLevel] = Query(None),
    channel: Optional[ChannelType] = Query(None),
    from_date: Optional[datetime] = Query(None, alias="from"),
    to_date: Optional[datetime] = Query(None, alias="to"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Case).where(Case.device_id == device.id)

    if level:
        stmt = stmt.where(Case.level == level)
    if channel:
        stmt = stmt.where(Case.channel == channel)
    if from_date:
        stmt = stmt.where(Case.created_at >= from_date)
    if to_date:
        stmt = stmt.where(Case.created_at <= to_date)
    if cursor:
        try:
            cursor_dt = datetime.fromisoformat(cursor)
            stmt = stmt.where(Case.created_at < cursor_dt)
        except ValueError:
            pass

    stmt = stmt.order_by(desc(Case.created_at)).limit(limit + 1)
    result = await session.execute(stmt)
    cases = result.scalars().all()

    next_cursor = None
    if len(cases) > limit:
        next_cursor = cases[limit - 1].created_at.isoformat()
        cases = cases[:limit]

    return CaseListResponse(
        cases=[
            CaseSummary(
                case_id=c.id,
                score=c.score,
                level=c.level,
                action=c.action,
                channel=c.channel,
                created_at=c.created_at,
                sender=c.sender,
                url_count=len(c.urls),
            )
            for c in cases
        ],
        next_cursor=next_cursor,
    )


@app.get(
    "/v1/cases/{case_id}",
    response_model=CaseDetail,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_case(
    case_id: UUID,
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Case).where(Case.id == case_id, Case.device_id == device.id)
    result = await session.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return CaseDetail(
        case_id=case.id,
        score=case.score,
        level=case.level,
        action=case.action,
        signals=[Signal(**s) for s in case.signals],
        urls=[URLAnalysis(**u) for u in case.urls],
        model_version=case.model_version,
        latency_ms=case.latency_ms,
        sender=case.sender,
        text=case.text,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


@app.post(
    "/v1/feedback",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
async def submit_feedback(
    request: FeedbackRequest,
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Case).where(Case.id == request.case_id, Case.device_id == device.id)
    result = await session.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    existing = await session.execute(
        select(Feedback).where(Feedback.case_id == request.case_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Feedback already submitted")

    feedback = Feedback(
        case_id=request.case_id,
        verdict=request.verdict,
        notes=request.notes,
    )
    session.add(feedback)
    await session.commit()

    await record_api_usage(device, "/v1/feedback", 200, 1, session)

    log_feedback(device.device_token, str(request.case_id), request.verdict)

    return {"success": True}


@app.post(
    "/v1/report",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
async def report_url(
    request: ReportRequest,
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    url_str = str(request.url)
    domain = url_str.split("://")[-1].split("/")[0] if "://" in url_str else url_str.split("/")[0]

    report = ReportedUrl(
        url=url_str,
        domain=domain,
        note=request.note,
        reporter_device_id=device.id,
    )
    session.add(report)
    await session.commit()

    await record_api_usage(device, "/v1/report", 200, 1, session)

    log_report(device.device_token, str(report.id), url_str)

    return {"success": True, "report_id": str(report.id)}


@app.get(
    "/v1/stats",
    response_model=StatsResponse,
    responses={401: {"model": ErrorResponse}},
)
async def get_stats(
    range: str = Query("30d", pattern="^(7d|30d|90d)$"),
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    days = {"7d": 7, "30d": 30, "90d": 90}[range]
    since = datetime.utcnow() - timedelta(days=days)

    stmt = select(Case).where(Case.device_id == device.id, Case.created_at >= since)
    result = await session.execute(stmt)
    cases = result.scalars().all()

    by_level = {level: 0 for level in RiskLevel}
    by_channel = {channel: 0 for channel in ChannelType}
    total_score = 0
    total_latency = 0

    for case in cases:
        by_level[case.level] += 1
        by_channel[case.channel] += 1
        total_score += case.score
        total_latency += case.latency_ms

    count = len(cases)
    return StatsResponse(
        total_cases=count,
        by_level=by_level,
        by_channel=by_channel,
        avg_score=total_score / count if count else 0,
        avg_latency_ms=total_latency / count if count else 0,
    )


@app.get(
    "/v1/blocklist/delta",
    response_model=BlocklistDeltaResponse,
    responses={400: {"model": ErrorResponse}},
)
async def get_blocklist_delta(
    since: datetime = Query(default=datetime(1970, 1, 1, tzinfo=timezone.utc)),
    session: AsyncSession = Depends(get_session),
):
    # Database timestamps are naive UTC; interpret naive query timestamps as UTC,
    # and convert offset-aware timestamps to the same UTC instant before querying.
    since_utc = (
        since.replace(tzinfo=timezone.utc)
        if since.tzinfo is None
        else since.astimezone(timezone.utc)
    )
    since_db = since_utc.replace(tzinfo=None)
    stmt = select(BlocklistEntry).where(BlocklistEntry.updated_at > since_db)
    result = await session.execute(stmt)
    entries = result.scalars().all()

    additions = [
        {"domain_hash": e.domain_hash, "reason": e.reason, "expires_at": e.expires_at}
        for e in entries
    ]

    removals = []  # Could be implemented with a separate removals table

    log_blocklist_delta(None, since_utc, len(additions), len(removals))

    return BlocklistDeltaResponse(
        additions=additions,
        removals=removals,
        timestamp=datetime.utcnow(),
    )


@app.post(
    "/v1/devices",
    response_model=DeviceRegisterResponse,
    responses={429: {"model": ErrorResponse}},
)
async def register_device(session: AsyncSession = Depends(get_session)):
    token = f"dev_{uuid.uuid4().hex}"
    expires_at = datetime.utcnow() + timedelta(days=settings.device_token_ttl_days)

    device = Device(
        device_token=token,
        expires_at=expires_at,
    )
    session.add(device)
    await session.commit()

    log_auth_event("device_registered", device_id=token)

    return DeviceRegisterResponse(device_token=token, expires_at=expires_at)


@app.delete(
    "/v1/devices/me",
    responses={401: {"model": ErrorResponse}},
)
async def wipe_device(
    device: Device = Depends(get_device),
    session: AsyncSession = Depends(get_session),
):
    """Wipe all data for the current device (GDPR/CCPA compliance)."""
    device_id = device.id
    token = device.device_token

    # Count related records before deletion
    cases_count = await session.execute(select(func.count(Case.id)).where(Case.device_id == device_id))
    cases_deleted = cases_count.scalar() or 0

    feedback_count = await session.execute(
        select(func.count(Feedback.id))
        .join(Case, Feedback.case_id == Case.id)
        .where(Case.device_id == device_id)
    )
    feedback_deleted = feedback_count.scalar() or 0

    # Hard delete device (cascades to cases, signals, urls, url_intel, feedback, reports, api_usage)
    await session.delete(device)
    await session.commit()

    log_device_wipe(token, cases_deleted, feedback_deleted)

    return {
        "success": True,
        "deleted_counts": {
            "cases": cases_deleted,
            "feedback": feedback_deleted,
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "ml": get_analyzer().get_ml_status(),
    }


@app.get("/ready")
async def readiness_check(session: AsyncSession = Depends(get_session)):
    """Readiness probe - checks DB and Redis connectivity."""
    try:
        # Check database
        await session.execute(select(1))
        return {
            "status": "ready",
            "version": "1.0.0",
            "components": {
                "database": "ready",
                "ml": get_analyzer().get_ml_status(),
            },
        }
    except Exception as exc:
        from src.middleware.logging import logger
        logger.error(
            "Guardian readiness check failed",
            exception_type=type(exc).__name__,
        )
        raise HTTPException(status_code=503, detail="Readiness check failed") from exc


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content=ErrorResponse(error=ErrorDetail(code=str(exc.status_code), message=exc.detail)).model_dump(),
    )


# Middleware to capture Prometheus metrics
@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    # Skip metrics for health/metrics endpoints
    if request.url.path in ("/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json"):
        return await call_next(request)

    start_time = time.perf_counter()
    handler = request.url.path

    response = await call_next(request)

    latency = time.perf_counter() - start_time

    # Record metrics
    REQUEST_COUNT.labels(
        method=request.method,
        handler=handler,
        status=response.status_code
    ).inc()

    REQUEST_LATENCY.labels(handler=handler).observe(latency)

    # Track rate limit exceeded
    if response.status_code == 429:
        RATE_LIMIT_EXCEEDED.labels(endpoint=handler).inc()

    return response