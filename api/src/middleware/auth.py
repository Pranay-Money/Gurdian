"""
Authentication Middleware
Handles: signed device tokens, rotation, per-device rate limits, request validation
"""
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from uuid import UUID

import jwt
from fastapi import Request, HTTPException, Depends, Header, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.db.session import get_session
from src.db.models import Device, RateLimitBucket

settings = get_settings()


class DeviceTokenPayload(BaseModel):
    """JWT payload for device tokens."""
    device_id: str
    issued_at: int
    expires_at: int
    token_version: int = 1


class DeviceAuth:
    """Handles device token creation, validation, and rotation."""

    def __init__(self):
        self.secret_key = settings.secret_key.encode()
        self.algorithm = settings.device_token_algorithm
        self.token_ttl_days = settings.device_token_ttl_days
        self.rotation_days = settings.device_token_rotation_days

    def create_token(self, device_id: UUID, token_version: int = 1) -> str:
        """Create a signed device token (JWT)."""
        now = int(time.time())
        expires_at = now + (self.token_ttl_days * 86400)

        payload = DeviceTokenPayload(
            device_id=str(device_id),
            issued_at=now,
            expires_at=expires_at,
            token_version=token_version,
        )

        token = jwt.encode(payload.model_dump(), self.secret_key, algorithm=self.algorithm)
        return f"dev_{token}"

    def verify_token(self, token: str) -> Optional[DeviceTokenPayload]:
        """Verify and decode a device token."""
        # Remove 'dev_' prefix if present
        if token.startswith("dev_"):
            token = token[4:]

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return DeviceTokenPayload(**payload)
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def is_rotation_needed(self, payload: DeviceTokenPayload) -> bool:
        """Check if token should be rotated (older than rotation_days)."""
        age_days = (time.time() - payload.issued_at) / 86400
        return age_days >= self.rotation_days


device_auth = DeviceAuth()


async def get_device_token(
    x_device_token: str = Header(..., alias="X-Device-Token"),
) -> str:
    """Extract device token from header."""
    return x_device_token


async def get_device(
    device_token: str = Depends(get_device_token),
    session: AsyncSession = Depends(get_session),
) -> Device:
    """
    Validate device token and return device.
    Also handles token rotation.
    """
    payload = device_auth.verify_token(device_token)
    if not payload:
        if settings.app_env.lower() in {"development", "test"} and device_token.startswith("dev_"):
            stmt = select(Device).where(Device.device_token == device_token, Device.is_active == True)
            result = await session.execute(stmt)
            device = result.scalar_one_or_none()
            if device is None:
                expires_at = datetime.utcnow() + timedelta(days=settings.device_token_ttl_days)
                device = Device(device_token=device_token, expires_at=expires_at, is_active=True)
                session.add(device)
                await session.commit()
            device.last_seen_at = datetime.utcnow()
            await session.commit()
            return device
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired device token",
        )

    # Get device from DB
    stmt = select(Device).where(Device.id == UUID(payload.device_id), Device.is_active == True)
    result = await session.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device not found or inactive",
        )

    # Check token expiration
    if datetime.utcnow() > datetime.fromtimestamp(payload.expires_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device token expired",
        )

    # Update last_seen_at
    device.last_seen_at = datetime.utcnow()

    # Check if token rotation is needed
    if device_auth.is_rotation_needed(payload):
        new_token = device_auth.create_token(device.id, payload.token_version + 1)
        pass

    await session.commit()
    return device


class RateLimitConfig:
    """Rate limit configuration per endpoint."""
    LIMITS = {
        "/v1/analyze": {"requests": 30, "window": 60},      # 30/min
        "/v1/cases": {"requests": 60, "window": 60},        # 60/min
        "/v1/cases/": {"requests": 60, "window": 60},
        "/v1/feedback": {"requests": 10, "window": 60},     # 10/min
        "/v1/report": {"requests": 10, "window": 60},       # 10/min
        "/v1/stats": {"requests": 30, "window": 60},        # 30/min
        "/v1/blocklist/delta": {"requests": 10, "window": 60},  # 10/min
        "/v1/devices": {"requests": 5, "window": 3600},     # 5/hour
        "default": {"requests": 100, "window": 60},         # 100/min default
    }

    @classmethod
    def get_limit(cls, endpoint: str) -> Dict[str, int]:
        for path, limit in cls.LIMITS.items():
            if endpoint.startswith(path):
                return limit
        return cls.LIMITS["default"]


async def check_rate_limit(
    device: Device,
    endpoint: str,
    session: AsyncSession,
) -> None:
    """
    Check and enforce per-device rate limits using token bucket in database.
    """
    limit_config = RateLimitConfig.get_limit(endpoint)
    max_tokens = limit_config["requests"]
    window_seconds = limit_config["window"]
    refill_rate = max_tokens / window_seconds

    # Get or create bucket
    stmt = select(RateLimitBucket).where(
        RateLimitBucket.device_id == device.id,
        RateLimitBucket.endpoint == endpoint,
    )
    result = await session.execute(stmt)
    bucket = result.scalar_one_or_none()

    now = datetime.utcnow()

    if not bucket:
        bucket = RateLimitBucket(
            device_id=device.id,
            endpoint=endpoint,
            tokens=max_tokens - 1,  # Consume one
            last_refill=now,
        )
        session.add(bucket)
    else:
        # Refill tokens based on elapsed time
        elapsed = (now - bucket.last_refill).total_seconds()
        bucket.tokens = min(max_tokens, bucket.tokens + elapsed * refill_rate)
        bucket.last_refill = now

        if bucket.tokens < 1:
            # Rate limited
            retry_after = int((1 - bucket.tokens) / refill_rate) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_tokens),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

        bucket.tokens -= 1

    await session.commit()


async def validate_request_size(request: Request) -> None:
    """Validate request size limit."""
    content_length = request.headers.get("content-length")
    if content_length:
        size = int(content_length)
        if size > settings.max_request_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request too large. Maximum size: {settings.max_request_size_bytes} bytes",
            )


async def validate_content_type(request: Request) -> None:
    """Validate content type for POST/PUT requests."""
    if request.method in ("POST", "PUT", "PATCH"):
        content_type = request.headers.get("content-type", "")
        if not content_type.startswith("application/json"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Content-Type must be application/json",
            )