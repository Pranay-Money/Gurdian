"""
Base classes for Threat Intelligence Adapters
"""
import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, List
import logging

import redis.asyncio as redis
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class IntelVerdict(str, Enum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class IntelSource(str, Enum):
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    VIRUSTOTAL = "virustotal"
    OPENPHISH = "openphish"
    PHISHTANK = "phishtank"
    RDAP = "rdap"
    DNS = "dns"
    TLS = "tls"


@dataclass
class IntelResult:
    """Result from an intel adapter check."""
    source: IntelSource
    verdict: IntelVerdict
    confidence: int  # 0-100
    details: Dict[str, Any] = field(default_factory=dict)
    note: Optional[str] = None
    latency_ms: int = 0
    cached: bool = False
    checked_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "details": self.details,
            "note": self.note,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
            "checked_at": self.checked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for external API calls.
    Prevents cascade failures when an external service is down.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if self._last_failure_time and \
               time.time() - self._last_failure_time > self.recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state

    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        async with self._lock:
            if self.state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is OPEN")

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except self.expected_exception as e:
            await self._on_failure()
            raise

    async def _on_success(self):
        async with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    async def _on_failure(self):
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit breaker {self.name} OPENED after {self._failure_count} failures")

    def reset(self):
        """Manually reset the circuit breaker."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._last_failure_time = None


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


class RateLimiter:
    """
    Token bucket rate limiter with Redis backend for distributed rate limiting.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        key_prefix: str = "ratelimit",
        max_tokens: int = 100,
        refill_rate: float = 1.0,  # tokens per second
    ):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate

    async def acquire(self, key: str, tokens: int = 1) -> bool:
        """
        Try to acquire tokens. Returns True if successful, False if rate limited.
        """
        redis_key = f"{self.key_prefix}:{key}"
        now = time.time()

        # Lua script for atomic token bucket
        script = """
        local key = KEYS[1]
        local max_tokens = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local tokens_requested = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])

        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])

        if tokens == nil then
            tokens = max_tokens
            last_refill = now
        end

        -- Refill tokens
        local elapsed = now - last_refill
        tokens = math.min(max_tokens, tokens + elapsed * refill_rate)

        local allowed = 0
        if tokens >= tokens_requested then
            tokens = tokens - tokens_requested
            allowed = 1
        end

        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, math.ceil(max_tokens / refill_rate) + 60)

        return {allowed, tokens}
        """

        result = await self.redis.eval(
            script,
            1,
            redis_key,
            self.max_tokens,
            self.refill_rate,
            tokens,
            now,
        )

        return bool(result[0])

    async def get_remaining(self, key: str) -> int:
        """Get remaining tokens for a key."""
        redis_key = f"{self.key_prefix}:{key}"
        bucket = await self.redis.hmget(redis_key, "tokens", "last_refill")
        if not bucket[0]:
            return self.max_tokens

        tokens = float(bucket[0])
        last_refill = float(bucket[1])
        elapsed = time.time() - last_refill
        tokens = min(self.max_tokens, tokens + elapsed * self.refill_rate)
        return int(tokens)


class CacheConfig(BaseModel):
    """Configuration for caching behavior based on verdict."""
    clean_ttl: int = 86400 * 7      # 7 days for clean
    suspicious_ttl: int = 86400 * 1  # 1 day for suspicious
    malicious_ttl: int = 86400 * 30  # 30 days for malicious
    unknown_ttl: int = 3600          # 1 hour for unknown
    error_ttl: int = 300             # 5 minutes for errors


class IntelAdapter(ABC):
    """
    Base class for all threat intelligence adapters.
    Provides: timeout, circuit breaker, Redis cache, rate limiting, fail-open.
    """

    def __init__(
        self,
        source: IntelSource,
        redis_client: redis.Redis,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        cache_config: Optional[CacheConfig] = None,
        rate_limit: Optional[int] = None,  # requests per minute
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 60,
    ):
        self.source = source
        self.redis = redis_client
        self.api_key = api_key
        self.timeout = timeout
        self.cache_config = cache_config or CacheConfig()
        self.circuit_breaker = CircuitBreaker(
            name=source.value,
            failure_threshold=circuit_breaker_threshold,
            recovery_timeout=circuit_breaker_timeout,
        )
        self.rate_limiter = None
        if rate_limit:
            self.rate_limiter = RateLimiter(
                redis_client=redis_client,
                key_prefix=f"ratelimit:{source.value}",
                max_tokens=rate_limit,
                refill_rate=rate_limit / 60.0,
            )

    @abstractmethod
    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Implementation-specific check logic. Must be implemented by subclasses."""
        pass

    def _get_cache_key(self, indicator: str, indicator_type: str) -> str:
        """Generate cache key for an indicator."""
        content = f"{self.source.value}:{indicator_type}:{indicator}"
        return f"intel:cache:{hashlib.sha256(content.encode()).hexdigest()[:32]}"

    def _get_ttl_for_verdict(self, verdict: IntelVerdict) -> int:
        """Get TTL based on verdict."""
        mapping = {
            IntelVerdict.CLEAN: self.cache_config.clean_ttl,
            IntelVerdict.SUSPICIOUS: self.cache_config.suspicious_ttl,
            IntelVerdict.MALICIOUS: self.cache_config.malicious_ttl,
            IntelVerdict.UNKNOWN: self.cache_config.unknown_ttl,
        }
        return mapping.get(verdict, self.cache_config.unknown_ttl)

    async def check(self, indicator: str, indicator_type: str = "url") -> IntelResult:
        """
        Main entry point for checking an indicator.
        Handles: cache, rate limiting, circuit breaker, timeout, fail-open.
        """
        start_time = time.perf_counter()

        # Check cache first
        cache_key = self._get_cache_key(indicator, indicator_type)
        cached = await self._get_cached(cache_key)
        if cached:
            cached.cached = True
            cached.latency_ms = int((time.perf_counter() - start_time) * 1000)
            return cached

        # Check rate limit
        if self.rate_limiter:
            allowed = await self.rate_limiter.acquire(f"{indicator_type}:{indicator}")
            if not allowed:
                return self._fail_open(
                    indicator, indicator_type,
                    "Rate limit exceeded",
                    int((time.perf_counter() - start_time) * 1000)
                )

        # Execute with circuit breaker and timeout
        try:
            result = await asyncio.wait_for(
                self.circuit_breaker.call(self._check_impl, indicator, indicator_type),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"{self.source.value}: Timeout checking {indicator_type}:{indicator}")
            return self._fail_open(
                indicator, indicator_type,
                "Request timeout",
                int((time.perf_counter() - start_time) * 1000)
            )
        except CircuitBreakerOpenError:
            logger.warning(f"{self.source.value}: Circuit breaker open for {indicator_type}:{indicator}")
            return self._fail_open(
                indicator, indicator_type,
                "Circuit breaker open",
                int((time.perf_counter() - start_time) * 1000)
            )
        except Exception as e:
            logger.error(f"{self.source.value}: Error checking {indicator_type}:{indicator}: {e}")
            return self._fail_open(
                indicator, indicator_type,
                f"Error: {type(e).__name__}",
                int((time.perf_counter() - start_time) * 1000)
            )

        # Cache the result
        ttl = self._get_ttl_for_verdict(result.verdict)
        await self._set_cached(cache_key, result, ttl)

        result.latency_ms = int((time.perf_counter() - start_time) * 1000)
        return result

    def _fail_open(
        self,
        indicator: str,
        indicator_type: str,
        note: str,
        latency_ms: int,
    ) -> IntelResult:
        """Fail-open: return UNKNOWN with intel_unavailable note."""
        return IntelResult(
            source=self.source,
            verdict=IntelVerdict.UNKNOWN,
            confidence=0,
            details={},
            note=f"intel_unavailable: {note}",
            latency_ms=latency_ms,
            checked_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=self.cache_config.error_ttl),
        )

    async def _get_cached(self, cache_key: str) -> Optional[IntelResult]:
        """Get cached result from Redis."""
        try:
            data = await self.redis.get(cache_key)
            if data:
                parsed = json.loads(data)
                # Reconstruct IntelResult
                return IntelResult(
                    source=IntelSource(parsed["source"]),
                    verdict=IntelVerdict(parsed["verdict"]),
                    confidence=parsed["confidence"],
                    details=parsed["details"],
                    note=parsed.get("note"),
                    latency_ms=parsed.get("latency_ms", 0),
                    cached=True,
                    checked_at=datetime.fromisoformat(parsed["checked_at"]),
                    expires_at=datetime.fromisoformat(parsed["expires_at"]) if parsed.get("expires_at") else None,
                )
        except Exception as e:
            logger.debug(f"Cache read error for {cache_key}: {e}")
        return None

    async def _set_cached(self, cache_key: str, result: IntelResult, ttl: int):
        """Cache result in Redis."""
        try:
            data = result.to_dict()
            await self.redis.setex(cache_key, ttl, json.dumps(data, default=str))
        except Exception as e:
            logger.debug(f"Cache write error for {cache_key}: {e}")

    async def close(self):
        """Cleanup resources."""
        pass


class BatchIntelAdapter(IntelAdapter):
    """Base class for adapters that support batch checking."""

    @abstractmethod
    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Implementation-specific batch check logic."""
        pass

    async def check_batch(self, indicators: List[str], indicator_type: str = "url") -> List[IntelResult]:
        """Check multiple indicators, using cache for each."""
        results = []
        uncached_indicators = []
        uncached_indices = []

        # Check cache for all
        for i, indicator in enumerate(indicators):
            cache_key = self._get_cache_key(indicator, indicator_type)
            cached = await self._get_cached(cache_key)
            if cached:
                cached.cached = True
                results.append((i, cached))
            else:
                uncached_indicators.append(indicator)
                uncached_indices.append(i)

        # Batch check uncached
        if uncached_indicators:
            try:
                batch_results = await asyncio.wait_for(
                    self.circuit_breaker.call(self._check_batch_impl, uncached_indicators, indicator_type),
                    timeout=self.timeout * len(uncached_indicators),
                )
                # Cache results
                for indicator, result in zip(uncached_indicators, batch_results):
                    ttl = self._get_ttl_for_verdict(result.verdict)
                    cache_key = self._get_cache_key(indicator, indicator_type)
                    await self._set_cached(cache_key, result, ttl)
                # Add to results
                for idx, result in zip(uncached_indices, batch_results):
                    results.append((idx, result))
            except Exception as e:
                logger.error(f"{self.source.value}: Batch check failed: {e}")
                # Fail open for all uncached
                for idx, indicator in zip(uncached_indices, uncached_indicators):
                    results.append((idx, self._fail_open(indicator, indicator_type, f"Batch error: {type(e).__name__}", 0)))

        # Sort by original index
        results.sort(key=lambda x: x[0])
        return [r for _, r in results]