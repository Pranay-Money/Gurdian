# Guardian API Specification

## Overview
A production-ready phishing, scam, and malicious URL detection API with threat intelligence integration, privacy controls, and blocklist distribution.

---

## 1. Threat Intelligence Adapters (`api/src/intel/`)

### Adapters Required
| Adapter | Source | Protocol | Key Features |
|---------|--------|----------|--------------|
| Google Safe Browsing | Google | v4 Lookup API | URL/hash-based, batch support |
| VirusTotal | VirusTotal | v3 API | URL/domain/file reputation |
| OpenPhish | OpenPhish | Local feed (JSON) | Phishing URLs, hourly updates |
| PhishTank | PhishTank | Local feed (CSV/JSON) | Community-verified phishing |
| RDAP Domain Age | RDAP | Bootstrap + direct | Domain registration date |
| DNS Analysis | System DNS | A/AAAA/NS/MX/TXT | Subdomain enumeration, records |
| TLS Certificate | System TLS | Certificate chain | Cert age, SANs, issuer, validity |

### Common Adapter Interface
```python
class IntelAdapter(ABC):
    name: str
    async def check(self, indicator: Indicator) -> IntelResult
    async def health_check() -> bool
```

### Cross-Cutting Concerns (per adapter)
- **Timeout**: Configurable per adapter (default: 5s)
- **Circuit Breaker**: 5 failures → open for 60s, half-open probe
- **Redis Cache**: TTL by verdict (malicious: 24h, suspicious: 6h, clean: 1h, unknown: 5m)
- **Rate Limit Budget**: Token bucket per adapter (configurable RPM)
- **Fail-Open**: On any error, return `IntelResult(verdict=UNKNOWN, note="intel_unavailable")`
- **Keys from Env Only**: No hardcoded secrets; loaded via `Settings`

### Intel Result Schema
```python
class IntelResult:
    source: IntelSource
    indicator: str
    verdict: IntelVerdict  # CLEAN, MALICIOUS, SUSPICIOUS, UNKNOWN
    confidence: float  # 0.0-1.0
    details: Dict[str, Any]
    note: Optional[str]  # e.g., "intel_unavailable"
    cached: bool
    latency_ms: int
```

---

## 2. Database Schema & Migrations

### Tables
| Table | Purpose |
|-------|---------|
| `devices` | Anonymous device registration |
| `cases` | Analysis cases (per request) |
| `signals` | Normalized signals per case (1:N) |
| `urls` | Normalized URLs per case (1:N) |
| `url_intel` | Intel results per URL (1:N per source) |
| `feedback` | User feedback on cases |
| `reports` | User-reported URLs |
| `blocklist_entries` | Merged blocklist domains |
| `stats_daily` | Pre-aggregated daily stats |
| `api_usage` | Request logging for rate limits |
| `rate_limit_buckets` | Per-device rate limit state |

### Key Indexes
- `cases`: `(device_id, created_at)`, `(level, created_at)`, `(sender)`, GIN on `tsv` (full-text)
- `urls`: `(case_id)`, `(registrable_domain)`, `(created_at)`
- `signals`: `(case_id)`, `(category, label)`
- `blocklist_entries`: `(domain)` unique, `(expires_at)`
- `stats_daily`: `(date)` unique

### Full-Text Search
```sql
ALTER TABLE cases ADD COLUMN tsv tsvector
    GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(text, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(sender, '')), 'B') ||
        setweight(to_tsvector('simple', coalesce(domains_text, '')), 'C') ||
        setweight(to_tsvector('simple', coalesce(signal_labels_text, '')), 'D')
    ) STORED;

CREATE INDEX ix_cases_fts ON cases USING GIN (tsv);
```

### Alembic
- Initial migration creates all tables + indexes + FTS trigger
- Subsequent migrations versioned separately

---

## 3. API Endpoints

### `/v1/cases` - Cursor Pagination + Filters + Search
```
GET /v1/cases?q=&level=&channel=&from=&to=&cursor=&limit=20
```
- `q`: Full-text search over text, sender, domains, signal labels
- `level`: RiskLevel filter
- `channel`: ChannelType filter
- `from`/`to`: Date range (ISO8601)
- `cursor`: ISO8601 timestamp for pagination (exclusive, descending)
- `limit`: 1-100 (default 20)

**Response**: `CaseListResponse` with `cases[]` and `next_cursor`

### `/v1/cases/{id}` - Case Detail
```
GET /v1/cases/{uuid}
```
Returns full case with signals, URLs, intel results, explanation.

### `/v1/feedback` - Submit Feedback
```
POST /v1/feedback { case_id, verdict, notes? }
```
- One feedback per case (unique constraint)
- Verdict: `false_positive`, `false_negative`, `correct`

### `/v1/report` - Report Suspicious URL
```
POST /v1/report { url, note? }
```
- Stores in `reported_urls` for review pipeline
- Returns `report_id`

### `/v1/stats` - Analytics Dashboard
```
GET /v1/stats?range=30d
```
**Response** (`StatsResponse`):
- `total_cases`: int
- `by_level`: Dict[RiskLevel, int]
- `by_channel`: Dict[ChannelType, int]
- `top_signals`: List[{label, count, category}]
- `top_domains`: List[{domain, count, max_level}]
- `daily_trend`: List[{date, count, avg_score}]
- `avg_score`: float
- `avg_latency_ms`: float

### `/v1/blocklist/delta` - Extension Blocklist Sync
```
GET /v1/blocklist/delta?since=ISO8601
```
**Response** (`BlocklistDeltaResponse`):
- `additions`: List[{domain_hash, reason, expires_at}]
- `removals`: List[domain_hash]
- `timestamp`: ISO8601
- `version`: int (monotonic)

---

## 4. Authentication & Security

### Device Token (Anonymous, Signed, Rotating)
- **Format**: `dev_{base64url(payload)}.{base64url(signature)}`
- **Payload**: `{device_id, iat, exp, rotation_counter}`
- **Signature**: HMAC-SHA256 with `SECRET_KEY`
- **Rotation**: On each request, issue new token in `X-Device-Token-New` header; old valid for 5 min grace
- **TTL**: Configurable (default 365 days)
- **Revocation**: Soft delete (`is_active=false`)

### Rate Limiting
- **Per-device**: Token bucket (configurable: default 100 req/min)
- **Per-endpoint**: Stricter limits on `/v1/analyze` (default 30 req/min)
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **Storage**: Redis sorted sets (sliding window)

### Request Size Limits
- Global: 1 MB (configurable)
- `/v1/analyze`: Text max 50KB, URLs max 20

### CORS
- Restricted to extension origin(s) from env `CORS_ORIGINS` (comma-separated)
- No wildcard in production

### Input Validation
- Pydantic v2 strict mode
- Sanitize text inputs (strip control chars)
- Validate URL schemes (http/https only)
- Reject oversized payloads early

### Structured JSON Logging
- Use `structlog` with processors:
  - `add_log_level`, `TimeStamper(fmt="iso")`, `JSONRenderer()`
- **Never log**: request bodies, tokens, API keys, PII
- Log: `request_id`, `device_id`, `endpoint`, `status`, `latency_ms`, `error_code`

---

## 5. Privacy Controls

### Data Retention
- **Setting**: `RETENTION_DAYS` (default 30)
- **Job**: Daily cron deletes cases older than retention
- **Cascade**: Deletes signals, urls, url_intel, feedback

### Device Wipe Endpoint
```
DELETE /v1/devices/me
```
- Requires valid device token
- Hard deletes: device, cases, signals, urls, url_intel, feedback, reports, api_usage
- Returns `{success: true, deleted_counts: {...}}`

### Text Storage Opt-In
- **Device setting**: `store_raw_text` (default: false)
- When **false**: Store SHA-256 hash of text + signals only
- When **true**: Store full text (for debugging/ML)
- **Schema**: `cases.text_hash` (CHAR(64)), `cases.text` (nullable)

---

## 6. Blocklist Generation Job

### Scheduled Task
- **Interval**: Configurable (default 5 min)
- **Sources**: All intel adapters + reported URLs + feedback-confirmed
- **Merge Strategy**: 
  1. Collect domains with MALICIOUS verdict from any source
  2. Deduplicate by registrable domain
  3. Assign reason: most severe source
  4. Set expiry: max 30 days from detection
- **Output Format**: Compact delta for extension
  - Domain hash: `sha256(domain)[:16]` (16 hex chars)
  - Version: monotonically increasing integer
  - Delta: additions + removals since last version

### Blocklist Delta Format (Extension)
```json
{
  "version": 12345,
  "timestamp": "2026-10-14T12:00:00Z",
  "additions": [{"h": "a1b2c3d4e5f67890", "r": "phishing", "exp": "2026-11-13T12:00:00Z"}],
  "removals": ["f0e1d2c3b4a59678"]
}
```

---

## 7. Acceptance Criteria

| Test | Target |
|------|--------|
| Integration tests with mocked intel adapters | All pass |
| Search on 1k seeded cases | <150ms p95 |
| DELETE /v1/devices/me wipes all data | Verified |
| No secrets in logs | Verified (grep for keys) |
| Rate limiting enforced | 429 on exceed |
| Token rotation works | New token issued, old valid 5min |
| Blocklist delta correct | Version increments, hashes match |
| Retention job deletes old data | Verified |
| Opt-in text storage works | Hash stored when off, text when on |

---

## 8. File Structure (New/Additions)

```
api/src/
├── intel/
│   ├── __init__.py
│   ├── base.py              # Abstract base, circuit breaker, cache, rate limit
│   ├── google_safe_browsing.py
│   ├── virustotal.py
│   ├── openphish.py
│   ├── phishtank.py
│   ├── rdap.py
│   ├── dns.py
│   ├── tls.py
│   ├── registry.py          # Adapter registry & orchestration
│   └── models.py            # IntelResult, Indicator types
├── auth/
│   ├── __init__.py
│   ├── tokens.py            # JWT/HMAC token creation/validation/rotation
│   ├── rate_limit.py        # Redis token bucket
│   └── middleware.py        # Auth, rate limit, size limit, CORS, logging
├── jobs/
│   ├── __init__.py
│   ├── blocklist.py         # Blocklist generation job
│   ├── retention.py         # Data retention cleanup
│   └── scheduler.py         # APScheduler setup
├── db/
│   ├── models.py            # Extended models
│   └── migrations/          # Alembic env + versions
├── schemas/
│   └── __init__.py          # Extended schemas
├── services/
│   ├── __init__.py
│   ├── analyzer.py          # Updated to use intel adapters
│   ├── blocklist.py         # Blocklist service
│   └── privacy.py           # Wipe, retention, opt-in
└── main.py                  # Updated with all endpoints + middleware
```

---

## 9. Configuration (Environment Variables)

```bash
# Application
APP_ENV=production
DEBUG=false
LOG_LEVEL=INFO
SECRET_KEY=<strong-random-64-chars>
CORS_ORIGINS=chrome-extension://abc123,https://myapp.com

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_CACHE_TTL=3600

# Device Tokens
DEVICE_TOKEN_TTL_DAYS=365
DEVICE_TOKEN_ROTATION_GRACE_SECONDS=300

# Rate Limits
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
ANALYZE_RATE_LIMIT=30

# Intel API Keys (optional - adapters degrade gracefully)
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
PHISHTANK_API_KEY=
URLHAUS_API_KEY=

# Intel Adapter Config (per adapter)
GSB_TIMEOUT=5
GSB_RATE_LIMIT=10000
VT_TIMEOUT=10
VT_RATE_LIMIT=500
OP_TIMEOUT=30
OP_RATE_LIMIT=10
PT_TIMEOUT=30
PT_RATE_LIMIT=10
RDAP_TIMEOUT=5
RDAP_RATE_LIMIT=100
DNS_TIMEOUT=3
DNS_RATE_LIMIT=200
TLS_TIMEOUT=5
TLS_RATE_LIMIT=100

# Cache TTL by Verdict (seconds)
CACHE_TTL_MALICIOUS=86400
CACHE_TTL_SUSPICIOUS=21600
CACHE_TTL_CLEAN=3600
CACHE_TTL_UNKNOWN=300

# Privacy
RETENTION_DAYS=30
DEFAULT_STORE_RAW_TEXT=false

# Blocklist
BLOCKLIST_SYNC_INTERVAL_SECONDS=300
BLOCKLIST_MAX_AGE_DAYS=30
BLOCKLIST_VERSION_KEY=blocklist:version
```

---

## 10. Implementation Priority

1. **Database Models + Migrations** - Foundation
2. **Auth Middleware (tokens, rate limit, logging)** - Security baseline
3. **Intel Adapters** - Core detection capability
4. **Analyzer Integration** - Wire intel into analysis
5. **API Endpoints** - All required endpoints
5. **Privacy Controls** - Wipe, retention, opt-in
6. **Blocklist Job** - Scheduled generation
7. **Tests** - Integration + performance