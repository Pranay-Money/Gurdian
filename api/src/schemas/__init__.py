from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl, UrlConstraints, field_validator

MAX_ANALYZE_URL_LENGTH = 2048
AnalyzeURL = Annotated[HttpUrl, UrlConstraints(max_length=MAX_ANALYZE_URL_LENGTH)]


class ChannelType(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    SOCIAL = "social"
    URL = "url"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ActionType(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class SignalCategory(str, Enum):
    LINGUISTIC = "linguistic"
    STRUCTURAL = "structural"
    REPUTATION = "reputation"
    BEHAVIORAL = "behavioral"
    METADATA = "metadata"
    IMPERSONATION = "impersonation"
    SENSITIVE_REQUEST = "sensitive_request"


class VerdictType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT = "correct"


class IntelSource(str, Enum):
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"
    PHISHTANK = "phishtank"


class IntelVerdict(str, Enum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class EvidenceItem(BaseModel):
    type: str
    value: str
    description: str


class Signal(BaseModel):
    key: str
    category: SignalCategory
    label: str
    points: int
    reason: str
    evidence: List[EvidenceItem] = []


class URLAnalysis(BaseModel):
    url: HttpUrl
    host: str
    registrable_domain: str
    tld: str
    https: bool
    subdomains: List[str] = []
    length: int
    age_days: Optional[int] = None
    redirects: List[HttpUrl] = []
    intel: Optional[Dict[IntelSource, Dict[str, Any]]] = None


class AnalyzeRequest(BaseModel):
    channel: ChannelType
    sender: Optional[str] = Field(None, max_length=256)
    text: Optional[str] = Field(None, max_length=50000)
    urls: List[AnalyzeURL] = []
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("options")
    @classmethod
    def validate_options(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if "deep" in v and not isinstance(v["deep"], bool):
            raise ValueError("options.deep must be boolean")
        return v


class AnalyzeResponse(BaseModel):
    case_id: UUID
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    action: ActionType
    signals: List[Signal]
    urls: List[URLAnalysis]
    model_version: str
    latency_ms: int


class CaseSummary(BaseModel):
    case_id: UUID
    score: int
    level: RiskLevel
    action: ActionType
    channel: ChannelType
    created_at: datetime
    sender: Optional[str] = None
    url_count: int


class CaseListResponse(BaseModel):
    cases: List[CaseSummary]
    next_cursor: Optional[str] = None


class CaseDetail(AnalyzeResponse):
    sender: Optional[str] = None
    text: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class FeedbackRequest(BaseModel):
    case_id: UUID
    verdict: VerdictType
    notes: Optional[str] = Field(None, max_length=1000)


class ReportRequest(BaseModel):
    url: HttpUrl
    note: Optional[str] = Field(None, max_length=2000)


class StatsResponse(BaseModel):
    total_cases: int
    by_level: Dict[RiskLevel, int]
    by_channel: Dict[ChannelType, int]
    avg_score: float
    avg_latency_ms: float


class BlocklistEntry(BaseModel):
    domain_hash: str
    reason: str
    expires_at: datetime


class BlocklistDeltaResponse(BaseModel):
    additions: List[BlocklistEntry]
    removals: List[str]
    timestamp: datetime


class DeviceRegisterResponse(BaseModel):
    device_token: str
    expires_at: datetime


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail