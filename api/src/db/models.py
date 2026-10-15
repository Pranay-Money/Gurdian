import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Column, String, Integer, DateTime, Enum, ForeignKey, Index, Text, JSON, Boolean, BigInteger
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, TSVECTOR
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class RiskLevel(PyEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ActionType(PyEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ChannelType(PyEnum):
    EMAIL = "email"
    SMS = "sms"
    SOCIAL = "social"
    URL = "url"


class VerdictType(PyEnum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT = "correct"


class SignalCategory(PyEnum):
    LINGUISTIC = "linguistic"
    STRUCTURAL = "structural"
    REPUTATION = "reputation"
    BEHAVIORAL = "behavioral"
    METADATA = "metadata"


class IntelSource(PyEnum):
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    VIRUSTOTAL = "virustotal"
    OPENPHISH = "openphish"
    PHISHTANK = "phishtank"
    RDAP = "rdap"
    DNS = "dns"
    TLS = "tls"


class IntelVerdict(PyEnum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_token = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    store_raw_text = Column(Boolean, default=False, nullable=False)

    cases = relationship("Case", back_populates="device", lazy="dynamic")


class Case(Base):
    __tablename__ = "cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    channel = Column(Enum(ChannelType), nullable=False, index=True)
    sender = Column(String(255), nullable=True, index=True)
    text = Column(Text, nullable=True)
    text_hash = Column(String(64), nullable=True, index=True)
    score = Column(Integer, nullable=False)
    level = Column(Enum(RiskLevel), nullable=False, index=True)
    action = Column(Enum(ActionType), nullable=False)
    model_version = Column(String(50), nullable=False)
    latency_ms = Column(Integer, nullable=False)
    signals = Column(JSONB, nullable=False, default=list)
    urls = Column(JSONB, nullable=False, default=list)
    domains_text = Column(Text, nullable=True)
    signal_labels_text = Column(Text, nullable=True)
    tsv = Column(TSVECTOR, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="cases")
    feedback = relationship("Feedback", back_populates="case", uselist=False)
    signals_rel = relationship("Signal", back_populates="case", cascade="all, delete-orphan")
    urls_rel = relationship("Url", back_populates="case", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_cases_device_created", "device_id", "created_at"),
        Index("ix_cases_level_created", "level", "created_at"),
        Index("ix_cases_sender", "sender"),
        Index("ix_cases_text_hash", "text_hash"),
        Index("ix_cases_tsv", "tsv", postgresql_using="gin"),
    )


class Signal(Base):
    __tablename__ = "signals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    key = Column(String(100), nullable=False)
    category = Column(Enum(SignalCategory), nullable=False, index=True)
    label = Column(String(200), nullable=False)
    points = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    evidence = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="signals_rel")

    __table_args__ = (
        Index("ix_signals_case_category", "case_id", "category"),
        Index("ix_signals_label", "label"),
    )


class Url(Base):
    __tablename__ = "urls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=False, index=True)
    registrable_domain = Column(String(255), nullable=False, index=True)
    tld = Column(String(50), nullable=False)
    scheme = Column(String(10), nullable=False)
    subdomains = Column(JSONB, nullable=False, default=list)
    length = Column(Integer, nullable=False)
    age_days = Column(Integer, nullable=True)
    redirects = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="urls_rel")
    intel_results = relationship("UrlIntel", back_populates="url", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_urls_case_created", "case_id", "created_at"),
        Index("ix_urls_registrable_domain", "registrable_domain"),
    )


class UrlIntel(Base):
    __tablename__ = "url_intel"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url_id = Column(UUID(as_uuid=True), ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(Enum(IntelSource), nullable=False, index=True)
    verdict = Column(Enum(IntelVerdict), nullable=False, index=True)
    confidence = Column(Integer, nullable=False)
    details = Column(JSONB, nullable=False, default=dict)
    note = Column(String(255), nullable=True)
    cached = Column(Boolean, default=False, nullable=False)
    latency_ms = Column(Integer, nullable=False)
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)

    url = relationship("Url", back_populates="intel_results")

    __table_args__ = (
        Index("ix_url_intel_url_source", "url_id", "source", unique=True),
        Index("ix_url_intel_expires", "expires_at"),
    )


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"), unique=True, nullable=False)
    verdict = Column(Enum(VerdictType), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="feedback")


class ReportedUrl(Base):
    __tablename__ = "reported_urls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    note = Column(Text, nullable=True)
    reporter_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=True)
    status = Column(String(50), default="pending", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    reviewed_at = Column(DateTime, nullable=True)


class BlocklistEntry(Base):
    __tablename__ = "blocklist"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    domain_hash = Column(String(16), unique=True, nullable=False, index=True)
    reason = Column(String(50), nullable=False)
    source = Column(String(50), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_blocklist_expires", "expires_at"),
        Index("ix_blocklist_domain_hash", "domain_hash"),
    )


class StatsDaily(Base):
    __tablename__ = "stats_daily"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    date = Column(DateTime, unique=True, nullable=False, index=True)
    total_cases = Column(Integer, default=0, nullable=False)
    by_level_low = Column(Integer, default=0, nullable=False)
    by_level_medium = Column(Integer, default=0, nullable=False)
    by_level_high = Column(Integer, default=0, nullable=False)
    by_level_critical = Column(Integer, default=0, nullable=False)
    by_channel_email = Column(Integer, default=0, nullable=False)
    by_channel_sms = Column(Integer, default=0, nullable=False)
    by_channel_social = Column(Integer, default=0, nullable=False)
    by_channel_url = Column(Integer, default=0, nullable=False)
    avg_score = Column(Integer, default=0, nullable=False)
    avg_latency_ms = Column(Integer, default=0, nullable=False)
    top_signals = Column(JSONB, nullable=False, default=list)
    top_domains = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_stats_daily_date", "date", unique=True),
    )


class ApiUsage(Base):
    __tablename__ = "api_usage"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    endpoint = Column(String(100), nullable=False)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_api_usage_device_created", "device_id", "created_at"),
    )


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    endpoint = Column(String(100), nullable=False, index=True)
    tokens = Column(Integer, default=0, nullable=False)
    last_refill = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_rate_limit_device_endpoint", "device_id", "endpoint", unique=True),
    )