"""
SQLAlchemy ORM Database Models for AI-WAF.
Includes Users, SecurityEvents, Rules, Applications, ModelVersions, RateLimitEvents.
"""

from datetime import datetime
import uuid
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database.database import Base

# Use JSONB for PostgreSQL, fallback to generic JSON for SQLite / other dialects
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)


class Application(Base):
    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    upstream_url = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    detection_mode = Column(String(20), default="BLOCK", nullable=False)
    rate_limit_requests = Column(Integer, default=100, nullable=False)
    rate_limit_window_seconds = Column(Integer, default=60, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    client_ip = Column(String(45), nullable=False, index=True)
    http_method = Column(String(10), nullable=False)
    path = Column(String(2048), nullable=False, index=True)
    query_params = Column(JSON_TYPE, default=dict)
    headers = Column(JSON_TYPE, default=dict)
    raw_payload = Column(Text, nullable=True)
    normalized_payload = Column(Text, nullable=True)

    attack_category = Column(String(50), nullable=False, index=True)  # SQL_INJECTION, XSS, etc.
    risk_score = Column(Integer, nullable=False, index=True)          # 0-100
    ml_confidence = Column(Float, nullable=True)
    action = Column(String(20), nullable=False, index=True)           # ALLOW, FLAG, BLOCK
    matched_rules = Column(JSON_TYPE, default=list)

    model_version = Column(String(50), nullable=True)
    response_status = Column(Integer, nullable=False)
    processing_latency_ms = Column(Float, nullable=False)

    # Analyst Feedback for Model Retraining
    review_status = Column(String(20), default="UNREVIEWED", nullable=False) # UNREVIEWED, TRUE_POSITIVE, FALSE_POSITIVE
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(50), unique=True, nullable=False, index=True) # e.g. SQLI-001
    name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False, index=True)
    pattern = Column(Text, nullable=False)
    score = Column(Integer, nullable=False)
    is_regex = Column(Boolean, default=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_name = Column(String(100), nullable=False)
    version = Column(String(50), unique=True, nullable=False)
    algorithm = Column(String(50), nullable=False)
    metrics = Column(JSON_TYPE, default=dict)
    artifact_path = Column(String(255), nullable=False)
    vectorizer_path = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class RateLimitEvent(Base):
    __tablename__ = "rate_limit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_ip = Column(String(45), nullable=False, index=True)
    request_count = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    action_taken = Column(String(20), default="BLOCK", nullable=False)
