"""
PostgreSQL Persistence & Repository Unit Tests (Phase 7).
Tests SQLAlchemy 2.0 async models, SecurityEventRepository, ApplicationRepository,
ModelVersionRepository, RuleRepository, and the AsyncEventQueue background worker.
"""

import asyncio
from datetime import datetime
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.database.database import Base
from app.database.models import SecurityEvent, Application, ModelVersion, Rule
from app.database.repositories import (
    SecurityEventRepository,
    ApplicationRepository,
    ModelVersionRepository,
    RuleRepository,
)
from app.logging.event_queue import AsyncEventQueue

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def async_session():
    """Initializes an in-memory SQLite async test database and yields a session."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory():
    """Initializes an in-memory SQLite engine and returns the sessionmaker."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_security_event_repository_create_and_retrieve(async_session: AsyncSession):
    """Verifies persisting and querying an individual SecurityEvent."""
    repo = SecurityEventRepository(async_session)

    event = SecurityEvent(
        request_id="req-persist-001",
        client_ip="192.168.1.100",
        http_method="POST",
        path="/api/v1/login",
        query_params={"redirect": ["/dashboard"]},
        headers={"user-agent": "Mozilla/5.0"},
        raw_payload="admin' OR 1=1--",
        normalized_payload="admin' or 1=1--",
        attack_category="SQL_INJECTION",
        risk_score=95,
        ml_confidence=0.98,
        action="BLOCK",
        matched_rules=[{"rule_id": "SQLI-001", "confidence": "HIGH_CONFIDENCE"}],
        primary_reason="Detected SQL tautology injection",
        ml_prediction={"predicted_class": "SQL_INJECTION", "confidence": 0.98},
        contextual_penalties=[{"factor": "SENSITIVE_PATH_ACCESS", "penalty_points": 15}],
        explanation_json={"decision": "BLOCK", "risk_score": 95},
        response_status=403,
        processing_latency_ms=1.45,
    )

    created = await repo.create(event)
    await async_session.commit()

    assert created.id is not None

    by_id = await repo.get_by_id(created.id)
    assert by_id is not None
    assert by_id.request_id == "req-persist-001"
    assert by_id.risk_score == 95
    assert by_id.action == "BLOCK"
    assert by_id.attack_category == "SQL_INJECTION"

    by_req_id = await repo.get_by_request_id("req-persist-001")
    assert by_req_id is not None
    assert by_req_id.id == created.id


@pytest.mark.asyncio
async def test_security_event_repository_batch_create_and_filtering(async_session: AsyncSession):
    """Verifies batch inserts, category filtering, and risk threshold pagination."""
    repo = SecurityEventRepository(async_session)

    events = [
        SecurityEvent(
            request_id=f"req-batch-{i}",
            client_ip="10.0.0.1",
            http_method="GET",
            path=f"/path/{i}",
            attack_category="SQL_INJECTION" if i % 2 == 0 else "CROSS_SITE_SCRIPTING",
            risk_score=20 + (i * 10),
            action="BLOCK" if (20 + i * 10) >= 70 else "ALLOW",
        )
        for i in range(10)
    ]

    count = await repo.create_batch(events)
    await async_session.commit()
    assert count == 10

    # Filter by category
    sqli_events, sqli_total = await repo.get_filtered(category="SQL_INJECTION")
    assert sqli_total == 5
    assert len(sqli_events) == 5

    # Filter by action
    blocked_events, blocked_total = await repo.get_filtered(action="BLOCK")
    assert blocked_total == 5
    for b in blocked_events:
        assert b.action == "BLOCK"

    # Filter by minimum risk
    high_risk_events, high_risk_total = await repo.get_filtered(min_risk=80)
    assert high_risk_total == 4


@pytest.mark.asyncio
async def test_security_event_repository_stats(async_session: AsyncSession):
    """Verifies aggregate cybersecurity dashboard metrics."""
    repo = SecurityEventRepository(async_session)

    events = [
        SecurityEvent(request_id="r1", client_ip="1.1.1.1", http_method="GET", path="/p1", attack_category="NORMAL", risk_score=10, action="ALLOW"),
        SecurityEvent(request_id="r2", client_ip="1.1.1.2", http_method="GET", path="/p2", attack_category="SQL_INJECTION", risk_score=85, action="BLOCK"),
        SecurityEvent(request_id="r3", client_ip="1.1.1.3", http_method="GET", path="/p3", attack_category="CROSS_SITE_SCRIPTING", risk_score=50, action="FLAG"),
    ]
    await repo.create_batch(events)
    await async_session.commit()

    stats = await repo.get_stats()
    assert stats["total_events"] == 3
    assert stats["blocked_events"] == 1
    assert stats["flagged_events"] == 1
    assert stats["allowed_events"] == 1
    assert stats["average_risk_score"] == pytest.approx(48.33, 0.1)
    assert stats["categories"]["SQL_INJECTION"] == 1


@pytest.mark.asyncio
async def test_application_repository_crud(async_session: AsyncSession):
    """Verifies CRUD operations on upstream protected applications."""
    repo = ApplicationRepository(async_session)

    app = Application(
        name="Demo Upstream",
        upstream_url="http://localhost:3000",
        is_active=True,
        detection_mode="BLOCK",
        rate_limit_requests=200,
    )
    created = await repo.create(app)
    await async_session.commit()
    assert created.id is not None

    by_name = await repo.get_by_name("Demo Upstream")
    assert by_name is not None
    assert by_name.rate_limit_requests == 200

    updated = await repo.update(created.id, rate_limit_requests=350, detection_mode="FLAG_ONLY")
    assert updated.rate_limit_requests == 350
    assert updated.detection_mode == "FLAG_ONLY"

    all_apps = await repo.get_all()
    assert len(all_apps) == 1

    deleted = await repo.delete(created.id)
    assert deleted is True
    assert await repo.get_by_id(created.id) is None


@pytest.mark.asyncio
async def test_model_version_repository(async_session: AsyncSession):
    """Verifies ML model version registry and activation switching."""
    repo = ModelVersionRepository(async_session)

    v1 = ModelVersion(
        model_name="waf_classifier",
        version="1.0.0",
        algorithm="LogisticRegression",
        metrics={"accuracy": 0.9833, "macro_f1": 0.99},
        artifact_path="ml/models/waf_classifier_v1.joblib",
        vectorizer_path="ml/models/tfidf_vectorizer_v1.joblib",
        is_active=True,
    )
    v2 = ModelVersion(
        model_name="waf_classifier",
        version="1.1.0",
        algorithm="LogisticRegression",
        metrics={"accuracy": 0.9912, "macro_f1": 0.995},
        artifact_path="ml/models/waf_classifier_v1_1.joblib",
        vectorizer_path="ml/models/tfidf_vectorizer_v1_1.joblib",
        is_active=False,
    )
    await repo.create(v1)
    await repo.create(v2)
    await async_session.commit()

    active = await repo.get_active()
    assert active is not None
    assert active.version == "1.0.0"

    # Switch active to v2
    await repo.set_active(v2.id)
    await async_session.commit()

    active_switched = await repo.get_active()
    assert active_switched.version == "1.1.0"


@pytest.mark.asyncio
async def test_rule_repository(async_session: AsyncSession):
    """Verifies detection rule toggling and score adjustment in database."""
    repo = RuleRepository(async_session)

    rule = Rule(
        rule_id="SQLI-TEST-001",
        name="Test SQL Injection Rule",
        category="SQL_INJECTION",
        pattern=r"(?i)\bUNION\b",
        score=85,
        is_regex=True,
        enabled=True,
    )
    async_session.add(rule)
    await async_session.commit()

    active_rules = await repo.get_all_active()
    assert len(active_rules) == 1
    assert active_rules[0].rule_id == "SQLI-TEST-001"

    # Toggle disable
    disabled = await repo.toggle_rule("SQLI-TEST-001", enabled=False)
    assert disabled.enabled is False
    assert len(await repo.get_all_active()) == 0

    # Update score
    updated_score = await repo.update_score("SQLI-TEST-001", score=90)
    assert updated_score.score == 90


@pytest.mark.asyncio
async def test_event_queue_batch_worker(session_factory):
    """Verifies non-blocking enqueue and background batch draining."""
    queue = AsyncEventQueue(maxsize=100, batch_size=5, flush_interval=0.1)

    # Enqueue 7 events
    for i in range(7):
        ev = SecurityEvent(
            request_id=f"req-queue-{i}",
            client_ip="192.0.2.1",
            http_method="GET",
            path="/queue-test",
            attack_category="NORMAL",
            risk_score=10,
            action="ALLOW",
        )
        assert queue.enqueue(ev) is True

    assert queue.queue_size == 7

    # Start worker and wait for queue to drain
    await queue.start(session_factory)
    await asyncio.sleep(0.3)
    await queue.stop(session_factory)

    assert queue.queue_size == 0

    # Verify all 7 events are persisted in database
    async with session_factory() as session:
        repo = SecurityEventRepository(session)
        events = await repo.get_recent(limit=50)
        assert len(events) == 7
