"""
Database Repositories for AI-WAF entities (Phase 7).
Provides asynchronous CRUD and analytical query interfaces for SecurityEvents,
Applications, Rules, and ModelVersions using SQLAlchemy 2.0.
"""

from typing import Any, Optional, Sequence
from sqlalchemy import func, select, desc, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import SecurityEvent, Rule, Application, ModelVersion


class SecurityEventRepository:
    """Repository managing security audit events with filtering and aggregation."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: SecurityEvent) -> SecurityEvent:
        """Persists an individual security event."""
        self.session.add(event)
        await self.session.flush()
        return event

    async def create_batch(self, events: list[SecurityEvent]) -> int:
        """Efficiently persists a batch of security events."""
        if not events:
            return 0
        self.session.add_all(events)
        await self.session.flush()
        return len(events)

    async def get_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Retrieves a single security event by primary key UUID."""
        query = select(SecurityEvent).where(SecurityEvent.id == event_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_request_id(self, request_id: str) -> Optional[SecurityEvent]:
        """Retrieves a security event by its correlation request ID."""
        query = select(SecurityEvent).where(SecurityEvent.request_id == request_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_recent(self, limit: int = 50, offset: int = 0) -> Sequence[SecurityEvent]:
        """Retrieves the most recent security events ordered by timestamp descending."""
        query = (
            select(SecurityEvent)
            .order_by(desc(SecurityEvent.timestamp))
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_filtered(
        self,
        category: Optional[str] = None,
        action: Optional[str] = None,
        min_risk: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[SecurityEvent], int]:
        """
        Retrieves filtered security events with total match count for pagination.
        """
        query = select(SecurityEvent)
        count_query = select(func.count(SecurityEvent.id))

        if category and category != "ALL":
            query = query.where(SecurityEvent.attack_category == category)
            count_query = count_query.where(SecurityEvent.attack_category == category)

        if action and action != "ALL":
            query = query.where(SecurityEvent.action == action)
            count_query = count_query.where(SecurityEvent.action == action)

        if min_risk is not None:
            query = query.where(SecurityEvent.risk_score >= min_risk)
            count_query = count_query.where(SecurityEvent.risk_score >= min_risk)

        # Count total
        total_res = await self.session.execute(count_query)
        total_count = total_res.scalar_one()

        # Fetch page
        query = query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit)
        result = await self.session.execute(query)
        events = result.scalars().all()

        return events, total_count

    async def get_stats(self) -> dict[str, Any]:
        """Computes summary statistics for cybersecurity dashboard."""
        total_q = select(func.count(SecurityEvent.id))
        blocked_q = select(func.count(SecurityEvent.id)).where(SecurityEvent.action == "BLOCK")
        flagged_q = select(func.count(SecurityEvent.id)).where(SecurityEvent.action == "FLAG")
        allowed_q = select(func.count(SecurityEvent.id)).where(SecurityEvent.action == "ALLOW")
        avg_risk_q = select(func.avg(SecurityEvent.risk_score))

        total = (await self.session.execute(total_q)).scalar_one()
        blocked = (await self.session.execute(blocked_q)).scalar_one()
        flagged = (await self.session.execute(flagged_q)).scalar_one()
        allowed = (await self.session.execute(allowed_q)).scalar_one()
        avg_risk = (await self.session.execute(avg_risk_q)).scalar_one() or 0.0

        # Category breakdown
        cat_q = (
            select(SecurityEvent.attack_category, func.count(SecurityEvent.id))
            .group_by(SecurityEvent.attack_category)
            .order_by(desc(func.count(SecurityEvent.id)))
        )
        cat_res = await self.session.execute(cat_q)
        categories = {row[0]: row[1] for row in cat_res.all()}

        return {
            "total_events": total,
            "blocked_events": blocked,
            "flagged_events": flagged,
            "allowed_events": allowed,
            "average_risk_score": round(float(avg_risk), 2),
            "categories": categories,
        }


class ApplicationRepository:
    """Repository managing protected upstream web applications."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, app: Application) -> Application:
        self.session.add(app)
        await self.session.flush()
        return app

    async def get_all(self) -> Sequence[Application]:
        query = select(Application).order_by(Application.name)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_by_id(self, app_id: str) -> Optional[Application]:
        query = select(Application).where(Application.id == app_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[Application]:
        query = select(Application).where(Application.name == name)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def update(self, app_id: str, **kwargs) -> Optional[Application]:
        stmt = (
            update(Application)
            .where(Application.id == app_id)
            .values(**kwargs)
            .execution_options(synchronize_session="fetch")
        )
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_by_id(app_id)

    async def delete(self, app_id: str) -> bool:
        stmt = delete(Application).where(Application.id == app_id)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0


class ModelVersionRepository:
    """Repository tracking trained ML classifier versions and performance metrics."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, model_version: ModelVersion) -> ModelVersion:
        self.session.add(model_version)
        await self.session.flush()
        return model_version

    async def get_all(self) -> Sequence[ModelVersion]:
        query = select(ModelVersion).order_by(desc(ModelVersion.created_at))
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_active(self) -> Optional[ModelVersion]:
        query = select(ModelVersion).where(ModelVersion.is_active == True) # noqa: E712
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def set_active(self, version_id: str) -> bool:
        # Deactivate all others
        await self.session.execute(
            update(ModelVersion).values(is_active=False)
        )
        # Activate target
        stmt = (
            update(ModelVersion)
            .where(ModelVersion.id == version_id)
            .values(is_active=True)
        )
        res = await self.session.execute(stmt)
        await self.session.flush()
        return res.rowcount > 0


class RuleRepository:
    """Repository managing detection rules and operator overrides."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_all(self) -> Sequence[Rule]:
        query = select(Rule).order_by(Rule.rule_id)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_all_active(self) -> Sequence[Rule]:
        query = select(Rule).where(Rule.enabled == True).order_by(Rule.rule_id) # noqa: E712
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_by_rule_id(self, rule_id: str) -> Optional[Rule]:
        query = select(Rule).where(Rule.rule_id == rule_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[Rule]:
        stmt = (
            update(Rule)
            .where(Rule.rule_id == rule_id)
            .values(enabled=enabled)
        )
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_by_rule_id(rule_id)

    async def update_score(self, rule_id: str, score: int) -> Optional[Rule]:
        stmt = (
            update(Rule)
            .where(Rule.rule_id == rule_id)
            .values(score=score)
        )
        await self.session.execute(stmt)
        await self.session.flush()
        return await self.get_by_rule_id(rule_id)
