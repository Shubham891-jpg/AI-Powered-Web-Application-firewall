"""
Database Repositories for AI-WAF entities.
"""

from typing import Sequence
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import SecurityEvent, Rule, Application


class SecurityEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: SecurityEvent) -> SecurityEvent:
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_recent(self, limit: int = 50) -> Sequence[SecurityEvent]:
        query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all()


class RuleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_all_active(self) -> Sequence[Rule]:
        query = select(Rule).where(Rule.enabled == True) # noqa: E712
        result = await self.session.execute(query)
        return result.scalars().all()


class ApplicationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_all(self) -> Sequence[Application]:
        query = select(Application).order_by(Application.name)
        result = await self.session.execute(query)
        return result.scalars().all()
