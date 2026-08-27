"""
Asynchronous Non-Blocking Security Event Ingestion Queue (Phase 7).
Ensures database I/O never adds latency to proxy request forwarding.
Buffers events in memory and commits them in batches to PostgreSQL via a background worker.
"""

import asyncio
import logging
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database.models import SecurityEvent

logger = logging.getLogger("waf.event_queue")


class AsyncEventQueue:
    """Non-blocking in-memory queue with batch asynchronous database draining."""

    def __init__(self, maxsize: int = 10000, batch_size: int = 50, flush_interval: float = 0.5):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self._dropped_events = 0

    def enqueue(self, event: SecurityEvent) -> bool:
        """
        Non-blocking enqueue.
        Returns True if enqueued, False if buffer is completely full.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._dropped_events += 1
            logger.warning("Event queue is full. Dropping security audit event (Total dropped: %d)", self._dropped_events)
            return False

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def dropped_count(self) -> int:
        return self._dropped_events

    async def start(self, session_factory: async_sessionmaker[AsyncSession]):
        """Starts the background draining worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop(session_factory))
        logger.info("Security event background ingestion worker started.")

    async def stop(self, session_factory: Optional[async_sessionmaker[AsyncSession]] = None):
        """Stops the worker and flushes any pending events."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

        # Flush remaining events if session_factory is available
        if session_factory and not self._queue.empty():
            await self._flush_remaining(session_factory)
        logger.info("Security event ingestion worker stopped.")

    async def _worker_loop(self, session_factory: async_sessionmaker[AsyncSession]):
        """Continuous batch draining loop."""
        while self._running:
            batch: list[SecurityEvent] = []
            try:
                # Wait for at least one event or timeout after flush_interval
                try:
                    first_event = await asyncio.wait_for(self._queue.get(), timeout=self.flush_interval)
                    batch.append(first_event)
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    continue

                # Drain additional available items up to batch_size
                while len(batch) < self.batch_size and not self._queue.empty():
                    try:
                        ev = self._queue.get_nowait()
                        batch.append(ev)
                        self._queue.task_done()
                    except asyncio.QueueEmpty:
                        break

                # Persist batch to database
                if batch:
                    await self._persist_batch(batch, session_factory)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unexpected error in event ingestion loop: %s", str(e), exc_info=True)
                await asyncio.sleep(0.5)

    async def _persist_batch(self, batch: list[SecurityEvent], session_factory: async_sessionmaker[AsyncSession]):
        """Writes a batch of events inside an isolated database session."""
        try:
            async with session_factory() as session:
                session.add_all(batch)
                await session.commit()
                logger.debug("Successfully persisted %d security events to database.", len(batch))
        except Exception as e:
            logger.error("Failed to commit security event batch to database: %s", str(e))

    async def _flush_remaining(self, session_factory: async_sessionmaker[AsyncSession]):
        """Flushes all queued events at shutdown."""
        batch: list[SecurityEvent] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break
        if batch:
            logger.info("Flushing %d pending security events on shutdown...", len(batch))
            await self._persist_batch(batch, session_factory)


# Global singleton instance
security_event_queue = AsyncEventQueue()
