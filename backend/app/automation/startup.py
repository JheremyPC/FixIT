from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .worker import AutomationWorker


@asynccontextmanager
async def automation_lifespan(app: FastAPI):
    """Lifespan listo para conectarse al FastAPI existente."""
    worker = AutomationWorker()
    task = asyncio.create_task(worker.run())
    app.state.automation_worker = worker
    try:
        yield
    finally:
        worker.stop()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
