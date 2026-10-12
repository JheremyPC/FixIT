from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.api.router import api
from app.api.llm import llm_api
from app.api.ml import ml_api
from app.core.config import settings
from app.core.database import Base, SessionLocal, engine
from app.services.seed import seed
import asyncio
from app.automation.worker import AutomationWorker

STATIC_DIR = Path(__file__).resolve().parent / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()

    # The automation worker relies on PostgreSQL features (SKIP LOCKED, automation_events triggers).
    worker = task = None
    if settings.database_url.startswith("postgresql"):
        worker = AutomationWorker()
        task = asyncio.create_task(
            worker.run(),
            name="fixit-automation-worker"
        )

    app.state.automation_worker = worker

    try:
        yield
    finally:
        if worker and task:
            worker.stop()
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

app=FastAPI(title="FixIT",version="1.0.0",lifespan=lifespan)
app.include_router(api)
app.include_router(ml_api)
app.include_router(llm_api)
app.mount("/static",StaticFiles(directory=STATIC_DIR),name="static")

@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422,content={"detail":"Datos inválidos","errors":exc.errors()})

@app.exception_handler(Exception)
async def generic_error(_: Request, exc: Exception):
    # Preserve HTTP errors, never expose implementation details to clients.
    from fastapi import HTTPException
    if isinstance(exc, HTTPException): return JSONResponse(status_code=exc.status_code,content={"detail":exc.detail})
    return JSONResponse(status_code=500,content={"detail":"Error interno del servidor"})

@app.get("/", include_in_schema=False)
def web(): return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
def health(): return {"status":"ok"}

