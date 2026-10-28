from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from sqlalchemy.exc import DataError, IntegrityError
from app.api.router import api
from app.api.llm import llm_api
from app.api.ml import ml_api
from app.api.agents import agents_api
from app.api.audit import audit_api
from app.api.legal import legal_api
from app import __version__
from app.core.config import settings
from app.security.hardening import security_headers
from app.core.database import Base, SessionLocal, engine
from app.services.seed import seed
import asyncio
import logging
from app.automation.worker import AutomationWorker
from app.ml.training import ensure_ready
from app.agents.runner import ensure_states
from app.agents.scheduler import scheduler_loop

STATIC_DIR = Path(__file__).resolve().parent / "static"
log = logging.getLogger("fixit.ml")
errors_log = logging.getLogger("fixit.errors")


def prepare_ml() -> None:
    """Load the models stored in the database, or train them if missing/incompatible. A failure
    never blocks startup: the ML panel then reports the models as not trained."""
    db = SessionLocal()
    try:
        log.info("Modelos ML: %s", "cargados" if ensure_ready(db) == "loaded" else "entrenados y guardados")
    except Exception:
        db.rollback()
        log.exception("No se pudieron preparar los modelos ML al iniciar")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()

    await asyncio.to_thread(prepare_ml)

    db = SessionLocal()
    try:
        ensure_states(db)
    finally:
        db.close()
    scheduler_stop = asyncio.Event()
    scheduler = asyncio.create_task(scheduler_loop(scheduler_stop), name="fixit-agent-scheduler")

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
        scheduler_stop.set()
        await scheduler
        if worker and task:
            worker.stop()
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

# Interactive API docs are off in production unless API_DOCS_ENABLED=true (they map every endpoint for an attacker).
docs = settings.api_docs_enabled
app=FastAPI(title="FixIT",version=__version__,lifespan=lifespan,docs_url="/docs" if docs else None,
            redoc_url="/redoc" if docs else None,openapi_url="/openapi.json" if docs else None)
app.middleware("http")(security_headers)
app.include_router(api)
app.include_router(ml_api)
app.include_router(llm_api)
app.include_router(agents_api)
app.include_router(audit_api)
app.include_router(legal_api)
app.mount("/static",StaticFiles(directory=STATIC_DIR),name="static")

@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    # Field location and message only: the submitted values (e.g. a password) are never echoed back.
    errors=[{"loc":[str(x) for x in e.get("loc",())],"msg":str(e.get("msg","")),"type":str(e.get("type",""))} for e in exc.errors()]
    return JSONResponse(status_code=422,content={"detail":"Datos inválidos","errors":errors})

@app.exception_handler(IntegrityError)
async def integrity_error(request: Request, exc: IntegrityError):
    # Duplicates or references that changed concurrently: a client-side conflict, not a server failure.
    errors_log.warning("Conflicto de integridad en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=409,content={"detail":"La operación entra en conflicto con datos existentes"})

@app.exception_handler(DataError)
async def data_error(request: Request, exc: DataError):
    errors_log.warning("Dato rechazado por la base de datos en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=422,content={"detail":"Datos inválidos"})

@app.exception_handler(Exception)
async def generic_error(request: Request, exc: Exception):
    # Preserve HTTP errors, never expose implementation details to clients.
    from fastapi import HTTPException
    if isinstance(exc, HTTPException): return JSONResponse(status_code=exc.status_code,content={"detail":exc.detail},headers=exc.headers)
    errors_log.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500,content={"detail":"Error interno del servidor"})

@app.get("/", include_in_schema=False)
def web(): return FileResponse(STATIC_DIR / "index.html")

@app.get("/legal", include_in_schema=False)
def legal_page(): return FileResponse(STATIC_DIR / "legal.html")

@app.get("/health")
def health(): return {"status":"ok"}

