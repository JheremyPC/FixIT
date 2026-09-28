from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from app.api.router import api
from app.core.database import Base, SessionLocal, engine
from app.models import Area, Category, Priority, Role, Setting, Specialty, TicketState, User
from app.security.auth import hash_password
from app.services.assignment import WEIGHT_DEFAULTS
import asyncio
from app.automation.worker import AutomationWorker
import os

def seed(db: Session):
    for code, name in [("ADMIN","Administrador"),("JEFE_TI","Jefe de TI"),("TECNICO","Técnico"),("USUARIO","Usuario")]:
        if not db.query(Role).filter_by(code=code).first(): db.add(Role(code=code,name=name))
    db.flush()
    if not db.query(Area).first(): db.add_all([Area(name="Tecnología"),Area(name="Administración"),Area(name="Operaciones")])
    if not db.query(Specialty).first(): db.add(Specialty(name="Soporte general",description="Atención general de primer nivel"))
    if not db.query(Category).first(): db.add(Category(name="Incidencia general",description="Solicitud de soporte no clasificada"))
    if not db.query(Priority).first(): db.add_all([Priority(code="BAJA",name="Baja",level=1,sla_hours=72,color="#22c55e"),Priority(code="MEDIA",name="Media",level=2,sla_hours=48,color="#3b82f6"),Priority(code="ALTA",name="Alta",level=3,sla_hours=24,color="#f59e0b"),Priority(code="CRITICA",name="Crítica",level=4,sla_hours=4,color="#ef4444")])
    for code, name, terminal in [("NUEVO","Nuevo",False),("ASIGNADO","Asignado",False),("EN_ATENCION","En atención",False),("EN_ESPERA","En espera",False),("RESUELTO","Resuelto",False),("CERRADO","Cerrado",True),("REABIERTO","Reabierto",False),("CANCELADO","Cancelado",True),("ESCALADO","Escalado",False)]:
        if not db.query(TicketState).filter_by(code=code).first(): db.add(TicketState(code=code,name=name,terminal=terminal))
    for key, value in WEIGHT_DEFAULTS.items():
        if not db.get(Setting,key): db.add(Setting(key=key,value=str(value),description="Peso del algoritmo de asignación"))
    db.flush()
    if not db.query(User).filter_by(email="admin@fixit.org").first():
        db.add(User(full_name="Administrador FixIT",email="admin@fixit.org",password_hash=hash_password(os.getenv("FIXIT_ADMIN_PASSWORD", "ChangeThisPassword!")),role_id=db.query(Role).filter_by(code="ADMIN").one().id))
    db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()

    worker = AutomationWorker()
    task = asyncio.create_task(
        worker.run(),
        name="fixit-automation-worker"
    )

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

app=FastAPI(title="FixIT",version="1.0.0",lifespan=lifespan)
app.include_router(api)
app.mount("/static",StaticFiles(directory="app/static"),name="static")

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
def web(): return FileResponse("app/static/index.html")

@app.get("/health")
def health(): return {"status":"ok"}

