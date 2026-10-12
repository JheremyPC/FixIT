import os
from sqlalchemy.orm import Session
from app.models import Area, Category, Priority, Role, Setting, Specialty, TicketState, User
from app.security.auth import hash_password
from app.services.assignment import WEIGHT_DEFAULTS


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
