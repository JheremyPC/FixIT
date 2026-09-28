import csv
import io
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from jose import JWTError, jwt
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import forbidden, not_found
from app.models import *
from app.schemas import *
from app.security.auth import ALGORITHM, create_token, current_user, hash_password, require_roles, verify_password
from app.services.assignment import AssignmentService, WEIGHT_DEFAULTS
from app.services.audit import audit, history, notify
from app.services.tickets import assign, initial_due, next_number, set_state, state

api = APIRouter(prefix="/api")

def user_data(user):
    return {"id": user.id, "full_name": user.full_name, "email": user.email, "role": user.role.code, "area_id": user.area_id, "active": user.active, "technician_id": user.technician.id if user.technician else None}

def ticket_data(t):
    return {"id": t.id, "number": t.number, "title": t.title, "description": t.description, "requester": user_data(t.requester),
            "technician": {"id": t.technician.id, "name": t.technician.user.full_name} if t.technician else None,
            "area": {"id":t.area.id,"name":t.area.name}, "category": {"id":t.category.id,"name":t.category.name},
            "priority": {"id":t.priority.id,"code":t.priority.code,"name":t.priority.name,"color":t.priority.color},
            "state": t.state.code, "due_at": t.due_at, "created_at": t.created_at, "updated_at": t.updated_at,
            "diagnosis": t.diagnosis, "solution": t.solution, "resolved_at": t.resolved_at, "rating": t.rating.score if t.rating else None}

def get_ticket(db, ticket_id):
    ticket = db.query(Ticket).options(joinedload(Ticket.requester).joinedload(User.role), joinedload(Ticket.technician).joinedload(Technician.user), joinedload(Ticket.area), joinedload(Ticket.category), joinedload(Ticket.priority), joinedload(Ticket.state), joinedload(Ticket.rating)).filter(Ticket.id == ticket_id).first()
    if not ticket: not_found("Ticket")
    return ticket

def can_access_ticket(user, ticket, write=False):
    role = user.role.code
    if role in {"ADMIN", "JEFE_TI"}: return
    if role == "USUARIO" and ticket.requester_id == user.id: return
    if role == "TECNICO" and user.technician and ticket.technician_id == user.technician.id: return
    forbidden()

@api.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).options(joinedload(User.role)).filter(func.lower(User.email) == payload.email.lower()).first()
    if not user or not user.active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Correo o contraseña inválidos")
    audit(db, user.id, "LOGIN", "AUTH", "USER", user.id, request=request); db.commit()
    return {"access_token": create_token(user, "access"), "refresh_token": create_token(user, "refresh"), "user": user_data(user)}

@api.post("/auth/register", status_code=201)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Self-registration intentionally always grants the least-privileged role."""
    if db.query(User).filter(func.lower(User.email) == payload.email.lower()).first(): raise HTTPException(409, "El correo ya existe")
    role=db.query(Role).filter_by(code="USUARIO").one()
    if payload.area_id and not db.get(Area,payload.area_id): not_found("Área")
    user=User(full_name=payload.full_name,email=payload.email.lower(),password_hash=hash_password(payload.password),role_id=role.id,area_id=payload.area_id)
    db.add(user);db.flush();audit(db,user.id,"REGISTRO","AUTH","USER",user.id,new={"email":user.email},request=request);db.commit()
    return {"id":user.id}

@api.post("/auth/refresh", response_model=TokenOut)
def refresh(payload: RefreshIn, db: Session = Depends(get_db)):
    try:
        claims = jwt.decode(payload.refresh_token, settings.jwt_secret_key, algorithms=[ALGORITHM])
        if claims.get("type") != "refresh": raise JWTError()
        user = db.query(User).options(joinedload(User.role)).get(claims.get("sub"))
    except JWTError: user = None
    if not user or not user.active: raise HTTPException(401, "Refresh token inválido")
    return {"access_token": create_token(user, "access"), "refresh_token": create_token(user, "refresh"), "user": user_data(user)}

@api.get("/auth/me")
def me(user: User = Depends(current_user)): return user_data(user)

@api.get("/users")
def users(_: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    return [user_data(x) for x in db.query(User).options(joinedload(User.role)).order_by(User.full_name).all()]

@api.post("/users", status_code=201)
def create_user(payload: UserCreate, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    if db.query(User).filter(func.lower(User.email) == payload.email.lower()).first(): raise HTTPException(409, "El correo ya existe")
    role = db.query(Role).filter_by(code=payload.role_code).first()
    if not role: raise HTTPException(422, "Rol inválido")
    if payload.area_id and not db.get(Area, payload.area_id): not_found("Área")
    item = User(full_name=payload.full_name, email=payload.email.lower(), password_hash=hash_password(payload.password), role_id=role.id, area_id=payload.area_id)
    db.add(item); db.flush(); audit(db, actor.id, "CREAR", "USUARIOS", "USER", item.id, new={"email": item.email, "role": role.code}, request=request); db.commit(); db.refresh(item)
    return {"id":item.id}

@api.patch("/users/{user_id}")
def update_user(user_id: str, payload: UserUpdate, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    item = db.get(User, user_id)
    if not item: not_found("Usuario")
    old = {"full_name":item.full_name,"active":item.active,"role_id":item.role_id}
    for key, value in payload.model_dump(exclude_unset=True, exclude={"role_code"}).items(): setattr(item, key, value)
    if payload.role_code:
        role = db.query(Role).filter_by(code=payload.role_code).first()
        if not role: raise HTTPException(422, "Rol inválido")
        item.role_id = role.id
    audit(db, actor.id, "ACTUALIZAR", "USUARIOS", "USER", item.id, old, {"full_name":item.full_name,"active":item.active,"role_id":item.role_id}, request); db.commit(); return user_data(item)

def catalog(model, db): return [{"id":x.id,"name":x.name,"active":getattr(x,"active",True)} for x in db.query(model).order_by(model.name).all()]

@api.get("/catalogs/{kind}")
def list_catalog(kind: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    mapping={"areas":Area,"categories":Category,"specialties":Specialty}
    if kind == "priorities": return [{"id":x.id,"code":x.code,"name":x.name,"level":x.level,"sla_hours":x.sla_hours,"color":x.color} for x in db.query(Priority).order_by(Priority.level).all()]
    if kind == "states": return [{"id":x.id,"code":x.code,"name":x.name} for x in db.query(TicketState).all()]
    if kind not in mapping: raise HTTPException(404,"Catálogo desconocido")
    return catalog(mapping[kind],db)

@api.post("/catalogs/{kind}", status_code=201)
def create_catalog(kind: str, payload: EntityIn, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    mapping={"areas":Area,"categories":Category,"specialties":Specialty}
    model=mapping.get(kind)
    if not model: raise HTTPException(404,"Catálogo no editable")
    if db.query(model).filter_by(name=payload.name).first(): raise HTTPException(409,"Nombre duplicado")
    if kind == "categories" and payload.specialty_id and not db.get(Specialty, payload.specialty_id): not_found("Especialidad")
    item=model(name=payload.name, description=payload.description, specialty_id=payload.specialty_id) if kind == "categories" else (model(name=payload.name, description=payload.description) if kind != "areas" else model(name=payload.name))
    db.add(item); db.flush(); audit(db,actor.id,"CREAR","CATALOGOS",kind,item.id,new={"name":item.name},request=request); db.commit(); return {"id":item.id}

@api.post("/priorities", status_code=201)
def create_priority(payload: PriorityIn, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    item=Priority(**payload.model_dump()); db.add(item); db.flush(); audit(db,actor.id,"CREAR","CATALOGOS","PRIORITY",item.id,new=payload.model_dump(),request=request); db.commit(); return {"id":item.id}

@api.get("/technicians")
def technicians(db: Session = Depends(get_db), _: User = Depends(current_user)):
    rows=db.query(Technician).options(joinedload(Technician.user),joinedload(Technician.specialties).joinedload(TechnicianSpecialty.specialty)).all()
    return [{"id":x.id,"user_id":x.user_id,"name":x.user.full_name,"email":x.user.email,"available":x.available,"max_load":x.max_load,"specialties":[s.specialty.name for s in x.specialties]} for x in rows]

@api.post("/technicians", status_code=201)
def create_technician(payload: TechnicianIn, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    user=db.get(User,payload.user_id)
    if not user: not_found("Usuario")
    if user.role.code != "TECNICO": raise HTTPException(422,"El usuario debe tener rol TECNICO")
    if db.query(Technician).filter_by(user_id=user.id).first(): raise HTTPException(409,"El técnico ya existe")
    ids=set(payload.specialty_ids)
    if len(ids) != len(payload.specialty_ids) or db.query(Specialty).filter(Specialty.id.in_(ids)).count()!=len(ids): raise HTTPException(422,"Especialidades inválidas")
    item=Technician(user_id=user.id,available=payload.available,max_load=payload.max_load); db.add(item); db.flush()
    db.add_all([TechnicianSpecialty(technician_id=item.id,specialty_id=sid) for sid in ids]); audit(db,actor.id,"CREAR","TECNICOS","TECHNICIAN",item.id,new={"user_id":user.id},request=request);db.commit();return {"id":item.id}

@api.patch("/technicians/{technician_id}")
def update_technician(technician_id: str, payload: TechnicianIn, request: Request, actor: User = Depends(require_roles("ADMIN")), db: Session = Depends(get_db)):
    item=db.get(Technician,technician_id)
    if not item: not_found("Técnico")
    item.available = payload.available
    item.max_load = payload.max_load
    db.query(TechnicianSpecialty).filter_by(technician_id=item.id).delete()
    db.add_all([TechnicianSpecialty(technician_id=item.id,specialty_id=s) for s in set(payload.specialty_ids)])
    audit(db,actor.id,"ACTUALIZAR","TECNICOS","TECHNICIAN",item.id,new={"available":item.available},request=request);db.commit();return {"id":item.id}

@api.post("/tickets", status_code=201)
def create_ticket(payload: TicketCreate, request: Request, actor: User = Depends(require_roles("USUARIO")), db: Session = Depends(get_db)):
    if not db.get(Area,payload.area_id) or not db.get(Category,payload.category_id): raise HTTPException(422,"Área o categoría inválida")
    priority=db.get(Priority,payload.priority_id) if payload.priority_id else db.query(Priority).order_by(Priority.level).first()
    if not priority: raise HTTPException(500,"No existen prioridades configuradas")
    ticket=Ticket(number=next_number(db),title=payload.title,description=payload.description,requester_id=actor.id,area_id=payload.area_id,category_id=payload.category_id,priority_id=priority.id,state_id=state(db,"NUEVO").id,due_at=initial_due(priority))
    db.add(ticket); db.flush(); history(db,ticket.id,actor.id,"CREADO","Ticket creado",new={"priority":priority.code}); audit(db,actor.id,"CREAR","TICKETS","TICKET",ticket.id,new={"number":ticket.number},request=request)
    candidate=AssignmentService(db).select(ticket)
    if candidate: assign(db,ticket,candidate.technician,None,"AUTOMATICA",candidate.score,candidate.reason)
    for chief in db.query(User).join(User.role).filter(Role.code.in_(["ADMIN","JEFE_TI"]),User.active.is_(True)): notify(db,chief.id,"NUEVO_TICKET",f"Nuevo ticket {ticket.number}",ticket.title,ticket.id)
    db.commit(); return {"id":ticket.id,"number":ticket.number,"assigned":bool(candidate)}

@api.get("/tickets")
def list_tickets(state_code: str | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    query=db.query(Ticket).options(joinedload(Ticket.requester).joinedload(User.role),joinedload(Ticket.technician).joinedload(Technician.user),joinedload(Ticket.area),joinedload(Ticket.category),joinedload(Ticket.priority),joinedload(Ticket.state),joinedload(Ticket.rating))
    if user.role.code == "USUARIO": query=query.filter(Ticket.requester_id==user.id)
    elif user.role.code == "TECNICO": query=query.filter(Ticket.technician_id==user.technician.id) if user.technician else query.filter(False)
    if state_code: query=query.join(Ticket.state).filter(TicketState.code==state_code)
    return [ticket_data(x) for x in query.order_by(Ticket.created_at.desc()).all()]

@api.get("/tickets/{ticket_id}")
def read_ticket(ticket_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item=get_ticket(db,ticket_id);can_access_ticket(user,item);data=ticket_data(item)
    comments=db.query(TicketComment).options(joinedload(TicketComment.author)).filter_by(ticket_id=item.id).order_by(TicketComment.created_at).all()
    if user.role.code not in {"ADMIN","JEFE_TI","TECNICO"}: comments=[c for c in comments if not c.internal]
    data["comments"]=[{"id":c.id,"body":c.body,"internal":c.internal,"author":c.author.full_name,"created_at":c.created_at} for c in comments]
    data["history"]=[{"event":h.event,"detail":h.detail,"created_at":h.created_at,"actor":h.actor.full_name if h.actor else "Sistema"} for h in db.query(TicketHistory).options(joinedload(TicketHistory.actor)).filter_by(ticket_id=item.id).order_by(TicketHistory.created_at).all()]
    data["attachments"]=[{"id":a.id,"name":a.original_name,"content_type":a.content_type,"size":a.size} for a in db.query(TicketAttachment).filter_by(ticket_id=item.id)]
    return data

@api.post("/tickets/{ticket_id}/assign")
def assign_ticket(ticket_id: str, payload: AssignIn, request: Request, actor: User = Depends(require_roles("ADMIN","JEFE_TI")), db: Session = Depends(get_db)):
    item=get_ticket(db,ticket_id); candidate=None
    if payload.technician_id:
        tech=db.get(Technician,payload.technician_id)
        if not tech or not tech.available: raise HTTPException(422,"Técnico no disponible")
        assign(db,item,tech,actor.id,"MANUAL",None,payload.reason or "Asignación manual")
    else:
        candidate=AssignmentService(db).select(item)
        if not candidate: raise HTTPException(422,"No hay técnico compatible disponible")
        assign(db,item,candidate.technician,actor.id,"AUTOMATICA",candidate.score,candidate.reason)
    audit(db,actor.id,"ASIGNAR","TICKETS","TICKET",item.id,request=request);db.commit();return {"id":item.id,"technician_id":item.technician_id,"score":candidate.score if candidate else None}

@api.post("/tickets/{ticket_id}/accept")
def accept(ticket_id: str, request: Request, actor: User = Depends(require_roles("TECNICO")), db: Session = Depends(get_db)):
    item=get_ticket(db,ticket_id);can_access_ticket(actor,item); 
    if item.state.code != "ASIGNADO": raise HTTPException(422,"Solo se puede aceptar un ticket asignado")
    item.accepted_at=datetime.now(timezone.utc); set_state(db,item,"EN_ATENCION",actor.id); audit(db,actor.id,"ACEPTAR","TICKETS","TICKET",item.id,request=request);db.commit();return ticket_data(item)

@api.post("/tickets/{ticket_id}/transition")
def transition(ticket_id: str, payload: TransitionIn, request: Request, actor: User = Depends(current_user), db: Session = Depends(get_db)):
    item=get_ticket(db,ticket_id); target=payload.state.upper(); can_access_ticket(actor,item)
    if target in {"EN_ATENCION","EN_ESPERA","RESUELTO","ESCALADO"} and actor.role.code != "TECNICO": forbidden()
    if target in {"CERRADO","REABIERTO"} and not (actor.role.code in {"ADMIN","JEFE_TI"} or item.requester_id==actor.id): forbidden()
    if target == "CANCELADO" and actor.role.code not in {"ADMIN","JEFE_TI"}: forbidden()
    set_state(db,item,target,actor.id,payload.diagnosis,payload.solution);audit(db,actor.id,"TRANSICION","TICKETS","TICKET",item.id,new={"state":target},request=request);db.commit();return ticket_data(item)

@api.post("/tickets/{ticket_id}/comments", status_code=201)
def comment(ticket_id: str,payload: CommentIn,request: Request,actor: User=Depends(current_user),db: Session=Depends(get_db)):
    item=get_ticket(db,ticket_id);can_access_ticket(actor,item)
    if payload.internal and actor.role.code not in {"ADMIN","JEFE_TI","TECNICO"}: forbidden()
    c=TicketComment(ticket_id=item.id,author_id=actor.id,body=payload.body,internal=payload.internal);db.add(c);history(db,item.id,actor.id,"COMENTARIO","Comentario agregado")
    recipients={item.requester_id};
    if item.technician: recipients.add(item.technician.user_id)
    for user_id in recipients-{actor.id}:notify(db,user_id,"COMENTARIO",f"Actualización en {item.number}","Hay un nuevo comentario.",item.id)
    audit(db,actor.id,"COMENTAR","TICKETS","TICKET",item.id,request=request);db.commit();return {"id":c.id}

ALLOWED_TYPES={"image/png","image/jpeg","application/pdf","text/plain"}
@api.post("/tickets/{ticket_id}/attachments", status_code=201)
async def attachment(ticket_id: str,file: UploadFile=File(...),request: Request=None,actor: User=Depends(current_user),db: Session=Depends(get_db)):
    item=get_ticket(db,ticket_id);can_access_ticket(actor,item)
    if file.content_type not in ALLOWED_TYPES: raise HTTPException(415,"Tipo de archivo no permitido")
    raw=await file.read()
    if not raw or len(raw)>settings.max_upload_bytes: raise HTTPException(413,"Archivo vacío o excede el máximo permitido")
    suffix=Path(file.filename or "").suffix.lower(); stored=f"{uuid.uuid4()}{suffix}"; (settings.upload_path/stored).write_bytes(raw)
    record=TicketAttachment(ticket_id=item.id,uploader_id=actor.id,original_name=Path(file.filename or "archivo").name,stored_name=stored,content_type=file.content_type,size=len(raw));db.add(record);history(db,item.id,actor.id,"ADJUNTO","Evidencia adjunta");audit(db,actor.id,"ADJUNTAR","TICKETS","TICKET",item.id,request=request);db.commit();return {"id":record.id}

@api.get("/attachments/{attachment_id}")
def download_attachment(attachment_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    record=db.get(TicketAttachment,attachment_id)
    if not record: not_found("Adjunto")
    ticket=get_ticket(db,record.ticket_id);can_access_ticket(user,ticket)
    path=settings.upload_path/record.stored_name
    if not path.is_file(): not_found("Archivo")
    return FileResponse(path,media_type=record.content_type,filename=record.original_name)

@api.post("/tickets/{ticket_id}/rating",status_code=201)
def rating(ticket_id: str,payload: RatingIn,request: Request,actor: User=Depends(require_roles("USUARIO")),db: Session=Depends(get_db)):
    item=get_ticket(db,ticket_id);can_access_ticket(actor,item)
    if item.state.code not in {"RESUELTO","CERRADO"} or not item.technician_id: raise HTTPException(422,"El ticket debe estar resuelto y asignado")
    if item.rating: raise HTTPException(409,"El ticket ya tiene calificación")
    row=Rating(ticket_id=item.id,technician_id=item.technician_id,user_id=actor.id,**payload.model_dump());db.add(row);history(db,item.id,actor.id,"CALIFICADO",f"Calificación {payload.score}/5",new={"score":payload.score});notify(db,item.technician.user_id,"CALIFICACION",f"Nueva calificación {payload.score}/5",payload.comment or "",item.id);audit(db,actor.id,"CALIFICAR","TICKETS","TICKET",item.id,new={"score":payload.score},request=request);db.commit();return {"id":row.id}

@api.get("/notifications")
def notifications(actor: User=Depends(current_user),db: Session=Depends(get_db)):
    return [{"id":x.id,"type":x.type,"title":x.title,"body":x.body,"ticket_id":x.ticket_id,"read":bool(x.read_at),"created_at":x.created_at} for x in db.query(Notification).filter_by(user_id=actor.id).order_by(Notification.created_at.desc()).limit(100)]

@api.patch("/notifications/{notification_id}/read")
def read_notification(notification_id: str,actor: User=Depends(current_user),db: Session=Depends(get_db)):
    item=db.query(Notification).filter_by(id=notification_id,user_id=actor.id).first()
    if not item: not_found("Notificación")
    item.read_at=datetime.now(timezone.utc);db.commit();return {"ok":True}

@api.get("/dashboard")
def dashboard(actor: User=Depends(current_user),db: Session=Depends(get_db)):
    query=db.query(Ticket)
    if actor.role.code=="USUARIO":query=query.filter(Ticket.requester_id==actor.id)
    elif actor.role.code=="TECNICO":query=query.filter(Ticket.technician_id==actor.technician.id) if actor.technician else query.filter(False)
    tickets=query.options(joinedload(Ticket.state),joinedload(Ticket.priority),joinedload(Ticket.technician)).all();now=datetime.now(timezone.utc)
    counts={code:sum(1 for t in tickets if t.state.code==code) for code in ["NUEVO","ASIGNADO","EN_ATENCION","EN_ESPERA","RESUELTO","CERRADO","REABIERTO","ESCALADO"]}
    resolved=[t for t in tickets if t.resolved_at]; start=[t for t in tickets if t.started_at];
    avg_resolution=round(sum((t.resolved_at-t.created_at).total_seconds()/3600 for t in resolved)/len(resolved),1) if resolved else 0
    avg_attention=round(sum((t.started_at-t.created_at).total_seconds()/3600 for t in start)/len(start),1) if start else 0
    ratings=db.query(func.avg(Rating.score)).scalar() or 0
    by_category={x.name:sum(1 for t in tickets if t.category_id==x.id) for x in db.query(Category).all()}
    by_priority={x.code:sum(1 for t in tickets if t.priority_id==x.id) for x in db.query(Priority).all()}
    by_area={x.name:sum(1 for t in tickets if t.area_id==x.id) for x in db.query(Area).all()}
    by_state={code:value for code,value in counts.items() if value}
    trend={}
    for t in tickets:
        key=t.created_at.strftime("%Y-%m-%d")
        trend[key]=trend.get(key,0)+1
    performance=[]
    if actor.role.code in {"ADMIN","JEFE_TI"}:
        for tech in db.query(Technician).options(joinedload(Technician.user)).all():
            mine=[t for t in tickets if t.technician_id==tech.id]; score=db.query(func.avg(Rating.score)).filter(Rating.technician_id==tech.id).scalar() or 0
            performance.append({"name":tech.user.full_name,"assigned":len(mine),"resolved":sum(t.state.code in {"RESUELTO","CERRADO"} for t in mine),"rating":round(float(score),2)})
    return {"total":len(tickets),"counts":counts,"critical":sum(t.priority.code in {"CRITICA","ALTA"} for t in tickets),"overdue":sum(t.due_at and t.due_at<now and t.state.code not in {"RESUELTO","CERRADO","CANCELADO"} for t in tickets),"avg_attention_hours":avg_attention,"avg_resolution_hours":avg_resolution,"satisfaction":round(float(ratings),2),"by_category":by_category,"by_priority":by_priority,"by_area":by_area,"by_state":by_state,"trend":trend,"technician_performance":performance}

@api.get("/audit")
def audit_list(_: User=Depends(require_roles("ADMIN","JEFE_TI")),db: Session=Depends(get_db)):
    rows=db.query(AuditLog).options(joinedload(AuditLog.user)).order_by(AuditLog.created_at.desc()).limit(500).all()
    return [{"id":x.id,"user":x.user.full_name if x.user else "Sistema","action":x.action,"module":x.module,"entity":x.entity,"entity_id":x.entity_id,"created_at":x.created_at,"ip":x.ip} for x in rows]

@api.get("/settings")
def get_settings(_: User=Depends(require_roles("ADMIN")),db: Session=Depends(get_db)):
    return [{"key":x.key,"value":x.value,"description":x.description} for x in db.query(Setting).order_by(Setting.key)]

@api.put("/settings/{key}")
def update_setting(key: str,payload: SettingIn,request: Request,actor: User=Depends(require_roles("ADMIN")),db: Session=Depends(get_db)):
    if key not in WEIGHT_DEFAULTS: raise HTTPException(422,"Solo se permiten pesos de asignación configurados")
    try:
        value=float(payload.value)
        if not 0<=value<=1:raise ValueError()
    except ValueError: raise HTTPException(422,"El peso debe ser decimal entre 0 y 1")
    item=db.get(Setting,key);old={"value":item.value} if item else None
    if item:item.value=payload.value;item.description=payload.description
    else:item=Setting(key=key,value=payload.value,description=payload.description);db.add(item)
    audit(db,actor.id,"ACTUALIZAR","CONFIGURACION","SETTING",key,old,{"value":payload.value},request);db.commit();return {"key":key,"value":payload.value}

@api.get("/reports/tickets.csv")
def tickets_report(_: User=Depends(require_roles("ADMIN","JEFE_TI")),db: Session=Depends(get_db)):
    rows=db.query(Ticket).options(joinedload(Ticket.state),joinedload(Ticket.priority),joinedload(Ticket.area),joinedload(Ticket.category),joinedload(Ticket.technician).joinedload(Technician.user)).order_by(Ticket.created_at.desc()).all()
    output=io.StringIO();writer=csv.writer(output);writer.writerow(["Número","Título","Estado","Prioridad","Área","Categoría","Técnico","Creado","Vencimiento"])
    for t in rows:writer.writerow([t.number,t.title,t.state.code,t.priority.code,t.area.name,t.category.name,t.technician.user.full_name if t.technician else "",t.created_at,t.due_at])
    return StreamingResponse(iter([output.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=fixit-tickets.csv"})

def report_rows(db):
    return db.query(Ticket).options(joinedload(Ticket.state),joinedload(Ticket.priority),joinedload(Ticket.area),joinedload(Ticket.category),joinedload(Ticket.technician).joinedload(Technician.user)).order_by(Ticket.created_at.desc()).all()

@api.get("/reports/tickets.xlsx")
def tickets_xlsx(_: User=Depends(require_roles("ADMIN","JEFE_TI")),db: Session=Depends(get_db)):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    workbook=Workbook(); sheet=workbook.active; sheet.title="Tickets"
    headers=["Número","Título","Estado","Prioridad","Área","Categoría","Técnico","Creado","Vencimiento"]
    sheet.append(headers)
    for cell in sheet[1]: cell.font=Font(bold=True)
    for t in report_rows(db): sheet.append([t.number,t.title,t.state.code,t.priority.code,t.area.name,t.category.name,t.technician.user.full_name if t.technician else "",str(t.created_at),str(t.due_at or "")])
    for col in sheet.columns: sheet.column_dimensions[col[0].column_letter].width=min(45,max(12,max(len(str(c.value or "")) for c in col)+2))
    buffer=io.BytesIO();workbook.save(buffer);buffer.seek(0)
    return StreamingResponse(buffer,media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":"attachment; filename=fixit-tickets.xlsx"})

@api.get("/reports/tickets.pdf")
def tickets_pdf(_: User=Depends(require_roles("ADMIN","JEFE_TI")),db: Session=Depends(get_db)):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Spacer, Table, TableStyle, Paragraph
    buffer=io.BytesIO();document=SimpleDocTemplate(buffer,pagesize=landscape(letter),leftMargin=24,rightMargin=24,topMargin=24,bottomMargin=24)
    styles=getSampleStyleSheet();data=[["Número","Título","Estado","Prioridad","Área","Técnico"]]
    for t in report_rows(db): data.append([t.number,t.title[:45],t.state.code,t.priority.code,t.area.name,(t.technician.user.full_name if t.technician else "—")[:25]])
    table=Table(data,repeatRows=1,colWidths=[100,220,90,70,100,130]);table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#102a43")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.3,colors.lightgrey),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8fafc")])]))
    document.build([Paragraph("FixIT · Reporte de tickets",styles["Title"]),Spacer(1,12),table]);buffer.seek(0)
    return StreamingResponse(buffer,media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=fixit-tickets.pdf"})
